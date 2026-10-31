//go:build unix

package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// installFixture is a local release base (LOCKLOG_RELEASE_BASE) with one
// release, v1.2.3, holding the launcher of this checkout, and a fake
// cosign whose answers the test sets.
type installFixture struct {
	root, base, bin, dest string
}

const (
	testDigest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	testVDigest = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
)

func newInstallFixture(t *testing.T) *installFixture {
	t.Helper()
	root := t.TempDir()
	f := &installFixture{root: root, base: filepath.Join(root, "rel"), bin: filepath.Join(root, "bin"), dest: filepath.Join(root, "dest")}
	rel := filepath.Join(f.base, "v1.2.3")
	for _, d := range []string{rel, f.bin} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	launcher, err := os.ReadFile(filepath.Join("..", "..", "scripts", "locklog"))
	if err != nil {
		t.Fatal(err)
	}
	archive := "locklog_1.2.3_" + runtime.GOOS + "_" + runtime.GOARCH + ".tar.gz"
	ap := filepath.Join(rel, archive)
	writeTarGz(t, ap, map[string][]byte{"scripts/locklog": launcher, "LICENSE": []byte("x")})
	b, _ := os.ReadFile(ap)
	sum := sha256.Sum256(b)
	if err := os.WriteFile(filepath.Join(rel, "checksums.txt"), []byte(hex.EncodeToString(sum[:])+"  "+archive+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rel, "checksums.txt.sigstore.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"sh", "mkdir", "id", "cat", "cp", "awk", "sha256sum", "shasum", "tar", "gzip", "install",
		"mktemp", "rm", "uname", "sed", "tr", "tail", "grep", "printf"} {
		if p, err := exec.LookPath(tool); err == nil {
			if err := os.Symlink(p, filepath.Join(f.bin, tool)); err != nil {
				t.Fatal(err)
			}
		}
	}
	// curl: no network in tests.
	writeExec(t, filepath.Join(f.bin, "curl"), "#!/bin/sh\nexit 7\n")
	// cosign: verify-blob exits BLOB_RC; verify prints the digest of the
	// tag (the -vault one for :X.Y.Z-vault) unless IMAGE_RC is set.
	writeExec(t, filepath.Join(f.bin, "cosign"), `#!/bin/sh
printf '%s\n' "$*" >> '`+filepath.Join(root, "cosign.calls")+`'
case "$1" in
verify-blob) exit "${BLOB_RC:-0}" ;;
verify)
	[ -n "${IMAGE_RC:-}" ] && exit "$IMAGE_RC"
	for a in "$@"; do last=$a; done
	case "$last" in
	*-vault) d='`+testVDigest+`' ;;
	*) d='`+testDigest+`' ;;
	esac
	printf '[{"critical":{"identity":{"docker-reference":"x"},"image":{"docker-manifest-digest":"%s"}}}]\n' "$d" ;;
esac
`)
	return f
}

func writeTarGz(t *testing.T, path string, files map[string][]byte) {
	t.Helper()
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}

func (f *installFixture) run(t *testing.T, env ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(f.bin, "sh"), filepath.Join("..", "..", "scripts", "install.sh"))
	cmd.Env = append([]string{"PATH=" + f.bin, "HOME=" + f.root, "LOCKLOG_INSTALL_DIR=" + f.dest}, env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestInstallSh(t *testing.T) {
	f := newInstallFixture(t)
	out, err := f.run(t, "LOCKLOG_RELEASE_BASE="+f.base, "LOCKLOG_VERSION=v1.2.3")
	if err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	b, err := os.ReadFile(filepath.Join(f.dest, "locklog"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, line := range []string{"launcher_version=1.2.3", "image_digest=" + testDigest, "vault_image_digest=" + testVDigest} {
		if !strings.Contains(s, "\n"+line+"\n") {
			t.Errorf("installed launcher lacks %q", line)
		}
	}
	calls, _ := os.ReadFile(filepath.Join(f.root, "cosign.calls"))
	if !strings.Contains(string(calls), "--certificate-identity https://github.com/DavidGodefroid/locklog/.github/workflows/release.yml@refs/tags/v1.2.3") {
		t.Errorf("cosign identity: %s", calls)
	}
	if fi, _ := os.Stat(filepath.Join(f.dest, "locklog")); fi.Mode().Perm() != 0o755 {
		t.Errorf("mode %v", fi.Mode())
	}
}

func TestInstallShSnapshot(t *testing.T) {
	f := newInstallFixture(t)
	if err := os.Remove(filepath.Join(f.bin, "cosign")); err != nil {
		t.Fatal(err)
	}
	out, err := f.run(t, "LOCKLOG_RELEASE_BASE="+f.base, "LOCKLOG_VERSION=1.2.3", "LOCKLOG_SKIP_COSIGN=1")
	if err != nil || !strings.Contains(out, "signatures are NOT checked") {
		t.Fatalf("snapshot install: %v\n%s", err, out)
	}
	b, _ := os.ReadFile(filepath.Join(f.dest, "locklog"))
	if !strings.Contains(string(b), "\nlauncher_version=1.2.3\n") || !strings.Contains(string(b), "\nimage_digest=\n") {
		t.Error("snapshot launcher: wrong version or a digest")
	}
}

func TestInstallShRefusals(t *testing.T) {
	f := newInstallFixture(t)
	local := "LOCKLOG_RELEASE_BASE=" + f.base
	for _, tt := range []struct {
		env  []string
		part string
	}{
		{[]string{"LOCKLOG_SKIP_COSIGN=1", "LOCKLOG_VERSION=v1.2.3"}, "only accepted with a local LOCKLOG_RELEASE_BASE"},
		{[]string{"LOCKLOG_SKIP_COSIGN=1", "LOCKLOG_VERSION=v1.2.3", "LOCKLOG_RELEASE_BASE=https://example.com/rel"}, "only accepted with a local"},
		{[]string{local}, "needs LOCKLOG_VERSION"},
		{[]string{local, "LOCKLOG_VERSION=v1.2"}, "invalid version"},
		{[]string{local, "LOCKLOG_VERSION=v1.2.3;rm"}, "invalid version"},
		{[]string{local, "LOCKLOG_VERSION=v9.9.9"}, "download failed"},
		{[]string{local, "LOCKLOG_VERSION=v1.2.3", "BLOB_RC=1"}, "signature of checksums.txt does not verify"},
		{[]string{local, "LOCKLOG_VERSION=v1.2.3", "IMAGE_RC=1"}, "does not verify, or the image is not published"},
		{[]string{"LOCKLOG_RELEASE_BASE=http://example.com", "LOCKLOG_VERSION=v1.2.3"}, "must be an https URL or an absolute directory"},
		{[]string{"LOCKLOG_RELEASE_BASE=" + filepath.Join(f.root, "none"), "LOCKLOG_VERSION=v1.2.3"}, "no directory"},
	} {
		out, err := f.run(t, tt.env...)
		if err == nil || !strings.Contains(out, tt.part) {
			t.Errorf("%v: err %v, want %q in:\n%s", tt.env, err, tt.part, out)
		}
		if _, err := os.Stat(filepath.Join(f.dest, "locklog")); err == nil {
			t.Errorf("%v: installed anyway", tt.env)
			_ = os.Remove(filepath.Join(f.dest, "locklog"))
		}
	}
	// A tampered archive.
	rel := filepath.Join(f.base, "v1.2.3")
	archive := filepath.Join(rel, "locklog_1.2.3_"+runtime.GOOS+"_"+runtime.GOARCH+".tar.gz")
	if err := os.WriteFile(archive, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := f.run(t, local, "LOCKLOG_VERSION=v1.2.3"); err == nil || !strings.Contains(out, "checksum mismatch") {
		t.Errorf("tampered: %v %s", err, out)
	}
	// No cosign, no skip.
	if err := os.Remove(filepath.Join(f.bin, "cosign")); err != nil {
		t.Fatal(err)
	}
	if out, err := f.run(t, local, "LOCKLOG_VERSION=v1.2.3"); err == nil || !strings.Contains(out, "cosign is required") {
		t.Errorf("no cosign: %v %s", err, out)
	}
}
