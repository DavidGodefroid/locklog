//go:build unix

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/hubclient"
)

// hub-key makes the instance key in the console's home on its first call
// and prints its public key, the same on every call.
func TestHubKey(t *testing.T) {
	home := t.TempDir()
	var out, errb bytes.Buffer
	if code := hubKey(home, []string{"--instance", "logs"}, &out, &errb); code != 0 {
		t.Fatalf("hub-key = %d %s", code, errb.String())
	}
	pub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out.String()))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key %q %v", out.String(), err)
	}
	key, err := hubclient.InstanceKey(home, "logs")
	if err != nil || !key.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(pub)) {
		t.Fatalf("not the instance key: %v", err)
	}
	var again bytes.Buffer
	if hubKey(home, []string{"--instance", "logs"}, &again, &errb) != 0 || again.String() != out.String() {
		t.Error("a second call changed the key")
	}
	for _, args := range [][]string{nil, {"--instance"}, {"--instance", "Bad_Name"}, {"--token", "s3cr3t"}, {"--instance", "logs", "extra"}} {
		var o, e bytes.Buffer
		if code := hubKey(home, args, &o, &e); code == 0 || o.Len() > 0 || strings.Contains(e.String(), "s3cr3t") {
			t.Errorf("hub-key %v = %d %q %q", args, code, o.String(), e.String())
		}
	}
}
