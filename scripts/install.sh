#!/bin/sh
# Installs the locklog launcher of a release on Linux or macOS. locklog runs
# in Docker: the launcher, installed as `locklog`, runs every command in the
# release's image (scripts/locklog). Nothing else lands on the host.
#
#   curl -fsSL https://locklog.dev/install.sh | sh
#
# or, to read it first, from the tag you install:
#
#   V=vX.Y.Z
#   curl -fsSLO "https://raw.githubusercontent.com/DavidGodefroid/locklog/$V/scripts/install.sh"
#   less install.sh
#   LOCKLOG_VERSION=$V sh install.sh
#
# Prerequisites: Docker 19.03 or later on the host with the logs, cosign
# (https://docs.sigstore.dev/cosign/system_config/installation/), and sudo
# to write /usr/local/bin.
#
# Environment:
#   LOCKLOG_VERSION       tag to install (default: the latest published
#                         release), e.g. v0.1.0
#   LOCKLOG_INSTALL_DIR   target directory (default: /usr/local/bin, owned
#                         by root, through sudo when needed)
#   LOCKLOG_RELEASE_BASE  a mirror of the releases: an https URL or a local
#                         directory holding vX.Y.Z/ folders (a snapshot)
#   LOCKLOG_SKIP_COSIGN=1 only with a local LOCKLOG_RELEASE_BASE: install
#                         without checking signatures (tests of snapshots)
#
# cosign is required: the keyless signature of checksums.txt must come from
# this repository's release workflow run for that very tag, the archive is
# checked against checksums.txt, and the image's signature is checked the
# same way; the launcher then runs the image by that digest.
set -eu

repo="DavidGodefroid/locklog"
registry="ghcr.io/davidgodefroid/locklog"
issuer="https://token.actions.githubusercontent.com"
dir="${LOCKLOG_INSTALL_DIR:-/usr/local/bin}"

say() { printf 'locklog: %s\n' "$*" >&2; }
die() {
	say "$*"
	exit 1
}

base="${LOCKLOG_RELEASE_BASE:-https://github.com/$repo/releases/download}"
local_base=
case "$base" in
/*)
	local_base=1
	[ -d "$base" ] || die "LOCKLOG_RELEASE_BASE: no directory $base"
	fetch() { cp "$1" "$2"; }
	latest() { return 1; }
	;;
https://*)
	if command -v curl >/dev/null 2>&1; then
		fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$2" "$1"; }
		latest() { curl -fsSLI --proto '=https' --tlsv1.2 -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest"; }
	elif command -v wget >/dev/null 2>&1; then
		fetch() { wget -q -O "$2" "$1"; }
		latest() { wget -q -S --spider "https://github.com/$repo/releases/latest" 2>&1 | sed -n 's/^ *[Ll]ocation: *//p' | tail -n 1 | tr -d '\r'; }
	else
		die "curl or wget is required"
	fi
	;;
*) die "LOCKLOG_RELEASE_BASE must be an https URL or an absolute directory" ;;
esac

skip_cosign=
if [ "${LOCKLOG_SKIP_COSIGN:-0}" = 1 ]; then
	[ -n "$local_base" ] || die "LOCKLOG_SKIP_COSIGN=1 is only accepted with a local LOCKLOG_RELEASE_BASE (a snapshot)"
	skip_cosign=1
	say "WARNING: LOCKLOG_SKIP_COSIGN=1: signatures are NOT checked (snapshot install)"
elif ! command -v cosign >/dev/null 2>&1; then
	die "cosign is required to check the release's signature (https://docs.sigstore.dev/cosign/system_config/installation/)"
fi

case "$(uname -s)" in
Linux) os=linux ;;
Darwin) os=darwin ;;
*) die "unsupported OS $(uname -s): Linux and macOS only" ;;
esac
case "$(uname -m)" in
x86_64 | amd64) arch=amd64 ;;
aarch64 | arm64) arch=arm64 ;;
*) die "unsupported architecture $(uname -m): amd64 and arm64 only" ;;
esac

tag="${LOCKLOG_VERSION:-}"
if [ -z "$tag" ]; then
	[ -z "$local_base" ] || die "a local LOCKLOG_RELEASE_BASE needs LOCKLOG_VERSION"
	# /releases/latest names the latest published release: a draft (a
	# release whose images are not signed yet) is never it.
	tag="$(latest)" || tag=""
	tag="${tag##*/}"
	case "$tag" in
	v[0-9]*) ;;
	*) die "no published release found; set LOCKLOG_VERSION" ;;
	esac
fi
case "$tag" in v*) ;; *) tag="v$tag" ;; esac
# Only a version tag: it goes into URLs and into the launcher's text.
printf '%s\n' "$tag" | grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?' ||
	die "invalid version $tag: a release tag, vX.Y.Z"
version="${tag#v}"

archive="locklog_${version}_${os}_${arch}.tar.gz"
url="$base/$tag"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

say "downloading $archive ($tag)"
fetch "$url/$archive" "$tmp/$archive" || die "download failed: $url/$archive"
fetch "$url/checksums.txt" "$tmp/checksums.txt" || die "download failed: checksums.txt"

# The release workflow run for this very tag: a tag moved to an older
# release's signed files does not verify.
identity="https://github.com/$repo/.github/workflows/release.yml@refs/tags/$tag"
if [ -z "$skip_cosign" ]; then
	fetch "$url/checksums.txt.sigstore.json" "$tmp/checksums.txt.sigstore.json" ||
		die "download failed: checksums.txt.sigstore.json"
	cosign verify-blob --bundle "$tmp/checksums.txt.sigstore.json" \
		--certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
		"$tmp/checksums.txt" >/dev/null 2>&1 || die "cosign: signature of checksums.txt does not verify"
	say "cosign: checksums.txt signature verified"
fi

want="$(awk -v f="$archive" '$2 == f { print $1 }' "$tmp/checksums.txt")"
[ -n "$want" ] || die "$archive is not listed in checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
	got="$(sha256sum "$tmp/$archive" | awk '{ print $1 }')"
else
	got="$(shasum -a 256 "$tmp/$archive" | awk '{ print $1 }')"
fi
[ "$want" = "$got" ] || die "checksum mismatch for $archive"

tar -xzf "$tmp/$archive" -C "$tmp" scripts/locklog 2>/dev/null ||
	die "$archive holds no launcher (scripts/locklog)"

# The launcher runs the image of its own version, by the digest whose
# cosign signature verifies (the release workflow, as for checksums.txt).
verified_digest() {
	cosign verify --certificate-identity "$identity" --certificate-oidc-issuer "$issuer" \
		"$registry:$1" 2>/dev/null |
		sed -n 's/.*"docker-manifest-digest":"\(sha256:[0-9a-f]\{64\}\)".*/\1/p' | sed -n 1p
}
digest=
vdigest=
if [ -z "$skip_cosign" ]; then
	digest="$(verified_digest "$version")"
	vdigest="$(verified_digest "$version-vault")"
	[ -n "$digest" ] && [ -n "$vdigest" ] && [ "$digest" != "$vdigest" ] ||
		die "cosign: the signature of $registry:$version (and -vault) does not verify, or the image is not published yet"
	say "cosign: image $registry:$version verified ($digest)"
else
	say "WARNING: the image is NOT verified and runs by its tag ($registry:$version), or LOCKLOG_IMAGE"
fi
sed -e "s/^launcher_version=dev\$/launcher_version=$version/" \
	-e "s/^image_digest=\$/image_digest=$digest/" \
	-e "s/^vault_image_digest=\$/vault_image_digest=$vdigest/" \
	"$tmp/scripts/locklog" >"$tmp/launcher"
grep -qx "launcher_version=$version" "$tmp/launcher" || die "the launcher of $tag does not take its version"

# Root-owned in a system directory, so that an agent's account cannot
# replace it. LOCKLOG_INSTALL_DIR installs it as you instead.
if [ -n "${LOCKLOG_INSTALL_DIR:-}" ]; then
	mkdir -p "$dir"
	install -m 0755 "$tmp/launcher" "$dir/locklog"
	say "installed as $(id -un) (LOCKLOG_INSTALL_DIR): an account that can write $dir can replace the launcher"
elif [ "$(id -u)" = 0 ]; then
	mkdir -p "$dir"
	install -o 0 -g 0 -m 0755 "$tmp/launcher" "$dir/locklog"
else
	command -v sudo >/dev/null 2>&1 || die "sudo is required to install to $dir (owned by root); or set LOCKLOG_INSTALL_DIR"
	say "installing to $dir with sudo"
	sudo mkdir -p "$dir"
	sudo install -o 0 -g 0 -m 0755 "$tmp/launcher" "$dir/locklog"
fi

say "installed the locklog launcher $tag to $dir/locklog (image $registry:$version${digest:+@$digest})"
case ":$PATH:" in
*":$dir:"*) ;;
*) say "$dir is not on your PATH" ;;
esac
command -v docker >/dev/null 2>&1 || say "docker is not installed: the launcher needs it"
say "next: locklog setup"
