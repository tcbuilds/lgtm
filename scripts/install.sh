#!/bin/sh
set -eu

REPOSITORY=${LGTM_REPOSITORY:-tcbuilds/lgtm}
INSTALL_DIR=${LGTM_INSTALL_DIR:-"$HOME/.local/bin"}
VERSION=${VERSION:-}

fail() {
  printf 'lgtm install failed: %s\n' "$1" >&2
  exit 1
}

command -v gh >/dev/null 2>&1 || fail "GitHub CLI (gh) is required for this private repository"
gh auth status --hostname github.com >/dev/null 2>&1 || fail "authenticate GitHub CLI with access to $REPOSITORY"

os=$(uname -s)
arch=$(uname -m)
test "$arch" = "x86_64" || fail "unsupported architecture: $arch (supported: x86_64)"
case "$os" in
  Linux) target=x86_64-unknown-linux-gnu ;;
  Darwin) target=x86_64-apple-darwin ;;
  *) fail "unsupported operating system: $os (supported: Linux, Darwin)" ;;
esac

if test -z "$VERSION"; then
  VERSION=$(gh release view --repo "$REPOSITORY" --json tagName --jq .tagName 2>/dev/null) \
    || fail "could not resolve the latest private release"
fi
case "$VERSION" in
  v[0-9]*) ;;
  *) fail "VERSION must be a v-prefixed release tag" ;;
esac
case "$VERSION" in
  *[!A-Za-z0-9._-]*) fail "VERSION contains unsafe characters" ;;
esac

archive="lgtm-$VERSION-$target.tar.gz"
checksum="$archive.sha256"
stage=
temp_dir=$(mktemp -d "${TMPDIR:-/tmp}/lgtm-install.XXXXXX") || fail "could not create temporary directory"

cleanup() {
  test -z "$stage" || test ! -f "$stage" || unlink "$stage"
  test ! -f "$temp_dir/lgtm" || unlink "$temp_dir/lgtm"
  test ! -f "$temp_dir/$archive" || unlink "$temp_dir/$archive"
  test ! -f "$temp_dir/$checksum" || unlink "$temp_dir/$checksum"
  rmdir "$temp_dir" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

mkdir -p "$INSTALL_DIR" || fail "could not create install directory: $INSTALL_DIR"
stage=$(mktemp "$INSTALL_DIR/.lgtm.install.XXXXXX") || fail "could not create atomic install stage"

gh release download "$VERSION" --repo "$REPOSITORY" --dir "$temp_dir" \
  --pattern "$archive" --pattern "$checksum" \
  || fail "private release download failed; verify the tag and repository access"

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$temp_dir" && sha256sum -c "$checksum") >/dev/null 2>&1 || fail "checksum verification failed"
else
  (cd "$temp_dir" && shasum -a 256 -c "$checksum") >/dev/null 2>&1 || fail "checksum verification failed"
fi

tar -C "$temp_dir" -xzf "$temp_dir/$archive" lgtm || fail "release archive is malformed"
install -m 755 "$temp_dir/lgtm" "$stage" || fail "could not stage binary in $INSTALL_DIR"
mv -f "$stage" "$INSTALL_DIR/lgtm" || fail "could not atomically install binary"
printf 'Installed lgtm %s to %s/lgtm\n' "$VERSION" "$INSTALL_DIR"
