#!/bin/sh
set -eu

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/lgtm-install-test.XXXXXX")
BIN="$ROOT/bin"
ASSETS="$ROOT/assets"
DEST="$ROOT/dest"
mkdir -p "$BIN" "$ASSETS" "$DEST"

cleanup() {
  for file in "$DEST/lgtm" "$ASSETS/lgtm" "$ASSETS"/*.tar.gz "$ASSETS"/*.sha256 "$BIN/gh" "$BIN/uname"; do
    test ! -f "$file" || unlink "$file"
  done
  rmdir "$DEST" "$ASSETS" "$BIN" "$ROOT" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

printf '#!/bin/sh\nprintf "fixture lgtm\\n"\n' > "$ASSETS/lgtm"
chmod 755 "$ASSETS/lgtm"
archive="$ASSETS/lgtm-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
tar -C "$ASSETS" -czf "$archive" lgtm
(cd "$ASSETS" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")

cat > "$BIN/gh" <<'EOF'
#!/bin/sh
set -eu
if test "$1 $2" = "auth status"; then test "${FAKE_AUTH_FAIL:-0}" != 1; exit; fi
if test "$1 $2" = "release view"; then printf 'v0.1.0\n'; exit 0; fi
if test "$1 $2" = "release download"; then
  destination=""
  while test "$#" -gt 0; do
    if test "$1" = "--dir"; then destination=$2; shift 2; else shift; fi
  done
  cp "$FAKE_ASSETS"/*.tar.gz "$FAKE_ASSETS"/*.sha256 "$destination/"
  exit 0
fi
exit 1
EOF
cat > "$BIN/uname" <<'EOF'
#!/bin/sh
if test "${1:-}" = "-s"; then printf '%s\n' "${FAKE_OS:-Linux}"; else printf '%s\n' "${FAKE_ARCH:-x86_64}"; fi
EOF
chmod 755 "$BIN/gh" "$BIN/uname"

PATH="$BIN:$PATH" FAKE_ASSETS="$ASSETS" LGTM_INSTALL_DIR="$DEST" VERSION=v0.1.0 \
  sh "$(dirname "$0")/install.sh" >/dev/null
test -x "$DEST/lgtm"
test "$("$DEST/lgtm")" = "fixture lgtm"

set +e
PATH="$BIN:$PATH" FAKE_ASSETS="$ASSETS" FAKE_ARCH=arm64 LGTM_INSTALL_DIR="$DEST" VERSION=v0.1.0 \
  sh "$(dirname "$0")/install.sh" >"$ROOT/unsupported.out" 2>"$ROOT/unsupported.err"
code=$?
set -e
test "$code" -ne 0
grep -q "unsupported architecture" "$ROOT/unsupported.err"
unlink "$ROOT/unsupported.out"
unlink "$ROOT/unsupported.err"

set +e
PATH="$BIN:$PATH" FAKE_AUTH_FAIL=1 LGTM_INSTALL_DIR="$DEST" VERSION=v0.1.0 \
  sh "$(dirname "$0")/install.sh" >"$ROOT/auth.out" 2>"$ROOT/auth.err"
code=$?
set -e
test "$code" -ne 0
grep -q "authenticate GitHub CLI" "$ROOT/auth.err"
unlink "$ROOT/auth.out"
unlink "$ROOT/auth.err"

set +e
PATH="$BIN:$PATH" FAKE_ASSETS="$ASSETS" LGTM_INSTALL_DIR="$DEST" VERSION='v1/../../unsafe' \
  sh "$(dirname "$0")/install.sh" >"$ROOT/version.out" 2>"$ROOT/version.err"
code=$?
set -e
test "$code" -ne 0
grep -q "unsafe characters" "$ROOT/version.err"
unlink "$ROOT/version.out"
unlink "$ROOT/version.err"
printf 'installer tests passed\n'
