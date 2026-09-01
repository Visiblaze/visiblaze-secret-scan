#!/usr/bin/env bash
#
# Guard tests for the secret-scan action wrapper.
#
# These run the REAL script out of action.yml rather than a copy of its logic, because a test that
# re-implements the guard it is testing passes whether or not the guard still exists.
#
# Covered here: boolean validation, the refusal to run unpinned, a non-allowlisted api-url, a scan
# path escaping the checkout, a REAL tampered download rejected by the checksum guard (served over
# file:// with pins overridden through ACTION_PATH, so it exercises the actual download path), the
# integrity-vs-availability split, and a successful dry run that publishes its output contract.
#
# NOT covered, and this file should not be read as covering them: a missing OIDC token, a server-side
# tenant rejection, and a real upload. Those need a token endpoint and an ingest that can satisfy the
# steps before them; they are exercised end to end on a private testbed.
#
# Usage: tests/guards.sh
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd -P)"
ACTION="${HERE}/../action.yml"
SCRIPT="$(mktemp)"
WORKROOT="$(mktemp -d)"
trap 'rm -rf "$SCRIPT" "$WORKROOT"' EXIT

python3 - "$ACTION" "$SCRIPT" <<'PY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
open(sys.argv[2], "w").write("#!/usr/bin/env bash\n" + d["runs"]["steps"][0]["run"])
PY

# The action publishes linux builds only, so the platform gate fires first on any other host.
# Stubbed so the guards BELOW it are reachable — the gate itself is checked explicitly at the end.
STUB="${WORKROOT}/stub"; mkdir -p "$STUB"
cat > "${STUB}/uname" <<'EOS'
#!/bin/sh
case "$1" in
  -m) echo x86_64 ;;
  *)  echo Linux ;;
esac
EOS
chmod +x "${STUB}/uname"

PASS=0; FAIL=0
API_OK="https://qwc3m6imgj.execute-api.ap-south-1.amazonaws.com/v1/code/secrets"

# run <name> <want-exit> <want-substring> [VAR=val ...]
run() {
  local name="$1" want_rc="$2" want_out="$3"; shift 3
  local out rc gho="${WORKROOT}/gho.$RANDOM"
  : > "$gho"
  out="$(env PATH="${STUB}:$PATH" GITHUB_OUTPUT="$gho" \
        IN_TENANT=t IN_API="$API_OK" IN_REPO_KEY='github#1' IN_PATH=. IN_SCOPE= \
        IN_FAIL_ON= IN_FAIL_ON_ERROR=false IN_DRY_RUN=true \
        ACTION_PATH="${WORKROOT}/actdir" GH_REPO_ID=1 GH_REF_NAME=main GH_SHA=abc \
        GH_WORKSPACE="${WORKROOT}/ws" "$@" bash "$SCRIPT" 2>&1)"
  rc=$?
  LAST_GHO="$gho"
  if [ "$rc" != "$want_rc" ] || ! printf '%s' "$out" | grep -q -- "$want_out"; then
    printf '  FAIL  %s\n        exit=%s (want %s)\n        out=%s\n' \
      "$name" "$rc" "$want_rc" "$(printf '%s' "$out" | tail -2)"
    FAIL=$((FAIL+1)); return 1
  fi
  printf '  ok    %s\n' "$name"
  PASS=$((PASS+1))
}

mkdir -p "${WORKROOT}/ws"
echo 'aws_access_key_id = AKIAIOSFODNN7EXAMPLE' > "${WORKROOT}/ws/settings.conf"

pins() {
  mkdir -p "${WORKROOT}/actdir"
  { echo "SCANNER_BASE_URL=${1}"
    echo "SCANNER_VERSION=${2}"
    echo "SCANNER_SHA256_LINUX_AMD64=${3}"
    echo "SCANNER_SHA256_LINUX_ARM64=${3}"
    echo "ALLOWED_API_ORIGINS=https://qwc3m6imgj.execute-api.ap-south-1.amazonaws.com"
  } > "${WORKROOT}/actdir/pins.env"
}

echo "== integrity guards must be fatal REGARDLESS of fail-on-error =="
pins "file://${WORKROOT}/rel" UNSET UNSET
run "unpinned version refused (fail-on-error=false)" 1 "SCANNER_VERSION is unset"
pins "file://${WORKROOT}/rel" v9.9.9 UNSET
run "unpinned digest refused" 1 "no scanner digest"
pins "file://${WORKROOT}/rel" v9.9.9 deadbeef
run "non-allowlisted api-url refused" 1 "is not one this action permits" IN_API=https://evil.example.com/x
run "non-https api-url refused" 1 "must be https" IN_API=http://qwc3m6imgj.execute-api.ap-south-1.amazonaws.com/x
mkdir -p "${WORKROOT}/outside"
run "path escaping the checkout refused" 1 "resolves outside the checkout" IN_PATH=../outside
run "nonexistent path refused" 1 "does not exist inside the checkout" IN_PATH=nope

echo "== booleans are validated, not guessed =="
run "dry-run: 'maybe' refused outright" 1 "dry-run must be true or false" IN_DRY_RUN=maybe
run "fail-on-error: 'maybe' refused outright" 1 "fail-on-error must be true or false" IN_FAIL_ON_ERROR=maybe

echo "== a real tampered artefact is rejected before execution =="
BIN="${WORKROOT}/bin"; mkdir -p "$BIN"
printf '#!/bin/sh\necho "SHOULD NEVER RUN"\nexit 0\n' > "${BIN}/visiblaze-secret-scan"
chmod +x "${BIN}/visiblaze-secret-scan"
mkdir -p "${WORKROOT}/rel/v9.9.9"
tar -czf "${WORKROOT}/rel/v9.9.9/visiblaze-secret-scan_v9.9.9_linux_amd64.tar.gz" -C "$BIN" visiblaze-secret-scan
GOOD="$(shasum -a 256 "${WORKROOT}/rel/v9.9.9/visiblaze-secret-scan_v9.9.9_linux_amd64.tar.gz" | awk '{print $1}')"
pins "file://${WORKROOT}/rel" v9.9.9 "$GOOD"
printf 'tampered' >> "${WORKROOT}/rel/v9.9.9/visiblaze-secret-scan_v9.9.9_linux_amd64.tar.gz"
run "tampered archive rejected, nothing executed" 1 "checksum mismatch"
if [ -n "${LAST_GHO:-}" ] && grep -q "SHOULD NEVER RUN" "$LAST_GHO" 2>/dev/null; then
  echo "  FAIL  the tampered binary was executed"; FAIL=$((FAIL+1))
fi

echo "== the happy path publishes its output contract =="
printf '#!/bin/sh\necho verified-stub-ran\nexit 0\n' > "${BIN}/visiblaze-secret-scan"
chmod +x "${BIN}/visiblaze-secret-scan"
tar -czf "${WORKROOT}/rel/v9.9.9/visiblaze-secret-scan_v9.9.9_linux_amd64.tar.gz" -C "$BIN" visiblaze-secret-scan
GOOD="$(shasum -a 256 "${WORKROOT}/rel/v9.9.9/visiblaze-secret-scan_v9.9.9_linux_amd64.tar.gz" | awk '{print $1}')"
pins "file://${WORKROOT}/rel" v9.9.9 "$GOOD"
# The stub writes no summary file, so the wrapper must still emit placeholders rather than leaving
# the declared outputs unwritten.
if run "verified archive is executed" 0 "verified-stub-ran"; then
  grep -q "^status=complete" "$LAST_GHO" \
    || { echo "  FAIL  status=complete missing from GITHUB_OUTPUT"; FAIL=$((FAIL+1)); }
  for key in findings actionable; do
    grep -q "^${key}=" "$LAST_GHO" \
      || { echo "  FAIL  ${key} missing from GITHUB_OUTPUT — a declared output that is never written reads as an empty string, and \"empty != 0\" is true"; FAIL=$((FAIL+1)); }
  done
fi

# 'True' must mean TRUE. Tested here and not earlier, because this is the only point where the two
# readings diverge observably: a dry run executes the scanner, whereas a run treated as REAL stops
# at the OIDC guard first ("no OIDC token available") since no token endpoint is present. Under the
# original exact-compare against lowercase "true", a plausible YAML capital performed a real upload.
run "dry-run: 'True' means true, not false" 0 "verified-stub-ran" IN_DRY_RUN=True

echo "== the platform gate itself =="
out="$(env GITHUB_OUTPUT="${WORKROOT}/g2" IN_TENANT=t IN_API="$API_OK" IN_REPO_KEY='github#1' \
      IN_PATH=. IN_SCOPE= IN_FAIL_ON= IN_FAIL_ON_ERROR=true IN_DRY_RUN=true \
      ACTION_PATH="${WORKROOT}/actdir" GH_REPO_ID=1 GH_REF_NAME=main GH_SHA=abc \
      GH_WORKSPACE="${WORKROOT}/ws" bash "$SCRIPT" 2>&1)"
case "$(uname -s)" in
  Linux) printf '  skip  unsupported-OS gate (this host IS Linux)\n' ;;
  *) if printf '%s' "$out" | grep -q "unsupported runner OS"; then
       printf '  ok    unsupported OS refused\n'; PASS=$((PASS+1))
     else
       printf '  FAIL  unsupported OS not refused\n'; FAIL=$((FAIL+1))
     fi ;;
esac

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
