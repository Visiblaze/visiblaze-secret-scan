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
# The stub answers -h like the real binary, because the action FEATURE-DETECTS the baseline flags
# before using them. A stub that does not advertise -base-dir makes the whole baseline block skip,
# and a test against it passes while proving nothing about the block.
cat > "${BIN}/visiblaze-secret-scan" <<'STUB'
#!/bin/sh
case "$1" in
  -h|--help) echo "  -base-dir string"; echo "  -base-sha string"; echo "  -repo-key string"; exit 0 ;;
esac
echo verified-stub-ran
exit 0
STUB
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

echo "== the baseline block =="
# These exist because the block was added WITHOUT them and broke two unrelated guards: the script
# runs under `set -u`, and BASE_SHA / GH_EVENT are unset on anything that is not a pull request.
# An unbound variable there turns every push into a hard failure of a step that should pass.
# GH_EVENT is read OUTSIDE the baseline block, so a dry run exercises the unset case that broke
# two guards when this was added.
run "a push run with GH_EVENT and BASE_SHA unset still completes" 0 "verified-stub-ran" IN_DRY_RUN=true
# For the in-block variables the run must be non-dry. ACTIONS_ID_TOKEN_REQUEST_URL is forced empty
# so the OIDC guard fires on EVERY host: without that the exit code depends on where the suite runs
# — 1 on a laptop with no token, 0 on a real Actions runner that has one — and the test passed
# locally for a reason that had nothing to do with what it was checking. The message is the
# assertion; the exit code just has to be the same everywhere.
run "a pull_request run with no git history degrades, never crashes" 1 "no git history available" \
    IN_DRY_RUN=false IN_FAIL_ON_ERROR=true BASE_SHA=aaa111 BASE_REF=main GH_EVENT=pull_request \
    ACTIONS_ID_TOKEN_REQUEST_URL=
# A dry run must not build a baseline at all: it is a local preview, and deepening someone's
# checkout to preview is a side effect they did not ask for.
if run "a dry run requests no baseline" 0 "verified-stub-ran" \
    IN_DRY_RUN=true BASE_SHA=aaa111 BASE_REF=main GH_EVENT=pull_request; then
  grep -q "merge base" "$LAST_GHO" 2>/dev/null && { echo "  FAIL  a dry run resolved a merge base"; FAIL=$((FAIL+1)); }
fi

echo "== the merge base is resolved from the PR HEAD, not the checked-out HEAD =="
# THE subtle one, and the only guard here that needs real git history.
#
# On a pull_request event the workspace sits at refs/pull/N/merge, whose FIRST PARENT is the base
# branch tip. So `merge-base HEAD "$BASE_SHA"` returns BASE_SHA itself — not an error, just the
# wrong commit: the base TIP rather than the fork point. Every credential that landed on the base
# branch since the branch was cut then reads as introduced by this pull request, and the baseline is
# stored under a sha the platform never reads.
#
# The fixture makes tip and fork point DIFFERENT, so the two answers are distinguishable.
GITWS="${WORKROOT}/gitws"
mkdir -p "$GITWS"
(
  cd "$GITWS"
  git init -q -b main && git config user.email t@t && git config user.name t
  echo a > f.txt && git add -A && git commit -qm A          # A = the fork point
  FORK=$(git rev-parse HEAD)
  git checkout -q -b feature && echo b >> f.txt && git commit -qam B
  PRHEAD=$(git rev-parse HEAD)
  git checkout -q main && echo c > other.txt && git add -A && git commit -qm C   # base moves on
  TIP=$(git rev-parse HEAD)
  git merge -q --no-ff feature -m M >/dev/null 2>&1        # M mimics refs/pull/N/merge
  git checkout -q --detach HEAD
  printf '%s %s %s\n' "$FORK" "$PRHEAD" "$TIP" > "${WORKROOT}/shas"
) >/dev/null 2>&1
read -r FORK PRHEAD TIP < "${WORKROOT}/shas"
echo "aws_access_key_id = AKIAIOSFODNN7EXAMPLE" > "${GITWS}/settings.conf"

: > "${WORKROOT}/gho.git"
OUT="$(env PATH="${STUB}:$PATH" GITHUB_OUTPUT="${WORKROOT}/gho.git" \
      IN_TENANT=t IN_API="$API_OK" IN_REPO_KEY='github#1' IN_PATH=. IN_SCOPE= IN_FAIL_ON= \
      IN_FAIL_ON_ERROR=true IN_DRY_RUN=false ACTION_PATH="${WORKROOT}/actdir" GH_REPO_ID=1 \
      GH_REF_NAME=feature GH_SHA="$PRHEAD" GH_WORKSPACE="$GITWS" GH_EVENT=pull_request \
      BASE_SHA="$TIP" BASE_REF=main PR_HEAD_SHA="$PRHEAD" \
      bash "$SCRIPT" 2>&1)"

if printf '%s' "$OUT" | grep -q "comparing against merge base ${FORK}"; then
  printf '  ok    merge base resolved to the fork point\n'; PASS=$((PASS+1))
elif printf '%s' "$OUT" | grep -q "comparing against merge base ${TIP}"; then
  printf '  FAIL  merge base resolved to the base TIP (%s), not the fork point (%s) —\n' "${TIP:0:7}" "${FORK:0:7}"
  printf '        every commit on the base since the branch was cut would read as introduced here\n'
  FAIL=$((FAIL+1))
else
  printf '  FAIL  no merge base resolved at all\n        %s\n' "$(printf '%s' "$OUT" | grep -i 'merge base' | tail -1)"
  FAIL=$((FAIL+1))
fi

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
