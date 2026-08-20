#!/usr/bin/env bash
# Off-device smoke of compat/canaryd.sh scan mode (no wl-paste required).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
SH="$ROOT/compat/canaryd.sh"
chmod +x "$SH"

out=$(printf 'AKIAIOSFODNN7EXAMPLE' | "$SH" scan clipboard)
printf '%s\n' "$out" | grep -q '"rule":"aws-access-key"' || { echo "FAIL aws"; echo "$out"; exit 1; }
printf '%s\n' "$out" | grep -q 'AKIA…\|AKIA' || { echo "FAIL preview"; echo "$out"; exit 1; }
printf '%s\n' "$out" | grep -q 'IOSFODNN' && { echo "FAIL leak"; echo "$out"; exit 1; }

clean=$(printf 'hello world' | "$SH" scan clipboard)
[ -z "$clean" ] || { echo "FAIL clean clipboard: $clean"; exit 1; }

uuid=$(printf '550e8400-e29b-41d4-a716-446655440000' | "$SH" scan clipboard)
[ -z "$uuid" ] || { echo "FAIL uuid: $uuid"; exit 1; }

gitout=$(printf 'diff --git a/.env b/.env\n--- a/.env\n+++ b/.env\n@@ -0,0 +1,1 @@\n+AKIAIOSFODNN7EXAMPLE\n' | "$SH" scan git)
printf '%s\n' "$gitout" | grep -q '"src":"git"' || { echo "FAIL git src"; echo "$gitout"; exit 1; }

pem=$(printf '%s\n' '-----BEGIN RSA PRIVATE KEY-----' | "$SH" scan clipboard)
printf '%s\n' "$pem" | grep -q '"rule":"private-key"' || { echo "FAIL pem"; echo "$pem"; exit 1; }

secret=$(printf 'aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' | "$SH" scan clipboard)
printf '%s\n' "$secret" | grep -q '"rule":"aws-secret-access-key"' || { echo "FAIL aws-secret"; echo "$secret"; exit 1; }

quoted=$("$SH" --parse-diff-git 'diff --git "a/my secrets/.env" "b/my secrets/.env"')
[ "$quoted" = "my secrets/.env" ] || { echo "FAIL quoted git path: $quoted"; exit 1; }

"$SH" --self-test >/dev/null

synth=$(printf '%s\n' '{"cmd":"test"}' | "$SH")
printf '%s\n' "$synth" | grep -q '"rule":"aws-access-key"' || { echo "FAIL synthetic test alert"; echo "$synth"; exit 1; }
printf '%s\n' "$synth" | grep -q '"hash":' || { echo "FAIL synthetic test hash"; echo "$synth"; exit 1; }

echo "ok  fallback scan mode"

make_tmpdir() {
  local d
  d=$(mktemp -d 2>/dev/null) && { printf '%s\n' "$d"; return 0; }
  d=$(mktemp -d -t canary 2>/dev/null) && { printf '%s\n' "$d"; return 0; }
  d="${TMPDIR:-/tmp}/canary-fallback-$$"
  mkdir -p "$d" 2>/dev/null && { printf '%s\n' "$d"; return 0; }
  d="$ROOT/tests/.tmp-fallback-$$"
  mkdir -p "$d" && { printf '%s\n' "$d"; return 0; }
  return 1
}

tmpdir=$(make_tmpdir) || { echo "skip fallback persist (no tmp dir)"; exit 0; }
export CANARY_ALLOW="$tmpdir/allow.json"
export CANARY_WATCH="$tmpdir/watch.json"
{
  printf '%s\n' '{"cmd":"allowlist","hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
  printf '%s\n' '{"cmd":"allow-rule","rule":"jwt"}'
  printf '%s\n' '{"cmd":"watch","path":"/tmp/canary-a"}'
  printf '%s\n' '{"cmd":"watch","path":"/tmp/canary-a"}'
  printf '%s\n' '{"cmd":"watch","path":"/tmp/canary-b"}'
  printf '%s\n' '{"cmd":"unwatch","path":"/tmp/canary-a"}'
  sleep 1.2
} | "$SH" > "$tmpdir/out" 2>/dev/null &
pid=$!
sleep 1.6
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

test -f "$CANARY_ALLOW" || { echo "FAIL allow.json missing"; exit 1; }
stat_mode=$(python3 -c 'import os,stat; print(oct(os.stat("'"$CANARY_ALLOW"'").st_mode & 0o777))')
[ "$stat_mode" = "0o600" ] || [ "$stat_mode" = "0600" ] || echo "WARN allow mode $stat_mode (expected 0o600)"
python3 - "$CANARY_ALLOW" <<'PY' || { echo "FAIL allow.json contents"; exit 1; }
import json,sys
d=json.load(open(sys.argv[1]))
assert "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in d.get("values",[]), d
assert "jwt" in d.get("rules",[]), d
assert "AKIA" not in json.dumps(d)
PY

test -f "$CANARY_WATCH" || { echo "FAIL watch.json missing"; exit 1; }
python3 - "$CANARY_WATCH" <<'PY' || { echo "FAIL watch.json contents"; exit 1; }
import json,sys
d=json.load(open(sys.argv[1]))
repos=d.get("repos") or []
assert repos == ["/tmp/canary-b"], repos
PY

# reload persists
{
  printf '%s\n' '{"cmd":"status"}'
  sleep 0.6
} | CANARY_ALLOW="$CANARY_ALLOW" CANARY_WATCH="$CANARY_WATCH" "$SH" > "$tmpdir/out2" 2>/dev/null &
pid2=$!
sleep 1
kill "$pid2" 2>/dev/null || true
wait "$pid2" 2>/dev/null || true
grep -q '"paths":\["/tmp/canary-b"\]' "$tmpdir/out2" || grep -q '/tmp/canary-b' "$tmpdir/out2" || { echo "FAIL reload watch"; cat "$tmpdir/out2"; exit 1; }
grep -q '"jwt"' "$tmpdir/out2" || { echo "FAIL reload rules"; cat "$tmpdir/out2"; exit 1; }

if command -v git >/dev/null 2>&1; then
  repo="$tmpdir/my repo"
  mkdir -p "$repo/my secrets"
  git -C "$repo" init -q
  git -C "$repo" config user.email "canary@example.test"
  git -C "$repo" config user.name "canary"
  printf '%s\n' 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' 'KEEP_ME=1' > "$repo/my secrets/.env"
  git -C "$repo" add "my secrets/.env"
  {
    printf '%s\n' "{\"cmd\":\"watch\",\"path\":\"$repo\"}"
    sleep 0.8
  } | CANARY_ALLOW="$tmpdir/allow2.json" CANARY_WATCH="$tmpdir/watch2.json" "$SH" > "$tmpdir/gitout" 2>/dev/null &
  gpid=$!
  sleep 1.2
  kill "$gpid" 2>/dev/null || true
  wait "$gpid" 2>/dev/null || true
  grep -q '"rule":"aws-access-key"' "$tmpdir/gitout" || { echo "FAIL missing aws-access-key alert"; cat "$tmpdir/gitout"; exit 1; }
  grep -q '"rule":"aws-secret-access-key"' "$tmpdir/gitout" && { echo "FAIL second AWS secret also alerted"; cat "$tmpdir/gitout"; exit 1; }
  grep -q 'my secrets/.env' "$tmpdir/gitout" || { echo "FAIL quoted git path in alert"; cat "$tmpdir/gitout"; exit 1; }
  grep -q '"hash":' "$tmpdir/gitout" || { echo "FAIL git alert missing hash"; cat "$tmpdir/gitout"; exit 1; }
  {
    printf '%s\n' "{\"cmd\":\"watch\",\"path\":\"$repo\"}"
    sleep 0.4
    printf '%s\n' '{"cmd":"restore-clip"}'
    sleep 0.6
  } | CANARY_ALLOW="$tmpdir/allowr.json" CANARY_WATCH="$tmpdir/watchr.json" "$SH" > "$tmpdir/restoreout" 2>/dev/null &
  rpid2=$!
  sleep 1.2
  kill "$rpid2" 2>/dev/null || true
  wait "$rpid2" 2>/dev/null || true
  grep -q 'nothing to restore' "$tmpdir/restoreout" || { echo "FAIL git alarm must not restore clipboard"; cat "$tmpdir/restoreout"; exit 1; }
  echo "ok  fallback first-only git alert + quoted path"

  {
    printf '%s\n' "{\"cmd\":\"watch\",\"path\":\"$repo\"}"
    sleep 0.4
    printf '%s\n' '{"cmd":"redact-git"}'
    sleep 0.8
  } | CANARY_ALLOW="$tmpdir/allow3.json" CANARY_WATCH="$tmpdir/watch3.json" "$SH" > "$tmpdir/redactout" 2>/dev/null &
  rpid=$!
  sleep 1.4
  kill "$rpid" 2>/dev/null || true
  wait "$rpid" 2>/dev/null || true
  grep -q 'file unstaged (all hunks)' "$tmpdir/redactout" || { echo "FAIL unborn unstage label"; cat "$tmpdir/redactout"; exit 1; }
  grep -q '"ok":true' "$tmpdir/redactout" || { echo "FAIL unborn unstage ok"; cat "$tmpdir/redactout"; exit 1; }
  staged=$(git -C "$repo" diff --cached) || true
  [ -z "$staged" ] || { echo "FAIL still staged after unborn unstage"; echo "$staged"; exit 1; }
  grep -q 'AKIAIOSFODNN7EXAMPLE' "$repo/my secrets/.env" || { echo "FAIL worktree touched"; exit 1; }
  echo "ok  fallback unborn HEAD git rm --cached"
fi

weird_dir="$tmpdir/has\"quote"
mkdir -p "$weird_dir"
cmd=$(python3 -c 'import json,sys; print(json.dumps({"cmd":"watch","path":sys.argv[1]}))' "$weird_dir")
{
  printf '%s\n' "$cmd"
  sleep 0.8
} | CANARY_ALLOW="$tmpdir/allowq.json" CANARY_WATCH="$tmpdir/watchq.json" "$SH" > "$tmpdir/qout" 2>/dev/null &
qpid=$!
sleep 1.2
kill "$qpid" 2>/dev/null || true
wait "$qpid" 2>/dev/null || true
python3 - "$tmpdir/watchq.json" "$weird_dir" <<'PY' || { echo "FAIL json path round-trip"; cat "$tmpdir/watchq.json"; exit 1; }
import json,sys
d=json.load(open(sys.argv[1]))
repos=d.get("repos") or []
assert sys.argv[2] in repos or any(sys.argv[2] in r for r in repos), repos
PY
echo "ok  fallback JSON path with quote"

rm -rf "$tmpdir"
echo "ok  fallback allowlist + watch persist"
