#!/usr/bin/env bash
# Poll-only Secret Canary helper. Used when bin/canaryd is missing.
# Tier-1 grep only: no inotify, no entropy, no JWT, git redact is whole-file
# unstage (not surgical). JSON events on stdout, JSON commands on stdin.
# Never prints secret values. Allowlist stores SHA-256 hashes only.
set -u

REDACT='[REDACTED by Secret Canary]'
CANNED='AKIAIOSFODNN7EXAMPLE'
MAX_BYTES=1048576
GIT_POLL_S=5
MAX_REPOS=64

CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"
ALLOW_FILE="${CANARY_ALLOW:-$CONFIG_HOME/secret-canary/allow.json}"
WATCH_FILE="${CANARY_WATCH:-$STATE_HOME/secret-canary/watch.json}"

clipboard_mode="poll"
git_mode="idle"
muted_until=0
last_clip_hash=""
last_clean=""
pre_alarm=""
incident_src=""
incident_repo=""
incident_file=""
incident_hash=""
incident_offer_hash=""
recent_offer_hash=""
recent_secret_hash=""
recent_until=0
declare -a REPOS=()
declare -a ALLOW_VALUES=()
declare -a DISABLED_RULES=()

emit() {
  printf '%s\n' "$1"
}

json_escape() {
  python3 -c 'import json,sys; sys.stdout.write(json.dumps(sys.argv[1]))' "$1" 2>/dev/null || {
    printf '"'
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
    printf '"'
  }
}

json_field() {
  python3 -c '
import json, sys
try:
    data = json.loads(sys.argv[1])
except Exception:
    raise SystemExit(1)
key = sys.argv[2]
if key not in data or data[key] is None:
    raise SystemExit(1)
v = data[key]
if isinstance(v, bool):
    sys.stdout.write("true" if v else "false")
elif isinstance(v, (dict, list)):
    sys.stdout.write(json.dumps(v))
else:
    sys.stdout.write(str(v))
' "$1" "$2"
}

canon_repo() {
  local p="$1" t
  t=$(git -C "$p" rev-parse --show-toplevel 2>/dev/null) && {
    printf '%s' "$t"
    return 0
  }
  ( CDPATH= cd -- "$p" && pwd -P )
}

sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then
    printf '%s' "$1" | sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    printf '%s' "$1" | shasum -a 256 | awk '{print $1}'
  else
    python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest())' "$1"
  fi
}

preview_of() {
  local s="$1"
  printf '%s…' "${s:0:4}"
}

now_s() { date +%s; }

is_muted() {
  local n
  n=$(now_s)
  [ "$muted_until" -gt "$n" ]
}

array_has() {
  local needle="$1"
  shift
  local x
  for x in "$@"; do
    [ "$x" = "$needle" ] && return 0
  done
  return 1
}

secure_write() {
  local path="$1" body="$2" dir
  dir=$(dirname "$path")
  mkdir -p "$dir"
  chmod 700 "$dir" 2>/dev/null || true
  printf '%s\n' "$body" > "$path"
  chmod 600 "$path" 2>/dev/null || true
}

json_string_array() {
  python3 -c 'import json,sys; sys.stdout.write(json.dumps([a for a in sys.argv[1:]]))' "$@" 2>/dev/null || {
    local first=1 x
    printf '['
    for x in "$@"; do
      [ $first -eq 1 ] || printf ','
      first=0
      json_escape "$x" | tr -d '\n'
    done
    printf ']'
  }
}

persist_allow() {
  local values rules body
  values=$(json_string_array "${ALLOW_VALUES[@]+"${ALLOW_VALUES[@]}"}")
  rules=$(json_string_array "${DISABLED_RULES[@]+"${DISABLED_RULES[@]}"}")
  body=$(printf '{"version":1,"values":%s,"rules":%s}' "$values" "$rules")
  secure_write "$ALLOW_FILE" "$body"
}

persist_watch() {
  local paths body
  paths=$(json_string_array "${REPOS[@]+"${REPOS[@]}"}")
  body=$(printf '{"version":1,"repos":%s}' "$paths")
  secure_write "$WATCH_FILE" "$body"
}

load_allow() {
  [ -f "$ALLOW_FILE" ] || return 0
  local line
  while IFS= read -r line; do
    case "$line" in
      V*) ALLOW_VALUES+=("${line#V}") ;;
      R*) DISABLED_RULES+=("${line#R}") ;;
    esac
  done < <(python3 - "$ALLOW_FILE" <<'PY' 2>/dev/null || true
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    data = {}
for v in data.get("values") or []:
    if v:
        print("V" + str(v))
for r in data.get("rules") or []:
    if r:
        print("R" + str(r))
PY
)
}

load_watch() {
  [ -f "$WATCH_FILE" ] || return 0
  local line
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    REPOS+=("$line")
  done < <(python3 - "$WATCH_FILE" <<'PY' 2>/dev/null || true
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    data = {}
for p in data.get("repos") or []:
    if p:
        print(p)
PY
)
  if [ "${#REPOS[@]}" -gt 0 ]; then
    git_mode="poll"
  fi
}

emit_allow() {
  local rules
  rules=$(json_string_array "${DISABLED_RULES[@]+"${DISABLED_RULES[@]}"}")
  emit "{\"type\":\"allowlist\",\"values\":${#ALLOW_VALUES[@]},\"rules\":${rules}}"
}

emit_repos() {
  local paths
  paths=$(json_string_array "${REPOS[@]+"${REPOS[@]}"}")
  emit "{\"type\":\"repos\",\"repos\":${#REPOS[@]},\"paths\":${paths}}"
}

status_event() {
  local note="${1:-}"
  local muted=false
  is_muted && muted=true
  local watching=false
  if [ "$clipboard_mode" != "unavailable" ] || [ "${#REPOS[@]}" -gt 0 ]; then
    watching=true
  fi
  emit "{\"type\":\"status\",\"watching\":${watching},\"clipboard\":\"${clipboard_mode}\",\"git\":\"${git_mode}\",\"repos\":${#REPOS[@]},\"muted\":${muted},\"degraded\":true,\"helper\":\"canaryd.sh\",\"note\":$(json_escape "$note")}"
}

classify() {
  local text="$1"
  case "$text" in
    *AKIA[0-9A-Z][0-9A-Z][0-9A-Z]*)
      if printf '%s' "$text" | grep -Eq -- 'AKIA[0-9A-Z]{16}'; then
        printf 'aws-access-key'; return
      fi
      ;;
  esac
  if printf '%s' "$text" | grep -Eiq -- '(aws)?_?secret_?(access)?_?key["'\''[:space:]=:]{0,16}[A-Za-z0-9/+=]{40}'; then printf 'aws-secret-access-key'; return; fi
  if printf '%s' "$text" | grep -Eq -- 'ghp_[A-Za-z0-9]{20,}'; then printf 'github-pat'; return; fi
  if printf '%s' "$text" | grep -Eq -- 'gho_[A-Za-z0-9]{20,}'; then printf 'github-oauth'; return; fi
  if printf '%s' "$text" | grep -Eq -- 'ghs_[A-Za-z0-9]{20,}'; then printf 'github-app'; return; fi
  if printf '%s' "$text" | grep -Eq -- 'github_pat_[A-Za-z0-9_]{20,}'; then printf 'github-fine-grained'; return; fi
  if printf '%s' "$text" | grep -Eq -- '-----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----'; then printf 'private-key'; return; fi
  if printf '%s' "$text" | grep -Eq -- '-----BEGIN PRIVATE KEY-----'; then printf 'private-key-pkcs8'; return; fi
  if printf '%s' "$text" | grep -Eq -- 'sk-(proj|svcacct)-[A-Za-z0-9_-]{20,}'; then printf 'openai-proj-key'; return; fi
  if printf '%s' "$text" | grep -Eq -- 'sk-[A-Za-z0-9]{20,}'; then printf 'openai-key'; return; fi
  if printf '%s' "$text" | grep -Eq -- 'xox[baprs]-[A-Za-z0-9-]{10,}'; then printf 'slack-token'; return; fi
  printf ''
}

title_for() {
  case "$1" in
    aws-access-key) printf 'AWS key' ;;
    aws-secret-access-key) printf 'AWS secret key' ;;
    github-pat|github-oauth|github-app|github-fine-grained) printf 'GitHub token' ;;
    private-key|private-key-pkcs8) printf 'Private key' ;;
    openai-key|openai-proj-key) printf 'API key' ;;
    slack-token) printf 'Slack token' ;;
    *) printf 'Secret' ;;
  esac
}

extract_match() {
  local text="$1" rule="$2"
  case "$rule" in
    aws-access-key) printf '%s' "$text" | grep -Eo -- 'AKIA[0-9A-Z]{16}' | head -1 ;;
    aws-secret-access-key) printf '%s' "$text" | grep -Eo -- '[A-Za-z0-9/+=]{40}' | head -1 ;;
    github-pat) printf '%s' "$text" | grep -Eo -- 'ghp_[A-Za-z0-9]{20,}' | head -1 ;;
    github-oauth) printf '%s' "$text" | grep -Eo -- 'gho_[A-Za-z0-9]{20,}' | head -1 ;;
    github-app) printf '%s' "$text" | grep -Eo -- 'ghs_[A-Za-z0-9]{20,}' | head -1 ;;
    github-fine-grained) printf '%s' "$text" | grep -Eo -- 'github_pat_[A-Za-z0-9_]{20,}' | head -1 ;;
    openai-key) printf '%s' "$text" | grep -Eo -- 'sk-[A-Za-z0-9]{20,}' | head -1 ;;
    openai-proj-key) printf '%s' "$text" | grep -Eo -- 'sk-(proj|svcacct)-[A-Za-z0-9_-]{20,}' | head -1 ;;
    slack-token) printf '%s' "$text" | grep -Eo -- 'xox[baprs]-[A-Za-z0-9-]{10,}' | head -1 ;;
    private-key|private-key-pkcs8) printf '%s' '-----BEGIN' ;;
    *) printf '%s' "$text" | head -c 64 ;;
  esac
}

extract_preview() {
  preview_of "$(extract_match "$1" "$2")"
}

paste_text() {
  command -v wl-paste >/dev/null 2>&1 || return 1
  local list
  list=$(wl-paste -l 2>/dev/null || true)
  if [ -n "$list" ] && ! printf '%s' "$list" | grep -Eq '^(text/|TEXT|STRING)'; then
    return 1
  fi
  wl-paste -n -t text/plain 2>/dev/null | head -c "$MAX_BYTES"
}

copy_text() {
  command -v wl-copy >/dev/null 2>&1 || return 1
  printf '%s' "$1" | wl-copy --type text/plain
}

remember_incident() {
  local text="$1" rule="$2"
  local match h
  match=$(extract_match "$text" "$rule")
  h=$(sha256_hex "$match")
  incident_hash="$h"
}

emit_restore_warning() {
  emit '{"type":"alert","src":"clipboard","rule":"clipboard-restore","title":"Clipboard manager restored a redacted secret","tier":1,"redacted_preview":"****…","actions":["redact-clip"],"note":"your clipboard manager restored it"}'
}

scan_clip() {
  local text rule title prev h now
  text=$(paste_text || true)
  [ -z "$text" ] && return
  h=$(sha256_hex "$text")
  [ "$h" = "$last_clip_hash" ] && return
  last_clip_hash="$h"
  [ "$h" = "$(sha256_hex "$REDACT")" ] && return
  now=$(now_s)
  if [ -n "$recent_offer_hash" ] && [ "$now" -le "$recent_until" ]; then
    if [ "$h" = "$recent_offer_hash" ] || [ "$h" = "$recent_secret_hash" ]; then
      emit_restore_warning
      return
    fi
  fi
  rule=$(classify "$text")
  if [ -z "$rule" ]; then
    last_clean="$text"
    return
  fi
  if array_has "$rule" "${DISABLED_RULES[@]+"${DISABLED_RULES[@]}"}"; then
    last_clean="$text"
    return
  fi
  remember_incident "$text" "$rule"
  if array_has "$incident_hash" "${ALLOW_VALUES[@]+"${ALLOW_VALUES[@]}"}"; then
    last_clean="$text"
    return
  fi
  pre_alarm="$text"
  incident_offer_hash="$h"
  incident_src="clipboard"
  incident_repo=""
  incident_file=""
  is_muted && return
  title=$(title_for "$rule")
  prev=$(extract_preview "$text" "$rule")
  emit "{\"type\":\"alert\",\"src\":\"clipboard\",\"rule\":\"$rule\",\"title\":\"${title} in clipboard\",\"tier\":1,\"redacted_preview\":$(json_escape "$prev"),\"actions\":[\"redact-clip\"],\"hash\":$(json_escape "$incident_hash")}"
}

git_diff_b_path() {
  python3 -c '
import sys
s = sys.argv[1]
if s.startswith("diff --git "):
    s = s[len("diff --git "):]
def stripab(p):
    return p[2:] if p.startswith(("a/", "b/")) else p
def unquote(x):
    if not x.startswith("\""):
        return None
    x = x[1:]
    out = []
    i = 0
    while i < len(x):
        c = x[i]
        if c == "\"":
            return "".join(out), x[i+1:]
        if c == "\\" and i+1 < len(x):
            n = x[i+1]
            out.append({"n": "\n", "t": "\t", "r": "\r"}.get(n, n))
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out), ""
def nextpath(s):
    s = s.lstrip()
    if not s:
        return None
    if s.startswith("\""):
        t, rest = unquote(s)
        return stripab(t), rest
    for i, c in enumerate(s):
        if c == " " and s[i+1:].startswith(("a/", "b/", "\"")):
            return stripab(s[:i]), s[i+1:]
    return stripab(s), ""
first = nextpath(s)
if not first:
    print("")
else:
    second = nextpath(first[1])
    print(second[0] if second else first[0])
' "$1" 2>/dev/null || {
    local p
    p=$(printf '%s' "$1" | sed -n 's/.*[[:space:]]"b\/\(.*\)"$/\1/p')
    if [ -z "$p" ]; then
      p=$(printf '%s' "$1" | sed -n 's/.*[[:space:]]b\/\([^[:space:]]*\)$/\1/p')
    fi
    printf '%s' "$p"
  }
}

emit_git_finding() {
  local root="$1" file="$2" line="$3" rule title prev t
  [ "${git_alerted:-0}" = "1" ] && return
  rule=$(classify "$line")
  [ -z "$rule" ] && return
  if array_has "$rule" "${DISABLED_RULES[@]+"${DISABLED_RULES[@]}"}"; then
    return
  fi
  remember_incident "$line" "$rule"
  if array_has "$incident_hash" "${ALLOW_VALUES[@]+"${ALLOW_VALUES[@]}"}"; then
    return
  fi
  is_muted && return
  title=$(title_for "$rule")
  prev=$(extract_preview "$line" "$rule")
  incident_src="git"
  incident_repo="$root"
  incident_file="$file"
  if [ -n "$file" ]; then
    t="${title} staged in ${file}"
  else
    t="${title} staged"
  fi
  git_alerted=1
  pre_alarm=""
  emit "{\"type\":\"alert\",\"src\":\"git\",\"rule\":\"$rule\",\"title\":$(json_escape "$t"),\"tier\":1,\"redacted_preview\":$(json_escape "$prev"),\"actions\":[\"redact-git\"],\"file\":$(json_escape "$file"),\"repo\":$(json_escape "$root"),\"hash\":$(json_escape "$incident_hash")}"
}

scan_repo() {
  local root="$1" diff file line
  [ -d "$root/.git" ] || [ -f "$root/.git" ] || return
  diff=$(git -C "$root" diff --cached -U0 2>/dev/null || true)
  [ -z "$diff" ] && return
  file=""
  git_alerted=0
  while IFS= read -r line; do
    if printf '%s' "$line" | grep -q '^diff --git '; then
      file=$(git_diff_b_path "$line")
      continue
    fi
    case "$line" in
      +++*) continue ;;
      +*) emit_git_finding "$root" "$file" "${line#+}" ;;
    esac
  done <<EOF
$diff
EOF
}

redact_clip() {
  if [ -n "$pre_alarm" ]; then
    recent_offer_hash=$(sha256_hex "$pre_alarm")
  elif [ -n "$incident_offer_hash" ]; then
    recent_offer_hash="$incident_offer_hash"
  fi
  recent_secret_hash="$incident_hash"
  recent_until=$(( $(now_s) + 60 ))
  if copy_text "$REDACT"; then
    last_clip_hash=$(sha256_hex "$REDACT")
    pre_alarm=""
    emit "{\"type\":\"result\",\"cmd\":\"redact-clip\",\"ok\":true,\"mode\":\"overwrite\",\"label\":\"clipboard redacted\"}"
  else
    emit "{\"type\":\"result\",\"cmd\":\"redact-clip\",\"ok\":false,\"mode\":\"overwrite\",\"label\":\"wl-copy failed\"}"
  fi
}

restore_clip() {
  if [ "$incident_src" != "clipboard" ] || [ -z "$pre_alarm" ]; then
    emit "{\"type\":\"result\",\"cmd\":\"restore-clip\",\"ok\":false,\"mode\":\"none\",\"label\":\"nothing to restore\"}"
    return
  fi
  if copy_text "$pre_alarm"; then
    last_clip_hash=$(sha256_hex "$pre_alarm")
    pre_alarm=""
    emit "{\"type\":\"result\",\"cmd\":\"restore-clip\",\"ok\":true,\"mode\":\"restore\",\"label\":\"previous clipboard restored\"}"
  else
    emit "{\"type\":\"result\",\"cmd\":\"restore-clip\",\"ok\":false,\"mode\":\"none\",\"label\":\"nothing to restore\"}"
  fi
}

unstage_file() {
  local root="$1" file="$2"
  if git -C "$root" rev-parse --verify --quiet HEAD >/dev/null 2>&1; then
    git -C "$root" restore --staged -- "$file"
  else
    git -C "$root" rm --cached -- "$file"
  fi
}

redact_git() {
  local root="${incident_repo:-}"
  if [ -z "$root" ] && [ "${#REPOS[@]}" -gt 0 ]; then
    root="${REPOS[0]}"
  fi
  if [ -z "$root" ]; then
    emit "{\"type\":\"result\",\"cmd\":\"redact-git\",\"ok\":false,\"mode\":\"none\",\"label\":\"no watched repo\"}"
    return
  fi
  local file="${incident_file:-}"
  if [ -z "$file" ]; then
    emit "{\"type\":\"result\",\"cmd\":\"redact-git\",\"ok\":false,\"mode\":\"none\",\"label\":\"nothing to redact\"}"
    return
  fi
  if unstage_file "$root" "$file" 2>/dev/null; then
    emit "{\"type\":\"result\",\"cmd\":\"redact-git\",\"ok\":true,\"mode\":\"unstaged-all\",\"label\":\"file unstaged (all hunks)\",\"file\":$(json_escape "$file")}"
    incident_src=""
    pre_alarm=""
    scan_repo "$root"
  else
    emit "{\"type\":\"result\",\"cmd\":\"redact-git\",\"ok\":false,\"mode\":\"none\",\"label\":\"git restore failed\"}"
  fi
}

allow_value() {
  local h="$1"
  if [ -z "$h" ]; then
    emit "{\"type\":\"result\",\"cmd\":\"allowlist\",\"ok\":false,\"mode\":\"none\",\"label\":\"no incident\"}"
    return
  fi
  if ! array_has "$h" "${ALLOW_VALUES[@]+"${ALLOW_VALUES[@]}"}"; then
    ALLOW_VALUES+=("$h")
    persist_allow
  fi
  emit_allow
  emit "{\"type\":\"result\",\"cmd\":\"allowlist\",\"ok\":true,\"mode\":\"value\",\"label\":\"value allowlisted\"}"
}

allow_rule() {
  local r="$1"
  if [ -z "$r" ]; then
    emit "{\"type\":\"result\",\"cmd\":\"allow-rule\",\"ok\":false,\"mode\":\"none\",\"label\":\"missing rule\"}"
    return
  fi
  if ! array_has "$r" "${DISABLED_RULES[@]+"${DISABLED_RULES[@]}"}"; then
    DISABLED_RULES+=("$r")
    persist_allow
  fi
  emit_allow
  emit "{\"type\":\"result\",\"cmd\":\"allow-rule\",\"ok\":true,\"mode\":\"rule\",\"label\":\"rule disabled\"}"
}

enable_rule() {
  local r="$1" x
  local -a kept=()
  for x in "${DISABLED_RULES[@]+"${DISABLED_RULES[@]}"}"; do
    [ "$x" = "$r" ] && continue
    kept+=("$x")
  done
  DISABLED_RULES=("${kept[@]+"${kept[@]}"}")
  persist_allow
  emit_allow
  emit "{\"type\":\"result\",\"cmd\":\"enable-rule\",\"ok\":true,\"mode\":\"rule\",\"label\":\"rule enabled\"}"
}

watch_repo() {
  local p="$1"
  if [ -z "$p" ]; then
    emit '{"type":"error","note":"missing path"}'
    return
  fi
  p=$(canon_repo "$p") || p="$1"
  if array_has "$p" "${REPOS[@]+"${REPOS[@]}"}"; then
    emit_repos
    return
  fi
  if [ "${#REPOS[@]}" -ge "$MAX_REPOS" ]; then
    emit '{"type":"error","note":"repo cap 64"}'
    return
  fi
  REPOS+=("$p")
  git_mode="poll"
  persist_watch
  emit_repos
  scan_repo "$p"
}

unwatch_repo() {
  local p="$1" x
  p=$(canon_repo "$p") || p="$1"
  local -a kept=()
  for x in "${REPOS[@]+"${REPOS[@]}"}"; do
    [ "$x" = "$p" ] && continue
    kept+=("$x")
  done
  REPOS=("${kept[@]+"${kept[@]}"}")
  if [ "${#REPOS[@]}" -eq 0 ]; then
    git_mode="idle"
  fi
  persist_watch
  emit_repos
}

handle_cmd() {
  local line="$1" cmd h r p
  cmd=$(json_field "$line" cmd) || {
    emit '{"type":"error","note":"bad command"}'
    return
  }
  case "$cmd" in
    ping) emit '{"type":"info","note":"pong"}' ;;
    status) status_event "" ;;
    redact-clip)
      h=$(json_field "$line" hash) || h=""
      [ -n "$h" ] && incident_hash="$h"
      redact_clip
      ;;
    restore-clip) restore_clip ;;
    redact-git)
      h=$(json_field "$line" hash) || h=""
      [ -n "$h" ] && incident_hash="$h"
      redact_git
      ;;
    allowlist)
      h=$(json_field "$line" hash) || h="$incident_hash"
      allow_value "$h"
      ;;
    allow-rule)
      r=$(json_field "$line" rule) || r=""
      allow_rule "$r"
      ;;
    enable-rule)
      r=$(json_field "$line" rule) || r=""
      enable_rule "$r"
      ;;
    dismiss) incident_src=""; incident_hash=""; pre_alarm=""; emit '{"type":"info","note":"dismissed"}' ;;
    scan-clip) last_clip_hash=""; scan_clip ;;
    mute)
      muted_until=$(( $(now_s) + 3600 ))
      status_event "muted"
      ;;
    unmute) muted_until=0; status_event "unmuted" ;;
    test)
      if copy_text "$CANNED"; then
        emit '{"type":"info","note":"test: copied canned AWS example key"}'
      else
        rule=$(classify "$CANNED")
        prev=$(extract_preview "$CANNED" "$rule")
        remember_incident "$CANNED" "aws-access-key"
        emit "{\"type\":\"alert\",\"src\":\"clipboard\",\"rule\":\"aws-access-key\",\"title\":\"AWS key in clipboard\",\"tier\":1,\"redacted_preview\":$(json_escape "$prev"),\"actions\":[\"redact-clip\"],\"hash\":$(json_escape "$incident_hash")}"
        emit '{"type":"info","note":"test: synthetic (wl-copy missing)"}'
      fi
      ;;
    watch)
      p=$(json_field "$line" path) || p=""
      watch_repo "$p"
      ;;
    unwatch)
      p=$(json_field "$line" path) || p=""
      unwatch_repo "$p"
      ;;
    *) emit '{"type":"error","note":"unknown cmd"}' ;;
  esac
}

if [ "${1:-}" = "--parse-diff-git" ]; then
  git_diff_b_path "${2:-}"
  printf '\n'
  exit 0
fi

if [ "${1:-}" = "scan" ]; then
  src="${2:-clipboard}"
  text=$(cat)
  if [ "$src" = "git" ] || [ "$src" = "--src" ]; then
    [ "$src" = "--src" ] && src="${3:-git}"
    added=$(printf '%s' "$text" | grep -E '^\+[^+]' | sed 's/^+//' || true)
    rule=$(classify "$added")
    if [ -n "$rule" ]; then
      prev=$(extract_preview "$added" "$rule")
      title=$(title_for "$rule")
      emit "{\"type\":\"alert\",\"src\":\"git\",\"rule\":\"$rule\",\"title\":\"${title} staged\",\"tier\":1,\"redacted_preview\":$(json_escape "$prev"),\"actions\":[\"redact-git\"]}"
    fi
  else
    rule=$(classify "$text")
    if [ -n "$rule" ]; then
      prev=$(extract_preview "$text" "$rule")
      title=$(title_for "$rule")
      emit "{\"type\":\"alert\",\"src\":\"clipboard\",\"rule\":\"$rule\",\"title\":\"${title} in clipboard\",\"tier\":1,\"redacted_preview\":$(json_escape "$prev"),\"actions\":[\"redact-clip\"]}"
    fi
  fi
  exit 0
fi

if [ "${1:-}" = "--version" ] || [ "${1:-}" = "-V" ]; then
  echo "canaryd.sh 1.0.0"
  exit 0
fi

if [ "${1:-}" = "--self-test" ]; then
  r=$(classify "$CANNED")
  [ "$r" = "aws-access-key" ] || { echo "self-test failed" >&2; exit 1; }
  echo "self-test ok"
  exit 0
fi

command -v wl-paste >/dev/null 2>&1 || clipboard_mode="unavailable"

load_allow
load_watch

emit '{"type":"ready","helper":"canaryd.sh"}'
status_event "fallback poll"
emit_allow
emit_repos

CMDFILE=$(mktemp "${TMPDIR:-/tmp}/canaryd.XXXXXX" 2>/dev/null) || {
  emit '{"type":"error","note":"cannot create command file"}'
  clipboard_mode="unavailable"
  status_event "no command file"
  exit 1
}
READER_PID=0
cleanup() {
  if [ "$READER_PID" -ne 0 ]; then
    kill "$READER_PID" 2>/dev/null || true
  fi
  rm -f "$CMDFILE" "$CMDFILE.work"
}
trap cleanup EXIT

# Background jobs in non-interactive bash get stdin from /dev/null.
# Duplicate the command pipe onto fd 3 before forking the reader.
exec 3<&0
(
  while IFS= read -r line <&3 || [ -n "${line:-}" ]; do
    [ -z "${line:-}" ] && continue
    printf '%s\n' "$line" >> "$CMDFILE"
  done
  printf '%s\n' '{"cmd":"__eof__"}' >> "$CMDFILE"
) &
READER_PID=$!

poll_sleep() {
  sleep 0.5 2>/dev/null || python3 -c 'import time; time.sleep(0.5)' 2>/dev/null || sleep 1
}

drain_cmds() {
  [ -s "$CMDFILE" ] || return 0
  mv "$CMDFILE" "$CMDFILE.work" 2>/dev/null || return 0
  while IFS= read -r line; do
    if [ "$line" = '{"cmd":"__eof__"}' ]; then
      rm -f "$CMDFILE.work"
      exit 0
    fi
    handle_cmd "$line"
  done < "$CMDFILE.work"
  rm -f "$CMDFILE.work"
}

last_git=0
while true; do
  drain_cmds
  scan_clip
  now=$(now_s)
  if [ "$git_mode" != "idle" ] && [ $((now - last_git)) -ge "$GIT_POLL_S" ]; then
    last_git=$now
    for r in "${REPOS[@]+"${REPOS[@]}"}"; do
      scan_repo "$r"
    done
  fi
  poll_sleep
done
