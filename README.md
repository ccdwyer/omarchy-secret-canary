# Secret Canary

The screen floods red the instant an AWS key, GitHub token, or private key
escapes into your clipboard or a staged git diff. One key redacts it.

This is an Omarchy shell plugin (service + overlay + bar-widget). It runs
inside the long-lived `omarchy-shell` process. It does not start a second
Quickshell instance. Detection is offline: no accounts, no network.

## Install

```sh
omarchy plugin add <git-url> --enable
```

Then install `canaryd` (recommended). QML falls back to `compat/canaryd.sh`
if `bin/canaryd` is missing or is not a compiled helper — that path is
poll-only and does **not** do surgical git redaction (see limitations).
`build.sh` only writes `bin/canaryd` after a successful cargo release
build; a missing toolchain does **not** copy the shell fallback into
`bin/` (that would make the plugin think the surgical helper is present).

**Source (any machine with Rust):**

```sh
~/.config/omarchy/plugins/io.github.chris.secret-canary/build.sh
```

**Linux artifact (after a git tag):** GitHub Actions
(`.github/workflows/release.yml`) smoke-tests and publishes
`canaryd-x86_64-unknown-linux-musl` and
`canaryd-aarch64-unknown-linux-musl` plus `SHA256SUMS-*`. This tree does
not contain those binaries (it was authored on macOS). Download from the
Release, verify the checksum, and copy onto `bin/canaryd`:

```sh
install -m 0755 canaryd-x86_64-unknown-linux-musl \
  ~/.config/omarchy/plugins/io.github.chris.secret-canary/bin/canaryd
```

Put the chip on the bar if `--enable` did not:

```sh
omarchy bar put io.github.chris.secret-canary --section right
```

Reload plugins if the shell was already running:

```sh
omarchy-shell shell rescanPlugins
```

## 60-second demo

1. Left-click the canary chip → **Test the canary**. The overlay floods.
2. Press **Enter**. Paste somewhere: `[REDACTED by Secret Canary]`.
3. Optional git path — from this plugin:

```sh
cd ~/.config/omarchy/plugins/io.github.chris.secret-canary/demo
git init
# add that directory as a watched repo in the popup, then:
git add .env
```

With the Rust helper (`bin/canaryd`), Enter reverse-applies only the
secret hunk so `KEEP_ME` stays staged. A cold install that is still on
`compat/canaryd.sh` unstages the whole incident file and labels it
**file unstaged (all hunks)**. On a fresh `git init` with no `HEAD` that
unstage is `git rm --cached -- <file>` (worktree kept); after the first
commit it is `git restore --staged`. Neither path touches the working tree.

Copy a random UUID. Nothing happens.

## What it watches

| Path | How | Alarm |
|---|---|---|
| Regular clipboard | `wl-paste -w` child, plus a startup `wl-paste -n`. If the watcher cannot spawn, 500 ms `wl-paste -n` poll (`clipboard: poll`) | Tier-1 overlay, tier-2 amber chip |
| Staged diffs | Explicit git roots only; `git rev-parse --git-path index` | Tier-1 overlay. Tier-2 is log-only |

Primary selection (middle-click paste) is **not** watched. Terminal
scrollback is **not** read. The public claim is clipboard + staged diffs.

Git roots are an explicit add in the bar popup. Nothing under `~/Developer`
is scanned unless you say so.

## Overlay keys

The alarm is a real overlay with exclusive keyboard focus.

| Key | Action |
|---|---|
| Enter | Redact clipboard, or surgically unstage the secret hunk |
| R | Restore the pre-alarm clipboard (held in memory only) |
| A | Allowlist this value (SHA-256 stored, never plaintext) |
| Esc | Dismiss (30 s auto-dismiss) |

The plugin does **not** write `hyprland.conf`. Bind backups yourself if you
want them when the overlay is not focused:

```
bind = SUPER CTRL, X, exec, omarchy-shell io.github.chris.secret-canary redact ''
bind = SUPER CTRL, C, exec, omarchy-shell shell summon io.github.chris.secret-canary '{}'
```

Left-click the chip for settings (Test the canary, mute, watched repos).
Right-click tests immediately. A red chip opens the alarm overlay.

## Tiers

**Tier 1** (overlay): `AKIA…` keys, GitHub `ghp_` / `gho_` / `ghs_` /
`github_pat_`, PEM private-key headers, `sk-` API keys, Slack `xox[baprs]-`.

**Tier 2** (amber chip only, and log-only in git): JWTs, and high-entropy
tokens (Shannon > 4.2 over 24+ chars) sitting near
`secret|token|password|api_key`.

## Honest limitations

- **Detection + fast remediation, not prevention.** Between the copy and
  Enter, another app can still read the clipboard. The README will not
  pretend otherwise.
- **Clipboard managers.** Canary cannot delete entries from a third-party
  history. If a manager re-injects the secret within 60 s of a redact, you
  get a follow-up warning ("your clipboard manager restored it").
- **Git redaction is surgical first, honest always — in `canaryd`.** The
  Rust helper reverse-applies only secret added lines with
  `git apply --cached -R`. If that fails, the file is unstaged wholesale
  and the UI says **file unstaged (all hunks)**. The worktree is never
  modified. **`compat/canaryd.sh` cannot do the surgical path**; it
  unstages the incident file wholesale (`git restore --staged`, or
  `git rm --cached` on a fresh `git init` with no `HEAD`) and labels it
  `file unstaged (all hunks)`.
- **No terminal scrollback.** Anything copied from a terminal transits the
  clipboard watcher; anything staged transits the git watcher.
- **Regular clipboard only.** Primary selection is a v1.1 gap.
- **Helper binary.** `bin/canaryd` is built by `build.sh` (no prebuilt Linux
  musl binaries in this tree). If it is missing, QML runs
  `compat/canaryd.sh`: clipboard polled at 500 ms, git polled every 5 s,
  **tier-1 grep only** (no JWT, no entropy), no inotify. Allowlist hashes
  and watched-repo lists still persist (`allow.json` mode 0600,
  `watch.json`, 64-repo cap, targeted unwatch). After three daemon deaths
  the chip goes amber **degraded** — it will not silently claim it is
  watching.
- **Sound is off.** The visual flood is the alarm. Chime is an opt-in on the
  chip (and the `sound` bar-widget setting).
- **Keybinds are yours to add.** Overlay keys work while the alarm is up.

## Threat model (the watcher)

`canaryd` sees clipboard bytes. It is engineered as the least-trusted
component:

- Content is scanned in a streaming buffer and dropped. **No clipboard
  content is ever persisted or logged.**
- Events carry a preview truncated to the first 4 characters (`AKIA…`) and
  nothing else.
- The allowlist stores SHA-256 of values, never plaintext
  (`~/.config/secret-canary/allow.json`, mode 0600).
- Raw matches never appear in logs or argv.
- The redaction string's hash is permanently suppressed, so overwriting the
  clipboard never re-triggers the scanner.

## Settings

Bar-widget settings arrive inline on the `shell.json` layout entry. There is
no plugin settings file for those.

| Key | Default | Meaning |
|---|---|---|
| `sound` | `false` | Play a theme-ish chime on tier-1 alarm |
| `hideUntilEvent` | `false` | Hide the chip until the first event |

Watched git roots are operational state (`~/.local/state/secret-canary/watch.json`),
not widget settings. Allowlisted hashes and disabled rule ids live in
`~/.config/secret-canary/allow.json` (mode 0600). Settings can toggle each
rule on/off via `allow-rule` / `enable-rule`.

Mute 1 hour is a runtime action on the settings overlay.

## IPC

`shell summon` / `hide` show the overlay. Service verbs (`redact`, `status`, …)
live on the keep-loaded service `IpcHandler`. `omarchy-shell shell call <id>`
hits the overlay loader only (open/close/toggle), so it cannot redact. Always
pass the string argument, even when unused:

```sh
omarchy-shell io.github.chris.secret-canary redact ''
omarchy-shell io.github.chris.secret-canary allowRule jwt
omarchy-shell io.github.chris.secret-canary enableRule jwt
omarchy-shell io.github.chris.secret-canary restore ''
omarchy-shell io.github.chris.secret-canary test ''
omarchy-shell io.github.chris.secret-canary mute ''
omarchy-shell io.github.chris.secret-canary status ''
omarchy-shell shell summon io.github.chris.secret-canary '{}'
omarchy-shell shell hide io.github.chris.secret-canary
```

## Tests (off-device)

```sh
node tests/run.js
bash tests/fallback.test.sh
# helper, if you have cargo:
cargo test --manifest-path src/canaryd/Cargo.toml
```

## Remove

```sh
omarchy plugin remove io.github.chris.secret-canary
```
