# Assumptions

Conservative choices where the Omarchy / Quickshell / Hyprland API was not
100% certain. The rule: isolate the uncertainty behind `Adapter.qml`, prefer
documented types (`Process`, `SplitParser`, `FileView`, `IpcHandler`,
`PanelWindow`), and degrade.

## Plugin host

- **Entry points are `Item`s** (bar widgets are `BarWidget`). Overlay exposes
  `open(payloadJson)` / `close()` / `toggle()` for
  `omarchy-shell shell summon|hide|toggle`. Taken from the Quattro shell
  README and the Desktop Undo plugin.
- **`keepLoaded: true`** so the overlay's layer-shell window survives between
  summons. Spec'd as a real overlay; the platform document says plugins that
  need to outlive a summon set this. Spec JSON omitted it — the reference
  wins.
- **`barWidget` metadata** (`displayName`, `category`, `defaultSection`,
  `defaults`, `schema`) is required by the platform README whenever `kinds`
  includes `bar-widget`. Spec JSON omitted the block; we added it. Widget
  settings (`sound`, `hideUntilEvent`) are inline on the `shell.json` layout
  entry. No plugin-owned settings file for those.
- **Allowlist path** `~/.config/secret-canary/allow.json` is operational
  state (SHA-256 hashes), not widget settings. Watched git roots persist
  under `~/.local/state/secret-canary/watch.json` for the same reason.
- **Third-party service lookup** is not `shell.firstPartyServiceFor`.
  Adapter tries `pluginRegistry.serviceFor`, `shell.serviceFor`, then
  `shell.firstPartyServiceFor`. Overlay/service commands that cannot
  reach the in-process object use the documented CLI:
  `omarchy-shell shell call|summon|hide`. Direct `shell.summon` /
  `shell.hide` / `shell.call` methods are not assumed.
- **IPC verb** is `omarchy-shell shell call <id> <method> <arg>` and
  `summon` / `hide` / `toggle`. Confirmed in `quattro-shell-reference.md`.
  `IpcHandler` target is the plugin id (extra path, not a second process).
- **Injected properties** on load: `omarchyPath`, `shell`, `manifest`,
  `pluginRegistry` (and `bar` on bar widgets). Overlay/BarWidget still
  function if some of these are missing.

## Quickshell

- **`Process.stdinEnabled` + `process.write(line)`** is how Service talks to
  canaryd. Documented on Quickshell.Io.Process in recent docs; if `write` is
  missing the adapter returns false and the overlay keys fall back to
  `omarchy-shell shell call`. Isolated in `Adapter.writeDaemon`.
- **`SplitParser.onRead`** for daemon stdout. Same pattern as Socket parsers
  in sibling plugins. Stderr is also SplitParser and must never carry
  secrets (canaryd does not print them).
- **`PanelWindow` + `WlrLayershell.keyboardFocus: Exclusive`** so Enter / R /
  A / Esc actually work. If the overlay kind cannot take focus, those keys
  still have IPC backups; the chip remains the demo path.
- **Click-through wash:** `PanelWindow.mask: Region { item: pill }` so only
  the incident pill (and settings controls inside it) is in the input
  region. Wash and the 4px frame sit outside the mask. Same `Region` type
  share-cloak uses for click-through (`mask: Region {}` there; here the
  region is the pill). Keyboard stays `WlrKeyboardFocus.Exclusive` so
  Enter/R/A/Esc still work. If a given Quickshell build ignores `mask`,
  the wash still paints and the pill still focuses.
- **Settings UI lives on the overlay** (`mode=settings`), not `PopupWindow`.
  `PopupWindow` anchoring is less clearly documented than `PanelWindow`,
  which we already use for the alarm. Left-click the chip summons settings;
  a red chip summons the alarm. Right-click tests. Same IPC:
  `omarchy-shell shell call … settings`.
- **Theme tokens** `Color.menu.*`, `Color.accent`, `Style.*`, `Border.*`,
  `WidgetButton`, `BarWidget`, `BorderSurface`, `PanelWindow` — copied from
  first-party clipboard / Desktop Undo. Danger color tries `Color.danger` /
  `Color.error` / `Color.menu.danger`, then `#cc4444`. Amber tries
  `Color.warning`. Reduced motion: `Style.reduceMotion` else
  `OMARCHY_REDUCED_MOTION=1`.
- **`paplay` of the freedesktop warning sound** for the opt-in chime. No
  QtMultimedia import (not a conservative Quickshell API). Sound stays off
  unless the widget setting is true.

## canaryd / clipboard

- Spec asked for a persistent `wl-paste -w cat` child whose stdout is the
  offer stream. Concatenated PEM + next copy would merge without a delimiter,
  so the watch command is `wl-paste -w -t text/plain sh -c 'cat; printf EOR'`
  (still not canaryd itself). Offers are split on that record separator.
  Oversize offers enter discard-until-EOR so a truncated tail is never
  scanned as a new item. MIME is requested as `text/plain` on the watch
  path and re-checked with `wl-paste -l` before scanning; NUL bytes and
  the 1 MB cap still drop the offer.
- After 3 child deaths, poll `wl-paste -n` at 500 ms. Startup always runs
  one `wl-paste -n`.
- `wl-copy --type text/plain` for redact/restore/test. If `wl-copy` is
  missing, **Test the canary** emits a synthetic alert so the overlay demo
  still works.
- Prebuilt musl binaries for x86_64/aarch64 are **not** committed from this
  macOS tree (no Linux cross toolchain here). `.github/workflows/release.yml`
  builds and smoke-tests them (`--self-test` + a canned AKIA scan on x86_64;
  ELF machine check on aarch64). The workflow is default **read-only**: the
  `linux` build job — which compiles and *runs* the checked-out (on PRs,
  untrusted) `canaryd` — holds only `contents: read` and uploads artifacts.
  Publishing a GitHub Release (`contents: write`) is a separate `release` job
  gated to tag pushes / `workflow_dispatch`; it never runs on `pull_request`
  and only attaches artifacts the build job produced, so a malicious PR never
  gets a write token. `build.sh` remains the source path. QML degrades to
  `compat/canaryd.sh` when `bin/canaryd` is missing.
- Restore (R) writes back the **detected** clipboard offer held in memory
  at alarm time, not the previous clean clipboard, and only while the
  active incident is a clipboard alarm. A later git alarm clears that
  restore buffer; dismiss, redact, and a successful restore clear it too.
  Git overlays hide R entirely. The redaction-string hash is permanently
  suppressed; the secret hash lives only in the 60s recent-redaction map
  so a clipboard-manager re-injection can warn.
- Git index watching covers the parent directory of
  `git rev-parse --git-path index` and filters `index` / `index.lock`
  events so git's atomic rename does not drop the watch.
- Overlay `close()` is local-only (opened=false, stop autodismiss). The
  shell hide verb is issued only by initiating callers (`Service.hideOverlay`,
  overlay `requestHide` for Esc/A). `close()` itself must not call
  `adapter.hide`, or `shell hide` recurses.
- Fallback IPC maps `testCanary`/`watchRepo`/`unwatchRepo` onto the
  registered verbs `test`/`watch`/`unwatch`.
- Surgical git redact is **pure insertions only**. A hunk that also
  deletes/replaces a line is labeled `file unstaged (all hunks)` instead
  of synthesizing an insertion-only reverse patch. Enter builds the
  redaction predicate from enabled, non-allowlisted findings in the
  active incident (file + value hash), not the full rule set. Patch
  construction and whole-file fallback are constrained to that incident
  file; duplicate credentials in other files and unrelated binaries are
  left alone.
- Helper crash budget: `restarts` is not cleared on `ready`. A 30s
  `healthyTimer` (started with the Process) is the only reset. A
  crash-looping binary therefore reaches the 3-retry shell fallback.
- Clipboard-manager reinjection stores both the matched-secret hash and
  the full-offer hash; the 60s lookup uses the full-offer hash. The
  POSIX fallback keeps the same in-memory expiry. Helpers emit a single
  `alert` for reinjection; Service does not turn the info line into a
  second overlay.
- A scan with several tier-1 hits emits **one** actionable alert (first
  finding) carrying `hash` (SHA-256 of the match). Redact/allowlist send
  that hash back so UI and daemon target the same finding. After a
  successful git redact the repo is scanned again for the next hit.
- Watcher spawn failure sets clipboard mode to `poll` immediately (no
  child, no death event). Status reports `clipboard: poll` rather than
  pretending a live watch exists.
- `build.sh` never installs `compat/canaryd.sh` as `bin/canaryd`. QML
  treats a shebang `bin/canaryd` as missing and uses `compat/canaryd.sh`.

## Git

- Index path is `git rev-parse --git-path index` (worktrees, submodules,
  linked gitdirs). Cap 64 repos; inotify via the `notify` crate; failure
  degrades that repo to 5 s polling with a status note.
- Surgical redact rebuilds a `-U0` patch containing **only secret added
  lines** (not whole mixed hunks) and reverse-applies with
  `git apply --cached -R --unidiff-zero`. Fallback is
  `git restore --staged -- <file>` labelled `file unstaged (all hunks)`,
  or `git rm --cached -- <file>` when the repo has no `HEAD` (the
  documented `git init` demo). Watched roots are canonicalized via
  `git rev-parse --show-toplevel`.
- PKCS#8 `BEGIN PRIVATE KEY` and `sk-proj-` / `sk-svcacct-` are extra
  tier-1 rules on top of the spec list (same threat, common in the wild).

## Out of scope (intentional)

- Primary selection (v1.1, tribunal rejected).
- Terminal scrollback.
- OCR "scan focused window" stretch.
- A second Quickshell process.
- Network, accounts, telemetry.
- Writing Hyprland config.

## Example secrets are synthetic

Every credential value committed to this repo (test fixtures, corpus, rule
examples, `demo/.env`) is **synthetic and obviously fake** — GitHub
push-protection, gitleaks, trufflehog, and similar scanners will not flag them,
and they carry no real access. They deliberately still match this plugin's own
detection regexes so the true-positive corpus fires every rule at the correct
tier. AWS uses the canonical `AKIAIOSFODNN7EXAMPLE` documentation example;
GitHub/Slack/OpenAI examples carry an `EXAMPLE`/`NOTAREAL` marker; private-key
entries are header-only (no key body). Real-world detection of genuine secrets
is unaffected — only the committed sample *values* are fake.
