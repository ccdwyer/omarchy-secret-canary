use canaryd::allow::{hash_value, AllowStore, REDACT_STRING};
use canaryd::clipboard::{
    content_hash, copy_text, mime_is_text, offer_to_text, paste_text, poll_interval, ClipMode,
    ClipMsg, ClipWatch,
};
use canaryd::detect::{findings_in_diff, public_event, Engine};
use canaryd::event::{emit, Event};
use canaryd::git::{cached_diff, redact_repo_with_pred, resolve_index};
use canaryd::{CANNED_TEST_SECRET, VERSION};
use notify::{Event as FsEvent, RecommendedWatcher, RecursiveMode, Watcher};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, BufRead, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_REPOS: usize = 64;
const GIT_POLL: Duration = Duration::from_secs(5);
const GIT_DEBOUNCE: Duration = Duration::from_millis(150);

#[derive(Debug)]
enum Msg {
    Stdin(String),
    StdinClosed,
    Clip(ClipMsg),
    GitDirty(PathBuf),
    Tick,
}

#[derive(Debug, Deserialize, Default)]
struct Cmd {
    cmd: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    rule: Option<String>,
    #[serde(default)]
    seconds: Option<u64>,
    #[serde(default)]
    hash: Option<String>,
}

struct Incident {
    #[allow(dead_code)]
    src: String,
    repo: Option<PathBuf>,
    #[allow(dead_code)]
    file: Option<String>,
    value_hash: String,
    offer_hash: String,
}

struct RepoWatch {
    root: PathBuf,
    index: PathBuf,
    watch_path: PathBuf,
    poll: bool,
}

struct Daemon {
    engine: Engine,
    allow: AllowStore,
    clip: ClipWatch,
    clip_tx: Sender<ClipMsg>,
    repos: Vec<RepoWatch>,
    last_clean: Option<String>,
    pre_alarm: Option<String>,
    last_clip_hash: String,
    incident: Option<Incident>,
    muted_until: Option<Instant>,
    git_mode: String,
    last_git_scan: HashMap<PathBuf, Instant>,
    watcher: Option<RecommendedWatcher>,
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut patterns: Option<PathBuf> = None;
    let mut allow_path: Option<PathBuf> = None;
    let mut scan_src: Option<String> = None;
    let mut self_test = false;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--version" | "-V" => {
                println!("canaryd {VERSION}");
                return;
            }
            "-h" | "--help" => {
                print_help();
                return;
            }
            "--self-test" => self_test = true,
            "--patterns" => patterns = args.next().map(PathBuf::from),
            "--allow" => allow_path = args.next().map(PathBuf::from),
            "scan" => scan_src = Some(args.next().unwrap_or_else(|| "clipboard".into())),
            "--src" => scan_src = Some(args.next().unwrap_or_else(|| "clipboard".into())),
            other => {
                eprintln!("canaryd: unknown argument {other}");
                print_help();
                std::process::exit(2);
            }
        }
    }

    let engine = load_engine(patterns.as_deref());
    if self_test {
        match run_self_test(&engine) {
            Ok(()) => {
                println!("self-test ok");
                return;
            }
            Err(e) => {
                eprintln!("self-test failed: {e}");
                std::process::exit(1);
            }
        }
    }
    if let Some(src) = scan_src {
        let mut buf = String::new();
        let _ = io::stdin().read_to_string(&mut buf);
        if src == "git" {
            for ev in engine.scan_added(&buf, None) {
                emit(&ev);
            }
        } else {
            for ev in engine.scan(&buf, "clipboard", None, None) {
                emit(&ev);
            }
        }
        return;
    }

    let allow_path = allow_path.unwrap_or_else(default_allow_path);
    run_daemon(engine, allow_path);
}

fn print_help() {
    eprintln!(
        "canaryd {VERSION}\n\
         Secret Canary helper. JSON events on stdout, JSON commands on stdin.\n\n\
         canaryd [--patterns FILE] [--allow FILE]\n\
         canaryd scan [--src clipboard|git]   # scan stdin, print events, exit\n\
         canaryd --self-test\n\
         canaryd --version"
    );
}

fn load_engine(path: Option<&Path>) -> Engine {
    if let Some(p) = path {
        match Engine::from_path(p) {
            Ok(e) => return e,
            Err(err) => eprintln!("canaryd: patterns {p:?}: {err}; using bundled"),
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let candidate = dir
                .parent()
                .unwrap_or(dir)
                .join("patterns")
                .join("rules.toml");
            if candidate.exists() {
                if let Ok(e) = Engine::from_path(&candidate) {
                    return e;
                }
            }
        }
    }
    Engine::bundled()
}

fn default_allow_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("secret-canary").join("allow.json");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".config")
        .join("secret-canary")
        .join("allow.json")
}

fn default_watch_path() -> PathBuf {
    if let Ok(xdg) = std::env::var("XDG_STATE_HOME") {
        if !xdg.is_empty() {
            return PathBuf::from(xdg).join("secret-canary").join("watch.json");
        }
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home)
        .join(".local")
        .join("state")
        .join("secret-canary")
        .join("watch.json")
}

fn run_self_test(engine: &Engine) -> Result<(), String> {
    let hits = engine.findings(CANNED_TEST_SECRET);
    if hits.len() != 1 || hits[0].rule != "aws-access-key" {
        return Err(format!("canned AWS key: {hits:?}"));
    }
    Ok(())
}

fn run_daemon(engine: Engine, allow_path: PathBuf) {
    let (tx, rx) = mpsc::channel::<Msg>();
    let (clip_tx, clip_rx) = mpsc::channel::<ClipMsg>();
    let (watch_tx, watch_rx) = mpsc::channel::<PathBuf>();

    {
        let tx = tx.clone();
        thread::spawn(move || {
            let stdin = io::stdin();
            for line in stdin.lock().lines() {
                match line {
                    Ok(l) => {
                        if tx.send(Msg::Stdin(l)).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(Msg::StdinClosed);
        });
    }
    {
        let tx = tx.clone();
        thread::spawn(move || {
            while let Ok(m) = clip_rx.recv() {
                if tx.send(Msg::Clip(m)).is_err() {
                    break;
                }
            }
        });
    }
    {
        let tx = tx.clone();
        thread::spawn(move || {
            while let Ok(p) = watch_rx.recv() {
                if tx.send(Msg::GitDirty(p)).is_err() {
                    break;
                }
            }
        });
    }
    {
        let tx = tx.clone();
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(250));
            if tx.send(Msg::Tick).is_err() {
                break;
            }
        });
    }

    let fs_tx = watch_tx.clone();
    let watcher = notify::recommended_watcher(move |res: Result<FsEvent, notify::Error>| {
        if let Ok(ev) = res {
            for p in ev.paths {
                let _ = fs_tx.send(p);
            }
        }
    })
    .ok();

    let mut d = Daemon {
        engine,
        allow: AllowStore::open(&allow_path),
        clip: ClipWatch::new(),
        clip_tx: clip_tx.clone(),
        repos: Vec::new(),
        last_clean: None,
        pre_alarm: None,
        last_clip_hash: String::new(),
        incident: None,
        muted_until: None,
        git_mode: "idle".into(),
        last_git_scan: HashMap::new(),
        watcher,
    };

    load_persisted_repos(&mut d);
    d.clip.start(clip_tx);
    startup_clip_scan(&mut d);
    emit(&Event::ready());
    let clip_note = match d.clip.mode {
        ClipMode::Poll => "clipboard poll (no live watcher)",
        ClipMode::Unavailable => "wl-paste missing",
        ClipMode::Watch => "",
    };
    d.emit_status(clip_note);
    d.emit_repos();
    d.emit_allow();

    loop {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(Msg::StdinClosed) => break,
            Ok(Msg::Stdin(line)) => d.handle_cmd(&line),
            Ok(Msg::Clip(ClipMsg::Offer(bytes))) => d.on_clip_bytes(&bytes),
            Ok(Msg::Clip(ClipMsg::Died)) => {
                let mode = d.clip.on_death(d.clip_tx.clone());
                d.emit_status(&format!("clipboard {}", mode.as_str()));
            }
            Ok(Msg::GitDirty(path)) => d.on_git_dirty(&path),
            Ok(Msg::Tick) => d.on_tick(),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

impl Daemon {
    fn muted(&self) -> bool {
        self.muted_until
            .map(|t| Instant::now() < t)
            .unwrap_or(false)
    }

    fn emit_status(&self, note: &str) {
        let degraded = self.clip.mode == ClipMode::Unavailable && self.repos.is_empty();
        emit(&Event::status(
            !degraded,
            self.clip.mode.as_str(),
            &self.git_mode,
            self.repos.len(),
            self.muted(),
            degraded,
            note,
        ));
    }

    fn emit_repos(&self) {
        let paths = self
            .repos
            .iter()
            .map(|r| r.root.to_string_lossy().into_owned())
            .collect();
        emit(&Event::repos(paths));
    }

    fn emit_allow(&self) {
        emit(&Event::allowlist(
            self.allow.values.len(),
            self.allow.disabled_rules(),
        ));
    }

    fn handle_cmd(&mut self, line: &str) {
        let line = line.trim();
        if line.is_empty() {
            return;
        }
        let cmd: Cmd = match serde_json::from_str(line) {
            Ok(c) => c,
            Err(_) => {
                emit(&Event::error("bad command"));
                return;
            }
        };
        match cmd.cmd.as_str() {
            "ping" => emit(&Event::info("pong")),
            "status" => self.emit_status(""),
            "redact-clip" => self.redact_clip(cmd.hash.as_deref()),
            "restore-clip" => self.restore_clip(),
            "redact-git" => self.redact_git(cmd.hash.as_deref()),
            "allowlist" => self.allow_current(cmd.hash.as_deref()),
            "allow-rule" => {
                if let Some(r) = cmd.rule {
                    self.allow.allow_rule(&r);
                    self.emit_allow();
                }
            }
            "enable-rule" => {
                if let Some(r) = cmd.rule {
                    self.allow.enable_rule(&r);
                    self.emit_allow();
                }
            }
            "mute" => {
                let secs = cmd.seconds.unwrap_or(3600).max(1);
                self.muted_until = Some(Instant::now() + Duration::from_secs(secs));
                self.emit_status("muted");
            }
            "unmute" => {
                self.muted_until = None;
                self.emit_status("unmuted");
            }
            "watch" => {
                if let Some(p) = cmd.path {
                    self.watch_repo(PathBuf::from(p));
                }
            }
            "unwatch" => {
                if let Some(p) = cmd.path {
                    self.unwatch_repo(Path::new(&p));
                }
            }
            "dismiss" => {
                self.incident = None;
                self.pre_alarm = None;
                emit(&Event::info("dismissed"));
            }
            "scan-clip" => self.scan_clipboard_now(),
            "test" => self.test_canary(),
            other => emit(&Event::error(&format!("unknown cmd {other}"))),
        }
    }

    fn on_clip_bytes(&mut self, bytes: &[u8]) {
        if !mime_is_text() {
            return;
        }
        if let Some(text) = offer_to_text(bytes) {
            self.scan_clipboard_text(&text);
        }
    }

    fn scan_clipboard_now(&mut self) {
        if let Some(text) = paste_text() {
            self.scan_clipboard_text(&text);
        }
    }

    fn scan_clipboard_text(&mut self, text: &str) {
        let hash = content_hash(text);
        if hash == self.last_clip_hash {
            return;
        }
        self.last_clip_hash = hash.clone();

        if self.allow.is_permanently_suppressed(&hash) {
            return;
        }
        if self.allow.restored_by_manager(&hash) {
            let mut ev = Event::bare("alert");
            ev.src = Some("clipboard".into());
            ev.rule = Some("clipboard-restore".into());
            ev.title = Some("Clipboard manager restored a redacted secret".into());
            ev.tier = Some(1);
            ev.redacted_preview = Some("****…".into());
            ev.actions = Some(vec!["redact-clip".into()]);
            ev.note = Some("your clipboard manager restored it".into());
            if !self.muted() {
                emit(&ev);
            }
            return;
        }
        if self.allow.is_value_allowed(&hash) {
            self.last_clean = Some(text.to_string());
            return;
        }

        let mut findings = self.engine.findings(text);
        findings.retain(|f| {
            !self.allow.is_rule_disabled(&f.rule)
                && !self.allow.is_value_allowed(&hash_value(&f.value))
        });
        if findings.is_empty() {
            self.last_clean = Some(text.to_string());
            return;
        }
        // Restore (R) puts back the detected offer, not the previous clean clip.
        self.pre_alarm = Some(text.to_string());
        let top = &findings[0];
        self.incident = Some(Incident {
            src: "clipboard".into(),
            repo: None,
            file: None,
            value_hash: hash_value(&top.value),
            offer_hash: hash.clone(),
        });
        if self.muted() {
            return;
        }
        if let Some(ev) = canaryd::public_event(top, "clipboard", None, None) {
            let mut ev = ev;
            ev.hash = Some(hash_value(&top.value));
            emit(&ev);
        }
    }

    fn redact_clip(&mut self, hash: Option<&str>) {
        if let Some(h) = hash {
            if let Some(inc) = self.incident.as_mut() {
                if !h.is_empty() {
                    inc.value_hash = h.to_string();
                }
            }
        }
        let Some(inc) = self.incident.as_ref() else {
            emit(&Event::result(
                "redact-clip",
                false,
                "none",
                "no incident",
                None,
            ));
            return;
        };
        let secret_hash = inc.value_hash.clone();
        let offer_hash = inc.offer_hash.clone();
        self.allow.remember_redact(&secret_hash);
        if !offer_hash.is_empty() {
            self.allow.remember_redact(&offer_hash);
        }
        self.allow.suppress_permanently(&hash_value(REDACT_STRING));
        let ok = copy_text(REDACT_STRING);
        self.last_clip_hash = content_hash(REDACT_STRING);
        self.pre_alarm = None;
        emit(&Event::result(
            "redact-clip",
            ok,
            "overwrite",
            if ok {
                "clipboard redacted"
            } else {
                "wl-copy failed"
            },
            None,
        ));
    }

    fn restore_clip(&mut self) {
        let clipboard_live = self
            .incident
            .as_ref()
            .map(|i| i.src == "clipboard")
            .unwrap_or(false);
        if !clipboard_live {
            emit(&Event::result(
                "restore-clip",
                false,
                "none",
                "nothing to restore",
                None,
            ));
            return;
        }
        match self.pre_alarm.clone() {
            Some(prev) => {
                let ok = copy_text(&prev);
                self.last_clip_hash = content_hash(&prev);
                if ok {
                    self.pre_alarm = None;
                }
                emit(&Event::result(
                    "restore-clip",
                    ok,
                    "restore",
                    if ok {
                        "previous clipboard restored"
                    } else {
                        "wl-copy failed"
                    },
                    None,
                ));
            }
            None => emit(&Event::result(
                "restore-clip",
                false,
                "none",
                "nothing to restore",
                None,
            )),
        }
    }

    fn redact_git(&mut self, hash: Option<&str>) {
        if let Some(h) = hash {
            if let Some(inc) = self.incident.as_mut() {
                if !h.is_empty() {
                    inc.value_hash = h.to_string();
                }
            }
        }
        let repo = self
            .incident
            .as_ref()
            .and_then(|i| i.repo.clone())
            .or_else(|| self.repos.first().map(|r| r.root.clone()));
        let Some(repo) = repo else {
            emit(&Event::result(
                "redact-git",
                false,
                "none",
                "no watched repo",
                None,
            ));
            return;
        };
        let mut want_file = self.incident.as_ref().and_then(|i| i.file.clone());
        let value_hash = hash
            .filter(|h| !h.is_empty())
            .map(|h| h.to_string())
            .or_else(|| self.incident.as_ref().map(|i| i.value_hash.clone()))
            .unwrap_or_default();
        let diff = match cached_diff(&repo) {
            Ok(d) => d,
            Err(e) => {
                emit(&Event::result("redact-git", false, "error", &e, None));
                return;
            }
        };
        let mut targets: Vec<String> = Vec::new();
        for (finding, file) in findings_in_diff(&diff, self.engine.rules()) {
            if self.allow.is_rule_disabled(&finding.rule) {
                continue;
            }
            if self.allow.is_value_allowed(&hash_value(&finding.value)) {
                continue;
            }
            if finding.tier != 1 {
                continue;
            }
            if !value_hash.is_empty() && hash_value(&finding.value) != value_hash {
                continue;
            }
            match &want_file {
                Some(want) if file.as_deref() != Some(want.as_str()) => continue,
                None => want_file = file.clone(),
                Some(_) => {}
            }
            targets.push(finding.value);
        }
        if targets.is_empty() {
            emit(&Event::result(
                "redact-git",
                false,
                "none",
                "nothing to redact",
                None,
            ));
            return;
        }
        let pred = |line: &str| targets.iter().any(|v| line.contains(v.as_str()));
        let result = redact_repo_with_pred(&repo, &pred, want_file.as_deref());
        emit(&Event::result(
            "redact-git",
            result.ok,
            &result.mode,
            &result.label,
            result.file.as_deref(),
        ));
        if result.ok {
            self.incident = None;
            self.pre_alarm = None;
            self.scan_repo(&repo);
        }
    }

    fn allow_current(&mut self, hex: Option<&str>) {
        let hash = hex
            .map(|s| s.to_string())
            .or_else(|| self.incident.as_ref().map(|i| i.value_hash.clone()));
        if let Some(h) = hash {
            self.allow.allow_value_hash(&h);
            self.emit_allow();
            emit(&Event::result(
                "allowlist",
                true,
                "value",
                "value allowlisted",
                None,
            ));
        } else {
            emit(&Event::result(
                "allowlist",
                false,
                "none",
                "no incident",
                None,
            ));
        }
    }

    fn test_canary(&mut self) {
        if !copy_text(CANNED_TEST_SECRET) {
            self.scan_clipboard_text(CANNED_TEST_SECRET);
            emit(&Event::info("test: synthetic (wl-copy missing)"));
            return;
        }
        emit(&Event::info("test: copied canned AWS example key"));
    }

    fn watch_repo(&mut self, path: PathBuf) {
        let path = canonicalize_repo(&path);
        if self.repos.len() >= MAX_REPOS {
            emit(&Event::error("repo cap 64"));
            return;
        }
        if self.repos.iter().any(|r| r.root == path) {
            self.emit_repos();
            return;
        }
        match resolve_index(&path) {
            Ok(index) => {
                let watch_path = index
                    .parent()
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| index.clone());
                let mut poll = self.watcher.is_none();
                if let Some(w) = self.watcher.as_mut() {
                    // Watch the parent directory so git's atomic
                    // index.lock → index rename does not drop the inode watch.
                    if w.watch(&watch_path, RecursiveMode::NonRecursive).is_err() {
                        poll = true;
                    }
                }
                if poll {
                    self.git_mode = "poll".into();
                } else if self.git_mode == "idle" {
                    self.git_mode = "inotify".into();
                }
                self.repos.push(RepoWatch {
                    root: path.clone(),
                    index,
                    watch_path,
                    poll,
                });
                persist_repos(&self.repos);
                self.scan_repo(&path);
                self.emit_repos();
                self.emit_status(if poll { "git poll (inotify failed)" } else { "" });
            }
            Err(e) => emit(&Event::error(&format!("not a git repo: {e}"))),
        }
    }

    fn unwatch_repo(&mut self, path: &Path) {
        let path = canonicalize_repo(path);
        if let Some(pos) = self.repos.iter().position(|r| r.root == path) {
            let rec = self.repos.remove(pos);
            if let Some(w) = self.watcher.as_mut() {
                let _ = w.unwatch(&rec.watch_path);
            }
            persist_repos(&self.repos);
            if self.repos.is_empty() {
                self.git_mode = "idle".into();
            }
            self.emit_repos();
        }
    }

    fn on_git_dirty(&mut self, path: &Path) {
        let now = Instant::now();
        let roots: Vec<PathBuf> = self
            .repos
            .iter()
            .filter(|r| is_index_event(path, &r.index))
            .map(|r| r.root.clone())
            .collect();
        for root in roots {
            if let Some(prev) = self.last_git_scan.get(&root) {
                if now.duration_since(*prev) < GIT_DEBOUNCE {
                    continue;
                }
            }
            self.last_git_scan.insert(root.clone(), now);
            self.scan_repo(&root);
        }
    }

    fn scan_repo(&mut self, root: &Path) {
        let diff = match cached_diff(root) {
            Ok(d) => d,
            Err(_) => return,
        };
        let repo_s = root.to_string_lossy().into_owned();
        let mut first_alert = true;
        for (finding, file) in findings_in_diff(&diff, self.engine.rules()) {
            if self.allow.is_rule_disabled(&finding.rule) {
                continue;
            }
            if self.allow.is_value_allowed(&hash_value(&finding.value)) {
                continue;
            }
            let Some(ev) = public_event(&finding, "git", file.as_deref(), Some(&repo_s)) else {
                continue;
            };
            if ev.kind == "log" {
                emit(&ev);
                continue;
            }
            if self.muted() {
                continue;
            }
            if ev.kind != "alert" {
                emit(&ev);
                continue;
            }
            if !first_alert {
                continue;
            }
            first_alert = false;
            let vh = hash_value(&finding.value);
            self.pre_alarm = None;
            self.incident = Some(Incident {
                src: "git".into(),
                repo: Some(root.to_path_buf()),
                file: ev.file.clone(),
                value_hash: vh.clone(),
                offer_hash: String::new(),
            });
            let mut ev = ev;
            ev.hash = Some(vh);
            emit(&ev);
        }
    }

    fn on_tick(&mut self) {
        if self.clip.mode == ClipMode::Poll {
            static LAST: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let now = now_ms();
            let prev = LAST.load(std::sync::atomic::Ordering::Relaxed);
            if now.saturating_sub(prev) >= poll_interval().as_millis() as u64 {
                LAST.store(now, std::sync::atomic::Ordering::Relaxed);
                self.scan_clipboard_now();
            }
        }
        if self.git_mode == "poll" {
            let now = Instant::now();
            let roots: Vec<PathBuf> = self
                .repos
                .iter()
                .filter(|r| r.poll)
                .filter(|r| {
                    self.last_git_scan
                        .get(&r.root)
                        .map(|t| now.duration_since(*t) >= GIT_POLL)
                        .unwrap_or(true)
                })
                .map(|r| r.root.clone())
                .collect();
            for root in roots {
                self.last_git_scan.insert(root.clone(), now);
                self.scan_repo(&root);
            }
        }
        if let Some(until) = self.muted_until {
            if Instant::now() >= until {
                self.muted_until = None;
                self.emit_status("unmuted");
            }
        }
    }
}

fn canonicalize_repo(path: &Path) -> PathBuf {
    let out = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(path)
        .output();
    if let Ok(o) = out {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if !s.is_empty() {
                return PathBuf::from(s);
            }
        }
    }
    match path.canonicalize() {
        Ok(c) => c,
        Err(_) if path.is_absolute() => path.to_path_buf(),
        Err(_) => std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf()),
    }
}

fn startup_clip_scan(d: &mut Daemon) {
    if let Some(text) = paste_text() {
        d.scan_clipboard_text(&text);
    }
}

fn is_index_event(path: &Path, index: &Path) -> bool {
    if path == index {
        return true;
    }
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name != "index" && name != "index.lock" {
        return false;
    }
    path.parent() == index.parent()
}

fn persist_repos(repos: &[RepoWatch]) {
    let path = default_watch_path();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let paths: Vec<String> = repos
        .iter()
        .map(|r| r.root.to_string_lossy().into_owned())
        .collect();
    let body = serde_json::json!({ "version": 1, "repos": paths });
    if let Ok(s) = serde_json::to_string_pretty(&body) {
        let _ = std::fs::write(path, s);
    }
}

fn load_persisted_repos(d: &mut Daemon) {
    let path = default_watch_path();
    let Ok(raw) = std::fs::read_to_string(path) else {
        return;
    };
    let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return;
    };
    if let Some(arr) = v.get("repos").and_then(|x| x.as_array()) {
        for p in arr {
            if let Some(s) = p.as_str() {
                d.watch_repo(PathBuf::from(s));
            }
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
