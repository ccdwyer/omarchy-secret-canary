use serde::Serialize;
use serde_json::Value;
use std::io::{self, Write};

#[derive(Debug, Clone, Serialize)]
pub struct Event {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub src: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watching: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub clipboard: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repos: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub muted: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub degraded: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub helper: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ok: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub values: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paths: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

impl Event {
    pub fn ready() -> Self {
        let mut e = Self::bare("ready");
        e.helper = Some("canaryd".into());
        e.watching = Some(true);
        e
    }

    pub fn status(
        watching: bool,
        clipboard: &str,
        git: &str,
        repos: usize,
        muted: bool,
        degraded: bool,
        note: &str,
    ) -> Self {
        let mut e = Self::bare("status");
        e.watching = Some(watching);
        e.clipboard = Some(clipboard.into());
        e.git = Some(git.into());
        e.repos = Some(repos);
        e.muted = Some(muted);
        e.degraded = Some(degraded);
        e.helper = Some("canaryd".into());
        if !note.is_empty() {
            e.note = Some(note.into());
        }
        e
    }

    pub fn info(note: &str) -> Self {
        let mut e = Self::bare("info");
        e.note = Some(note.into());
        e
    }

    pub fn error(note: &str) -> Self {
        let mut e = Self::bare("error");
        e.note = Some(note.into());
        e
    }

    pub fn result(cmd: &str, ok: bool, mode: &str, label: &str, file: Option<&str>) -> Self {
        let mut e = Self::bare("result");
        e.cmd = Some(cmd.into());
        e.ok = Some(ok);
        e.mode = Some(mode.into());
        e.label = Some(label.into());
        e.file = file.map(|s| s.to_string());
        e
    }

    pub fn allowlist(values: usize, rules: Vec<String>) -> Self {
        let mut e = Self::bare("allowlist");
        e.values = Some(values);
        e.rules = Some(rules);
        e
    }

    pub fn repos(paths: Vec<String>) -> Self {
        let mut e = Self::bare("repos");
        e.repos = Some(paths.len());
        e.paths = Some(paths);
        e
    }

    pub fn bare(kind: &str) -> Self {
        Event {
            kind: kind.into(),
            src: None,
            rule: None,
            title: None,
            tier: None,
            redacted_preview: None,
            actions: None,
            file: None,
            repo: None,
            note: None,
            watching: None,
            clipboard: None,
            git: None,
            repos: None,
            muted: None,
            degraded: None,
            helper: None,
            cmd: None,
            ok: None,
            mode: None,
            label: None,
            values: None,
            rules: None,
            paths: None,
            hash: None,
        }
    }
}

pub fn emit(event: &Event) {
    let mut stdout = io::stdout().lock();
    if let Err(err) = writeln!(stdout, "{}", to_line(event)) {
        let _ = writeln!(io::stderr().lock(), "canaryd: stdout write failed: {err}");
    }
    let _ = stdout.flush();
}

pub fn to_line(event: &Event) -> String {
    serde_json::to_string(event).unwrap_or_else(|_| "{\"type\":\"error\"}".into())
}

pub fn to_value(event: &Event) -> Value {
    serde_json::to_value(event).unwrap_or(Value::Null)
}
