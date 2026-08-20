use crate::event::Event;
use regex::Regex;
use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

pub const MAX_BYTES: usize = 1024 * 1024;
pub const ENTROPY_THRESHOLD: f64 = 4.2;
pub const ENTROPY_MIN_LEN: usize = 24;
pub const CONTEXT_RADIUS: usize = 40;
pub const PREVIEW_CHARS: usize = 4;

const DEFAULT_TOML: &str = include_str!("../../../patterns/rules.toml");

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub tier: u8,
    pub title: String,
    pub re: Regex,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: String,
    pub title: String,
    pub tier: u8,
    pub value: String,
    pub index: usize,
}

#[derive(Debug, Clone)]
pub struct Engine {
    rules: Vec<Rule>,
}

#[derive(Debug, Deserialize)]
struct TomlFile {
    rules: Vec<TomlRule>,
}

#[derive(Debug, Deserialize)]
struct TomlRule {
    id: String,
    #[serde(default)]
    tier: u8,
    #[serde(default)]
    title: String,
    regex: String,
}

impl Engine {
    pub fn bundled() -> Self {
        Self::from_toml(DEFAULT_TOML).unwrap_or_else(|_| Self { rules: Vec::new() })
    }

    pub fn from_path(path: &Path) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        Self::from_toml(&raw)
    }

    pub fn from_toml(raw: &str) -> Result<Self, String> {
        let parsed: TomlFile = toml::from_str(raw).map_err(|e| e.to_string())?;
        let mut rules = Vec::new();
        for r in parsed.rules {
            let re = Regex::new(&r.regex).map_err(|e| format!("{}: {e}", r.id))?;
            rules.push(Rule {
                id: r.id,
                tier: if r.tier == 0 { 1 } else { r.tier },
                title: if r.title.is_empty() {
                    "Secret".into()
                } else {
                    r.title
                },
                re,
            });
        }
        Ok(Engine { rules })
    }

    pub fn scan(&self, text: &str, src: &str, file: Option<&str>, repo: Option<&str>) -> Vec<Event> {
        let findings = self.findings(text);
        findings
            .iter()
            .filter_map(|f| public_event(f, src, file, repo))
            .collect()
    }

    pub fn findings(&self, text: &str) -> Vec<Finding> {
        scan_text(text, &self.rules)
    }

    pub fn scan_added(&self, diff: &str, repo: Option<&str>) -> Vec<Event> {
        scan_added_lines(diff, &self.rules, repo)
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

pub fn scan_text(text: &str, rules: &[Rule]) -> Vec<Finding> {
    if text.contains('\0') {
        return Vec::new();
    }
    let body = cap_text(text);
    if body.is_empty() {
        return Vec::new();
    }
    let mut out: Vec<Finding> = Vec::new();
    let mut seen: HashMap<String, bool> = HashMap::new();
    for rule in rules {
        for caps in rule.re.captures_iter(body) {
            let whole = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let value = caps
                .get(1)
                .map(|m| m.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or(whole);
            if value.is_empty() {
                continue;
            }
            let key = format!("{}\0{value}", rule.id);
            if seen.contains_key(&key) {
                continue;
            }
            seen.insert(key, true);
            let index = caps.get(0).map(|m| m.start()).unwrap_or(0);
            out.push(Finding {
                rule: rule.id.clone(),
                title: rule.title.clone(),
                tier: rule.tier,
                value: value.to_string(),
                index,
            });
        }
    }
    let mut covered: HashMap<String, bool> = HashMap::new();
    for f in &out {
        covered.insert(f.value.clone(), true);
    }
    for hit in entropy_hits(body, &mut covered) {
        out.push(hit);
    }
    out.sort_by(|a, b| a.tier.cmp(&b.tier).then(a.index.cmp(&b.index)));
    out
}

pub fn scan_added_lines(diff: &str, rules: &[Rule], repo: Option<&str>) -> Vec<Event> {
    findings_in_diff(diff, rules)
        .iter()
        .filter_map(|(f, file)| public_event(f, "git", file.as_deref(), repo))
        .collect()
}

pub fn public_event(f: &Finding, src: &str, file: Option<&str>, repo: Option<&str>) -> Option<Event> {
    let git_log_only = src == "git" && f.tier > 1;
    let mut ev = Event::bare(if git_log_only { "log" } else { "alert" });
    ev.src = Some(src.into());
    ev.rule = Some(f.rule.clone());
    ev.title = Some(human_title(&f.title, src, file));
    ev.tier = Some(f.tier);
    ev.hash = Some(crate::allow::hash_value(&f.value));
    ev.redacted_preview = Some(preview_of(&f.value));
    ev.actions = Some(if git_log_only {
        Vec::new()
    } else if src == "git" {
        vec!["redact-git".into()]
    } else {
        vec!["redact-clip".into()]
    });
    ev.file = file.map(|s| s.to_string());
    ev.repo = repo.map(|s| s.to_string());
    Some(ev)
}

pub fn preview_of(value: &str) -> String {
    let mut head: String = value.chars().take(PREVIEW_CHARS).collect();
    head.push('…');
    head
}

pub fn human_title(title: &str, src: &str, file: Option<&str>) -> String {
    if src == "git" {
        if let Some(f) = file {
            format!("{title} staged in {f}")
        } else {
            format!("{title} staged")
        }
    } else {
        format!("{title} in clipboard")
    }
}

pub fn shannon(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<char, u32> = HashMap::new();
    let mut n = 0.0;
    for c in s.chars() {
        *freq.entry(c).or_insert(0) += 1;
        n += 1.0;
    }
    let mut h = 0.0;
    for count in freq.values() {
        let p = f64::from(*count) / n;
        h -= p * p.log2();
    }
    h
}

fn floor_char_boundary(text: &str, mut i: usize) -> usize {
    if i >= text.len() {
        return text.len();
    }
    while i > 0 && !text.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn cap_text(text: &str) -> &str {
    if text.len() <= MAX_BYTES {
        return text;
    }
    let mut end = MAX_BYTES;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

pub fn findings_in_diff(diff: &str, rules: &[Rule]) -> Vec<(Finding, Option<String>)> {
    let (text, files, map) = extract_added(diff);
    if text.is_empty() {
        return Vec::new();
    }
    scan_text(&text, rules)
        .into_iter()
        .map(|f| {
            let file = map
                .iter()
                .find(|(chunk, _)| chunk.contains(&f.value))
                .map(|(_, p)| p.clone())
                .or_else(|| files.first().cloned());
            (f, file)
        })
        .collect()
}

fn entropy_hits(text: &str, already: &mut HashMap<String, bool>) -> Vec<Finding> {
    let token_re = Regex::new(r"[A-Za-z0-9/_+=.-]{24,}").expect("token regex");
    let ctx_re = Regex::new(r"(?i)secret|token|password|api[_-]?key").expect("ctx regex");
    let mut hits = Vec::new();
    for m in token_re.find_iter(text) {
        let token = m.as_str();
        if token.len() < ENTROPY_MIN_LEN {
            continue;
        }
        if already.contains_key(token) {
            continue;
        }
        if shannon(token) <= ENTROPY_THRESHOLD {
            continue;
        }
        let start = floor_char_boundary(text, m.start().saturating_sub(CONTEXT_RADIUS));
        let end = floor_char_boundary(text, (m.end() + CONTEXT_RADIUS).min(text.len()));
        let ctx = &text[start..end];
        if !ctx_re.is_match(ctx) {
            continue;
        }
        already.insert(token.to_string(), true);
        hits.push(Finding {
            rule: "entropy".into(),
            title: "High-entropy secret".into(),
            tier: 2,
            value: token.to_string(),
            index: m.start(),
        });
    }
    hits
}

fn extract_added(diff: &str) -> (String, Vec<String>, Vec<(String, String)>) {
    let mut chunks = Vec::new();
    let mut files = Vec::new();
    let mut map = Vec::new();
    let mut current = String::new();
    for line in diff.lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            let path = crate::gitpath::b_path_from_diff_git(rest);
            current = path.clone();
            if !path.is_empty() {
                files.push(path);
            }
            continue;
        }
        if line.starts_with("+++ ") {
            continue;
        }
        if let Some(added) = line.strip_prefix('+') {
            if !line.starts_with("+++") {
                chunks.push(added.to_string());
                map.push((added.to_string(), current.clone()));
            }
        }
    }
    (chunks.join("\n"), files, map)
}

pub fn event_leaks_secret(ev: &Event, secret: &str) -> bool {
    if secret.len() < 8 {
        return false;
    }
    let dumped = serde_json::to_string(ev).unwrap_or_default();
    for i in 0..=secret.len() - 8 {
        if dumped.contains(&secret[i..i + 8]) {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CANNED_TEST_SECRET;

    fn eng() -> Engine {
        Engine::bundled()
    }

    #[test]
    fn aws_example_key_is_tier1() {
        let hits = eng().findings(CANNED_TEST_SECRET);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].rule, "aws-access-key");
        assert_eq!(hits[0].tier, 1);
        assert_eq!(hits[0].value, CANNED_TEST_SECRET);
    }

    #[test]
    fn preview_is_four_chars() {
        assert_eq!(preview_of(CANNED_TEST_SECRET), "AKIA…");
    }

    #[test]
    fn uuid_is_not_a_hit() {
        let hits = eng().findings("550e8400-e29b-41d4-a716-446655440000");
        assert!(hits.is_empty(), "{hits:?}");
    }

    #[test]
    fn jwt_is_tier2() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.signaturexx";
        let hits = eng().findings(jwt);
        assert!(hits.iter().any(|h| h.rule == "jwt" && h.tier == 2));
    }

    #[test]
    fn git_tier2_is_log_only() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.signaturexx";
        let diff = format!("diff --git a/t b/t\n--- a/t\n+++ b/t\n@@ -0,0 +1,1 @@\n+{jwt}\n");
        let evs = eng().scan_added(&diff, None);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "log");
        assert_eq!(evs[0].tier, Some(2));
        assert_eq!(evs[0].actions.as_ref().map(|a| a.len()), Some(0));
    }

    #[test]
    fn nul_and_empty_skipped() {
        assert!(eng().findings("").is_empty());
        assert!(eng().findings("AKI\0AIOSFODNN7EXAMPLE").is_empty());
    }

    #[test]
    fn public_event_does_not_leak() {
        let hits = eng().findings(CANNED_TEST_SECRET);
        let ev = public_event(&hits[0], "clipboard", None, None).unwrap();
        assert!(!event_leaks_secret(&ev, CANNED_TEST_SECRET));
        assert_eq!(ev.redacted_preview.as_deref(), Some("AKIA…"));
    }

    #[test]
    fn pem_header_matches() {
        let hits = eng().findings("-----BEGIN RSA PRIVATE KEY-----");
        assert!(hits.iter().any(|h| h.rule == "private-key" && h.tier == 1));
    }

    #[test]
    fn fixture_true_positives() {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/true-positives.json");
        let raw = std::fs::read_to_string(&path).expect("true-positives.json");
        let rows: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
        let eng = eng();
        for row in rows {
            let text = row["text"].as_str().unwrap();
            let rule = row["rule"].as_str().unwrap();
            let tier = row["tier"].as_u64().unwrap() as u8;
            let hits = eng.findings(text);
            assert!(
                hits.iter().any(|h| h.rule == rule && h.tier == tier),
                "{}: expected {} t{} in {:?}",
                row["id"],
                rule,
                tier,
                hits
            );
            if let Some(ev) = public_event(&hits[0], "clipboard", None, None) {
                assert!(!event_leaks_secret(&ev, &hits[0].value));
            }
        }
    }

    #[test]
    fn cap_text_does_not_split_utf8() {
        let snow = "☃".repeat((MAX_BYTES / 3) + 8);
        let capped = cap_text(&snow);
        assert!(capped.len() <= MAX_BYTES);
        assert!(capped.is_char_boundary(capped.len()));
        assert!(std::str::from_utf8(capped.as_bytes()).is_ok());
        let hits = Engine::bundled().findings(&snow);
        assert!(hits.is_empty());
    }

    #[test]
    fn entropy_needs_context() {
        let blob = "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW";
        assert!(shannon(blob) > ENTROPY_THRESHOLD);
        let no_ctx = eng().findings(blob);
        assert!(
            !no_ctx.iter().any(|h| h.rule == "entropy"),
            "entropy without keyword: {no_ctx:?}"
        );
        let with = eng().findings(&format!("api_key={blob}"));
        assert!(with.iter().any(|h| h.rule == "entropy" && h.tier == 2));
    }

    #[test]
    fn demo_aws_pair_first_alert_hash_is_first_finding() {
        let text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nKEEP_ME=1\n";
        let hits: Vec<_> = eng()
            .findings(text)
            .into_iter()
            .filter(|h| h.tier == 1)
            .collect();
        assert!(
            hits.iter().any(|h| h.rule == "aws-access-key"),
            "{hits:?}"
        );
        assert!(
            hits.iter().any(|h| h.rule == "aws-secret-access-key"),
            "{hits:?}"
        );
        let first = &hits[0];
        let last = hits.last().unwrap();
        assert_ne!(first.value, last.value);
        let ev = public_event(first, "git", Some(".env"), None).unwrap();
        let first_hash = crate::allow::hash_value(&first.value);
        let last_hash = crate::allow::hash_value(&last.value);
        assert_eq!(ev.hash.as_deref(), Some(first_hash.as_str()));
        assert_ne!(ev.hash.as_deref(), Some(last_hash.as_str()));
    }
}
