use crate::detect::{scan_text, Finding, Rule};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const FALLBACK_LABEL: &str = "file unstaged (all hunks)";

#[derive(Debug, Clone)]
pub struct DiffFile {
    pub header: Vec<String>,
    pub path: String,
    pub binary: bool,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Clone)]
pub struct Hunk {
    pub header: String,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct GitRedactResult {
    pub ok: bool,
    pub mode: String,
    pub label: String,
    pub file: Option<String>,
    pub files: Vec<String>,
}

pub fn parse_diff(text: &str) -> Vec<DiffFile> {
    let mut files = Vec::new();
    let mut current: Option<DiffFile> = None;
    let mut in_hunk = false;
    for line in text.replace("\r\n", "\n").lines() {
        if let Some(rest) = line.strip_prefix("diff --git ") {
            if let Some(cur) = current.take() {
                files.push(cur);
            }
            current = Some(DiffFile {
                header: vec![line.to_string()],
                path: path_from_diff_git(rest),
                binary: false,
                hunks: Vec::new(),
            });
            in_hunk = false;
            continue;
        }
        let Some(cur) = current.as_mut() else {
            continue;
        };
        if line.starts_with("Binary files ") || line.starts_with("GIT binary patch") {
            cur.binary = true;
            cur.header.push(line.to_string());
            in_hunk = false;
            continue;
        }
        if line.starts_with("@@ ") {
            cur.hunks.push(Hunk {
                header: line.to_string(),
                lines: Vec::new(),
            });
            in_hunk = true;
            continue;
        }
        if in_hunk {
            if let Some(hunk) = cur.hunks.last_mut() {
                hunk.lines.push(line.to_string());
            }
        } else {
            cur.header.push(line.to_string());
        }
    }
    if let Some(cur) = current {
        files.push(cur);
    }
    files
}

fn path_from_diff_git(rest: &str) -> String {
    crate::gitpath::b_path_from_diff_git(rest)
}

fn parse_hunk_header(header: &str) -> Option<(u32, u32)> {
    // @@ -oldStart,oldCount +newStart,newCount @@
    let plus = header.find('+')?;
    let rest = header.get(plus + 1..)?;
    let end = rest.find(' ').or_else(|| rest.find('@'))?;
    let spec = &rest[..end];
    let mut parts = spec.split(',');
    let start = parts.next()?.parse::<u32>().ok()?;
    let count = parts.next().and_then(|s| s.parse::<u32>().ok()).unwrap_or(1);
    Some((start, count))
}

fn hunk_has_secret(hunk: &Hunk, pred: &dyn Fn(&str) -> bool) -> bool {
    hunk.lines.iter().any(|line| {
        line.starts_with('+') && !line.starts_with("+++") && pred(&line[1..])
    })
}

fn hunk_has_deletion(hunk: &Hunk) -> bool {
    hunk.lines
        .iter()
        .any(|line| line.starts_with('-') && !line.starts_with("---"))
}

fn secret_insertions(hunk: &Hunk, pred: &dyn Fn(&str) -> bool) -> Vec<(String, Vec<String>)> {
    let (new_start, _) = parse_hunk_header(&hunk.header).unwrap_or((1, 0));
    let mut new_line = new_start;
    let mut run_start: Option<u32> = None;
    let mut run_lines: Vec<String> = Vec::new();
    let mut rebuilt = Vec::new();
    let flush = |start: u32, lines: &[String], into: &mut Vec<(String, Vec<String>)>| {
        if lines.is_empty() {
            return;
        }
        let header = format!("@@ -0,0 +{start},{} @@", lines.len());
        into.push((header, lines.to_vec()));
    };
    for line in &hunk.lines {
        if line.starts_with("+++") {
            continue;
        }
        if let Some(added) = line.strip_prefix('+') {
            if pred(added) {
                if run_start.is_none() {
                    run_start = Some(new_line);
                }
                run_lines.push(line.clone());
            } else if let Some(start) = run_start.take() {
                flush(start, &run_lines, &mut rebuilt);
                run_lines.clear();
            }
            new_line = new_line.saturating_add(1);
        } else if line.starts_with('-') {
            if let Some(start) = run_start.take() {
                flush(start, &run_lines, &mut rebuilt);
                run_lines.clear();
            }
        } else {
            if let Some(start) = run_start.take() {
                flush(start, &run_lines, &mut rebuilt);
                run_lines.clear();
            }
            new_line = new_line.saturating_add(1);
        }
    }
    if let Some(start) = run_start.take() {
        flush(start, &run_lines, &mut rebuilt);
    }
    rebuilt
}

/// Surgical path keeps only *pure insertion* hunks whose added lines match
/// `pred`. Replacement hunks (any `-` line plus a secret `+` line) go to
/// the labeled whole-file fallback — reversing a synthesized insertion-only
/// hunk would drop the original line instead of restoring it.
///
/// When `only_file` is set, every other path — including unrelated binaries —
/// is ignored. Binaries never enter fallback unless they *are* the incident file.
pub fn filter_patch(diff: &str, pred: &dyn Fn(&str) -> bool) -> (String, Vec<String>, Vec<String>) {
    filter_patch_for(diff, pred, None)
}

pub fn filter_patch_for(
    diff: &str,
    pred: &dyn Fn(&str) -> bool,
    only_file: Option<&str>,
) -> (String, Vec<String>, Vec<String>) {
    let files = parse_diff(diff);
    let mut fallback = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    let mut out = String::new();

    for file in files {
        if let Some(want) = only_file {
            if file.path != want {
                continue;
            }
        }
        if file.binary {
            if only_file == Some(file.path.as_str()) {
                fallback.push(file.path.clone());
            }
            continue;
        }
        let mut must_fallback = false;
        let mut rebuilt: Vec<(String, Vec<String>)> = Vec::new();
        for hunk in &file.hunks {
            if !hunk_has_secret(hunk, pred) {
                continue;
            }
            if hunk_has_deletion(hunk) {
                must_fallback = true;
                continue;
            }
            rebuilt.extend(secret_insertions(hunk, pred));
        }
        if must_fallback {
            fallback.push(file.path.clone());
            continue;
        }
        if rebuilt.is_empty() {
            continue;
        }
        paths.push(file.path.clone());
        for h in &file.header {
            out.push_str(h);
            out.push('\n');
        }
        for (header, lines) in rebuilt {
            out.push_str(&header);
            out.push('\n');
            for line in lines {
                out.push_str(&line);
                out.push('\n');
            }
        }
    }
    (out, paths, fallback)
}

pub fn secret_line_pred<'a>(rules: &'a [Rule]) -> impl Fn(&str) -> bool + 'a {
    move |line: &str| scan_text(line, rules).iter().any(|f: &Finding| f.tier == 1)
}

pub fn plan_redact(diff: &str, rules: &[Rule]) -> (String, Vec<String>, Vec<String>) {
    let pred = secret_line_pred(rules);
    filter_patch(diff, &pred)
}

pub fn resolve_index(repo: &Path) -> Result<PathBuf, String> {
    let out = Command::new("git")
        .args(["rev-parse", "--git-path", "index"])
        .current_dir(repo)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    let p = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if p.is_empty() {
        return Err("empty git-path index".into());
    }
    let path = PathBuf::from(&p);
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(repo.join(path))
    }
}

pub fn cached_diff(repo: &Path) -> Result<String, String> {
    let out = Command::new("git")
        .args(["diff", "--cached", "-U0"])
        .current_dir(repo)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn apply_reverse(repo: &Path, patch: &str) -> Result<(), String> {
    let mut child = Command::new("git")
        .args(["apply", "--cached", "-R", "--unidiff-zero"])
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(patch.as_bytes()).map_err(|e| e.to_string())?;
    }
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub fn repo_has_head(repo: &Path) -> bool {
    Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", "HEAD"])
        .current_dir(repo)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn unstage_file(repo: &Path, file: &str) -> Result<(), String> {
    // `git restore --staged` needs HEAD. A fresh `git init` demo has none;
    // `git rm --cached` unstages and leaves the worktree alone.
    let mut cmd = Command::new("git");
    cmd.current_dir(repo);
    if repo_has_head(repo) {
        cmd.args(["restore", "--staged", "--", file]);
    } else {
        cmd.args(["rm", "--cached", "--", file]);
    }
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

pub fn redact_repo(repo: &Path, rules: &[Rule]) -> GitRedactResult {
    redact_repo_with_pred(repo, &secret_line_pred(rules), None)
}

pub fn redact_repo_with_pred(
    repo: &Path,
    pred: &dyn Fn(&str) -> bool,
    only_file: Option<&str>,
) -> GitRedactResult {
    let diff = match cached_diff(repo) {
        Ok(d) => d,
        Err(e) => {
            return GitRedactResult {
                ok: false,
                mode: "error".into(),
                label: e,
                file: None,
                files: Vec::new(),
            }
        }
    };
    let (patch, files, fallback) = filter_patch_for(&diff, pred, only_file);
    if !patch.is_empty() {
        match apply_reverse(repo, &patch) {
            Ok(()) => {
                return GitRedactResult {
                    ok: true,
                    mode: "surgical".into(),
                    label: "surgical hunk reverse".into(),
                    file: files.first().cloned(),
                    files,
                }
            }
            Err(_) => {
                let mut did = Vec::new();
                for f in files.iter().chain(fallback.iter()) {
                    if unstage_file(repo, f).is_ok() {
                        did.push(f.clone());
                    }
                }
                return GitRedactResult {
                    ok: !did.is_empty(),
                    mode: "unstaged-all".into(),
                    label: FALLBACK_LABEL.into(),
                    file: did.first().cloned(),
                    files: did,
                };
            }
        }
    }
    if !fallback.is_empty() {
        let mut did = Vec::new();
        for f in &fallback {
            if unstage_file(repo, f).is_ok() {
                did.push(f.clone());
            }
        }
        return GitRedactResult {
            ok: !did.is_empty(),
            mode: "unstaged-all".into(),
            label: FALLBACK_LABEL.into(),
            file: did.first().cloned(),
            files: did,
        };
    }
    GitRedactResult {
        ok: false,
        mode: "none".into(),
        label: "nothing to redact".into(),
        file: None,
        files: Vec::new(),
    }
}

pub fn fallback_label() -> &'static str {
    FALLBACK_LABEL
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Engine;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn quoted_diff_git_paths() {
        let mut s = String::from("diff --git \"a/my secrets/.env\" \"b/my secrets/.env\"\n");
        s.push_str("index 111..222 100644\n");
        s.push_str("--- \"a/my secrets/.env\"\n+++ \"b/my secrets/.env\"\n");
        s.push_str("@@ -1,0 +2,1 @@\n");
        s.push_str("+AKIAIOSFODNN7EXAMPLE\n");
        let files = parse_diff(&s);
        assert_eq!(files[0].path, "my secrets/.env");
    }

    fn mixed_diff() -> String {
        let mut s = String::from("diff --git a/.env b/.env\n");
        s.push_str("index 111..222 100644\n");
        s.push_str("--- a/.env\n+++ b/.env\n");
        s.push_str("@@ -1,0 +2,1 @@\n");
        s.push_str("+AKIAIOSFODNN7EXAMPLE\n");
        s.push_str("@@ -10,0 +12,1 @@\n");
        s.push_str("+UNRELATED_SETTING=1\n");
        s
    }

    #[test]
    fn filter_keeps_only_secret_hunk() {
        let eng = Engine::bundled();
        let pred = secret_line_pred(eng.rules());
        let (patch, files, _) = filter_patch(&mixed_diff(), &pred);
        assert_eq!(files, vec![".env"]);
        assert!(patch.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!patch.contains("UNRELATED_SETTING=1"));
        assert!(!patch.contains("@@ -10,0 +12,1 @@"));
    }

    #[test]
    fn plan_drops_clean_hunk() {
        let eng = Engine::bundled();
        let (patch, files, _) = plan_redact(&mixed_diff(), eng.rules());
        assert_eq!(files, vec![".env"]);
        assert!(patch.contains("+AKIAIOSFODNN7EXAMPLE"));
        assert!(!patch.contains("UNRELATED_SETTING"));
    }

    #[test]
    fn pred_can_exclude_a_second_secret_line() {
        let mut diff = String::from("diff --git a/.env b/.env\n");
        diff.push_str("--- a/.env\n+++ b/.env\n");
        diff.push_str("@@ -1,0 +2,2 @@\n");
        diff.push_str("+AKIAIOSFODNN7EXAMPLE\n");
        diff.push_str("+ghp_EXAMPLENOTAREALTOKEN1234567890\n");
        let keep = "AKIAIOSFODNN7EXAMPLE";
        let pred = |line: &str| line.contains(keep);
        let (patch, files, fallback) = filter_patch(&diff, &pred);
        assert_eq!(files, vec![".env"]);
        assert!(fallback.is_empty());
        assert!(patch.contains(keep));
        assert!(!patch.contains("ghp_"));
    }

    #[test]
    fn scope_skips_other_files_and_unrelated_binaries() {
        let mut diff = String::from("diff --git a/.env b/.env\n");
        diff.push_str("--- a/.env\n+++ b/.env\n");
        diff.push_str("@@ -0,0 +1,1 @@\n+AKIAIOSFODNN7EXAMPLE\n");
        diff.push_str("diff --git a/other.env b/other.env\n");
        diff.push_str("--- a/other.env\n+++ b/other.env\n");
        diff.push_str("@@ -0,0 +1,1 @@\n+AKIAIOSFODNN7EXAMPLE\n");
        diff.push_str("diff --git a/blob.bin b/blob.bin\n");
        diff.push_str("Binary files a/blob.bin and b/blob.bin differ\n");
        let pred = |line: &str| line.contains("AKIAIOSFODNN7EXAMPLE");
        let (patch, files, fallback) = filter_patch_for(&diff, &pred, Some(".env"));
        assert_eq!(files, vec![".env"]);
        assert!(fallback.is_empty(), "unrelated binary must not fall back: {fallback:?}");
        assert!(patch.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(!patch.contains("other.env"));
        assert!(!patch.contains("blob.bin"));
        let unconstrained = filter_patch(&diff, &pred);
        assert!(
            !unconstrained.2.iter().any(|f| f == "blob.bin"),
            "binaries without an incident file must not enter fallback"
        );
    }

    #[test]
    fn replacement_hunk_uses_whole_file_fallback() {
        let mut diff = String::from("diff --git a/.env b/.env\n");
        diff.push_str("index 111..222 100644\n");
        diff.push_str("--- a/.env\n+++ b/.env\n");
        diff.push_str("@@ -1,1 +1,1 @@\n");
        diff.push_str("-KEEP=1\n");
        diff.push_str("+AKIAIOSFODNN7EXAMPLE\n");
        let eng = Engine::bundled();
        let (patch, files, fallback) = plan_redact(&diff, eng.rules());
        assert!(patch.is_empty(), "replacement must not synthesize an insertion hunk");
        assert!(files.is_empty());
        assert_eq!(fallback, vec![".env"]);
    }

    fn tmp_repo() -> PathBuf {
        let n = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("canaryd-git-{n}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn git(repo: &Path, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .args(args)
            .current_dir(repo)
            .output()
            .expect("git")
    }

    #[test]
    fn surgical_redact_leaves_other_hunks() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let repo = tmp_repo();
        git(&repo, &["init", "-q"]);
        git(&repo, &["config", "user.email", "canary@test"]);
        git(&repo, &["config", "user.name", "Canary"]);
        fs::write(repo.join(".env"), "KEEP=1\n").unwrap();
        git(&repo, &["add", ".env"]);
        git(&repo, &["commit", "-qm", "base"]);
        fs::write(
            repo.join(".env"),
            "KEEP=1\nAKIAIOSFODNN7EXAMPLE\nUNRELATED_SETTING=1\n",
        )
        .unwrap();
        git(&repo, &["add", ".env"]);
        let eng = Engine::bundled();
        let result = redact_repo(&repo, eng.rules());
        assert!(result.ok, "{result:?}");
        assert_eq!(result.mode, "surgical");
        let cached = cached_diff(&repo).unwrap();
        assert!(
            !cached.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret still staged:\n{cached}"
        );
        assert!(
            cached.contains("UNRELATED_SETTING=1") || cached.contains("UNRELATED_SETTING"),
            "unrelated hunk lost:\n{cached}"
        );
        let worktree = fs::read_to_string(repo.join(".env")).unwrap();
        assert!(
            worktree.contains("AKIAIOSFODNN7EXAMPLE"),
            "worktree must be untouched"
        );
        let _ = fs::remove_dir_all(&repo);
    }

    #[test]
    fn unborn_repo_unstages_with_rm_cached() {
        if Command::new("git").arg("--version").output().is_err() {
            return;
        }
        let repo = tmp_repo();
        git(&repo, &["init", "-q"]);
        fs::write(repo.join(".env"), "AKIAIOSFODNN7EXAMPLE\nKEEP_ME=1\n").unwrap();
        git(&repo, &["add", ".env"]);
        assert!(!repo_has_head(&repo), "fresh init must have no HEAD");
        unstage_file(&repo, ".env").expect("unstage unborn");
        let cached = cached_diff(&repo).unwrap();
        assert!(
            !cached.contains("AKIAIOSFODNN7EXAMPLE"),
            "still staged:\n{cached}"
        );
        let worktree = fs::read_to_string(repo.join(".env")).unwrap();
        assert!(worktree.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(worktree.contains("KEEP_ME=1"));
        let _ = fs::remove_dir_all(&repo);
    }
}
