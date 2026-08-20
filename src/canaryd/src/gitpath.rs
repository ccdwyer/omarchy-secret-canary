//! Quote-aware parser for `diff --git a/… b/…` paths.
//! Git C-quotes names with spaces or unusual bytes.

pub fn b_path_from_diff_git(rest: &str) -> String {
    let s = rest.trim();
    let (first, tail) = match next_path(s) {
        Some(v) => v,
        None => return String::new(),
    };
    if let Some((second, _)) = next_path(tail) {
        return second;
    }
    first
}

fn next_path(s: &str) -> Option<(String, &str)> {
    let s = s.trim_start();
    if s.is_empty() {
        return None;
    }
    if let Some(inner) = s.strip_prefix('"') {
        let (raw, rest) = unquote_c(inner);
        return Some((strip_ab_prefix(&raw), rest));
    }
    if let Some(idx) = unquoted_sep(s) {
        return Some((strip_ab_prefix(&s[..idx]), &s[idx + 1..]));
    }
    Some((strip_ab_prefix(s), ""))
}

fn unquoted_sep(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] != b' ' {
            continue;
        }
        let rest = &s[i + 1..];
        if rest.starts_with("a/") || rest.starts_with("b/") || rest.starts_with('"') {
            return Some(i);
        }
    }
    None
}

fn strip_ab_prefix(p: &str) -> String {
    p.strip_prefix("a/")
        .or_else(|| p.strip_prefix("b/"))
        .unwrap_or(p)
        .to_string()
}

fn unquote_c(s: &str) -> (String, &str) {
    let mut out = String::new();
    let mut it = s.char_indices();
    while let Some((i, c)) = it.next() {
        match c {
            '"' => return (out, &s[i + 1..]),
            '\\' => match it.next() {
                Some((_, 'n')) => out.push('\n'),
                Some((_, 't')) => out.push('\t'),
                Some((_, 'r')) => out.push('\r'),
                Some((_, '"')) => out.push('"'),
                Some((_, '\\')) => out.push('\\'),
                Some((_, d)) if d.is_ascii_digit() => out.push(d),
                Some((_, x)) => out.push(x),
                None => break,
            },
            _ => out.push(c),
        }
    }
    (out, "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_paths() {
        assert_eq!(b_path_from_diff_git("a/.env b/.env"), ".env");
        assert_eq!(b_path_from_diff_git("a/src/lib.rs b/src/lib.rs"), "src/lib.rs");
    }

    #[test]
    fn quoted_space_paths() {
        assert_eq!(
            b_path_from_diff_git("\"a/my secrets/.env\" \"b/my secrets/.env\""),
            "my secrets/.env"
        );
    }
}
