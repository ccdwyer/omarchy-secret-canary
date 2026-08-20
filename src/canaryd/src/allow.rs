use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub const REDACT_STRING: &str = "[REDACTED by Secret Canary]";
pub const RESTORE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AllowFile {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AllowStore {
    pub path: PathBuf,
    pub values: HashSet<String>,
    pub rules: HashSet<String>,
    permanent: HashSet<String>,
    recent: HashMap<String, Instant>,
}

impl AllowStore {
    pub fn open(path: &Path) -> Self {
        let mut store = AllowStore {
            path: path.to_path_buf(),
            values: HashSet::new(),
            rules: HashSet::new(),
            permanent: HashSet::new(),
            recent: HashMap::new(),
        };
        store.permanent.insert(hash_value(REDACT_STRING));
        if let Ok(raw) = fs::read_to_string(path) {
            if let Ok(parsed) = serde_json::from_str::<AllowFile>(&raw) {
                for v in parsed.values {
                    store.values.insert(v.to_lowercase());
                }
                for r in parsed.rules {
                    store.rules.insert(r);
                }
            }
        }
        store
    }

    pub fn persist(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let file = AllowFile {
            version: 1,
            values: {
                let mut v: Vec<String> = self.values.iter().cloned().collect();
                v.sort();
                v
            },
            rules: {
                let mut v: Vec<String> = self.rules.iter().cloned().collect();
                v.sort();
                v
            },
        };
        let body = serde_json::to_string_pretty(&file).unwrap_or_else(|_| "{}".into());
        fs::write(&self.path, body)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn allow_value_hash(&mut self, hex: &str) {
        self.values.insert(hex.to_lowercase());
        let _ = self.persist();
    }

    pub fn allow_rule(&mut self, id: &str) {
        self.rules.insert(id.to_string());
        let _ = self.persist();
    }

    pub fn enable_rule(&mut self, id: &str) {
        self.rules.remove(id);
        let _ = self.persist();
    }

    pub fn remove_value(&mut self, hex: &str) {
        self.values.remove(&hex.to_lowercase());
        let _ = self.persist();
    }

    pub fn is_value_allowed(&self, hex: &str) -> bool {
        self.values.contains(&hex.to_lowercase())
    }

    pub fn is_rule_disabled(&self, id: &str) -> bool {
        self.rules.contains(id)
    }

    pub fn suppress_permanently(&mut self, hex: &str) {
        self.permanent.insert(hex.to_lowercase());
    }

    pub fn remember_redact(&mut self, hex: &str) {
        // Secret hash is only remembered for the 60s clipboard-manager
        // window. Permanent suppression is reserved for the redaction marker.
        self.recent.insert(hex.to_lowercase(), Instant::now());
    }

    pub fn is_permanently_suppressed(&self, hex: &str) -> bool {
        self.permanent.contains(&hex.to_lowercase())
    }

    pub fn restored_by_manager(&self, hex: &str) -> bool {
        self.recent
            .get(&hex.to_lowercase())
            .map(|t| t.elapsed() <= RESTORE_WINDOW)
            .unwrap_or(false)
    }

    pub fn disabled_rules(&self) -> Vec<String> {
        let mut v: Vec<String> = self.rules.iter().cloned().collect();
        v.sort();
        v
    }
}

pub fn hash_value(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_string_is_stable() {
        assert_eq!(REDACT_STRING, "[REDACTED by Secret Canary]");
        let a = hash_value(REDACT_STRING);
        let b = hash_value(REDACT_STRING);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn hashes_are_not_plaintext() {
        let secret = "AKIAIOSFODNN7EXAMPLE";
        let h = hash_value(secret);
        assert!(!h.contains("AKIA"));
        assert!(!h.to_uppercase().contains("EXAMPLE"));
    }

    #[test]
    fn remember_redact_is_not_permanent() {
        let dir = std::env::temp_dir().join(format!(
            "canary-allow-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("allow.json");
        let mut store = AllowStore::open(&path);
        let secret = hash_value("AKIAIOSFODNN7EXAMPLE");
        store.remember_redact(&secret);
        assert!(
            !store.is_permanently_suppressed(&secret),
            "secret hash must not be permanent"
        );
        assert!(store.restored_by_manager(&secret));
        assert!(store.is_permanently_suppressed(&hash_value(REDACT_STRING)));
        let offer = "export KEY=AKIAIOSFODNN7EXAMPLE";
        let offer_h = hash_value(offer);
        store.remember_redact(&offer_h);
        assert!(store.restored_by_manager(&offer_h));
        assert!(!store.is_permanently_suppressed(&offer_h));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
