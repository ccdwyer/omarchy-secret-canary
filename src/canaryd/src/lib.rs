//! Secret Canary detection, git redaction, and allowlist store.
//! The daemon binary is a thin watcher around these modules.

pub mod allow;
pub mod clipboard;
pub mod detect;
pub mod event;
pub mod git;
pub mod gitpath;

pub use allow::{hash_value, AllowStore, REDACT_STRING, RESTORE_WINDOW};
pub use detect::{
    findings_in_diff, public_event, scan_added_lines, scan_text, Engine, Finding, MAX_BYTES,
};
pub use event::{emit, Event};
pub use git::{
    filter_patch, filter_patch_for, plan_redact, redact_repo, redact_repo_with_pred, resolve_index,
    GitRedactResult,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CANNED_TEST_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";
