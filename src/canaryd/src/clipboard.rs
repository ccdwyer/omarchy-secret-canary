use crate::allow::hash_value;
use std::io::{BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Sender;
use std::thread;
use std::time::Duration;

pub const EOR: &[u8] = b"\n\x1eCANARY_EOR\x1e\n";
pub const MAX_OFFER: usize = crate::detect::MAX_BYTES;
const WATCH_DEATH_LIMIT: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipMode {
    Watch,
    Poll,
    Unavailable,
}

impl ClipMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ClipMode::Watch => "watch",
            ClipMode::Poll => "poll",
            ClipMode::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug)]
pub enum ClipMsg {
    Offer(Vec<u8>),
    Died,
}

pub struct ClipWatch {
    pub mode: ClipMode,
    pub deaths: u8,
    child: Option<Child>,
}

impl ClipWatch {
    pub fn new() -> Self {
        ClipWatch {
            mode: ClipMode::Unavailable,
            deaths: 0,
            child: None,
        }
    }

    pub fn start(&mut self, tx: Sender<ClipMsg>) -> ClipMode {
        self.reap();
        if !wl_paste_exists() {
            self.mode = ClipMode::Unavailable;
            return self.mode;
        }
        self.apply_spawn(spawn_watch(), tx)
    }

    /// Apply a `wl-paste -w` spawn result. A failed spawn has no child and
    /// therefore no death event, so this must enter poll immediately and
    /// must never report `watch`.
    fn apply_spawn(&mut self, spawned: std::io::Result<Child>, tx: Sender<ClipMsg>) -> ClipMode {
        match spawned {
            Ok(mut child) => {
                if let Some(stdout) = child.stdout.take() {
                    thread::spawn(move || read_framed(stdout, tx));
                    self.child = Some(child);
                    self.mode = ClipMode::Watch;
                } else {
                    let _ = child.kill();
                    let _ = child.wait();
                    self.enter_poll();
                }
            }
            Err(_) => self.enter_poll(),
        }
        self.mode
    }

    fn enter_poll(&mut self) {
        self.child = None;
        self.deaths = WATCH_DEATH_LIMIT;
        self.mode = ClipMode::Poll;
    }

    pub fn on_death(&mut self, tx: Sender<ClipMsg>) -> ClipMode {
        self.deaths = self.deaths.saturating_add(1);
        self.reap();
        if self.deaths >= WATCH_DEATH_LIMIT {
            self.mode = ClipMode::Poll;
            return self.mode;
        }
        self.start(tx)
    }

    pub fn reap(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for ClipWatch {
    fn drop(&mut self) {
        self.reap();
    }
}

fn wl_paste_exists() -> bool {
    Command::new("wl-paste")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn spawn_watch() -> std::io::Result<Child> {
    // Framing wrapper, not canaryd itself: wl-paste -w re-execs the command
    // per copy, so pointing it at canaryd would fork a process per paste.
    // -t text/plain skips image/binary offers at the source.
    Command::new("wl-paste")
        .args([
            "-w",
            "-t",
            "text/plain",
            "sh",
            "-c",
            "cat; printf '\\n\\x1eCANARY_EOR\\x1e\\n'",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
}

/// Length-capped record splitter. Oversize offers enter discard-until-EOR
/// so the tail of a huge paste is never treated as a new clipboard item.
pub struct OfferFramer {
    buf: Vec<u8>,
    discarding: bool,
}

impl OfferFramer {
    pub fn new() -> Self {
        OfferFramer {
            buf: Vec::new(),
            discarding: false,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        self.buf.extend_from_slice(chunk);
        loop {
            if self.discarding {
                if let Some(pos) = find_subslice(&self.buf, EOR) {
                    self.buf.drain(..pos + EOR.len());
                    self.discarding = false;
                    continue;
                }
                let keep = EOR.len().saturating_sub(1);
                if self.buf.len() > keep {
                    let drop = self.buf.len() - keep;
                    self.buf.drain(..drop);
                }
                break;
            }
            if let Some(pos) = find_subslice(&self.buf, EOR) {
                let offer = self.buf[..pos].to_vec();
                self.buf.drain(..pos + EOR.len());
                if offer.len() <= MAX_OFFER {
                    out.push(offer);
                }
                continue;
            }
            if self.buf.len() > MAX_OFFER + EOR.len() {
                self.discarding = true;
                let keep = EOR.len().saturating_sub(1);
                if self.buf.len() > keep {
                    let drop = self.buf.len() - keep;
                    self.buf.drain(..drop);
                }
                continue;
            }
            break;
        }
        out
    }
}

fn read_framed<R: Read>(stdout: R, tx: Sender<ClipMsg>) {
    let mut reader = BufReader::new(stdout);
    let mut framer = OfferFramer::new();
    let mut tmp = [0u8; 8192];
    loop {
        match reader.read(&mut tmp) {
            Ok(0) => {
                let _ = tx.send(ClipMsg::Died);
                break;
            }
            Ok(n) => {
                for offer in framer.push(&tmp[..n]) {
                    if tx.send(ClipMsg::Offer(offer)).is_err() {
                        return;
                    }
                }
            }
            Err(_) => {
                let _ = tx.send(ClipMsg::Died);
                break;
            }
        }
    }
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

pub fn mime_is_text() -> bool {
    let out = Command::new("wl-paste")
        .arg("-l")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match out {
        Ok(o) if o.status.success() => {
            let list = String::from_utf8_lossy(&o.stdout);
            list.lines().any(|l| l.starts_with("text/") || l == "TEXT" || l == "STRING")
        }
        _ => true,
    }
}

pub fn paste_text() -> Option<String> {
    if !mime_is_text() {
        return None;
    }
    let out = Command::new("wl-paste")
        .args(["-n", "-t", "text/plain"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    if out.stdout.contains(&0) {
        return None;
    }
    let mut bytes = out.stdout;
    if bytes.len() > MAX_OFFER {
        bytes.truncate(MAX_OFFER);
    }
    String::from_utf8(bytes).ok()
}

pub fn copy_text(text: &str) -> bool {
    let mut child = match Command::new("wl-copy")
        .args(["--type", "text/plain"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return false,
    };
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        if stdin.write_all(text.as_bytes()).is_err() {
            return false;
        }
    }
    child
        .wait()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn offer_to_text(bytes: &[u8]) -> Option<String> {
    if bytes.contains(&0) {
        return None;
    }
    let slice = if bytes.len() > MAX_OFFER {
        &bytes[..MAX_OFFER]
    } else {
        bytes
    };
    String::from_utf8(slice.to_vec()).ok()
}

pub fn content_hash(text: &str) -> String {
    hash_value(text)
}

pub fn poll_interval() -> Duration {
    Duration::from_millis(500)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eor_is_not_a_secret() {
        assert!(EOR.len() > 4);
        assert!(!EOR.contains(&0));
    }

    #[test]
    fn spawn_failure_is_poll_not_watch() {
        let mut w = ClipWatch::new();
        let (tx, _rx) = std::sync::mpsc::channel();
        let mode = w.apply_spawn(
            Err(std::io::Error::new(std::io::ErrorKind::Other, "spawn failed")),
            tx,
        );
        assert_eq!(mode, ClipMode::Poll);
        assert_eq!(w.mode.as_str(), "poll");
        assert_ne!(w.mode, ClipMode::Watch);
        assert!(w.child.is_none());
        assert_eq!(w.deaths, WATCH_DEATH_LIMIT);
    }

    #[test]
    fn offer_skips_nul() {
        assert!(offer_to_text(b"hello\0world").is_none());
        assert_eq!(offer_to_text(b"hello").as_deref(), Some("hello"));
    }

    #[test]
    fn framer_splits_on_eor() {
        let mut f = OfferFramer::new();
        let mut raw = b"hello".to_vec();
        raw.extend_from_slice(EOR);
        raw.extend_from_slice(b"world");
        raw.extend_from_slice(EOR);
        let offers = f.push(&raw);
        assert_eq!(offers, vec![b"hello".to_vec(), b"world".to_vec()]);
    }

    #[test]
    fn framer_discards_oversize_until_eor() {
        let mut f = OfferFramer::new();
        let mut huge = vec![b'x'; MAX_OFFER + 64];
        huge.extend_from_slice(b"TAIL-SHOULD-NOT-SCAN");
        huge.extend_from_slice(EOR);
        huge.extend_from_slice(b"ok");
        huge.extend_from_slice(EOR);
        let offers = f.push(&huge);
        assert_eq!(offers.len(), 1);
        assert_eq!(offers[0], b"ok");
        assert!(!offers.iter().any(|o| o.windows(4).any(|w| w == b"TAIL")));
    }
}
