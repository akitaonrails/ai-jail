//! One JSON line per connection accepted by the egress proxy, plus
//! run-wide counters kept whether or not a log file was asked for.
//! The line carries only the documented fields: the proxy hands
//! this module a parsed host and port, never the request bytes.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use crate::{audit, output};

/// Version of the egress line; bumped only on an incompatible change, as
/// a consumer checks `v` before reading the other fields.
const EGRESS_LINE_VERSION: u64 = 1;

/// Run-wide connection and byte counters. Relaxed is enough: every value is
/// read once, after the proxy has drained, and no other data hangs on it.
#[derive(Default)]
pub struct EgressStats {
    allowed: AtomicU64,
    denied: AtomicU64,
    errored: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
}

/// A plain copy of [`EgressStats`] at one instant. Only the tests read
/// the totals on their own; a consumer of the counters adds its reader.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressTotals {
    pub allowed: u64,
    pub denied: u64,
    pub errored: u64,
    pub bytes_up: u64,
    pub bytes_down: u64,
}

impl EgressStats {
    #[cfg(test)]
    pub fn snapshot(&self) -> EgressTotals {
        EgressTotals {
            allowed: self.allowed.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            errored: self.errored.load(Ordering::Relaxed),
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
        }
    }
}

/// The `--egress-log` file. Appends are serialised by the mutex so a line
/// is never split by another thread's `write_all`: `O_APPEND` alone
/// only makes each `write(2)` atomic, and a long line takes several.
pub struct EgressLog {
    /// The file, and whether its last write was torn (no final `\n`).
    file: Mutex<(File, bool)>,
    warned: AtomicBool,
    run_id: String,
    path: PathBuf,
}

impl EgressLog {
    /// Open `path` for append, creating it 0600 and refusing a symlink at
    /// the last component, with the owner check of
    /// `audit::open_log_for_append`. The error names the path, and keeps a
    /// kind `audit::is_security_open_error` still recognises.
    pub fn open(path: &Path, run_id: &str) -> io::Result<EgressLog> {
        let file = open_egress_file(path).map_err(|error| {
            // A context wrap drops raw_os_error (ELOOP from O_NOFOLLOW is
            // the symlink refusal), so carry the security class in the
            // kind instead.
            let kind = if audit::is_security_open_error(&error) {
                io::ErrorKind::PermissionDenied
            } else {
                error.kind()
            };
            io::Error::new(
                kind,
                format!("cannot open egress log {}: {error}", path.display()),
            )
        })?;
        // A run that died mid-write leaves a fragment with no `\n`; the
        // next line must not be glued onto it.
        let needs_newline = ends_without_newline(&file);
        Ok(EgressLog {
            file: Mutex::new((file, needs_newline)),
            warned: AtomicBool::new(false),
            run_id: run_id.to_string(),
            path: path.to_path_buf(),
        })
    }

    /// Append one line. A failure warns once and is dropped: logging must
    /// never stop the relay.
    fn write_line(&self, value: &serde_json::Value) {
        let result = encode_line(value).and_then(|line| {
            // A poisoned lock only means another writer panicked; the
            // file itself is still usable.
            let mut guard = self.file.lock().unwrap_or_else(|p| p.into_inner());
            let (file, needs_newline) = &mut *guard;
            write_framed(file, needs_newline, &line)
        });
        if let Err(error) = result
            && !self.warned.swap(true, Ordering::SeqCst)
        {
            // security_warn, not warn: --exec silences warn, and a lost egress
            // line must still be visible.
            output::security_warn(&format!(
                "egress log write failed for {}: {error}; further errors \
                 suppressed",
                self.path.display()
            ));
        }
    }
}

/// Write one encoded line, starting it with `\n` when an earlier write was
/// torn (`needs_newline`), so a fragment can never swallow a good record.
fn write_framed<W: Write>(
    writer: &mut W,
    needs_newline: &mut bool,
    line: &[u8],
) -> io::Result<()> {
    let result = if *needs_newline {
        writer
            .write_all(b"\n")
            .and_then(|()| writer.write_all(line))
    } else {
        writer.write_all(line)
    };
    // Any failure may have left part of a line behind.
    *needs_newline = result.is_err();
    result
}

/// Whether a non-empty `file` ends in anything but `\n`. An unreadable
/// last byte counts as torn: one spare newline is harmless, a glued line
/// is not.
fn ends_without_newline(file: &File) -> bool {
    use std::os::unix::fs::FileExt;
    let Ok(len) = file.metadata().map(|m| m.len()) else {
        return true;
    };
    if len == 0 {
        return false;
    }
    let mut last = [0_u8; 1];
    !matches!(file.read_at(&mut last, len - 1), Ok(1) if last[0] == b'\n')
}

/// Serialise `value` as one line, newline included. `serde_json` escapes
/// only U+0000-U+001F, so DEL and every non-ASCII character are escaped
/// here too: a hostile host can never put a raw byte a terminal or
/// a line-based reader would act on into the file.
fn encode_line(value: &serde_json::Value) -> io::Result<Vec<u8>> {
    use serde::Serialize;

    let mut line = Vec::new();
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut line, AsciiFormatter);
    value.serialize(&mut serializer).map_err(io::Error::other)?;
    line.push(b'\n');
    Ok(line)
}

/// A compact `serde_json` formatter whose output is printable ASCII only.
struct AsciiFormatter;

impl serde_json::ser::Formatter for AsciiFormatter {
    fn write_string_fragment<W>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> io::Result<()>
    where
        W: ?Sized + io::Write,
    {
        let mut units = [0u16; 2];
        for ch in fragment.chars() {
            if ch.is_ascii() && ch != '\u{7f}' {
                writer.write_all(&[ch as u8])?;
            } else {
                for unit in ch.encode_utf16(&mut units) {
                    write!(writer, "\\u{unit:04x}")?;
                }
            }
        }
        Ok(())
    }
}

fn open_egress_file(path: &Path) -> io::Result<File> {
    use nix::libc;
    use std::fs::{OpenOptions, Permissions};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    // std adds O_CLOEXEC itself. O_NONBLOCK keeps a FIFO planted at the
    // path from blocking startup, as open_log_for_append does; it has no
    // effect on a regular file.
    // Read access only serves the torn-line check at open
    // (ends_without_newline); every write still goes through O_APPEND.
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.uid() != nix::unistd::geteuid().as_raw()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "egress log must be a regular file owned by this user",
        ));
    }
    // Mode 0600 from O_CREAT applies only to a new file; an existing one
    // is narrowed through the pinned descriptor (fchmod).
    file.set_permissions(Permissions::from_mode(0o600))?;
    Ok(file)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    Error,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::Allow => "allow",
            Verdict::Deny => "deny",
            Verdict::Error => "error",
        }
    }
}

/// One accepted connection. Created on the first line of the proxy's
/// connection handler, so every early return drops it and still yields
/// exactly one line.
pub struct ConnRecord {
    host: Option<String>,
    port: Option<u16>,
    verdict: Verdict,
    reason: &'static str,
    up: Arc<AtomicU64>,
    down: Arc<AtomicU64>,
    started: Instant,
    log: Option<Arc<EgressLog>>,
    stats: Arc<EgressStats>,
}

impl ConnRecord {
    /// Starts as `error` / `client-read-failed`: a record dropped before
    /// anything is set is a connection that never sent a usable request.
    pub fn begin(log: Option<Arc<EgressLog>>, stats: Arc<EgressStats>) -> Self {
        ConnRecord {
            host: None,
            port: None,
            verdict: Verdict::Error,
            reason: "client-read-failed",
            up: Arc::new(AtomicU64::new(0)),
            down: Arc::new(AtomicU64::new(0)),
            started: Instant::now(),
            log,
            stats,
        }
    }

    pub fn target(&mut self, host: &str, port: u16) {
        self.host = Some(host.to_string());
        self.port = Some(port);
    }

    pub fn verdict(&mut self, verdict: Verdict, reason: &'static str) {
        self.verdict = verdict;
        self.reason = reason;
    }

    /// The (upstream, downstream) byte counters, for [`CountingReader`].
    pub fn counters(&self) -> (Arc<AtomicU64>, Arc<AtomicU64>) {
        (Arc::clone(&self.up), Arc::clone(&self.down))
    }
}

impl Drop for ConnRecord {
    fn drop(&mut self) {
        let up = self.up.load(Ordering::Relaxed);
        let down = self.down.load(Ordering::Relaxed);
        let counter = match self.verdict {
            Verdict::Allow => &self.stats.allowed,
            Verdict::Deny => &self.stats.denied,
            Verdict::Error => &self.stats.errored,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        self.stats.bytes_up.fetch_add(up, Ordering::Relaxed);
        self.stats.bytes_down.fetch_add(down, Ordering::Relaxed);

        let Some(log) = &self.log else {
            return;
        };
        let duration_ms = u64::try_from(self.started.elapsed().as_millis())
            .unwrap_or(u64::MAX);
        // Exactly the documented fields; the host goes through serde_json only,
        // so a hostile name stays escaped on one line.
        let line = serde_json::json!({
            "v": EGRESS_LINE_VERSION,
            "ts": audit::rfc3339(SystemTime::now()),
            "run_id": log.run_id,
            "host": self.host,
            "port": self.port,
            "verdict": self.verdict.as_str(),
            "reason": self.reason,
            "bytes_up": up,
            "bytes_down": down,
            "duration_ms": duration_ms,
        });
        log.write_line(&line);
    }
}

/// A reader that adds every successful read to a shared counter.
/// `io::copy` returns no count on error, so counting per read is what
/// keeps the bytes of a reset connection.
pub struct CountingReader<R> {
    inner: R,
    count: Arc<AtomicU64>,
}

impl<R> CountingReader<R> {
    pub fn new(inner: R, count: Arc<AtomicU64>) -> Self {
        CountingReader { inner, count }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.count.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// 16 bytes of `/dev/urandom` as 32 lowercase hex characters.
pub fn run_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot read /dev/urandom for the run id: {error}"),
            )
        })?;
    Ok(hex(&bytes))
}

/// When `/dev/urandom` is unreadable, 32 hex characters from the pid
/// (8) and the low 96 bits of the start time in nanoseconds (24). Unique
/// enough to tell runs apart, never meant to be unguessable.
pub fn fallback_run_id(pid: u32, nanos: u128) -> String {
    let low96 = nanos & ((1u128 << 96) - 1);
    format!("{pid:08x}{low96:024x}")
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            // Writing to a String cannot fail.
            let _ = write!(s, "{b:02x}");
            s
        })
}

#[cfg(test)]
mod tests {
    // The egress line's fields, its escaping, the file's open rules and the
    // warn-once write failure. Assumes `EgressStats: Default` (ProxyConfig
    // defaults it).

    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    const FIELDS: [&str; 10] = [
        "bytes_down",
        "bytes_up",
        "duration_ms",
        "host",
        "port",
        "reason",
        "run_id",
        "ts",
        "v",
        "verdict",
    ];

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("ai-jail-egress-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn stats() -> Arc<EgressStats> {
        Arc::new(EgressStats::default())
    }

    fn lines(path: &std::path::Path) -> Vec<serde_json::Value> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).expect("every line is JSON"))
            .collect()
    }

    fn is_rfc3339_utc(s: &str) -> bool {
        let b = s.as_bytes();
        b.len() == 20
            && b[4] == b'-'
            && b[7] == b'-'
            && b[10] == b'T'
            && b[13] == b':'
            && b[16] == b':'
            && b[19] == b'Z'
    }

    #[test]
    fn run_id_is_32_lowercase_hex_and_unique() {
        let a = run_id().unwrap();
        let b = run_id().unwrap();
        for id in [&a, &b] {
            assert_eq!(id.len(), 32, "{id}");
            assert!(
                id.bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
                "{id}"
            );
        }
        assert_ne!(a, b, "two run ids must never collide");
    }

    #[test]
    fn allowed_connection_line_has_exactly_the_documented_fields() {
        let dir = temp_dir("shape");
        let path = dir.join("egress.jsonl");
        let log = Arc::new(
            EgressLog::open(&path, "0123456789abcdef0123456789abcdef").unwrap(),
        );
        let st = stats();
        {
            let mut rec =
                ConnRecord::begin(Some(Arc::clone(&log)), Arc::clone(&st));
            rec.target("api.example.com", 443);
            rec.verdict(Verdict::Allow, "in-allowlist");
            let (up, down) = rec.counters();
            up.fetch_add(5120, Ordering::Relaxed);
            down.fetch_add(88213, Ordering::Relaxed);
        }
        let got = lines(&path);
        assert_eq!(got.len(), 1, "exactly one line per connection");
        let line = &got[0];
        let mut keys: Vec<&str> = line
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, FIELDS, "only the documented fields");
        assert_eq!(line["v"], 1);
        assert_eq!(line["run_id"], "0123456789abcdef0123456789abcdef");
        assert_eq!(line["host"], "api.example.com");
        assert_eq!(line["port"], 443);
        assert_eq!(line["verdict"], "allow");
        assert_eq!(line["reason"], "in-allowlist");
        assert_eq!(line["bytes_up"], 5120);
        assert_eq!(line["bytes_down"], 88213);
        assert!(line["duration_ms"].is_u64());
        assert!(is_rfc3339_utc(line["ts"].as_str().unwrap()), "{line}");

        let totals = st.snapshot();
        assert_eq!(totals.allowed, 1);
        assert_eq!(totals.denied, 0);
        assert_eq!(totals.errored, 0);
        assert_eq!(totals.bytes_up, 5120);
        assert_eq!(totals.bytes_down, 88213);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_dropped_before_any_verdict_is_one_error_line_with_null_host() {
        // Every early return in handle_conn drops the record: it must still
        // write exactly one line, as an error with no target.
        let dir = temp_dir("early");
        let path = dir.join("egress.jsonl");
        let log = Arc::new(EgressLog::open(&path, &run_id().unwrap()).unwrap());
        let st = stats();
        drop(ConnRecord::begin(Some(Arc::clone(&log)), Arc::clone(&st)));
        let got = lines(&path);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0]["verdict"], "error");
        assert!(got[0]["host"].is_null(), "{}", got[0]);
        assert!(got[0]["port"].is_null(), "{}", got[0]);
        assert_eq!(got[0]["bytes_up"], 0);
        assert_eq!(got[0]["bytes_down"], 0);
        assert_eq!(st.snapshot().errored, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn deny_and_error_keep_their_targets_and_count_separately() {
        let dir = temp_dir("verdicts");
        let path = dir.join("egress.jsonl");
        let log = Arc::new(EgressLog::open(&path, &run_id().unwrap()).unwrap());
        let st = stats();
        {
            let mut rec =
                ConnRecord::begin(Some(Arc::clone(&log)), Arc::clone(&st));
            rec.target("evil.example", 443);
            rec.verdict(Verdict::Deny, "not-in-allowlist");
        }
        {
            // An error AFTER a target was parsed keeps the host (only an
            // unparsed target is null).
            let mut rec =
                ConnRecord::begin(Some(Arc::clone(&log)), Arc::clone(&st));
            rec.target("down.example", 8443);
            rec.verdict(Verdict::Error, "upstream-unreachable");
        }
        let got = lines(&path);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0]["verdict"], "deny");
        assert_eq!(got[0]["reason"], "not-in-allowlist");
        assert_eq!(got[0]["bytes_up"], 0);
        assert_eq!(got[0]["bytes_down"], 0);
        assert_eq!(got[1]["verdict"], "error");
        assert_eq!(got[1]["host"], "down.example");
        assert_eq!(got[1]["port"], 8443);
        let t = st.snapshot();
        assert_eq!((t.allowed, t.denied, t.errored), (0, 1, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stats_count_even_without_a_log_file() {
        let st = stats();
        {
            let mut rec = ConnRecord::begin(None, Arc::clone(&st));
            rec.target("a.example", 443);
            rec.verdict(Verdict::Allow, "in-allowlist");
            rec.counters().0.fetch_add(7, Ordering::Relaxed);
        }
        let t = st.snapshot();
        assert_eq!((t.allowed, t.bytes_up), (1, 7));
    }

    #[test]
    fn hostile_hosts_stay_escaped_on_one_line() {
        let dir = temp_dir("escape");
        let path = dir.join("egress.jsonl");
        let log = Arc::new(EgressLog::open(&path, &run_id().unwrap()).unwrap());
        let hostile = "a\nb\r\u{1b}[31m\u{7f}\u{0}é\u{2028}\"\\.example";
        {
            let mut rec = ConnRecord::begin(Some(Arc::clone(&log)), stats());
            rec.target(hostile, 443);
            rec.verdict(Verdict::Deny, "not-in-allowlist");
        }
        let raw = std::fs::read(&path).unwrap();
        assert_eq!(raw.iter().filter(|b| **b == b'\n').count(), 1, "one line");
        assert_eq!(raw.last(), Some(&b'\n'));
        assert!(
            raw[..raw.len() - 1]
                .iter()
                .all(|b| *b >= 0x20 && *b != 0x7f),
            "no raw control byte in the record"
        );
        let got = lines(&path);
        assert_eq!(got[0]["host"], hostile, "round-trips exactly");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_records_never_interleave() {
        let dir = temp_dir("concurrent");
        let path = dir.join("egress.jsonl");
        let log = Arc::new(EgressLog::open(&path, &run_id().unwrap()).unwrap());
        let st = stats();
        let threads: Vec<_> = (0..32)
            .map(|i| {
                let log = Arc::clone(&log);
                let st = Arc::clone(&st);
                std::thread::spawn(move || {
                    for j in 0..8 {
                        // Long hosts make a split write_all likely to show.
                        let host =
                            format!("{}{i}-{j}.example", "h".repeat(6000));
                        let mut rec = ConnRecord::begin(
                            Some(Arc::clone(&log)),
                            Arc::clone(&st),
                        );
                        rec.target(&host, 443);
                        rec.verdict(Verdict::Deny, "not-in-allowlist");
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let got = lines(&path); // panics on any torn line
        assert_eq!(got.len(), 32 * 8);
        assert_eq!(st.snapshot().denied, 32 * 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_file_is_created_0600_and_appended() {
        let dir = temp_dir("mode");
        let path = dir.join("egress.jsonl");
        std::fs::write(&path, b"{\"earlier\":true}\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let log = Arc::new(EgressLog::open(&path, &run_id().unwrap()).unwrap());
        drop(ConnRecord::begin(Some(log), stats()));
        let got = lines(&path);
        assert_eq!(got.len(), 2, "append, never truncate");
        assert_eq!(got[0]["earlier"], true);

        let fresh = dir.join("fresh.jsonl");
        let _log = EgressLog::open(&fresh, &run_id().unwrap()).unwrap();
        let mode =
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "created with mode 0600");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_symlink_at_the_path_is_refused_and_never_followed() {
        let dir = temp_dir("symlink");
        // A dangling symlink must not create its target.
        let dangling = dir.join("dangling.jsonl");
        let ghost = dir.join("ghost-target");
        symlink(&ghost, &dangling).unwrap();
        assert!(EgressLog::open(&dangling, &run_id().unwrap()).is_err());
        assert!(!ghost.exists(), "the symlink target was created");

        let victim = dir.join("victim");
        std::fs::write(&victim, b"untouched").unwrap();
        let link = dir.join("egress.jsonl");
        symlink(&victim, &link).unwrap();
        let err = EgressLog::open(&link, &run_id().unwrap());
        assert!(err.is_err(), "a symlinked path must be refused");
        assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_missing_directory_is_an_open_error() {
        let dir = temp_dir("missing");
        let path = dir.join("no-such-dir").join("egress.jsonl");
        assert!(EgressLog::open(&path, &run_id().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// a failing write warns once and keeps counting. Runs in a child
    /// test process because it lowers RLIMIT_FSIZE and ignores SIGXFSZ.
    #[test]
    fn write_failure_warns_once_and_keeps_counting() {
        let dir = temp_dir("writefail");
        let output =
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("egress_log::tests::write_failure_warns_once_child")
                .arg("--ignored")
                .arg("--nocapture")
                .env("AI_JAIL_EGRESS_CHILD", &dir)
                .output()
                .expect("spawn child test");
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "child failed\n{stdout}\n{stderr}");
        let path = dir.join("egress.jsonl");
        let warnings = stderr
            .lines()
            .filter(|l| {
                l.contains(&*path.to_string_lossy()) || l.contains("egress")
            })
            .count();
        assert_eq!(warnings, 1, "warn exactly once: {stderr}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[ignore]
    fn write_failure_warns_once_child() {
        let Some(dir) = std::env::var_os("AI_JAIL_EGRESS_CHILD") else {
            return;
        };
        use nix::sys::resource::{Resource, setrlimit};
        use nix::sys::signal::{SigHandler, Signal, signal};
        // SAFETY: SIG_IGN installs no handler code; this child test
        // process runs nothing else that relies on SIGXFSZ.
        unsafe { signal(Signal::SIGXFSZ, SigHandler::SigIgn) }.unwrap();
        let path = PathBuf::from(dir).join("egress.jsonl");
        let log = Arc::new(EgressLog::open(&path, &run_id().unwrap()).unwrap());
        setrlimit(Resource::RLIMIT_FSIZE, 16, 16).unwrap();
        let st = stats();
        for _ in 0..3 {
            let mut rec =
                ConnRecord::begin(Some(Arc::clone(&log)), Arc::clone(&st));
            rec.target("blocked-by-fsize.example", 443);
            rec.verdict(Verdict::Allow, "in-allowlist");
        }
        assert_eq!(st.snapshot().allowed, 3, "relaying keeps counting");
    }

    // ── torn lines ──────────────────────────────
    // Fakes and tests for torn lines: a short write must never leave half a
    // line that the next writer's line is glued onto.

    /// A writer that accepts `budget` bytes, then fails every write.
    struct ShortWriter {
        written: Vec<u8>,
        budget: usize,
    }

    impl Write for ShortWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.budget == 0 {
                return Err(io::Error::other("file too large"));
            }
            let n = buf.len().min(self.budget);
            self.budget -= n;
            self.written.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_line_after_a_failed_write_starts_on_its_own_line() {
        let mut writer = ShortWriter {
            written: Vec::new(),
            budget: 5,
        };
        let mut needs_newline = false;
        assert!(
            write_framed(&mut writer, &mut needs_newline, b"{\"a\":1}\n")
                .is_err()
        );
        assert!(needs_newline, "a torn write must be remembered");
        writer.budget = usize::MAX;
        write_framed(&mut writer, &mut needs_newline, b"{\"b\":2}\n").unwrap();
        assert_eq!(writer.written, b"{\"a\":\n{\"b\":2}\n");
        assert!(!needs_newline);
    }

    #[test]
    fn a_clean_log_gets_no_extra_newline() {
        let mut writer = ShortWriter {
            written: Vec::new(),
            budget: usize::MAX,
        };
        let mut needs_newline = false;
        write_framed(&mut writer, &mut needs_newline, b"{}\n").unwrap();
        write_framed(&mut writer, &mut needs_newline, b"{}\n").unwrap();
        assert_eq!(writer.written, b"{}\n{}\n");
    }

    #[test]
    fn a_fragment_left_by_an_earlier_run_is_terminated() {
        let dir = std::env::temp_dir()
            .join(format!("egress-torn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("egress.jsonl");
        std::fs::write(&path, b"{\"ok\":1}\n{\"bytes_down\":0,").unwrap();
        let log = EgressLog::open(&path, "r1").unwrap();
        log.write_line(&serde_json::json!({"x": 1}));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "{\"ok\":1}\n{\"bytes_down\":0,\n{\"x\":1}\n");
        // An intact log is left as it is.
        std::fs::write(&path, b"{\"ok\":1}\n").unwrap();
        let log = EgressLog::open(&path, "r1").unwrap();
        log.write_line(&serde_json::json!({"x": 1}));
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text, "{\"ok\":1}\n{\"x\":1}\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
