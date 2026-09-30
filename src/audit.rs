//! Opt-in launch audit log (phase 5 of docs/connect-proxy-plan.md).
//!
//! One JSONL record per launch, appended when the child exits; when
//! filtered egress is active the proxy threads append CONNECT verdict
//! records through the same supervisor-side handle. The file lives at
//! `~/.local/share/ai-jail/history.jsonl` -- the sandbox never sees it
//! (it is outside every mount).
//!
//! Logging must never break a launch: write errors warn once and are
//! otherwise ignored. Unsafe paths, file types and ownership get
//! `security_warn`, including in quiet mode.
//!
//! Every record is hash-chained over the raw line bytes as written (no
//! JSON canonicalization): each line carries `seq` (its 0-based line
//! index) and `prev` (sha256 of the previous raw line, null at
//! genesis), so `--audit-verify` re-hashes file bytes directly. Legacy
//! v2.x unchained lines need no migration: the first chained record
//! simply links to the sha256 of the previous raw line, whatever it is.

use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::output;

pub(crate) struct ShowReport {
    pub total: u64,
    pub invalid: u64,
}

/// Open one entry relative to a pinned directory, without following symlinks.
fn open_entry(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
    flags: nix::libc::c_int,
    mode: nix::libc::mode_t,
) -> std::io::Result<std::fs::File> {
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd};

    // SAFETY: parent is live and name is a NUL-terminated C string.
    // The creation mode is supplied even when O_CREAT is absent. Promote
    // mode_t for the variadic argument (it is u16 on macOS).
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_CLOEXEC | libc::O_NOFOLLOW | flags,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh descriptor owned by this function.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

/// Read existing events only. The writer receives one safe line per record;
/// malformed records are marked and counted, and I/O errors propagate.
pub(crate) fn show(
    home: &Path,
    writer: &mut impl Write,
) -> std::io::Result<Option<ShowReport>> {
    use nix::libc;
    use std::io::{BufRead, Error, ErrorKind};
    use std::os::unix::fs::MetadataExt;

    let open_log = || -> std::io::Result<std::fs::File> {
        let mut parent = std::fs::File::open(home)?;
        for name in [c".local", c"share", c"ai-jail"] {
            parent = open_entry(
                &parent,
                name,
                libc::O_RDONLY | libc::O_DIRECTORY,
                0,
            )?;
        }
        // NONBLOCK avoids hanging on a FIFO before checking the file type.
        open_entry(
            &parent,
            c"history.jsonl",
            libc::O_RDONLY | libc::O_NONBLOCK,
            0,
        )
    };
    let file = match open_log() {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "audit log is not a regular file",
        ));
    }
    // SAFETY: geteuid has no preconditions.
    if metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "audit log must be owned by this user with no group/other permissions",
        ));
    }

    let mut report = ShowReport {
        total: 0,
        invalid: 0,
    };
    let mut reader = std::io::BufReader::new(file);
    let mut line = Vec::new();
    loop {
        line.clear();
        if reader.read_until(b'\n', &mut line)? == 0 {
            break;
        }
        report.total += 1;
        let summary = serde_json::from_slice::<serde_json::Value>(&line)
            .ok()
            .and_then(|record| summarize(&record));
        let summary = summary.unwrap_or_else(|| {
            report.invalid += 1;
            format!("[invalid record at line {}]", report.total)
        });
        let mut safe = String::with_capacity(summary.len());
        for ch in summary.chars() {
            // Also escape Unicode bidi controls and line/paragraph separators.
            if ch.is_control()
                || matches!(
                    ch,
                    '\u{061c}'
                        | '\u{200e}'
                        | '\u{200f}'
                        | '\u{2028}'..='\u{202e}'
                        | '\u{2066}'..='\u{2069}'
                )
            {
                safe.extend(ch.escape_default());
            } else {
                safe.push(ch);
            }
        }
        writeln!(writer, "{safe}")?;
    }
    writer.flush()?;
    Ok(Some(report))
}

fn summarize(record: &serde_json::Value) -> Option<String> {
    let ts = record.get("ts")?.as_str()?;
    let kind = record.get("type")?.as_str()?;
    Some(match kind {
        "launch" => {
            let command = record.get("command")?.as_array()?;
            if !command.iter().all(serde_json::Value::is_string) {
                return None;
            }
            let command = serde_json::to_string(command).ok()?;
            let code = record.get("exit_code")?.as_i64()?;
            let duration = record.get("duration_s")?.as_f64()?;
            format!("{ts}  launch {command}  (exit {code}, {duration:.1}s)")
        }
        "connect" => {
            let host = record.get("host")?.as_str()?;
            let port = u16::try_from(record.get("port")?.as_u64()?).ok()?;
            let verdict = record.get("verdict")?.as_str()?;
            let reason = record.get("reason")?.as_str()?;
            format!("{ts}  connect {host}:{port}  {verdict} ({reason})")
        }
        "secret_inject" => {
            let key = record.get("key")?.as_str()?;
            let host = record.get("host")?.as_str()?;
            let count = record.get("substitutions")?.as_u64()?;
            format!("{ts}  credential {key} -> {host}  ({count} substitutions)")
        }
        _ => format!("{ts}  {kind}  (unrecognized audit record)"),
    })
}

/// Append-only JSONL audit log handle. Cheap to share: the proxy
/// threads hold an `Arc<AuditLog>` clone of the supervisor's handle.
pub(crate) struct AuditLog {
    chain: Mutex<ChainState>,
    warned: AtomicBool,
}

struct ChainState {
    file: std::fs::File,
    /// sha256 of the last line written, as lowercase hex.
    prev: Option<String>,
    seq: u64,
    /// The file on disk did not end with a newline (e.g. truncated
    /// tail): the next append must first terminate that remnant, or the
    /// new record would glue onto it.
    needs_newline: bool,
}

/// What one launch record carries. Kept deliberately small: the same
/// capability summary `ai-jail status` prints, not the whole config.
pub(crate) struct LaunchRecord<'a> {
    pub command: &'a [String],
    pub network_mode: &'static str,
    pub allow_hosts: &'a [String],
    pub lockdown: bool,
    pub agent_state: bool,
    pub gpu: bool,
    pub display: bool,
    pub audio: bool,
    pub browser_profile: Option<&'a str>,
    pub project_config: bool,
    pub project_trusted: bool,
    pub global_config: bool,
    pub exit_code: i32,
    pub duration: std::time::Duration,
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

#[derive(Debug)]
enum WriteLogError {
    Unsafe(&'static str),
    Io(std::io::Error),
}

impl From<std::io::Error> for WriteLogError {
    fn from(error: std::io::Error) -> Self {
        use nix::libc;

        match error.raw_os_error() {
            // O_DIRECTORY | O_NOFOLLOW can report ENOTDIR for a link.
            // Opening a directory or Unix socket as a writable log can
            // fail before we have a descriptor to inspect.
            Some(libc::ELOOP | libc::ENOTDIR | libc::EISDIR | libc::ENXIO) => {
                Self::Unsafe(
                    "audit path contains a symlink or invalid file type",
                )
            }
            _ => Self::Io(error),
        }
    }
}

impl std::fmt::Display for WriteLogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsafe(message) => f.write_str(message),
            Self::Io(error) => error.fmt(f),
        }
    }
}

/// Open or create one directory below an already pinned parent. A
/// competing mkdir is harmless: the subsequent open still refuses links.
fn open_write_directory(
    parent: &std::fs::File,
    name: &std::ffi::CStr,
    mode: nix::libc::mode_t,
) -> Result<std::fs::File, WriteLogError> {
    use nix::libc;
    use std::io::ErrorKind;
    use std::os::fd::AsRawFd;

    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    match open_entry(parent, name, flags, 0) {
        Ok(directory) => return Ok(directory),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    // SAFETY: parent is live, name is NUL-terminated and mode is valid.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), mode) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.kind() != ErrorKind::AlreadyExists {
            return Err(error.into());
        }
    }
    Ok(open_entry(parent, name, flags, 0)?)
}

fn privatize_log_directory(
    directory: &std::fs::File,
) -> Result<(), WriteLogError> {
    use nix::libc;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no preconditions.
    if !metadata.is_dir() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(WriteLogError::Unsafe(
            "audit directory must be owned by this user",
        ));
    }
    directory.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn open_write_dir(home: &Path) -> Result<std::fs::File, WriteLogError> {
    let mut parent = std::fs::File::open(home)?;
    for name in [c".local", c"share"] {
        parent = open_write_directory(&parent, name, 0o777)?;
    }
    let directory = open_write_directory(&parent, c"ai-jail", 0o700)?;
    privatize_log_directory(&directory)?;
    Ok(directory)
}

fn validate_write_file(
    file: &std::fs::File,
) -> Result<std::fs::Metadata, WriteLogError> {
    use nix::libc;
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(WriteLogError::Unsafe("audit log is not a regular file"));
    }
    // SAFETY: geteuid has no preconditions.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(WriteLogError::Unsafe(
            "audit log must be owned by this user",
        ));
    }
    Ok(metadata)
}

/// Recover a user-owned write-only log without changing permissions on a
/// pathname. Keep the original fd live until the readable fd's identity
/// has been checked; a replacement must not seed or receive an append.
fn recover_write_only_log(
    directory: &std::fs::File,
    original: std::fs::File,
) -> Result<std::fs::File, WriteLogError> {
    use nix::libc;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let before = validate_write_file(&original)?;
    original.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let file = open_entry(
        directory,
        c"history.jsonl",
        libc::O_RDWR | libc::O_APPEND | libc::O_NONBLOCK,
        0,
    )?;
    let after = validate_write_file(&file)?;
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(WriteLogError::Unsafe(
            "audit log changed while recovering permissions",
        ));
    }
    Ok(file)
}

fn open_write_file(
    directory: &std::fs::File,
) -> Result<std::fs::File, WriteLogError> {
    use nix::libc;
    use std::io::ErrorKind;

    let flags = libc::O_APPEND | libc::O_NONBLOCK;
    match open_entry(
        directory,
        c"history.jsonl",
        libc::O_RDWR | libc::O_CREAT | flags,
        0o600,
    ) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            let original = open_entry(
                directory,
                c"history.jsonl",
                libc::O_WRONLY | flags,
                0,
            )?;
            recover_write_only_log(directory, original)
        }
        Err(error) => Err(error.into()),
    }
}

/// Seed the chain from an existing log file: stream it once, counting
/// lines and hashing each raw line (without its trailing newline), so
/// appends link to the last line as written -- chained or legacy. The
/// bool reports whether the file lacks a trailing newline (the next
/// append must then terminate the remnant first). A read failure disables
/// logging rather than inventing a new genesis on an unread history.
fn seed_chain(
    file: &mut std::fs::File,
) -> std::io::Result<(Option<String>, u64, bool)> {
    use std::io::{BufRead, Seek};

    file.rewind()?;
    let mut reader = std::io::BufReader::new(file);
    let mut prev = None;
    let mut seq = 0_u64;
    let mut needs_newline = false;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        match reader.read_until(b'\n', &mut buf) {
            Ok(0) => break,
            Ok(_) => {
                needs_newline = !buf.ends_with(b"\n");
                let line = buf.strip_suffix(b"\n").unwrap_or(&buf);
                prev = Some(sha256_hex(line));
                seq += 1;
            }
            Err(error) => return Err(error),
        }
    }
    Ok((prev, seq, needs_newline))
}

fn prepare_chain(mut file: std::fs::File) -> Result<ChainState, WriteLogError> {
    use std::os::unix::fs::PermissionsExt;

    validate_write_file(&file)?;
    // Existing user-owned logs may have looser permissions. Correct only
    // the validated fd, then seed and append through that same file.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    let (prev, seq, needs_newline) = seed_chain(&mut file)?;
    Ok(ChainState {
        file,
        prev,
        seq,
        needs_newline,
    })
}

impl AuditLog {
    /// Open the log under `home`, creating `~/.local/share/ai-jail`
    /// (0700) and `history.jsonl` (0600). All components below trusted
    /// HOME are opened without following links. Unsafe paths/types/owners
    /// warn even in quiet mode; other failures warn plainly. The launch
    /// proceeds either way.
    pub(crate) fn open(home: &Path) -> Option<std::sync::Arc<AuditLog>> {
        let open = || {
            let directory = open_write_dir(home)?;
            prepare_chain(open_write_file(&directory)?)
        };
        let chain = match open() {
            Ok(chain) => chain,
            Err(error) => {
                let message = format!(
                    "audit log disabled: {}: {error}",
                    home.join(".local/share/ai-jail/history.jsonl").display()
                );
                match error {
                    WriteLogError::Unsafe(_) => output::security_warn(&message),
                    WriteLogError::Io(_) => output::warn(&message),
                }
                return None;
            }
        };
        Some(std::sync::Arc::new(AuditLog {
            chain: Mutex::new(chain),
            warned: AtomicBool::new(false),
        }))
    }

    /// Append one JSON record. Write errors warn once and are dropped:
    /// logging must not break sandboxes.
    ///
    /// The `seq`/`prev` chain fields are inserted here, not in the
    /// record builders, so every record type participates unchanged.
    pub(crate) fn record(&self, entry: serde_json::Value) {
        let mut entry = entry;
        let mut state = self.chain.lock().unwrap();
        if let Some(obj) = entry.as_object_mut() {
            obj.insert("seq".to_string(), state.seq.into());
            obj.insert(
                "prev".to_string(),
                state
                    .prev
                    .as_deref()
                    .map_or(serde_json::Value::Null, |p| p.into()),
            );
        }
        // The chain hashes the raw line bytes as written, without the
        // trailing newline.
        let mut line = entry.to_string();
        let hash = sha256_hex(line.as_bytes());
        line.push('\n');
        if state.needs_newline {
            line.insert(0, '\n');
            state.needs_newline = false;
        }
        let result = state.file.write_all(line.as_bytes());
        if result.is_err() && !self.warned.swap(true, Ordering::SeqCst) {
            output::warn("audit log write failed; further errors suppressed");
        }
        if result.is_ok() {
            state.prev = Some(hash);
            state.seq += 1;
        }
    }
}

/// RFC3339 (UTC, second precision) from std alone -- no chrono. The
/// civil-date conversion is Howard Hinnant's days-from-civil algorithm.
fn rfc3339(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (hour, min, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}Z")
}

/// One launch record: who ran, with which effective capabilities, from
/// which config sources, and how it ended.
pub(crate) fn launch_record(record: &LaunchRecord<'_>) -> serde_json::Value {
    serde_json::json!({
        "ts": rfc3339(SystemTime::now()),
        "type": "launch",
        "command": record.command,
        "network": record.network_mode,
        "allow_hosts": record.allow_hosts,
        "lockdown": record.lockdown,
        "agent_state": record.agent_state,
        "gpu": record.gpu,
        "display": record.display,
        "audio": record.audio,
        "browser_profile": record.browser_profile,
        "config": {
            "project": record.project_config,
            "project_trusted": record.project_trusted,
            "global": record.global_config,
        },
        "exit_code": record.exit_code,
        "duration_s": record.duration.as_millis() as f64 / 1000.0,
    })
}

/// One proxy CONNECT verdict record (filtered egress only).
pub(crate) fn connect_record(
    host: &str,
    port: u16,
    verdict: &str,
    reason: &str,
) -> serde_json::Value {
    serde_json::json!({
        "ts": rfc3339(SystemTime::now()),
        "type": "connect",
        "host": host,
        "port": port,
        "verdict": verdict,
        "reason": reason,
    })
}

/// One phantom-credential substitution record (filtered egress +
/// `--secret`). Names the host, the env var, and the substitution
/// count -- never a value, real or placeholder.
pub(crate) fn secret_inject_record(
    host: &str,
    key: &str,
    substitutions: usize,
) -> serde_json::Value {
    serde_json::json!({
        "ts": rfc3339(SystemTime::now()),
        "type": "secret_inject",
        "host": host,
        "key": key,
        "substitutions": substitutions,
    })
}

/// Outcome of [`verify`]: line counts and the first chain break.
pub(crate) struct VerifyReport {
    /// Lines in the file.
    pub total: u64,
    /// Lines carrying `seq`/`prev` chain fields.
    pub chained: u64,
    /// Valid JSON lines without chain fields (pre-chain records).
    pub legacy: u64,
    /// 1-based number of the first offending line, if any.
    pub first_break: Option<u64>,
}

/// Verify the hash chain of an audit log, line by line (1-based):
///
/// - a line that is not valid JSON is a break (a corrupt record --
///   e.g. a truncated tail) and counts as neither chained nor legacy;
/// - a valid JSON line without both `seq` and `prev` fields is a
///   legacy (pre-chain) record and re-seeds the chain expectation from
///   its own raw bytes;
/// - a chained line breaks when its `prev` is not the sha256 of the
///   previous raw line (genesis, line 1, expects null) or its `seq` is
///   not the line's 0-based index.
///
/// Every expectation is computed from the actual bytes on disk, so a
/// break does not cascade: `first_break` is the first offending line.
pub(crate) fn verify(path: &Path) -> std::io::Result<VerifyReport> {
    use std::io::BufRead;

    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let mut report = VerifyReport {
        total: 0,
        chained: 0,
        legacy: 0,
        first_break: None,
    };
    let mut prev_hash: Option<String> = None;
    let mut buf = Vec::new();
    loop {
        buf.clear();
        if reader.read_until(b'\n', &mut buf)? == 0 {
            break;
        }
        report.total += 1;
        let line = buf.strip_suffix(b"\n").unwrap_or(&buf);
        let parsed: Option<serde_json::Value> =
            serde_json::from_slice(line).ok();
        let chain_fields =
            parsed.as_ref().and_then(|v| v.as_object()).and_then(|obj| {
                let seq = obj.get("seq")?.as_u64()?;
                let prev = obj.get("prev")?;
                Some((seq, prev))
            });
        match chain_fields {
            None if parsed.is_none() => {
                // Corrupt record: not verifiable as anything.
                if report.first_break.is_none() {
                    report.first_break = Some(report.total);
                }
            }
            None => {
                report.legacy += 1;
            }
            Some((seq, prev)) => {
                report.chained += 1;
                let prev_matches = match (&prev_hash, prev) {
                    (None, serde_json::Value::Null) => true,
                    (Some(expected), serde_json::Value::String(actual)) => {
                        expected == actual
                    }
                    _ => false,
                };
                let seq_matches = seq == report.total - 1;
                if !(prev_matches && seq_matches)
                    && report.first_break.is_none()
                {
                    report.first_break = Some(report.total);
                }
            }
        }
        prev_hash = Some(sha256_hex(line));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn test_home(name: &str) -> PathBuf {
        let home = std::env::temp_dir()
            .join(format!("ai-jail-audit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    fn log_path(home: &Path) -> PathBuf {
        home.join(".local/share/ai-jail/history.jsonl")
    }

    struct WriterFixture {
        home: PathBuf,
    }

    impl WriterFixture {
        fn new(name: &str) -> Self {
            Self {
                home: test_home(name),
            }
        }

        fn write(&self, content: &str, mode: u32) -> PathBuf {
            let path = log_path(&self.home);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(
                &path,
                std::fs::Permissions::from_mode(mode),
            )
            .unwrap();
            path
        }
    }

    impl Drop for WriterFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn log_from_chain(chain: ChainState) -> AuditLog {
        AuditLog {
            chain: Mutex::new(chain),
            warned: AtomicBool::new(false),
        }
    }

    #[test]
    fn writer_preserves_owned_modes_and_legacy_content() {
        let legacy = "{\"legacy\":true}";
        for permissions in [0o600, 0o644, 0o660, 0o200] {
            let fixture =
                WriterFixture::new(&format!("writer-mode-{permissions}"));
            let path = fixture.write(&format!("{legacy}\n"), permissions);
            for ancestor in [".local", ".local/share"] {
                std::fs::set_permissions(
                    fixture.home.join(ancestor),
                    std::fs::Permissions::from_mode(0o755),
                )
                .unwrap();
            }
            let log = AuditLog::open(&fixture.home).unwrap();
            probe(&log, 1);
            drop(log);
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
            for ancestor in [".local", ".local/share"] {
                assert_eq!(mode(&fixture.home.join(ancestor)), 0o755);
            }
            let content = std::fs::read_to_string(&path).unwrap();
            assert!(content.starts_with(&format!("{legacy}\n")));
            let record: serde_json::Value =
                serde_json::from_str(content.lines().nth(1).unwrap()).unwrap();
            assert_eq!(record["seq"], 1);
            assert_eq!(record["prev"], sha256_hex(legacy.as_bytes()));
            assert_eq!(verify(&path).unwrap().first_break, None);
        }
    }

    #[test]
    fn writer_accepts_trusted_home_symlink() {
        let fixture = WriterFixture::new("writer-home-link");
        let alias = fixture.home.join("trusted-home");
        std::os::unix::fs::symlink(&fixture.home, &alias).unwrap();
        let log = AuditLog::open(&alias).unwrap();
        probe(&log, 1);
        drop(log);
        assert_eq!(verify(&log_path(&fixture.home)).unwrap().chained, 1);
    }

    #[test]
    fn writer_refuses_live_and_dangling_links_at_every_component() {
        for suffix in [
            ".local",
            ".local/share",
            ".local/share/ai-jail",
            ".local/share/ai-jail/history.jsonl",
        ] {
            for dangling in [false, true] {
                let fixture = WriterFixture::new(&format!(
                    "writer-link-{}-{dangling}",
                    suffix.replace('/', "-")
                ));
                let link = fixture.home.join(suffix);
                std::fs::create_dir_all(link.parent().unwrap()).unwrap();
                let target = fixture.home.join("outside");
                let victim = if suffix.ends_with("history.jsonl") {
                    target.clone()
                } else {
                    std::fs::create_dir_all(&target).unwrap();
                    target.join("history.jsonl")
                };
                if !dangling {
                    std::fs::write(&victim, "untouched\n").unwrap();
                    std::fs::set_permissions(
                        &victim,
                        std::fs::Permissions::from_mode(0o644),
                    )
                    .unwrap();
                } else if target.is_dir() {
                    std::fs::remove_dir(&target).unwrap();
                }
                std::os::unix::fs::symlink(&target, &link).unwrap();
                assert!(AuditLog::open(&fixture.home).is_none());
                assert!(
                    std::fs::symlink_metadata(&link)
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
                if dangling {
                    assert!(!target.exists());
                } else {
                    assert_eq!(
                        std::fs::read_to_string(&victim).unwrap(),
                        "untouched\n"
                    );
                    assert_eq!(mode(&victim), 0o644);
                }
            }
        }
    }

    #[test]
    fn writer_refuses_non_regular_entries_without_chmod() {
        use std::os::unix::ffi::OsStrExt;

        let fixture = WriterFixture::new("writer-log-directory");
        let path = log_path(&fixture.home);
        std::fs::create_dir_all(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert!(AuditLog::open(&fixture.home).is_none());
        assert_eq!(mode(&path), 0o755);

        // Keep the socket path below macOS's 104-byte limit even when
        // TMPDIR is long. mkdtemp creates a private, exclusive directory;
        // WriterFixture removes it on drop.
        let mut template = *b"/tmp/ai-jail-audit-XXXXXX\0";
        // SAFETY: template is writable, NUL-terminated and ends in six Xs.
        let directory =
            unsafe { nix::libc::mkdtemp(template.as_mut_ptr().cast()) };
        assert!(!directory.is_null(), "{}", std::io::Error::last_os_error());
        let fixture = WriterFixture {
            home: PathBuf::from(std::ffi::OsStr::from_bytes(
                &template[..template.len() - 1],
            )),
        };
        let path = log_path(&fixture.home);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let before = mode(&path);
        assert!(AuditLog::open(&fixture.home).is_none());
        assert_eq!(mode(&path), before);

        for suffix in [".local", ".local/share", ".local/share/ai-jail"] {
            let fixture = WriterFixture::new(&format!(
                "writer-parent-file-{}",
                suffix.replace('/', "-")
            ));
            let path = fixture.home.join(suffix);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "untouched").unwrap();
            let before = mode(&path);
            assert!(AuditLog::open(&fixture.home).is_none());
            assert_eq!(std::fs::read_to_string(&path).unwrap(), "untouched");
            assert_eq!(mode(&path), before);
        }
    }

    #[test]
    fn writer_uses_pinned_directories_after_path_replacement() {
        let names = [c".local", c"share", c"ai-jail"];
        let suffixes = [".local", ".local/share", ".local/share/ai-jail"];
        let remaining = [
            "share/ai-jail/history.jsonl",
            "ai-jail/history.jsonl",
            "history.jsonl",
        ];
        for (replaced, rest) in remaining.into_iter().enumerate() {
            let fixture =
                WriterFixture::new(&format!("writer-pinned-dir-{replaced}"));
            let legacy = "{\"legacy\":true}";
            fixture.write(&format!("{legacy}\n"), 0o644);
            let outside = fixture.home.join("outside");
            let victim = outside.join(rest);
            std::fs::create_dir_all(victim.parent().unwrap()).unwrap();
            std::fs::write(&victim, "untouched\n").unwrap();
            std::fs::set_permissions(
                &outside,
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
            let before = mode(&victim);
            let moved = fixture.home.join("moved");
            let mut parent = std::fs::File::open(&fixture.home).unwrap();
            for (index, name) in names.into_iter().enumerate() {
                parent = open_write_directory(&parent, name, 0o700).unwrap();
                if index == replaced {
                    let path = fixture.home.join(suffixes[index]);
                    std::fs::rename(&path, &moved).unwrap();
                    std::os::unix::fs::symlink(&outside, &path).unwrap();
                }
            }
            privatize_log_directory(&parent).unwrap();
            let log = log_from_chain(
                prepare_chain(open_write_file(&parent).unwrap()).unwrap(),
            );
            probe(&log, 1);
            drop(log);
            let actual = moved.join(rest);
            assert_eq!(verify(&actual).unwrap().first_break, None);
            assert_eq!(verify(&actual).unwrap().chained, 1);
            assert_eq!(
                std::fs::read_to_string(&victim).unwrap(),
                "untouched\n"
            );
            assert_eq!(mode(&victim), before);
            assert_eq!(mode(&outside), 0o755);
        }
    }

    #[test]
    fn writer_chmods_seeds_and_appends_to_the_opened_file() {
        let fixture = WriterFixture::new("writer-pinned-leaf");
        let path = fixture.write("{\"legacy\":true}\n", 0o644);
        let directory = open_write_dir(&fixture.home).unwrap();
        let file = open_write_file(&directory).unwrap();
        let moved = fixture.home.join("moved.jsonl");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, "untouched\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let log = log_from_chain(prepare_chain(file).unwrap());
        probe(&log, 1);
        drop(log);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "untouched\n");
        assert_eq!(mode(&path), 0o644);
        assert_eq!(mode(&moved), 0o600);
        let report = verify(&moved).unwrap();
        assert_eq!(report.first_break, None);
        assert_eq!(report.total, 2);
        assert_eq!(report.chained, 1);
    }

    #[test]
    fn writer_write_only_recovery_refuses_replaced_inode() {
        use nix::libc;

        let fixture = WriterFixture::new("writer-replaced-write-only");
        let path = fixture.write("{\"legacy\":true}\n", 0o200);
        let directory = open_write_dir(&fixture.home).unwrap();
        let original = open_entry(
            &directory,
            c"history.jsonl",
            libc::O_WRONLY | libc::O_APPEND | libc::O_NONBLOCK,
            0,
        )
        .unwrap();
        let moved = fixture.home.join("moved.jsonl");
        std::fs::rename(&path, &moved).unwrap();
        std::fs::write(&path, "untouched\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        assert!(matches!(
            recover_write_only_log(&directory, original),
            Err(WriteLogError::Unsafe(
                "audit log changed while recovering permissions"
            ))
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "untouched\n");
        assert_eq!(mode(&path), 0o644);
        assert_eq!(mode(&moved), 0o600);
    }

    #[test]
    fn writer_seed_read_error_does_not_return_genesis() {
        let fixture = WriterFixture::new("writer-seed-error");
        let path = fixture.write("{\"legacy\":true}\n", 0o600);
        let file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        assert!(matches!(prepare_chain(file), Err(WriteLogError::Io(_))));
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "{\"legacy\":true}\n"
        );
    }

    struct TestChild(std::process::Child);

    impl Drop for TestChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    #[test]
    #[ignore = "subprocess entry for the bounded FIFO regression"]
    fn writer_fifo_child() {
        let home = std::env::var_os("AI_JAIL_TEST_AUDIT_FIFO_HOME").unwrap();
        assert!(AuditLog::open(Path::new(&home)).is_none());
    }

    #[test]
    fn writer_refuses_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt;
        use std::time::{Duration, Instant};

        let fixture = WriterFixture::new("writer-fifo");
        let path = log_path(&fixture.home);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let name = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: name is a valid NUL-terminated pathname.
        assert_eq!(unsafe { nix::libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let mut child = TestChild(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "audit::tests::writer_fifo_child",
                ])
                .env("AI_JAIL_TEST_AUDIT_FIFO_HOME", &fixture.home)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "audit writer blocked on a FIFO"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    #[ignore = "requires root to open entries owned by another UID"]
    fn writer_refuses_foreign_owned_entries() {
        use std::os::unix::fs::{MetadataExt, chown};

        // SAFETY: geteuid has no preconditions.
        assert_eq!(unsafe { nix::libc::geteuid() }, 0, "run this test as root");
        for directory in [false, true] {
            let fixture = WriterFixture::new(&format!(
                "writer-foreign-owner-{directory}"
            ));
            let path = fixture.write("{\"legacy\":true}\n", 0o640);
            let foreign = if directory {
                path.parent().unwrap()
            } else {
                &path
            };
            std::fs::set_permissions(
                foreign,
                std::fs::Permissions::from_mode(if directory {
                    0o750
                } else {
                    0o640
                }),
            )
            .unwrap();
            chown(foreign, Some(1), None).unwrap();
            let before = mode(foreign);
            assert_eq!(std::fs::metadata(foreign).unwrap().uid(), 1);
            // Root can access it: refusal must come from our metadata policy.
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "{\"legacy\":true}\n"
            );
            assert!(AuditLog::open(&fixture.home).is_none());
            assert_eq!(mode(foreign), before);
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "{\"legacy\":true}\n"
            );
            chown(foreign, Some(0), None).unwrap();
            let log = AuditLog::open(&fixture.home).unwrap();
            probe(&log, 1);
            drop(log);
            assert_eq!(verify(&path).unwrap().first_break, None);
        }
    }

    #[test]
    fn rfc3339_shape_and_known_epoch() {
        // 1970-01-01T00:00:00Z
        assert_eq!(rfc3339(UNIX_EPOCH), "1970-01-01T00:00:00Z");
        // 1_789_094_096 s past the epoch is 2026-09-11T02:34:56Z.
        let ts =
            rfc3339(UNIX_EPOCH + std::time::Duration::from_secs(1_789_094_096));
        assert_eq!(ts, "2026-09-11T02:34:56Z");
        assert_eq!(rfc3339(SystemTime::now()).len(), 20);
    }

    #[test]
    fn open_creates_dir_and_file_with_private_modes() {
        let home = test_home("create");
        let log = AuditLog::open(&home).expect("open should succeed");
        let dir_mode = std::fs::metadata(log_path(&home).parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        log.record(serde_json::json!({"probe": true}));
        drop(log);
        let file_mode = std::fs::metadata(log_path(&home))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600);
        let content = std::fs::read_to_string(log_path(&home)).unwrap();
        let line: serde_json::Value =
            serde_json::from_str(content.trim()).unwrap();
        assert_eq!(line["probe"], true);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn open_refuses_symlinked_directory() {
        let home = test_home("dir-symlink");
        let target = test_home("dir-symlink-target");
        std::fs::create_dir_all(home.join(".local/share")).unwrap();
        std::os::unix::fs::symlink(&target, home.join(".local/share/ai-jail"))
            .unwrap();
        assert!(AuditLog::open(&home).is_none());
        // Nothing was written through the link.
        assert!(!log_path(&target).exists());
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(&target);
    }

    #[test]
    fn open_refuses_symlinked_file() {
        let home = test_home("file-symlink");
        let outside = test_home("file-symlink-outside").join("victim");
        std::fs::write(&outside, b"").unwrap();
        let dir = home.join(".local/share/ai-jail");
        std::fs::create_dir_all(&dir).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("history.jsonl"))
            .unwrap();
        assert!(AuditLog::open(&home).is_none());
        assert!(std::fs::read_to_string(&outside).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&home);
        let _ = std::fs::remove_dir_all(outside.parent().unwrap());
    }

    #[test]
    fn launch_and_connect_records_are_json_lines() {
        let home = test_home("records");
        let log = AuditLog::open(&home).unwrap();
        let launch = LaunchRecord {
            command: &["claude".to_string(), "--continue".to_string()],
            network_mode: "filtered",
            allow_hosts: &["api.anthropic.com".to_string()],
            lockdown: false,
            agent_state: true,
            gpu: false,
            display: false,
            audio: false,
            browser_profile: None,
            project_config: true,
            project_trusted: false,
            global_config: true,
            exit_code: 0,
            duration: std::time::Duration::from_millis(1500),
        };
        log.record(launch_record(&launch));
        log.record(connect_record(
            "api.anthropic.com",
            443,
            "allow",
            "in-allowlist",
        ));
        drop(log);
        let content = std::fs::read_to_string(log_path(&home)).unwrap();
        let lines: Vec<serde_json::Value> = content
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["type"], "launch");
        assert_eq!(lines[0]["command"][0], "claude");
        assert_eq!(lines[0]["network"], "filtered");
        assert_eq!(lines[0]["exit_code"], 0);
        assert_eq!(lines[0]["duration_s"], 1.5);
        assert_eq!(lines[1]["type"], "connect");
        assert_eq!(lines[1]["host"], "api.anthropic.com");
        assert_eq!(lines[1]["verdict"], "allow");
        let _ = std::fs::remove_dir_all(&home);
    }

    fn probe(log: &AuditLog, n: u64) {
        log.record(serde_json::json!({"probe": n}));
    }

    #[test]
    fn genesis_record_has_null_prev_and_seq_zero() {
        let home = test_home("genesis");
        let log = AuditLog::open(&home).unwrap();
        probe(&log, 1);
        drop(log);
        let content = std::fs::read_to_string(log_path(&home)).unwrap();
        let line: serde_json::Value =
            serde_json::from_str(content.trim()).unwrap();
        assert_eq!(line["seq"], 0);
        assert_eq!(line["prev"], serde_json::Value::Null);
        let report = verify(&log_path(&home)).unwrap();
        assert_eq!(report.total, 1);
        assert_eq!(report.chained, 1);
        assert_eq!(report.legacy, 0);
        assert_eq!(report.first_break, None);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn chain_survives_drop_and_reopen() {
        let home = test_home("reopen");
        let log = AuditLog::open(&home).unwrap();
        probe(&log, 1);
        probe(&log, 2);
        drop(log);

        // Re-open: the chain seeds from the last line on disk.
        let log = AuditLog::open(&home).unwrap();
        probe(&log, 3);
        drop(log);

        let content = std::fs::read_to_string(log_path(&home)).unwrap();
        let lines: Vec<serde_json::Value> = content
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 3);
        let seqs: Vec<u64> =
            lines.iter().map(|l| l["seq"].as_u64().unwrap()).collect();
        assert_eq!(seqs, vec![0, 1, 2]);
        let raw: Vec<&str> = content.lines().collect();
        assert_eq!(
            lines[1]["prev"].as_str().unwrap(),
            sha256_hex(raw[0].as_bytes())
        );
        assert_eq!(
            lines[2]["prev"].as_str().unwrap(),
            sha256_hex(raw[1].as_bytes())
        );
        let report = verify(&log_path(&home)).unwrap();
        assert_eq!(report.first_break, None);
        assert_eq!(report.chained, 3);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn verify_detects_tampered_middle_line() {
        let home = test_home("tamper");
        let log = AuditLog::open(&home).unwrap();
        for n in 1..=3 {
            probe(&log, n);
        }
        drop(log);

        // Rewrite line 2's payload, keeping it valid JSON. Its own
        // seq/prev still check out; the break surfaces at line 3, whose
        // prev no longer matches the bytes now on disk.
        let path = log_path(&home);
        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replacen("\"probe\":2", "\"probe\":99", 1);
        std::fs::write(&path, tampered).unwrap();

        let report = verify(&path).unwrap();
        assert_eq!(report.first_break, Some(3));
        assert_eq!(report.total, 3);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn verify_legacy_only_file_is_intact() {
        let home = test_home("legacy");
        let path = log_path(&home);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            "{\"ts\":\"2026-01-01T00:00:00Z\",\"type\":\"launch\"}\n\
             {\"ts\":\"2026-01-01T00:01:00Z\",\"type\":\"launch\"}\n",
        )
        .unwrap();
        let report = verify(&path).unwrap();
        assert_eq!(report.total, 2);
        assert_eq!(report.legacy, 2);
        assert_eq!(report.chained, 0);
        assert_eq!(report.first_break, None);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn append_after_legacy_line_chains_from_its_bytes() {
        let home = test_home("legacy-append");
        let path = log_path(&home);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let legacy = "{\"ts\":\"2026-01-01T00:00:00Z\",\"type\":\"launch\"}";
        std::fs::write(&path, format!("{legacy}\n")).unwrap();

        let log = AuditLog::open(&home).unwrap();
        probe(&log, 1);
        drop(log);

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = content
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        // The first chained record links to the legacy line's bytes.
        assert_eq!(lines[1]["seq"], 1);
        assert_eq!(
            lines[1]["prev"].as_str().unwrap(),
            sha256_hex(legacy.as_bytes())
        );
        let report = verify(&path).unwrap();
        assert_eq!(report.first_break, None);
        assert_eq!(report.legacy, 1);
        assert_eq!(report.chained, 1);
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn verify_detects_truncated_tail_after_append() {
        let home = test_home("truncate");
        let log = AuditLog::open(&home).unwrap();
        probe(&log, 1);
        probe(&log, 2);
        drop(log);

        // Cut the tail of the last line: no longer valid JSON.
        let path = log_path(&home);
        let content = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, &content[..content.len() - 20]).unwrap();

        // A later append chains from the truncated bytes, but verify
        // flags the corrupt line itself.
        let log = AuditLog::open(&home).unwrap();
        probe(&log, 3);
        drop(log);

        let report = verify(&path).unwrap();
        assert_eq!(report.first_break, Some(2));
        assert_eq!(report.total, 3);
        assert_eq!(report.chained, 2);
        let _ = std::fs::remove_dir_all(&home);
    }
}
