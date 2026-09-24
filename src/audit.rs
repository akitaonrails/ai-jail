//! Opt-in launch audit log (phase 5 of docs/connect-proxy-plan.md).
//!
//! One JSONL record per launch, appended when the child exits; when
//! filtered egress is active the proxy threads append CONNECT verdict
//! records through the same supervisor-side handle. The file lives at
//! `~/.local/share/ai-jail/history.jsonl` -- the sandbox never sees it
//! (it is outside every mount).
//!
//! Logging must never break a launch: write errors warn once and are
//! otherwise ignored. The exception is symlink refusal, which is a
//! security decision and gets `security_warn`.
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

/// Seed the chain from an existing log file: stream it once, counting
/// lines and hashing each raw line (without its trailing newline), so
/// appends link to the last line as written -- chained or legacy. The
/// bool reports whether the file lacks a trailing newline (the next
/// append must then terminate the remnant first). Any read failure
/// yields the genesis state: logging must never break a launch.
fn seed_chain(path: &Path) -> (Option<String>, u64, bool) {
    use std::io::BufRead;

    let Ok(file) = std::fs::File::open(path) else {
        return (None, 0, false);
    };
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
            Err(_) => return (None, 0, false),
        }
    }
    (prev, seq, needs_newline)
}

impl AuditLog {
    /// Open the log under `home`, creating `~/.local/share/ai-jail`
    /// (0700) and `history.jsonl` (0600). A symlink at any level --
    /// directory or file -- refuses to log with a security warning; any
    /// other failure warns plainly. Either way the launch proceeds.
    pub(crate) fn open(home: &Path) -> Option<std::sync::Arc<AuditLog>> {
        use std::os::unix::fs::PermissionsExt;

        let dir = home.join(".local/share/ai-jail");
        for path in
            [home.join(".local"), home.join(".local/share"), dir.clone()]
        {
            if let Ok(metadata) = std::fs::symlink_metadata(&path)
                && metadata.file_type().is_symlink()
            {
                output::security_warn(&format!(
                    "audit log disabled: {} is a symlink",
                    path.display()
                ));
                return None;
            }
        }
        if let Err(e) = std::fs::create_dir_all(&dir) {
            output::warn(&format!(
                "audit log disabled: cannot create {}: {e}",
                dir.display()
            ));
            return None;
        }
        if let Err(e) = std::fs::set_permissions(
            &dir,
            std::fs::Permissions::from_mode(0o700),
        ) {
            output::warn(&format!(
                "audit log disabled: cannot chmod {}: {e}",
                dir.display()
            ));
            return None;
        }

        let path = dir.join("history.jsonl");
        if let Ok(metadata) = std::fs::symlink_metadata(&path)
            && metadata.file_type().is_symlink()
        {
            output::security_warn(&format!(
                "audit log disabled: {} is a symlink",
                path.display()
            ));
            return None;
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path);
        let file = match file {
            Ok(file) => file,
            Err(e) => {
                output::warn(&format!(
                    "audit log disabled: cannot open {}: {e}",
                    path.display()
                ));
                return None;
            }
        };
        // Covers a pre-existing file created with looser permissions.
        if let Err(e) = std::fs::set_permissions(
            &path,
            std::fs::Permissions::from_mode(0o600),
        ) {
            output::warn(&format!(
                "audit log disabled: cannot chmod {}: {e}",
                path.display()
            ));
            return None;
        }
        let (prev, seq, needs_newline) = seed_chain(&path);
        Some(std::sync::Arc::new(AuditLog {
            chain: Mutex::new(ChainState {
                file,
                prev,
                seq,
                needs_newline,
            }),
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
