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

use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::output;

/// Append-only JSONL audit log handle. Cheap to share: the proxy
/// threads hold an `Arc<AuditLog>` clone of the supervisor's handle.
pub(crate) struct AuditLog {
    file: Mutex<std::fs::File>,
    warned: AtomicBool,
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
        Some(std::sync::Arc::new(AuditLog {
            file: Mutex::new(file),
            warned: AtomicBool::new(false),
        }))
    }

    /// Append one JSON record. Write errors warn once and are dropped:
    /// logging must not break sandboxes.
    pub(crate) fn record(&self, entry: serde_json::Value) {
        let mut line = entry.to_string();
        line.push('\n');
        let result = self.file.lock().unwrap().write_all(line.as_bytes());
        if result.is_err() && !self.warned.swap(true, Ordering::SeqCst) {
            output::warn("audit log write failed; further errors suppressed");
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
}
