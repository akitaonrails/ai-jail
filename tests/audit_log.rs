// Integration test for the opt-in launch audit log (phase 5 of
// docs/connect-proxy-plan.md): a real sandboxed launch with HOME
// pointed at a temp dir leaves exactly one JSONL record.
//
// Linux-only (requires bwrap); skips gracefully when unavailable, like
// tests/sandbox_escape.rs.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;

fn bwrap_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        Command::new("bwrap")
            .args([
                "--ro-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--unshare-pid",
                "--",
                "true",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn ai_jail() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-jail"))
}

fn test_tree(name: &str) -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("audit-log-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    let home = root.join("home");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    (project, home)
}

fn run(project: &PathBuf, home: &PathBuf, args: &[&str]) -> Output {
    Command::new(ai_jail())
        .args(args)
        .current_dir(project)
        .env("HOME", home)
        .env_remove("AI_JAIL_QUIET")
        .output()
        .expect("failed to run ai-jail")
}

#[test]
fn audit_log_records_one_launch_with_exit_code() {
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }
    let (project, home) = test_tree("launch");
    let output = run(
        &project,
        &home,
        &[
            "--clean",
            "--no-status-bar",
            "--exec",
            "--audit-log",
            "bash",
            "-c",
            "exit 3",
        ],
    );
    assert_eq!(output.status.code(), Some(3));

    let log = home.join(".local/share/ai-jail/history.jsonl");
    use std::os::unix::fs::PermissionsExt;
    let dir_mode = std::fs::metadata(log.parent().unwrap())
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(dir_mode, 0o700, "log dir mode");
    let file_mode =
        std::fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(file_mode, 0o600, "log file mode");

    let content = std::fs::read_to_string(&log).unwrap();
    let records: Vec<serde_json::Value> = content
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 1, "one record per launch: {content}");
    let record = &records[0];
    assert_eq!(record["type"], "launch");
    assert_eq!(record["command"][0], "bash");
    assert_eq!(record["network"], "off");
    assert_eq!(record["exit_code"], 3);
    assert!(record["duration_s"].is_number());
    assert!(record["ts"].as_str().unwrap().ends_with('Z'));

    let _ = std::fs::remove_dir_all(&project)
        .and_then(|()| std::fs::remove_dir_all(project.parent().unwrap()));
}

#[test]
fn audit_log_off_by_default_creates_no_file() {
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }
    let (project, home) = test_tree("default-off");
    let output = run(
        &project,
        &home,
        &["--clean", "--no-status-bar", "--exec", "true"],
    );
    assert!(output.status.success());
    assert!(!home.join(".local/share/ai-jail/history.jsonl").exists());

    let _ = std::fs::remove_dir_all(project.parent().unwrap());
}
