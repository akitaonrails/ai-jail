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

struct Fixture {
    project: PathBuf,
    home: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let (project, home) = test_tree(name);
        Self { project, home }
    }

    fn log(&self) -> PathBuf {
        self.home.join(".local/share/ai-jail/history.jsonl")
    }

    fn run_bounded(&self) -> Output {
        use std::process::Stdio;
        use std::time::{Duration, Instant};

        struct ChildGuard(Option<std::process::Child>);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                if let Some(child) = &mut self.0 {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        let mut child = ChildGuard(Some(
            Command::new(ai_jail())
                .args([
                    "--clean",
                    "--no-status-bar",
                    "--exec",
                    "--audit-log",
                    "sh",
                    "-c",
                    "exit 3",
                ])
                .current_dir(&self.project)
                .env("HOME", &self.home)
                .env_remove("AI_JAIL_QUIET")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        ));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if child.0.as_mut().unwrap().try_wait().unwrap().is_some() {
                return child.0.take().unwrap().wait_with_output().unwrap();
            }
            assert!(Instant::now() < deadline, "audit log blocked the launch");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.project.parent().unwrap());
    }
}

#[test]
fn audit_log_refusals_preserve_launch_exit_code_and_warn_in_exec_mode() {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;

    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }
    for kind in ["symlink", "directory", "fifo"] {
        let fixture = Fixture::new(kind);
        let log = fixture.log();
        std::fs::create_dir_all(log.parent().unwrap()).unwrap();
        let victim = fixture.home.join("victim");
        std::fs::write(&victim, "untouched\n").unwrap();
        std::fs::set_permissions(
            &victim,
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        match kind {
            "symlink" => std::os::unix::fs::symlink(&victim, &log).unwrap(),
            "directory" => std::fs::create_dir(&log).unwrap(),
            "fifo" => {
                let path =
                    std::ffi::CString::new(log.as_os_str().as_bytes()).unwrap();
                // SAFETY: path is a valid NUL-terminated pathname.
                assert_eq!(
                    unsafe { nix::libc::mkfifo(path.as_ptr(), 0o600) },
                    0
                );
            }
            _ => unreachable!(),
        }
        let output = fixture.run_bounded();
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("audit log disabled:"),
            "{output:?}"
        );
        assert!(output.stdout.is_empty());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "untouched\n");
        assert_eq!(
            std::fs::metadata(&victim).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }
}

#[test]
fn audit_log_appends_to_legacy_and_write_only_files_then_verifies() {
    use std::os::unix::fs::PermissionsExt;

    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }
    for mode in [0o644, 0o200] {
        let fixture = Fixture::new(&format!("legacy-{mode}"));
        let path = fixture.log();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let legacy = "{\"legacy\":true}";
        // No trailing newline: the append must terminate the old record.
        std::fs::write(&path, legacy).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode))
            .unwrap();
        let output = fixture.run_bounded();
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.starts_with(&format!("{legacy}\n")));
        let record: serde_json::Value =
            serde_json::from_str(content.lines().nth(1).unwrap()).unwrap();
        assert_eq!(record["seq"], 1);
        assert_eq!(record["exit_code"], 3);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let verified =
            run(&fixture.project, &fixture.home, &["--audit-verify"]);
        assert!(verified.status.success(), "{verified:?}");
    }
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
