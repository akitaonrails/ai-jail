use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("audit-verify-{}-{id}", std::process::id()));
        let home = root.join("home");
        fs::create_dir_all(&home).unwrap();
        let log = home.join(".local/share/ai-jail/history.jsonl");
        Self { root, home, log }
    }

    fn write(&self, content: impl AsRef<[u8]>) {
        fs::create_dir_all(self.log.parent().unwrap()).unwrap();
        fs::write(&self.log, content).unwrap();
        fs::set_permissions(&self.log, fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ai-jail"));
        command
            .arg("--audit-verify")
            .env("HOME", &self.home)
            .current_dir(&self.root);
        command
    }

    fn run(&self) -> Output {
        self.command().output().unwrap()
    }

    fn assert_refused(&self) {
        let output = self.run();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stdout.is_empty());
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains("chain intact")
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("Cannot read")
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn chain() -> String {
    let mut content = String::new();
    let mut prev = None::<String>;
    for seq in 0..3 {
        let line = serde_json::json!({"seq": seq, "prev": prev, "probe": seq})
            .to_string();
        prev = Some(format!("{:x}", Sha256::digest(line.as_bytes())));
        content.push_str(&line);
        content.push('\n');
    }
    content
}

#[test]
fn verifies_private_logs_without_loading_or_writing_config() {
    let fixture = Fixture::new();
    let content = chain();
    fixture.write(&content);
    for path in [fixture.root.join(".ai-jail"), fixture.home.join(".ai-jail")] {
        fs::write(path, "malformed = [").unwrap();
    }
    let output = fixture.command().arg("--verbose").output().unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("OK 3 records (0 legacy), chain intact"));
    assert!(text.contains("Audit log: 3 chained records"));
    assert_eq!(fs::read_to_string(&fixture.log).unwrap(), content);
    for path in [fixture.root.join(".ai-jail"), fixture.home.join(".ai-jail")] {
        assert_eq!(fs::read_to_string(path).unwrap(), "malformed = [");
    }
}

#[test]
fn missing_and_empty_logs_have_distinct_exit_codes() {
    for relative in ["", ".local", ".local/share", ".local/share/ai-jail"] {
        let fixture = Fixture::new();
        fs::create_dir_all(fixture.home.join(relative)).unwrap();
        let output = fixture.run();
        assert_eq!(output.status.code(), Some(2), "{relative}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("No audit log")
        );
        assert!(!fixture.log.exists());
        if relative.is_empty() {
            assert!(!fixture.home.join(".local").exists());
        }
    }
    let fixture = Fixture::new();
    fixture.write("");
    let output = fixture.run();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("OK 0 records"));
}

#[test]
fn legacy_and_mixed_logs_remain_verifiable() {
    let fixture = Fixture::new();
    let legacy = r#"{"type":"launch","ts":"now"}"#;
    fixture.write(format!("{legacy}\n"));
    let output = fixture.run();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("1 legacy"));
    let next = serde_json::json!({
        "seq": 1, "prev": format!("{:x}", Sha256::digest(legacy.as_bytes()))
    });
    fixture.write(format!("{legacy}\n{next}"));
    let output = fixture.run();
    assert!(output.status.success(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("OK 2 records (1 legacy), chain intact")
    );
}

#[test]
fn tampered_and_corrupt_logs_still_report_the_first_break() {
    let fixture = Fixture::new();
    let tampered = chain().replacen("\"probe\":1", "\"probe\":99", 1);
    fixture.write(&tampered);
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("BROKEN at line 3")
    );
    assert_eq!(fs::read_to_string(&fixture.log).unwrap(), tampered);
    for tail in [b"{broken".as_slice(), b"{\"ts\":\"bad\xff\"}\n"] {
        let mut content = b"{\"type\":\"launch\"}\n".to_vec();
        content.extend_from_slice(tail);
        fixture.write(&content);
        let output = fixture.run();
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("BROKEN at line 2")
        );
        assert_eq!(fs::read(&fixture.log).unwrap(), content);
    }
}

#[test]
fn refuses_group_or_other_permissions_but_allows_private_read_only_log() {
    let fixture = Fixture::new();
    fixture.write(chain());
    for mode in [0o644, 0o640, 0o604, 0o620, 0o601] {
        fs::set_permissions(&fixture.log, fs::Permissions::from_mode(mode))
            .unwrap();
        fixture.assert_refused();
    }
    fs::set_permissions(&fixture.log, fs::Permissions::from_mode(0o400))
        .unwrap();
    assert!(fixture.run().status.success());
}

#[test]
#[ignore = "requires root to read a private log owned by another UID"]
fn refuses_foreign_owned_private_log() {
    use std::os::unix::fs::{MetadataExt, chown};

    // SAFETY: geteuid has no preconditions.
    assert_eq!(unsafe { nix::libc::geteuid() }, 0, "run this test as root");
    let fixture = Fixture::new();
    let content = chain();
    fixture.write(&content);
    chown(&fixture.log, Some(1), None).unwrap();
    fs::set_permissions(&fixture.log, fs::Permissions::from_mode(0o400))
        .unwrap();
    let metadata = fs::metadata(&fixture.log).unwrap();
    assert!(metadata.is_file());
    assert_eq!(metadata.uid(), 1);
    assert_eq!(metadata.mode() & 0o777, 0o400);
    // Root can read it, so refusal must come from the ownership check.
    assert_eq!(fs::read_to_string(&fixture.log).unwrap(), content);
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(
            "audit log must be owned by this user with no group/other permissions"
        ),
        "{output:?}"
    );
    assert_eq!(fs::read_to_string(&fixture.log).unwrap(), content);
    // With only the owner corrected, the same private log is accepted.
    chown(&fixture.log, Some(0), None).unwrap();
    assert!(fixture.run().status.success());
}

#[test]
fn refuses_live_and_dangling_symlinks_at_each_log_path_component() {
    for dangling in [false, true] {
        for relative in [
            ".local",
            ".local/share",
            ".local/share/ai-jail",
            ".local/share/ai-jail/history.jsonl",
        ] {
            let fixture = Fixture::new();
            fixture.write(chain());
            let original = fixture.home.join(relative);
            let moved = fixture.root.join("moved");
            fs::rename(&original, &moved).unwrap();
            let target = if dangling {
                fixture.root.join("absent")
            } else {
                moved
            };
            symlink(&target, &original).unwrap();
            fixture.assert_refused();
        }
    }
}

#[test]
fn accepts_a_symlinked_home_as_the_trusted_path_root() {
    let fixture = Fixture::new();
    fixture.write(chain());
    let home_link = fixture.root.join("home-link");
    symlink(&fixture.home, &home_link).unwrap();
    let output = fixture.command().env("HOME", &home_link).output().unwrap();
    assert!(output.status.success(), "{output:?}");
}

#[test]
fn refuses_directory_as_log_and_regular_file_as_parent() {
    let fixture = Fixture::new();
    fs::create_dir_all(&fixture.log).unwrap();
    fixture.assert_refused();
    let fixture = Fixture::new();
    fs::write(fixture.home.join(".local"), "not a directory").unwrap();
    fixture.assert_refused();
}

#[test]
fn refuses_fifo_without_blocking() {
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    let fixture = Fixture::new();
    fs::create_dir_all(fixture.log.parent().unwrap()).unwrap();
    let path =
        std::ffi::CString::new(fixture.log.as_os_str().as_bytes()).unwrap();
    // SAFETY: path is a valid NUL-terminated string.
    assert_eq!(unsafe { nix::libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    let mut child = fixture
        .command()
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(1));
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("audit verifier blocked on a FIFO");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
