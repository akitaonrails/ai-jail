use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

const MAX_RECORD: usize = 8 * 1024 * 1024;
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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn legacy() -> &'static [u8] {
    b"{\"ts\":\"now\",\"type\":\"future\"}\n"
}

#[test]
fn intact_and_broken_logs_keep_existing_exit_semantics() {
    let fixture = Fixture::new();
    fixture.write(legacy());
    let output = fixture.run();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("chain intact"));

    fixture.write(b"{broken\n");
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("BROKEN at line 1")
    );
}

#[test]
fn missing_home_and_missing_log_have_distinct_exit_codes() {
    let fixture = Fixture::new();
    for output in [
        fixture.command().env_remove("HOME").output().unwrap(),
        fixture.command().env("HOME", "").output().unwrap(),
    ] {
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("HOME is not set or empty")
        );
    }

    let output = fixture.run();
    assert_eq!(output.status.code(), Some(2));
    assert!(!fixture.home.join(".local").exists());

    fs::remove_dir(&fixture.home).unwrap();
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Cannot read"));
}

#[test]
fn refuses_public_log_but_allows_private_read_only_log() {
    let fixture = Fixture::new();
    fixture.write(legacy());
    fs::set_permissions(&fixture.log, fs::Permissions::from_mode(0o644))
        .unwrap();
    assert_eq!(fixture.run().status.code(), Some(1));
    fs::set_permissions(&fixture.log, fs::Permissions::from_mode(0o400))
        .unwrap();
    assert!(fixture.run().status.success());
}

#[test]
fn refuses_symlinks_below_home() {
    for relative in [
        ".local",
        ".local/share",
        ".local/share/ai-jail",
        ".local/share/ai-jail/history.jsonl",
    ] {
        let fixture = Fixture::new();
        fixture.write(legacy());
        let original = fixture.home.join(relative);
        let target = fixture.root.join("moved");
        fs::rename(&original, &target).unwrap();
        symlink(&target, &original).unwrap();
        assert_eq!(fixture.run().status.code(), Some(1), "{relative}");
    }
}

#[test]
fn supports_trusted_symlinked_home_spellings() {
    let fixture = Fixture::new();
    fixture.write(legacy());
    let real_home = fixture.root.join("real-home");
    fs::rename(&fixture.home, &real_home).unwrap();
    symlink(&real_home, &fixture.home).unwrap();

    let ancestor = fixture.root.join("ancestor-link");
    symlink(&fixture.root, &ancestor).unwrap();
    for home in [
        fixture.home.clone(),
        PathBuf::from(format!("{}/", fixture.home.display())),
        fixture.home.join("."),
        ancestor.join("home"),
    ] {
        let output = fixture.command().env("HOME", home).output().unwrap();
        assert!(output.status.success(), "{output:?}");
    }
}

#[test]
fn refuses_directory_and_fifo_without_blocking() {
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, Instant};

    for home_fifo in [false, true] {
        let fixture = Fixture::new();
        let fifo = if home_fifo {
            fs::remove_dir(&fixture.home).unwrap();
            fixture.home.clone()
        } else {
            fs::create_dir_all(fixture.log.parent().unwrap()).unwrap();
            fixture.log.clone()
        };
        let path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
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
                panic!("audit verify blocked on a FIFO");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    let fixture = Fixture::new();
    fs::create_dir_all(&fixture.log).unwrap();
    assert_eq!(fixture.run().status.code(), Some(1));
}

#[test]
fn oversized_records_are_drained_and_later_records_are_processed() {
    let fixture = Fixture::new();
    let mut content = vec![b'x'; MAX_RECORD + 1];
    content.push(b'\n');
    content.extend_from_slice(legacy());
    fixture.write(content);
    let output = fixture.command().arg("--verbose").output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("BROKEN at line 1"));
    assert!(stderr.contains("Audit log: 0 chained records"));

    fixture.write(vec![b'x'; MAX_RECORD + 1]);
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("BROKEN at line 1")
    );
}

#[test]
fn aggregate_larger_than_record_cap_is_still_valid() {
    let fixture = Fixture::new();
    let mut content = Vec::new();
    for _ in 0..300_000 {
        content.extend_from_slice(legacy());
    }
    assert!(content.len() > MAX_RECORD);
    fixture.write(content);
    assert!(fixture.run().status.success());
}
