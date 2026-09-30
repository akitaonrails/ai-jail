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
            .join(format!("audit-show-{}-{id}", std::process::id()));
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
            .arg("--audit-show")
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

fn event() -> String {
    serde_json::json!({
        "ts": "2026-09-29T12:00:00Z", "type": "connect",
        "host": "api.example.com", "port": 443,
        "verdict": "deny", "reason": "not-in-allowlist"
    })
    .to_string()
        + "\n"
}

#[test]
fn shows_events_without_loading_or_writing_config() {
    let fixture = Fixture::new();
    let records = [
        serde_json::json!({"ts":"now", "type":"launch", "command":["bash", "-c", "echo one two"], "exit_code":3, "duration_s":1.25}),
        serde_json::from_str::<serde_json::Value>(&event()).unwrap(),
        serde_json::json!({"ts":"now", "type":"secret_inject", "key":"API_KEY", "host":"api.example.com", "substitutions":1}),
        serde_json::json!({"ts":"now", "type":"future_event"}),
    ];
    let content = records
        .iter()
        .map(|record| record.to_string() + "\n")
        .collect::<String>();
    fixture.write(&content);
    for path in [fixture.root.join(".ai-jail"), fixture.home.join(".ai-jail")] {
        fs::write(path, "malformed = [").unwrap();
    }
    let output = fixture.run();
    assert!(output.status.success(), "{:?}", output);
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 4);
    assert!(
        text.contains(r#"launch ["bash","-c","echo one two"]  (exit 3, 1.2s)"#)
    );
    assert!(
        text.contains("connect api.example.com:443  deny (not-in-allowlist)")
    );
    assert!(
        text.contains(
            "credential API_KEY -> api.example.com  (1 substitutions)"
        )
    );
    assert!(text.contains("future_event  (unrecognized audit record)"));
    assert_eq!(fs::read_to_string(&fixture.log).unwrap(), content);
    assert_eq!(
        fs::read_to_string(fixture.root.join(".ai-jail")).unwrap(),
        "malformed = ["
    );
    assert_eq!(
        fs::read_to_string(fixture.home.join(".ai-jail")).unwrap(),
        "malformed = ["
    );
}

#[test]
fn missing_and_empty_logs_have_distinct_exit_codes() {
    let fixture = Fixture::new();
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(!fixture.home.join(".local").exists());
    fixture.write("");
    let output = fixture.run();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn malformed_records_fail_but_do_not_hide_later_events() {
    let fixture = Fixture::new();
    fixture.write(
        String::from("{broken\nnull\n{\"ts\":\"now\",\"type\":\"connect\"}\n")
            + &event(),
    );
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    for line in 1..=3 {
        assert!(text.contains(&format!("[invalid record at line {line}]")));
    }
    assert!(text.contains("connect api.example.com:443"));
}

#[test]
fn invalid_utf8_records_do_not_hide_later_events() {
    let fixture = Fixture::new();
    let mut content = event().into_bytes();
    // A write truncated inside a multibyte character, then an invalid byte
    // inside an otherwise well-formed JSON record.
    content.extend_from_slice(b"{\"ts\":\"caf\xc3\n");
    content
        .extend_from_slice(b"{\"ts\":\"bad\xff\",\"type\":\"future_event\"}\n");
    // Accept a final valid record even without a trailing newline.
    content.extend_from_slice(event().trim_end().as_bytes());
    fixture.write(&content);

    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 4);
    assert!(text.contains("[invalid record at line 2]"));
    assert!(text.contains("[invalid record at line 3]"));
    assert_eq!(text.matches("connect api.example.com:443").count(), 2);
    assert_eq!(fs::read(&fixture.log).unwrap(), content);
}

#[test]
fn oversized_records_are_invalid_and_later_records_are_displayed() {
    let fixture = Fixture::new();
    let mut content = vec![b'x'; MAX_RECORD + 1];
    content.push(b'\n');
    content.extend_from_slice(event().as_bytes());
    fixture.write(content);
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("[invalid record at line 1]"));
    assert!(text.contains("connect api.example.com:443"));

    fixture.write(vec![b'x'; MAX_RECORD + 1]);
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "[invalid record at line 1]\n"
    );
}

#[test]
fn many_small_records_can_exceed_record_cap_in_aggregate() {
    let fixture = Fixture::new();
    let line = event();
    let count = MAX_RECORD / line.len() + 1;
    fixture.write(line.repeat(count));
    let output = fixture.run();
    assert!(output.status.success());
    assert_eq!(
        output.stdout.iter().filter(|byte| **byte == b'\n').count(),
        count
    );
}

#[test]
fn refuses_public_log_but_allows_private_read_only_log() {
    let fixture = Fixture::new();
    fixture.write(event());
    fs::set_permissions(&fixture.log, fs::Permissions::from_mode(0o644))
        .unwrap();
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    fs::set_permissions(&fixture.log, fs::Permissions::from_mode(0o400))
        .unwrap();
    assert!(fixture.run().status.success());
}

#[test]
fn refuses_symlinks_at_each_log_path_component() {
    for relative in [
        ".local",
        ".local/share",
        ".local/share/ai-jail",
        ".local/share/ai-jail/history.jsonl",
    ] {
        let fixture = Fixture::new();
        fixture.write(event());
        let original = fixture.home.join(relative);
        let target = fixture.root.join("moved");
        fs::rename(&original, &target).unwrap();
        symlink(&target, &original).unwrap();
        let output = fixture.run();
        assert_eq!(output.status.code(), Some(1), "{relative}: {output:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn supports_trusted_symlinked_home_spellings() {
    let fixture = Fixture::new();
    fixture.write(event());
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
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("connect api.example.com:443")
        );
    }
}

#[test]
fn refuses_directory_as_log() {
    let fixture = Fixture::new();
    fs::create_dir_all(&fixture.log).unwrap();
    let output = fixture.run();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
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
            panic!("audit reader blocked on a FIFO");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn escapes_terminal_controls_and_record_separators() {
    let fixture = Fixture::new();
    let mut record: serde_json::Value = serde_json::from_str(&event()).unwrap();
    record["host"] = "bad\u{1b}[2J\nforged\r\t\u{9b}2J".into();
    fixture.write(record.to_string());
    let output = fixture.run();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(text.lines().count(), 1);
    assert!(text.chars().all(|ch| ch == '\n' || !ch.is_control()));
}

#[test]
fn escapes_unicode_direction_controls_and_line_separators() {
    for (control, escaped) in [
        ('\u{061c}', r"\u{61c}"),
        ('\u{200e}', r"\u{200e}"),
        ('\u{200f}', r"\u{200f}"),
        ('\u{2028}', r"\u{2028}"),
        ('\u{2029}', r"\u{2029}"),
        ('\u{202a}', r"\u{202a}"),
        ('\u{202b}', r"\u{202b}"),
        ('\u{202c}', r"\u{202c}"),
        ('\u{202d}', r"\u{202d}"),
        ('\u{202e}', r"\u{202e}"),
        ('\u{2066}', r"\u{2066}"),
        ('\u{2067}', r"\u{2067}"),
        ('\u{2068}', r"\u{2068}"),
        ('\u{2069}', r"\u{2069}"),
    ] {
        let fixture = Fixture::new();
        let mut record: serde_json::Value =
            serde_json::from_str(&event()).unwrap();
        record["host"] = format!("café例.example{control}").into();
        fixture.write(format!("{record}\r\n"));

        let output = fixture.run();
        assert!(output.status.success(), "{escaped}: {output:?}");
        let text = String::from_utf8(output.stdout).unwrap();
        assert_eq!(
            text,
            format!(
                "2026-09-29T12:00:00Z  connect café例.example{escaped}:443  deny (not-in-allowlist)\n"
            ),
            "{escaped}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn output_failure_returns_error() {
    let fixture = Fixture::new();
    fixture.write(event());
    let output = fixture
        .command()
        .stdout(fs::File::options().write(true).open("/dev/full").unwrap())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("Cannot display audit log")
    );
}

#[test]
fn missing_or_empty_home_is_an_error() {
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
}
