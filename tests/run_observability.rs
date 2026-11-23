// End-to-end tests for run observability, driven through the real
// binary and bwrap.
//
// Linux-only; every test skips (does not fail) when bwrap cannot create
// the namespaces it needs, like tests/filtered_egress.rs. The egress
// cases use the test-only proxy hatch (AI_JAIL_TEST_PROXY_ALLOW_PRIVATE),
// so the file needs `cargo test --features test-hooks`.
#![cfg(feature = "test-hooks")]
#![cfg(target_os = "linux")]

mod common;

use common::{SANDBOX_RUN_LOCK, ai_jail, http_fixture};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

// ── shared helpers ─────────────────────────────────────────────

/// A fresh project dir + HOME under the cargo test tmpdir.
fn tree(name: &str) -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("run-observability-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    let home = root.join("home");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    // The mandatory `.ai-jail` mask warns (even under --exec) when the file
    // is absent, so give it one to mask.
    std::fs::write(project.join(".ai-jail"), "").unwrap();
    (project, home)
}

fn command(project: &Path, home: &Path) -> Command {
    let mut c = Command::new(ai_jail());
    c.args(["--clean", "--no-save-config", "--no-status-bar"])
        .current_dir(project)
        .env("HOME", home)
        .env("AI_JAIL_TEST_PROXY_ALLOW_PRIVATE", "1")
        .stdin(Stdio::null());
    for k in [
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "no_proxy",
        "NO_PROXY",
    ] {
        c.env_remove(k);
    }
    c
}

/// Run `ai-jail <args>` in a fresh tree.
fn run(name: &str, args: &[&str]) -> Output {
    let (project, home) = tree(name);
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    command(&project, &home).args(args).output().unwrap()
}

/// Run `ai-jail <args>` in a fresh tree; returns output and elapsed time.
fn timed_run(name: &str, args: &[&str]) -> (Output, Duration) {
    let (project, home) = tree(name);
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let started = Instant::now();
    let out = command(&project, &home).args(args).output().unwrap();
    (out, started.elapsed())
}
fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).expect("egress line is JSON"))
        .collect()
}

const CURL_UP: &str =
    "--retry 20 --retry-delay 0 --retry-connrefused --max-time 20";

fn is_hex32(v: &serde_json::Value) -> bool {
    v.as_str().is_some_and(|s| {
        s.len() == 32
            && s.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

fn is_rfc3339_utc(v: &serde_json::Value) -> bool {
    v.as_str().is_some_and(|s| {
        let b = s.as_bytes();
        b.len() == 20 && b[4] == b'-' && b[10] == b'T' && b[19] == b'Z'
    })
}

// ── egress log: "egress_" ──────────────────────────────────────

const EGRESS_FIELDS: [&str; 10] = [
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

/// Filtered run (allowlist 127.0.0.1) writing the egress log to `log`.
fn egress_run(name: &str, log: &Path, script: &str) -> Output {
    let (project, home) = tree(name);
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    command(&project, &home)
        .args(["--exec", "--allow-host", "127.0.0.1", "--egress-log"])
        .arg(log)
        .args(["bash", "-c", script])
        .output()
        .unwrap()
}

/// Opens exactly three proxy connections: one allowed tunnel, one
/// non-allowlisted CONNECT, one malformed request.
fn three_connections(fixture: u16) -> String {
    // The sandbox exports loopback in no_proxy
    // (proxy.rs, b7a5358), so force the loopback fixture through the proxy
    // as tests/filtered_egress.rs does.
    format!(
        "curl --noproxy '' -p -sS {CURL_UP} \
           http://127.0.0.1:{fixture}/ >/dev/null; \
         curl -p -sS --max-time 10 http://not-allowed.example:80/ \
           >/dev/null 2>&1; \
         exec 3<>/dev/tcp/127.0.0.1/15919; \
         printf 'GARBAGE\\r\\n\\r\\n' >&3; cat <&3 >/dev/null; exec 3>&-; \
         exit 0"
    )
}

#[test]
fn egress_log_has_one_line_per_connection() {
    require_bwrap_net!();
    require_curl!();
    let fixture = http_fixture();
    let dir = tree("egress-count").0;
    let log = dir.join("egress.jsonl");
    let out = egress_run("egress-count-run", &log, &three_connections(fixture));
    assert!(out.status.success(), "{}", text(&out.stderr));
    let lines = read_jsonl(&log);
    assert_eq!(lines.len(), 3, "one line per connection: {lines:#?}");
    for l in &lines {
        let mut keys: Vec<&str> =
            l.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, EGRESS_FIELDS, "{l}");
        assert_eq!(l["v"], 1);
        assert!(is_hex32(&l["run_id"]), "{l}");
        assert!(is_rfc3339_utc(&l["ts"]), "{l}");
        assert_eq!(l["run_id"], lines[0]["run_id"], "one run id per run");
    }
    let by = |v: &str| lines.iter().find(|l| l["verdict"] == v).unwrap();
    let allow = by("allow");
    assert_eq!(allow["reason"], "in-allowlist");
    assert_eq!(allow["host"], "127.0.0.1");
    assert_eq!(allow["port"], fixture);
    assert!(allow["bytes_up"].as_u64().unwrap() > 0);
    assert!(allow["bytes_down"].as_u64().unwrap() > 0);
    let deny = by("deny");
    assert_eq!(deny["reason"], "not-in-allowlist");
    assert_eq!(deny["host"], "not-allowed.example");
    assert_eq!(deny["bytes_up"], 0);
    assert_eq!(deny["bytes_down"], 0);
    let error = by("error");
    assert_eq!(error["reason"], "malformed-request");
    assert!(error["host"].is_null());
}

#[test]
fn egress_log_file_is_private_and_appended_across_runs() {
    require_bwrap_net!();
    require_curl!();
    let dir = tree("egress-append").0;
    let log = dir.join("egress.jsonl");
    let script = "curl -p -sS --retry 20 --retry-delay 0 --retry-connrefused \
                  --max-time 10 http://not-allowed.example:80/ \
                  >/dev/null 2>&1; exit 0";
    egress_run("egress-append-1", &log, script);
    egress_run("egress-append-2", &log, script);
    let lines = read_jsonl(&log);
    assert_eq!(lines.len(), 2, "append, never truncate: {lines:#?}");
    assert_ne!(lines[0]["run_id"], lines[1]["run_id"], "run ids differ");
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&log).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}

#[test]
fn egress_log_unopenable_path_refuses_the_launch() {
    require_bwrap_net!();
    let dir = tree("egress-unopenable").0;
    let marker = dir.join("ran");
    let touch = format!("touch {}; exit 7", marker.display());
    let refused = |name: &str, path: &Path, shown: &str| {
        let out = egress_run(name, path, &touch);
        let stderr = text(&out.stderr);
        assert_ne!(out.status.code(), Some(7), "command ran: {stderr}");
        assert!(!out.status.success(), "{stderr}");
        assert!(!marker.exists(), "command ran: {stderr}");
        assert!(stderr.contains(shown), "names the path: {stderr}");
    };

    // A missing directory.
    let missing = dir.join("no-such-dir").join("egress.jsonl");
    refused("egress-unopenable-1", &missing, "no-such-dir");

    // A symlink: refused, never followed.
    let victim = dir.join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    let link = dir.join("link.jsonl");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    refused("egress-unopenable-2", &link, "link.jsonl");
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");

    // Non-regular files: a directory and a FIFO.
    let directory = dir.join("dir.jsonl");
    std::fs::create_dir(&directory).unwrap();
    refused("egress-unopenable-3", &directory, "dir.jsonl");
    let fifo = dir.join("fifo.jsonl");
    let made = std::process::Command::new("mkfifo").arg(&fifo).status();
    assert!(made.is_ok_and(|s| s.success()), "mkfifo failed");
    refused("egress-unopenable-4", &fifo, "fifo.jsonl");
}

#[test]
fn egress_log_refused_without_filtered_network() {
    require_bwrap_net!();
    let dir = tree("egress-refused").0;
    let log = dir.join("egress.jsonl");
    let marker = dir.join("ran");
    let touch = format!("touch {}", marker.display());
    // The refusal must not fire in filtered mode.
    let (project, home) = tree("egress-refused-filtered");
    let ok = command(&project, &home)
        .args(["--exec", "--allow-host", "127.0.0.1", "--egress-log"])
        .arg(&log)
        .args(["sh", "-c", "exit 0"])
        .output()
        .unwrap();
    assert!(
        ok.status.success(),
        "filtered + --egress-log starts: {}",
        text(&ok.stderr)
    );
    for (name, flag) in [("off", "--no-network"), ("full", "--network")] {
        let (project, home) = tree(&format!("egress-refused-{name}"));
        let out = command(&project, &home)
            .args(["--exec", flag, "--egress-log"])
            .arg(&log)
            .args(["sh", "-c", &touch])
            .output()
            .unwrap();
        let stderr = text(&out.stderr);
        assert!(!out.status.success(), "{name}: must refuse to start");
        assert!(stderr.contains("--egress-log"), "{name}: {stderr}");
        assert!(stderr.contains("filtered"), "{name}: {stderr}");
        assert!(!marker.exists(), "{name}: the command ran");
    }
}

/// A loopback port whose accept queue is already full: the kernel drops
/// every further SYN, so a dial to it waits in SYN_SENT until the dialer
/// gives up. The proxy's dial then holds the connection open past the
/// command's exit, and no socket shutdown can end it early.
fn blackhole_port() -> (TcpListener, std::net::TcpStream, u16) {
    use std::os::fd::AsRawFd;
    let l = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    // SAFETY: `l` is an open listening socket; listen() on it again only
    // lowers its backlog.
    assert_eq!(unsafe { nix::libc::listen(l.as_raw_fd(), 0) }, 0);
    let port = l.local_addr().unwrap().port();
    let filler =
        std::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port)).unwrap();
    (l, filler, port)
}

/// True while some socket of this host's netns (the supervisor's proxy
/// lives there) is dialing 127.0.0.1:`port`.
fn dialing(port: u16) -> bool {
    let remote = format!("0100007F:{port:04X}");
    std::fs::read_to_string("/proc/net/tcp")
        .unwrap_or_default()
        .lines()
        .skip(1)
        .any(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            f.len() > 3 && f[2] == remote && f[3] == "02"
        })
}

/// A filtered launch whose command starts a tunnel to `port` in the
/// background and exits. Returns the output, whether the proxy was seen
/// dialing, and how long the run lasted after that was first seen.
fn held_open_run(
    name: &str,
    extra: &[&str],
    port: u16,
) -> (Output, bool, Duration) {
    let (project, home) = tree(name);
    let script = format!(
        "curl --noproxy '' -p -sS --max-time 30 http://127.0.0.1:{port}/ \
           >/dev/null 2>&1 & sleep 0.5; exit 0"
    );
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut child = command(&project, &home)
        .args(["--exec", "--allow-host", "127.0.0.1"])
        .args(extra)
        .args(["bash", "-c", &script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut seen = None;
    while child.try_wait().unwrap().is_none() {
        if seen.is_none() && dialing(port) {
            seen = Some(Instant::now());
        }
        assert!(Instant::now() < deadline, "{name}: the run never ended");
        std::thread::sleep(Duration::from_millis(5));
    }
    let ended = Instant::now();
    let out = child.wait_with_output().unwrap();
    (
        out,
        seen.is_some(),
        seen.map_or(Duration::ZERO, |t| ended - t),
    )
}

#[test]
fn filtered_launch_without_egress_log_does_not_drain() {
    require_bwrap_net!();
    require_curl!();
    let (_listener, _filler, port) = blackhole_port();

    // The passing case first, so the fixture is proved to hold a connection the
    // drain must wait for: with --egress-log the run waits the grace and
    // says what it could not close.
    let dir = tree("egress-held-logged").0;
    let log = dir.join("egress.jsonl");
    let log_arg = log.display().to_string();
    let (out, seen, after) = held_open_run(
        "egress-held-logged-run",
        &["--egress-log", &log_arg],
        port,
    );
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(seen, "setup: the proxy never dialed the held port");
    assert!(stderr.contains("still open"), "drain warned: {stderr}");
    assert!(
        after >= Duration::from_millis(1900),
        "the drain waited its grace: {after:?}"
    );

    // Without --egress-log the proxy ends as it did before the flag
    // existed: no drain wait after the command, no drain warning.
    let (out, seen, after) = held_open_run("egress-held-plain", &[], port);
    let stderr = text(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert!(seen, "setup: the proxy never dialed the held port");
    assert!(
        !stderr.contains("still open") && !stderr.contains("drain"),
        "no drain warning without --egress-log: {stderr}"
    );
    assert!(
        after < Duration::from_millis(1500),
        "no drain wait without --egress-log: {after:?}"
    );
}
// ── exit reason: "exit_" ───────────────────────────────────────

#[test]
fn exit_file_size_limit_is_named_under_lockdown() {
    require_bwrap_net!();
    // A 1 MiB write at offset 2 GiB crosses the 1 GiB lockdown FSIZE
    // without writing a gigabyte (sparse file on the sandbox tmpfs).
    let out = run(
        "xfsz",
        &[
            "--lockdown",
            "--exec",
            "sh",
            "-c",
            "exec dd if=/dev/zero of=/tmp/big bs=1M count=1 seek=2048 2>/dev/null",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(153), "{stderr}");
    assert!(stderr.contains("SIGXFSZ"), "{stderr}");
    assert!(
        stderr.contains("file-size") || stderr.contains("file size"),
        "{stderr}"
    );
    assert!(
        stderr.contains("1 GiB")
            || stderr.contains("1.0 GiB")
            || stderr.contains("1073741824"),
        "the value in force: {stderr}"
    );
}

#[test]
fn exit_cpu_time_signal_names_no_limit() {
    require_bwrap_net!();
    // Soft limit only: with soft == hard (`ulimit -t 1`) the kernel
    // sends SIGKILL, not SIGXCPU (measured: exit 137). The limit is the
    // command's own, not ai-jail's, so the line names the signal alone.
    let out = run(
        "xcpu",
        &["--exec", "sh", "-c", "ulimit -S -t 1; while :; do :; done"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(152), "{stderr}");
    assert!(stderr.contains("consistent with SIGXCPU"), "{stderr}");
    assert!(!stderr.contains("rlimit"), "no limit claimed: {stderr}");
    assert_eq!(stderr.lines().count(), 1, "one line: {stderr}");
}

#[test]
fn exit_sigkill_names_the_signal_alone() {
    require_bwrap_net!();
    let out = run("kill9", &["--exec", "sh", "-c", "kill -9 $$"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(137), "{stderr}");
    assert!(
        stderr.contains("sandbox exited with 137: consistent with SIGKILL"),
        "{stderr}"
    );
    assert!(!stderr.to_lowercase().contains("oom"), "no cause: {stderr}");
    assert!(!stderr.contains("journalctl"), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "one line: {stderr}");
}

#[test]
fn ordinary_exit_153_does_not_claim_the_file_size_limit_was_reached() {
    require_bwrap_net!();
    let out = run(
        "ordinary-153",
        &["--lockdown", "--exec", "sh", "-c", "exit 153"],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(153), "{stderr}");
    assert!(stderr.contains("consistent with SIGXFSZ"), "{stderr}");
    assert!(
        stderr.contains("file-size rlimit set by ai-jail:"),
        "{stderr}"
    );
    assert!(!stderr.contains("was reached"), "{stderr}");
}

#[test]
fn exit_only_unexplained_signals_speak() {
    require_bwrap_net!();
    // Clean exits and deliberate signals must stay silent, with their codes
    // unchanged ...
    for (name, script, code) in [
        ("clean", "exit 0", 0),
        ("exit3", "exit 3", 3),
        ("term", "kill -TERM $$", 143),
        ("int", "kill -INT $$", 130),
        ("hup", "kill -HUP $$", 129),
        ("pipe", "kill -PIPE $$", 141),
    ] {
        let out = run(name, &["--exec", "sh", "-c", script]);
        assert_eq!(out.status.code(), Some(code), "{name}");
        assert_eq!(text(&out.stderr), "", "{name} must print nothing");
    }
    // ... and an unexplained signal must say which one, on one line.
    let out = run("segv", &["--exec", "sh", "-c", "kill -SEGV $$"]);
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(139), "{stderr}");
    assert!(stderr.contains("SIGSEGV"), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
}

// ── teardown report: "teardown_" ───────────────────────────────

#[test]
fn teardown_survivor_is_named_and_stopped_gracefully() {
    require_bwrap_net!();
    // No survivors -> no line and no grace delay.
    let (out, took) = timed_run(
        "td-none",
        &["--teardown-report", "--exec", "sh", "-c", "exit 0"],
    );
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert_eq!(text(&out.stderr), "", "nothing printed");
    // The claim is "no grace", not a launch speed.
    assert!(took < Duration::from_millis(2000), "no delay ({took:?})");

    let (out, took) = timed_run(
        "td-sleep",
        &[
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "sleep 300 & exit 0",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(took < Duration::from_secs(3), "SIGTERM ends it: {took:?}");
    assert!(stderr.contains("sleep"), "names it: {stderr}");
    assert!(stderr.contains('1'), "counts it: {stderr}");
    assert!(
        !stderr.contains("ai-jail"),
        "no phantom wrapper/bridge: {stderr}"
    );
}

#[test]
fn teardown_sigterm_ignoring_survivor_is_killed_after_the_grace() {
    require_bwrap_net!();
    let (out, took) = timed_run(
        "td-stubborn",
        &[
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "sh -c 'trap \"\" TERM; exec sleep 300' & sleep 0.2; exit 0",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        took >= Duration::from_millis(1900),
        "grace honoured: {took:?}"
    );
    assert!(took < Duration::from_secs(5), "then SIGKILL: {took:?}");
    assert!(stderr.contains("sleep"), "{stderr}");
}

#[test]
fn teardown_works_under_lockdown() {
    require_bwrap_net!();
    let (out, took) = timed_run(
        "td-lockdown",
        &[
            "--lockdown",
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "sleep 300 & exit 0",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(took < Duration::from_secs(3), "{took:?}");
    assert!(stderr.contains("sleep"), "{stderr}");
}

#[test]
fn teardown_report_fd_is_not_visible_to_the_command() {
    require_bwrap_net!();
    // The shell lists its own descriptors with a
    // glob and a builtin, so no pipeline adds pipe ends to the listing.
    let script = "cd /proc/$$/fd && echo *";
    let (plain, _) = timed_run("td-fd-plain", &["--exec", "sh", "-c", script]);
    let (with, _) = timed_run(
        "td-fd-report",
        &["--teardown-report", "--exec", "sh", "-c", script],
    );
    assert!(with.status.success(), "{}", text(&with.stderr));
    assert_eq!(
        text(&with.stdout),
        text(&plain.stdout),
        "the command holds no extra descriptor"
    );
}

#[test]
fn teardown_keeps_the_exit_code_of_every_end() {
    require_bwrap_net!();
    for (name, script, code) in [
        ("exit7", "exit 7", 7),
        ("term", "kill -TERM $$", 143),
        ("segv", "kill -SEGV $$", 139),
        ("kill", "kill -9 $$", 137),
    ] {
        let (out, _) = timed_run(
            &format!("td-code-{name}"),
            &["--teardown-report", "--exec", "sh", "-c", script],
        );
        assert_eq!(
            out.status.code(),
            Some(code),
            "exit code unchanged, {name}: {}",
            text(&out.stderr)
        );
    }
}

#[test]
fn teardown_wrapper_forwards_term_and_hup_and_ignores_int() {
    require_bwrap_net!();
    // With the report active the command's parent is the wrapper.
    for sig in ["TERM", "HUP"] {
        let script = format!(
            "trap 'echo got-{sig}; exit 42' {sig}; w=$PPID; \
             (sleep 0.3; kill -{sig} $w) & \
             i=0; while [ $i -lt 100 ]; do sleep 0.1; i=$((i+1)); done; exit 1"
        );
        let (out, _) = timed_run(
            &format!("td-fwd-{sig}"),
            &["--teardown-report", "--exec", "sh", "-c", &script],
        );
        assert_eq!(out.status.code(), Some(42), "{sig}: {}", text(&out.stderr));
        assert!(text(&out.stdout).contains(&format!("got-{sig}")));
    }
    let (out, _) = timed_run(
        "td-int",
        &[
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "kill -INT $PPID; sleep 0.3; echo alive; exit 5",
        ],
    );
    assert_eq!(out.status.code(), Some(5), "{}", text(&out.stderr));
    assert!(
        text(&out.stdout).contains("alive"),
        "the wrapper ignored SIGINT"
    );
}

/// The stderr lines that announce an incomplete teardown report.
fn incomplete_lines(stderr: &str) -> Vec<String> {
    stderr
        .lines()
        .filter(|l| l.contains("Teardown report incomplete"))
        .map(str::to_owned)
        .collect()
}

#[test]
fn teardown_incomplete_report_prints_one_line() {
    require_bwrap_net!();
    // A complete report with a survivor names it and
    // says nothing about being incomplete.
    let (out, _) = timed_run(
        "td-complete",
        &[
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "sleep 300 & exit 0",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    assert!(
        stderr.contains("sleep"),
        "setup: the survivor line: {stderr}"
    );
    assert!(
        incomplete_lines(&stderr).is_empty(),
        "a complete report is announced as incomplete: {stderr}"
    );

    // More survivors than one report lists: it arrives marked incomplete
    // (survivor-list-truncated), and that is said once. --no-rlimits:
    // RLIMIT_NPROC counts the user's processes host-wide, so on a busy
    // desktop it could refuse the forks this setup needs.
    let (out, _) = timed_run(
        "td-truncated",
        &[
            "--no-rlimits",
            "--teardown-report",
            "--exec",
            "sh",
            "-c",
            "i=0; while [ $i -lt 300 ]; do sleep 300 & i=$((i+1)); done; exit 0",
        ],
    );
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{stderr}");
    let lines = incomplete_lines(&stderr);
    assert_eq!(lines.len(), 1, "exactly one incomplete line: {stderr}");
    assert!(
        lines[0].contains("Teardown report incomplete: ")
            && lines[0].contains("survivor-list-truncated"),
        "the line names the reason: {}",
        lines[0]
    );
}

/// The words of a dry run's printed argv, shell quotes removed.
fn dry_run_words(out: &Output) -> Vec<String> {
    text(&out.stdout)
        .split_whitespace()
        .map(|w| w.trim_matches(|c| c == '\'' || c == '"').to_string())
        .collect()
}

#[test]
fn teardown_dry_run_shows_the_wrapper_and_a_placeholder_fd() {
    require_bwrap_net!();
    // Every other reason for the wrapper is off, so only the teardown
    // report can put it on the argv.
    let controls_off = [
        "--no-landlock",
        "--no-seccomp",
        "--no-rlimits",
        "--no-network",
    ];
    let dry = |name: &str, extra: &[&str]| {
        let mut args: Vec<&str> = controls_off.to_vec();
        args.extend_from_slice(extra);
        args.extend_from_slice(&["--dry-run", "sh", "-c", "exit 0"]);
        let (out, _) = timed_run(name, &args);
        assert!(out.status.success(), "{name}: {}", text(&out.stderr));
        dry_run_words(&out)
    };

    // Without the report, the dry run shows neither
    // the wrapper nor a report descriptor, as the launch uses neither.
    let plain = dry("td-dry-plain", &[]);
    assert!(
        plain.iter().any(|w| w.ends_with("bwrap")),
        "setup: a dry run prints the bwrap argv: {plain:?}"
    );
    assert!(
        !plain.iter().any(|w| w == "--teardown-report-fd"),
        "{plain:?}"
    );
    assert!(!plain.iter().any(|w| w == "--landlock-exec"), "{plain:?}");

    // With it: the argv the real launch runs, wrapper included, with the
    // descriptor a dry run never opens shown as a placeholder.
    let with = dry("td-dry-report", &["--teardown-report"]);
    let exec_at = with
        .iter()
        .position(|w| w == "--landlock-exec")
        .unwrap_or_else(|| panic!("the wrapper is missing: {with:?}"));
    let fd_at = with
        .iter()
        .position(|w| w == "--teardown-report-fd")
        .unwrap_or_else(|| panic!("the report flag is missing: {with:?}"));
    assert!(
        fd_at > exec_at,
        "the wrapper takes the flag only after --landlock-exec: {with:?}"
    );
    let fd = with.get(fd_at + 1).map(String::as_str).unwrap_or("");
    assert!(
        !fd.is_empty()
            && !fd.starts_with("--")
            && !fd.bytes().all(|b| b.is_ascii_digit()),
        "the fd is a placeholder, not a number no dry run opened: {fd:?}"
    );
}

#[test]
fn run_summary_preserves_exit_status_and_has_private_permissions() {
    use std::os::unix::fs::PermissionsExt;

    require_bwrap_net!();
    let (project, home) = tree("summary");
    let report = home.join("run.json");
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let out = command(&project, &home)
        .args(["--exec", "--no-network", "--no-toolchains", "--run-summary"])
        .arg(&report)
        .args(["sh", "-c", "exit 7", "argument-not-in-report"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7), "{}", text(&out.stderr));
    let body = std::fs::read_to_string(&report).unwrap();
    assert!(!body.contains("argument-not-in-report"));
    let doc: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(doc["schema_version"], 1);
    assert_eq!(doc["program"], "sh");
    assert_eq!(doc["exit"]["code"], 7);
    assert_eq!(doc["exit"]["source"], "exit_code");
    assert!(doc["egress"].is_null());
    assert_eq!(doc["teardown"]["status"], "complete");
    assert!(doc["resources"]["peak_rss_kib"].as_u64().is_some());
    assert!(is_rfc3339_utc(&doc["started_at"]));
    assert!(is_rfc3339_utc(&doc["finished_at"]));
    assert_eq!(
        std::fs::metadata(&report).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(std::fs::read_dir(&home).unwrap().count(), 1);
}

#[test]
fn run_summary_and_egress_log_share_the_run_id_and_totals() {
    require_bwrap_net!();
    require_curl!();
    let fixture = http_fixture();
    let (project, home) = tree("summary-egress");
    let report = home.join("run.json");
    let log = home.join("egress.jsonl");
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let out = command(&project, &home)
        .args(["--exec", "--allow-host", "127.0.0.1", "--egress-log"])
        .arg(&log)
        .arg("--run-summary")
        .arg(&report)
        .args(["bash", "-c", &three_connections(fixture)])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    let doc: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    let lines = read_jsonl(&log);
    assert_eq!(lines.len(), 3);
    assert!(is_hex32(&doc["run_id"]));
    for line in &lines {
        assert_eq!(line["run_id"], doc["run_id"]);
    }
    assert_eq!(doc["egress"]["complete"], true);
    assert_eq!(doc["egress"]["allowed"], 1);
    assert_eq!(doc["egress"]["denied"], 1);
    assert_eq!(doc["egress"]["errored"], 1);
}

#[test]
fn run_summary_refuses_existing_output_and_leaves_dry_run_read_only() {
    require_bwrap_net!();
    let (project, home) = tree("summary-destination");
    let report = home.join("run.json");
    let mut dry_run = command(&project, &home);
    dry_run
        .args(["--dry-run", "--run-summary"])
        .arg(&report)
        .arg("sh");
    let out = dry_run.output().unwrap();
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(!report.exists());

    std::fs::write(&report, "existing").unwrap();
    let out = command(&project, &home)
        .args(["--exec", "--run-summary"])
        .arg(&report)
        .args(["sh", "-c", "printf should-not-start"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    assert_eq!(std::fs::read_to_string(report).unwrap(), "existing");
}
