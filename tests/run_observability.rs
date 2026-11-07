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
fn egress_log_unopenable_path_warns_and_launches() {
    require_bwrap_net!();
    let dir = tree("egress-unopenable").0;
    // A missing directory, then a symlink: both warn with the path and
    // the launch goes on.
    let missing = dir.join("no-such-dir").join("egress.jsonl");
    let out = egress_run("egress-unopenable-1", &missing, "exit 7");
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(7), "launch continued: {stderr}");
    assert!(
        stderr.contains("no-such-dir"),
        "warns with the path: {stderr}"
    );

    let victim = dir.join("victim");
    std::fs::write(&victim, b"untouched").unwrap();
    let link = dir.join("link.jsonl");
    std::os::unix::fs::symlink(&victim, &link).unwrap();
    let out = egress_run("egress-unopenable-2", &link, "exit 5");
    let stderr = text(&out.stderr);
    assert_eq!(out.status.code(), Some(5), "{stderr}");
    assert!(stderr.contains("link.jsonl"), "{stderr}");
    assert_eq!(std::fs::read(&victim).unwrap(), b"untouched");
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
