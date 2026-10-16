// End-to-end tests for `--forward-port` on macOS: no relay, the Seatbelt
// profile names the host loopback port and refuses every other one.
//
// macOS-only (requires sandbox-exec); tests skip gracefully when a
// profile cannot be applied.
#![cfg(target_os = "macos")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};

// Serialize launches, like tests/port_forward.rs.
static SANDBOX_RUN_LOCK: Mutex<()> = Mutex::new(());

fn sandbox_exec_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        Command::new("sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

fn curl_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        Command::new("curl")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

macro_rules! require_sandbox {
    () => {
        if !sandbox_exec_available() {
            eprintln!(
                "SKIPPED: sandbox-exec cannot apply a profile here \
                 (already sandboxed?)"
            );
            return;
        }
        if !curl_available() {
            eprintln!("SKIPPED: curl not found in PATH");
            return;
        }
    };
}

fn ai_jail() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-jail"))
}

/// Answer each connection with a fixed `ok` body, on its own thread.
fn serve_ok(listener: TcpListener) {
    std::thread::spawn(move || {
        for conn in listener.incoming().map_while(Result::ok) {
            std::thread::spawn(move || {
                let mut stream = conn;
                let mut buf = [0_u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
                );
            });
        }
    });
}

/// Minimal HTTP fixture on host 127.0.0.1.
fn http_fixture() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    serve_ok(listener);
    port
}

const CURL_OPTS: &str = "--max-time 20";

/// Run `bash -c <script>` in a sandbox from `dir` with extra flags,
/// without the caller's proxy env.
fn run_in(dir: Option<&Path>, flags: &[&str], script: &str) -> Output {
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
    let mut command = Command::new(ai_jail());
    command.args(["--no-status-bar", "--exec", "--no-save-config"]);
    if dir.is_none() {
        command.arg("--clean");
    }
    command.args(flags);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    command
        .args(["bash", "-c", script])
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("no_proxy")
        .env_remove("NO_PROXY")
        .output()
        .expect("failed to spawn ai-jail")
}

fn curl(url: &str) -> String {
    format!("curl -g -sS {CURL_OPTS} {url}")
}

fn assert_ok(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "sandbox run failed: stdout={stdout:?} stderr={stderr:?}"
    );
    stdout
}

#[test]
fn forward_port_reaches_host_service_without_network() {
    require_sandbox!();
    let port = http_fixture();
    let port_text = port.to_string();
    let output = run_in(
        None,
        &["--forward-port", &port_text],
        &curl(&format!("http://127.0.0.1:{port}/")),
    );
    assert_eq!(assert_ok(&output), "ok");
}

#[test]
fn forward_port_composes_with_filtered_egress_and_lockdown() {
    require_sandbox!();
    let port = http_fixture();
    let port_text = port.to_string();
    let output = run_in(
        None,
        &[
            "--lockdown",
            "--allow-host",
            "example.invalid",
            "--forward-port",
            &port_text,
        ],
        &curl(&format!("http://127.0.0.1:{port}/")),
    );
    assert_eq!(assert_ok(&output), "ok");
}

#[test]
fn unforwarded_host_port_stays_unreachable() {
    require_sandbox!();
    let forwarded = http_fixture();
    let other = http_fixture();
    let forwarded_text = forwarded.to_string();
    // The forwarded port answers; its neighbour, also live on the host,
    // does not -- the profile names one port, not loopback.
    let script = format!(
        "{} >/dev/null && curl -sS --max-time 3 \
         http://127.0.0.1:{other}/ && echo LEAK || echo BLOCKED",
        curl(&format!("http://127.0.0.1:{forwarded}/"))
    );
    let output = run_in(None, &["--forward-port", &forwarded_text], &script);
    assert_eq!(assert_ok(&output).trim(), "BLOCKED");
}

#[test]
fn forward_port_reaches_a_host_service_listening_on_ipv6_only() {
    require_sandbox!();
    // No relay, so no 127.0.0.1 -> ::1 fallback: dial ::1, which the
    // rule's `localhost` covers.
    let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
        eprintln!("SKIPPED: no IPv6 loopback on this host");
        return;
    };
    let port = listener.local_addr().unwrap().port();
    serve_ok(listener);
    let port_text = port.to_string();
    let output = run_in(
        None,
        &["--forward-port", &port_text],
        &curl(&format!("http://[::1]:{port}/")),
    );
    assert_eq!(assert_ok(&output), "ok");
}

#[test]
fn project_config_cannot_open_a_forward() {
    require_sandbox!();
    let port = http_fixture();
    let dir = std::env::temp_dir().join(format!(
        "ai-jail-forward-project.{}.{port}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(".ai-jail"), format!("forward_ports = [{port}]\n"))
        .unwrap();
    let script = format!(
        "curl -sS --max-time 3 http://127.0.0.1:{port}/ \
         && echo LEAK || echo BLOCKED"
    );
    let output = run_in(Some(&dir), &[], &script);
    let _ = std::fs::remove_dir_all(&dir);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(assert_ok(&output).trim(), "BLOCKED");
    assert!(
        stderr.contains("forward_ports ignored"),
        "missing warning: {stderr:?}"
    );
}

#[test]
fn forward_port_with_network_is_refused() {
    let output = run_in(None, &["--network", "--forward-port", "8080"], "true");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mutually exclusive"), "stderr={stderr:?}");
}

#[test]
fn privileged_port_is_refused_before_launch() {
    let output = run_in(None, &["--forward-port", "631"], "echo LAUNCHED");
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("LAUNCHED"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("below 1024"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
