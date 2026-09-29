// End-to-end tests for `--forward-port`: a host loopback service
// relayed onto the sandbox's own loopback through a Unix socket, with
// the private netns left in place for everything else.
//
// Linux-only (requires bwrap with network namespaces); tests skip
// gracefully when unavailable, like tests/filtered_egress.rs.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};

// Serialize launches: parallel bwrap runs against one project dir race.
static SANDBOX_RUN_LOCK: Mutex<()> = Mutex::new(());

fn bwrap_net_available() -> bool {
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
                "--unshare-uts",
                "--unshare-ipc",
                "--unshare-net",
                "--",
                "true",
            ])
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
        if !bwrap_net_available() {
            eprintln!(
                "SKIPPED: bwrap cannot create network namespaces \
                 on this system (AppArmor/kernel restriction)"
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

/// Minimal HTTP fixture on host loopback: one request in, a fixed
/// `ok` body out. Runs forever on its own thread.
fn http_fixture() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
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
    port
}

/// No `--retry-connrefused`: the agent is exec'd only once every
/// forward bridge reports it is listening, so a refused first connect is
/// a regression, not a race to paper over.
const CURL_OPTS: &str = "--max-time 20";

/// Run `bash -c <script>` in a sandbox from `dir` with extra flags.
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
    command.args(["bash", "-c", script]);
    command.output().expect("failed to spawn ai-jail")
}

fn curl(port: u16) -> String {
    format!("curl --noproxy '*' -sS {CURL_OPTS} http://127.0.0.1:{port}/")
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
    let output = run_in(None, &["--forward-port", &port_text], &curl(port));
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
        &curl(port),
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
    // does not -- the netns still isolates everything not named.
    let script = format!(
        "{} >/dev/null && curl --noproxy '*' -sS --max-time 3 \
         http://127.0.0.1:{other}/ && echo LEAK || echo BLOCKED",
        curl(forwarded)
    );
    let output = run_in(None, &["--forward-port", &forwarded_text], &script);
    assert_eq!(assert_ok(&output).trim(), "BLOCKED");
}

#[test]
fn host_side_socket_is_removed_on_exit() {
    require_sandbox!();
    let port = http_fixture();
    let port_text = port.to_string();
    let output = run_in(None, &["--forward-port", &port_text], &curl(port));
    assert_ok(&output);
    let suffix = format!(".{port}.sock");
    let leftovers: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("ai-jail-forward.") && n.ends_with(&suffix))
        .collect();
    assert!(leftovers.is_empty(), "stale forward sockets: {leftovers:?}");
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
        "curl --noproxy '*' -sS --max-time 3 http://127.0.0.1:{port}/ \
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
fn forward_port_reaches_a_host_service_listening_on_ipv6_only() {
    require_sandbox!();
    // Node >= 17 dev servers bound to "localhost" often listen on ::1
    // only; the sandbox side always dials 127.0.0.1.
    let Ok(listener) = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)) else {
        eprintln!("SKIPPED: no IPv6 loopback on this host");
        return;
    };
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().map_while(Result::ok) {
            let mut stream = conn;
            let mut buf = [0_u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
        }
    });
    let port_text = port.to_string();
    let output = run_in(None, &["--forward-port", &port_text], &curl(port));
    assert_eq!(assert_ok(&output), "ok");
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

#[test]
fn simultaneous_relays_are_capped_on_the_host() {
    require_sandbox!();
    if !Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        eprintln!("SKIPPED: python3 not found");
        return;
    }
    // A host service that accepts and holds every connection, counting.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = std::sync::Arc::clone(&accepted);
    std::thread::spawn(move || {
        let mut held = Vec::new();
        for conn in listener.incoming().map_while(Result::ok) {
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            held.push(conn);
        }
    });
    // The agent opens far more connections than the cap and keeps them.
    let script = format!(
        "import socket, time\n\
         held = []\n\
         for _ in range(400):\n    \
         try:\n        held.append(socket.create_connection(('127.0.0.1', {port}), timeout=5))\n    \
         except OSError:\n        pass\n\
         time.sleep(2)\n"
    );
    let port_text = port.to_string();
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
    let output = Command::new(ai_jail())
        .args(["--clean", "--no-status-bar", "--exec", "--no-save-config"])
        .args(["--forward-port", &port_text])
        .args(["python3", "-c", &script])
        .output()
        .expect("failed to spawn ai-jail");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let reached = accepted.load(std::sync::atomic::Ordering::SeqCst);
    assert!(
        reached <= 256,
        "host service saw {reached} relays, cap is 256"
    );
    assert!(reached >= 200, "only {reached} relays reached the host");
}

#[test]
fn agent_starts_only_after_the_forward_is_listening() {
    require_sandbox!();
    // The bridge is held back 700 ms before it binds. The agent's first,
    // single connect attempt must still succeed: the launch waits for the
    // bridge's readiness instead of racing it.
    let port = http_fixture();
    let port_text = port.to_string();
    let output = run_in(
        None,
        &[
            "--forward-port",
            &port_text,
            "--env",
            "AI_JAIL_TEST_BRIDGE_DELAY_MS=700",
        ],
        &curl(port),
    );
    assert_eq!(assert_ok(&output), "ok");
}
