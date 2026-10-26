// End-to-end tests for `--publish-port`: a service listening on the
// sandbox's own loopback, reached from the host's 127.0.0.1 through the
// supervisor, with the private netns left in place for everything else.
//
// Linux-only (requires bwrap with network namespaces); tests skip
// gracefully when unavailable, like tests/port_forward.rs.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

mod common;

use common::{SANDBOX_RUN_LOCK, ai_jail, run_in};

fn python3_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
}

fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A python service for inside the sandbox: answers one connection on
/// 127.0.0.1:`port` with `ok`, then exits (and with it, the launch).
fn serve_once(port: u16) -> String {
    format!(
        "import socket\n\
         s = socket.socket()\n\
         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         s.bind(('127.0.0.1', {port}))\n\
         s.listen()\n\
         c, _ = s.accept()\n\
         c.recv(4096)\n\
         c.sendall(b'ok')\n\
         c.close()\n"
    )
}

/// Launch ai-jail in the background with `flags`, serving once on `port`.
fn spawn_service(flags: &[&str], port: u16) -> Child {
    Command::new(ai_jail())
        .args(["--clean", "--no-status-bar", "--exec", "--no-save-config"])
        .args(flags)
        .args(["python3", "-c", &serve_once(port)])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn ai-jail")
}

/// Ask the host's 127.0.0.1:`port` until the jailed service answers. The
/// host side listens before the service does, so early attempts may be
/// closed without a reply.
fn ask_host_port(port: u16) -> Option<String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if let Ok(mut stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
        {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
            let _ = stream.write_all(b"hi");
            let mut reply = String::new();
            if stream.read_to_string(&mut reply).is_ok() && reply == "ok" {
                return Some(reply);
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

fn finish(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(20);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    child.wait_with_output().unwrap()
}

fn publish_round_trip(flags: &[&str], port: u16) {
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
    let child = spawn_service(flags, port);
    let reply = ask_host_port(port);
    let output = finish(child);
    assert_eq!(
        reply.as_deref(),
        Some("ok"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn publish_port_reaches_sandbox_service_from_host() {
    require_bwrap_net!();
    if !python3_available() {
        eprintln!("SKIPPED: python3 not found");
        return;
    }
    let port = free_port();
    let port_text = port.to_string();
    publish_round_trip(&["--publish-port", &port_text], port);
}

#[test]
fn publish_port_composes_with_filtered_egress_and_lockdown() {
    require_bwrap_net!();
    require_lockdown_tools!("python3");
    let port = free_port();
    let port_text = port.to_string();
    publish_round_trip(
        &[
            "--lockdown",
            "--allow-host",
            "example.invalid",
            "--publish-port",
            &port_text,
        ],
        port,
    );
}

#[test]
fn host_side_socket_is_removed_on_exit() {
    require_bwrap_net!();
    if !python3_available() {
        eprintln!("SKIPPED: python3 not found");
        return;
    }
    let port = free_port();
    let port_text = port.to_string();
    publish_round_trip(&["--publish-port", &port_text], port);
    let suffix = format!(".{port}.sock");
    let leftovers: Vec<_> = std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("ai-jail-publish.") && n.ends_with(&suffix))
        .collect();
    assert!(leftovers.is_empty(), "stale publish sockets: {leftovers:?}");
    // And the host port is released with it.
    assert!(TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err());
}

#[test]
fn project_config_cannot_publish_a_port() {
    require_bwrap_net!();
    let port = free_port();
    let dir = std::env::temp_dir().join(format!(
        "ai-jail-publish-project.{}.{port}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(".ai-jail"), format!("publish_ports = [{port}]\n"))
        .unwrap();
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
    let child = Command::new(ai_jail())
        .args(["--no-status-bar", "--exec", "--no-save-config"])
        .args(["bash", "-c", "echo LAUNCHED; sleep 3"])
        .current_dir(&dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn ai-jail");
    // While the sandbox runs, nothing listens on the host port.
    std::thread::sleep(Duration::from_millis(1500));
    let published = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_ok();
    let output = finish(child);
    let _ = std::fs::remove_dir_all(&dir);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!published, "a project .ai-jail published port {port}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("LAUNCHED"));
    assert!(
        stderr.contains("publish_ports ignored"),
        "missing warning: {stderr:?}"
    );
}

#[test]
fn publish_port_with_network_is_refused() {
    let output = run_in(None, &["--network", "--publish-port", "8080"], "true");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("mutually exclusive"), "stderr={stderr:?}");
}

#[test]
fn privileged_port_is_refused_before_launch() {
    let output = run_in(None, &["--publish-port", "631"], "echo LAUNCHED");
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("LAUNCHED"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("below 1024"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn taken_host_port_is_refused_before_launch() {
    require_bwrap_net!();
    let taken = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port_text = taken.local_addr().unwrap().port().to_string();
    let output = run_in(None, &["--publish-port", &port_text], "echo LAUNCHED");
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("LAUNCHED"));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Failed to publish"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
