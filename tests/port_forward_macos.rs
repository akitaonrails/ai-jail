// End-to-end tests for `--forward-port` on macOS: no relay, the Seatbelt
// profile names the host loopback port and refuses every other one.
//
// macOS-only (requires sandbox-exec); tests skip gracefully when a
// profile cannot be applied.
#![cfg(target_os = "macos")]

use std::net::{Ipv6Addr, TcpListener};

mod common;

use common::{assert_ok, curl, curl_url, http_fixture, run_in, serve_ok};

#[test]
fn forward_port_reaches_host_service_without_network() {
    require_sandbox_exec!();
    let port = http_fixture();
    let port_text = port.to_string();
    let output = run_in(None, &["--forward-port", &port_text], &curl(port));
    assert_eq!(assert_ok(&output), "ok");
}

#[test]
fn forward_port_composes_with_filtered_egress_and_lockdown() {
    require_sandbox_exec!();
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
    require_sandbox_exec!();
    let forwarded = http_fixture();
    let other = http_fixture();
    let forwarded_text = forwarded.to_string();
    // The forwarded port answers; its neighbour, also live on the host,
    // does not -- the profile names one port, not loopback.
    let script = format!(
        "{} >/dev/null && curl -sS --max-time 3 \
         http://127.0.0.1:{other}/ && echo LEAK || echo BLOCKED",
        curl(forwarded)
    );
    let output = run_in(None, &["--forward-port", &forwarded_text], &script);
    assert_eq!(assert_ok(&output).trim(), "BLOCKED");
}

#[test]
fn forward_port_reaches_a_host_service_listening_on_ipv6_only() {
    require_sandbox_exec!();
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
        &curl_url(&format!("http://[::1]:{port}/")),
    );
    assert_eq!(assert_ok(&output), "ok");
}

#[test]
fn project_config_cannot_open_a_forward() {
    require_sandbox_exec!();
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
