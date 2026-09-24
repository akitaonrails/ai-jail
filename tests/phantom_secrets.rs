// End-to-end tests for phantom credential injection (issue #135): the
// sandbox sees a placeholder, and only the supervisor-side proxy swaps
// in the real value for requests terminating at the bound host.
//
// Linux-only (requires bwrap); skips gracefully when unavailable, like
// tests/filtered_egress.rs. The TLS fixture uses the committed TEST
// ONLY self-signed cert in tests/fixtures/, trusted through the
// test-only AI_JAIL_TEST_PROXY_EXTRA_ROOTS env seam (undocumented, same
// rule as AI_JAIL_TEST_PROXY_ALLOW_PRIVATE).
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Arc, Mutex, OnceLock};

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

/// Lockdown mode clears the environment and sets PATH to standard FHS
/// directories; on non-FHS systems (NixOS) guest binaries are absent.
fn lockdown_cmd_available(cmd: &str) -> bool {
    const LOCKDOWN_PATH: &str =
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    LOCKDOWN_PATH
        .split(':')
        .any(|dir| std::path::Path::new(dir).join(cmd).is_file())
}

fn ai_jail() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-jail"))
}

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// TLS fixture on host loopback using the TEST ONLY cert: answers each
/// request with the received x-test-key header value in the body.
fn tls_fixture() -> u16 {
    use rustls::pki_types::pem::PemObject;
    let cert = rustls::pki_types::CertificateDer::from_pem_slice(
        &std::fs::read(fixture_dir().join("test-only-cert.pem")).unwrap(),
    )
    .unwrap();
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(
        &std::fs::read(fixture_dir().join("test-only-key.pem")).unwrap(),
    )
    .unwrap();
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap(),
    );
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for conn in listener.incoming().map_while(Result::ok) {
            let config = Arc::clone(&config);
            std::thread::spawn(move || {
                let Ok(server) = rustls::ServerConnection::new(config) else {
                    return;
                };
                let mut tls = rustls::StreamOwned::new(server, conn);
                let mut buf = Vec::new();
                let mut chunk = [0_u8; 4096];
                loop {
                    match tls.read(&mut chunk) {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                    }
                }
                let head = String::from_utf8_lossy(&buf);
                let value = head
                    .lines()
                    .find_map(|line| {
                        line.split_once(':').and_then(|(name, v)| {
                            name.trim()
                                .eq_ignore_ascii_case("x-test-key")
                                .then(|| v.trim().to_string())
                        })
                    })
                    .unwrap_or_default();
                let body = format!("key={value}");
                let _ = tls.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                         Connection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                );
            });
        }
    });
    port
}

const REAL: &str = "sk-real-test-value";

/// Launch a filtered sandbox with the secret binding and run
/// `bash -c <script>` inside it.
fn phantom_run(fixture: u16, lockdown: bool, script: &str) -> Output {
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
    let mut command = Command::new(ai_jail());
    command.args([
        "--clean",
        "--no-status-bar",
        "--exec",
        "--allow-host",
        "127.0.0.1",
        "--allow-host",
        "127.0.0.2",
        "--secret",
        "X_TEST_KEY=127.0.0.1",
        "--env",
        &format!("X_TEST_KEY={REAL}"),
    ]);
    if lockdown {
        command.arg("--lockdown");
    }
    command
        .env("AI_JAIL_TEST_PROXY_ALLOW_PRIVATE", "1")
        .env(
            "AI_JAIL_TEST_PROXY_EXTRA_ROOTS",
            fixture_dir().join("test-only-cert.pem"),
        )
        .env_remove("no_proxy")
        .env_remove("NO_PROXY");
    command.args(["bash", "-c", script]);
    let _ = fixture;
    command.output().expect("failed to spawn ai-jail")
}

#[test]
fn phantom_child_env_shows_placeholder_not_real_value() {
    if !bwrap_net_available() {
        eprintln!("SKIPPED: bwrap cannot create network namespaces");
        return;
    }
    let output = phantom_run(0, false, "echo \"SEEN=$X_TEST_KEY\"");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "run failed: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("SEEN=AIJAIL-PHANTOM-"),
        "placeholder missing: {stdout:?}"
    );
    assert!(
        !stdout.contains(REAL),
        "real value leaked into the sandbox env: {stdout:?}"
    );
}

#[test]
fn phantom_proxy_substitutes_real_value_over_tls() {
    if !bwrap_net_available() || !curl_available() {
        eprintln!("SKIPPED: bwrap netns or curl unavailable");
        return;
    }
    let fixture = tls_fixture();
    let script = format!(
        "curl -sS --retry 20 --retry-delay 0 --retry-connrefused \
         --max-time 20 -H \"x-test-key: $X_TEST_KEY\" \
         http://127.0.0.1:{fixture}/v1/models"
    );
    let output = phantom_run(fixture, false, &script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "run failed: stdout={stdout:?} stderr={stderr:?}"
    );
    // The fixture (past the TLS termination) saw the real value.
    assert!(
        stdout.contains(&format!("key={REAL}")),
        "real value not substituted: {stdout:?}"
    );
    assert!(
        !stdout.contains("AIJAIL-PHANTOM"),
        "placeholder reached upstream: {stdout:?}"
    );
}

#[test]
fn phantom_lockdown_still_substitutes() {
    if !bwrap_net_available() || !curl_available() {
        eprintln!("SKIPPED: bwrap netns or curl unavailable");
        return;
    }
    if !lockdown_cmd_available("bash") || !lockdown_cmd_available("curl") {
        eprintln!("SKIPPED: bash/curl not in lockdown PATH (non-FHS system)");
        return;
    }
    let fixture = tls_fixture();
    let script = format!(
        "curl -sS --retry 20 --retry-delay 0 --retry-connrefused \
         --max-time 20 -H \"x-test-key: $X_TEST_KEY\" \
         http://127.0.0.1:{fixture}/"
    );
    let output = phantom_run(fixture, true, &script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "lockdown run failed: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(stdout.contains(&format!("key={REAL}")), "{stdout:?}");
}

#[test]
fn phantom_absolute_form_to_non_secret_host_is_405() {
    if !bwrap_net_available() || !curl_available() {
        eprintln!("SKIPPED: bwrap netns or curl unavailable");
        return;
    }
    // 127.0.0.2 is allowlisted but not secret-bound: absolute-form to
    // it keeps the 405 (the proxy is not a general HTTP relay). For
    // plain HTTP the proxy's 405 is a normal response, so assert the
    // status code, not curl's exit code.
    let script = "curl -sS -o /dev/null -w \"%{http_code}\" \
                  --max-time 10 http://127.0.0.2:1/";
    let output = phantom_run(0, false, script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("405"),
        "expected 405: stdout={stdout:?} stderr={stderr:?}"
    );
}

#[test]
fn phantom_secret_validation_hard_errors() {
    // All three violations fail before any sandbox starts; no bwrap
    // needed.
    let cases: &[(&[&str], &str)] = &[
        (
            // No filtered egress.
            &[
                "--clean",
                "--exec",
                "--secret",
                "X=127.0.0.1",
                "--env",
                "X=1",
                "true",
            ],
            "--allow-host",
        ),
        (
            // Secret key missing from env_pass.
            &[
                "--clean",
                "--exec",
                "--allow-host",
                "127.0.0.1",
                "--secret",
                "MISSING=127.0.0.1",
                "true",
            ],
            "--env-from-file",
        ),
        (
            // Host not covered by the allowlist.
            &[
                "--clean",
                "--exec",
                "--allow-host",
                "127.0.0.1",
                "--env",
                "X=1",
                "--secret",
                "X=10.0.0.1",
                "true",
            ],
            "not in allow_hosts",
        ),
    ];
    for (args, needle) in cases {
        let output = Command::new(ai_jail())
            .args(*args)
            .output()
            .expect("failed to spawn ai-jail");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(1),
            "args {args:?}: stderr={stderr:?}"
        );
        assert!(
            stderr.contains(needle),
            "args {args:?}: missing {needle:?} in {stderr:?}"
        );
    }
}
