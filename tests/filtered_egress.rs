// End-to-end tests for filtered egress (phase 3 of
// docs/connect-proxy-plan.md): a real sandbox whose private netns can
// reach nothing but the in-sandbox proxy bridge.
//
// Linux-only (requires bwrap with network namespaces); tests skip
// gracefully when unavailable, like tests/sandbox_escape.rs.
//
// The proxy's SSRF guard refuses loopback targets, so these launches
// set AI_JAIL_TEST_PROXY_ALLOW_PRIVATE=1 on the OUTER ai-jail process
// to CONNECT to loopback fixture servers. The knob is read only in
// main.rs's proxy construction; it is never documented.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

// Serialize launches: the orphan scan must not see another test's
// bridge, and parallel bwrap runs against one project dir race.
static SANDBOX_RUN_LOCK: Mutex<()> = Mutex::new(());

/// bwrap needs unprivileged user namespaces, and filtered egress adds a
/// network namespace on top; detect restrictions at runtime and skip.
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

macro_rules! require_bwrap_net {
    () => {
        if !bwrap_net_available() {
            eprintln!(
                "SKIPPED: bwrap cannot create network namespaces \
                 on this system (AppArmor/kernel restriction)"
            );
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

/// Run `bash -c <script>` inside a filtered-egress sandbox.
fn filtered_run(
    allow_hosts: &[&str],
    extra_env: &[(&str, &str)],
    script: &str,
) -> Output {
    filtered_run_locked(allow_hosts, extra_env, script, false)
}

/// Lockdown variant: same filtered sandbox plus --lockdown, which on
/// kernels ≥ 6.7 also stacks the Landlock V4 net ruleset.
fn filtered_run_locked(
    allow_hosts: &[&str],
    extra_env: &[(&str, &str)],
    script: &str,
    lockdown: bool,
) -> Output {
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
    let mut command = Command::new(ai_jail());
    command.args(["--clean", "--no-status-bar", "--exec"]);
    if lockdown {
        command.arg("--lockdown");
    }
    for host in allow_hosts {
        command.args(["--allow-host", host]);
    }
    command
        .env("AI_JAIL_TEST_PROXY_ALLOW_PRIVATE", "1")
        .env_remove("http_proxy")
        .env_remove("https_proxy")
        .env_remove("all_proxy")
        .env_remove("HTTP_PROXY")
        .env_remove("HTTPS_PROXY")
        .env_remove("ALL_PROXY")
        .env_remove("no_proxy")
        .env_remove("NO_PROXY");
    for (key, value) in extra_env {
        command.env(key, value);
    }
    command.args(["bash", "-c", script]);
    command.output().expect("failed to spawn ai-jail")
}

/// The in-sandbox bridge can take a moment to bind after the agent
/// starts; retry short-lived connection refusals.
const CURL_RETRY: &str =
    "--retry 20 --retry-delay 0 --retry-connrefused --max-time 20";

#[test]
fn filtered_egress_allowlisted_host_tunnels() {
    require_bwrap_net!();
    let fixture = http_fixture();
    let script = format!(
        "echo \"PROXY=$http_proxy\"; \
         echo \"NOPROXY=${{no_proxy-unset}}\"; \
         ls -a /tmp; \
         curl -p -sS {CURL_RETRY} http://127.0.0.1:{fixture}/"
    );
    let output = filtered_run(&["127.0.0.1"], &[], &script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "sandbox run failed: stdout={stdout:?} stderr={stderr:?}"
    );
    // The forced proxy env names the in-sandbox bridge.
    assert!(
        stdout.contains("PROXY=http://127.0.0.1:15919"),
        "forced proxy env missing: {stdout:?}"
    );
    assert!(
        stdout.contains("NOPROXY="),
        "no_proxy not emptied: {stdout:?}"
    );
    assert!(
        !stdout.contains("NOPROXY=unset"),
        "no_proxy was unset instead of emptied: {stdout:?}"
    );
    // Bytes flowed fixture -> proxy -> bridge -> child.
    assert!(stdout.contains("ok"), "fixture body missing: {stdout:?}");
    // The host temp dir is not mounted: only the fixed socket dest
    // exists, never the host-side nonce socket name (which, unlike the
    // fixed dest, has no leading dot).
    let leaked = stdout
        .lines()
        .any(|line| line.starts_with("ai-jail-proxy."));
    assert!(
        !leaked,
        "host proxy socket name leaked into sandbox /tmp: {stdout:?}"
    );
}

#[test]
fn filtered_egress_disallowed_host_gets_403() {
    require_bwrap_net!();
    let fixture = http_fixture();
    // The fixture is reachable but NOT allowlisted; the allowlist
    // covers only 127.0.0.2 (nothing listens there).
    let script = format!(
        "curl -p -sS {CURL_RETRY} http://127.0.0.1:{fixture}/ 2>&1; \
         echo \"CURL_EXIT=$?\""
    );
    let output = filtered_run(&["127.0.0.2"], &[], &script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("403"),
        "expected a proxy 403 for a disallowed host: {stdout:?}"
    );
    assert!(
        stdout.contains("CURL_EXIT="),
        "curl did not run: {stdout:?}"
    );
    assert!(
        !stdout.contains("CURL_EXIT=0"),
        "disallowed host tunneled: {stdout:?}"
    );
}

#[test]
fn filtered_egress_direct_tcp_and_udp_are_dead() {
    require_bwrap_net!();
    let fixture = http_fixture();
    let script = format!(
        // Direct connect to the fixture port on 127.0.0.1: nothing
        // listens there inside the netns (the fixture is on the host).
        "curl --noproxy '*' -sS --max-time 5 http://127.0.0.1:{fixture}/ \
           2>/dev/null; echo \"DIRECT_LOCAL=$?\"; \
         curl --noproxy '*' -sS --max-time 5 http://192.0.2.1:80/ \
           2>/dev/null; echo \"DIRECT_WAN=$?\"; \
         timeout 5 bash -c 'echo x > /dev/udp/192.0.2.1/53' \
           2>/dev/null; echo \"UDP=$?\""
    );
    let output = filtered_run(&["127.0.0.1"], &[], &script);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "sandbox run failed: stdout={stdout:?} stderr={stderr:?}"
    );
    for marker in ["DIRECT_LOCAL=0", "DIRECT_WAN=0", "UDP=0"] {
        assert!(
            !stdout.contains(marker),
            "{marker}: unproxied egress worked: {stdout:?}"
        );
    }
    for marker in ["DIRECT_LOCAL=", "DIRECT_WAN=", "UDP="] {
        assert!(stdout.contains(marker), "{marker} missing: {stdout:?}");
    }
}

#[test]
fn filtered_egress_forced_env_wins_over_user_env() {
    require_bwrap_net!();
    // A trusted --env must not redirect the child to another proxy in
    // filtered mode: the forced values are emitted after env_args.
    let output = filtered_run(
        &["127.0.0.1"],
        &[],
        "echo \"HTTP_PROXY_SEEN=$HTTP_PROXY\"",
    );
    // First without a user override attempt.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("HTTP_PROXY_SEEN=http://127.0.0.1:15919"));

    let _lock = SANDBOX_RUN_LOCK.lock().unwrap();
    let output = Command::new(ai_jail())
        .args([
            "--clean",
            "--no-status-bar",
            "--exec",
            "--allow-host",
            "127.0.0.1",
            "--env",
            "http_proxy=http://127.0.0.1:1",
            "--env",
            "no_proxy=*",
            "bash",
            "-c",
            "echo \"SEEN=$http_proxy/$no_proxy\"",
        ])
        .env("AI_JAIL_TEST_PROXY_ALLOW_PRIVATE", "1")
        .output()
        .expect("failed to spawn ai-jail");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("SEEN=http://127.0.0.1:15919/"),
        "user --env overrode the forced proxy env: stdout={stdout:?} \
         stderr={stderr:?}"
    );
}

#[test]
fn filtered_egress_lockdown_still_tunnels() {
    require_bwrap_net!();
    // Lockdown stacks the Landlock V4 net ruleset on kernels ≥ 6.7;
    // without the bridge-port ConnectTcp rule the child gets EACCES
    // reaching its own proxy. On older kernels Landlock net is
    // unavailable and this passes through the netns path instead.
    let fixture = http_fixture();
    let script = format!(
        "echo \"PROXY=$http_proxy\"; \
         curl -p -sS {CURL_RETRY} http://127.0.0.1:{fixture}/"
    );
    let output = filtered_run_locked(&["127.0.0.1"], &[], &script, true);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "lockdown run failed: stdout={stdout:?} stderr={stderr:?}"
    );
    assert!(
        stdout.contains("PROXY=http://127.0.0.1:15919"),
        "forced proxy env missing under lockdown: {stdout:?}"
    );
    assert!(
        stdout.contains("ok"),
        "fixture body missing under lockdown: {stdout:?}"
    );
}

#[test]
fn filtered_egress_bridge_does_not_outlive_sandbox() {
    require_bwrap_net!();
    let output = filtered_run(&["127.0.0.1"], &[], "true");
    assert!(output.status.success());

    // The bridge is a process inside the sandbox's private pid
    // namespace; when the agent (namespace init) exits, the kernel
    // kills every namespace member. From the host that process is
    // still visible in /proc until it dies -- scan for it, with a
    // short grace window for the teardown to land.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let alive = std::fs::read_dir("/proc")
            .unwrap()
            .map_while(Result::ok)
            .filter_map(|entry| {
                std::fs::read_to_string(entry.path().join("cmdline")).ok()
            })
            .any(|cmdline| cmdline.contains("--proxy-bridge"));
        if !alive {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "proxy bridge process survived the sandbox"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}
