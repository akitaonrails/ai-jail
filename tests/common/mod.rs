//! Shared helpers for integration tests.
//!
//! Each file in `tests/` compiles as its own crate, so shared code lives
//! here and is pulled in with `mod common;` at the crate root. The module
//! must be named `common` because the `require_*!` macros expand to
//! `$crate::common::...`.
//!
//! The macros are `#[macro_export]`ed, so they need no import. Functions
//! and statics are imported with `use common::{...};`.
//!
//! Not every test file uses every helper; unused items would trip
//! `-D warnings` in the files that skip them, hence `allow(dead_code)`.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};

/// Maximum size of one audit record, mirrored from the product code.
pub const MAX_RECORD: usize = 8 * 1024 * 1024;

/// Serialize sandbox launches. Parallel bwrap runs against one project
/// dir race, and some tests must not see another test's bridge.
pub static SANDBOX_RUN_LOCK: Mutex<()> = Mutex::new(());

pub fn ai_jail() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-jail"))
}

/// Can bwrap create the namespaces needed for normal mode?
/// Some kernels restrict unprivileged user namespaces (Ubuntu 24.04+
/// AppArmor policy, hardened sysctl, ...); detect that and skip.
pub fn bwrap_available() -> bool {
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
                "--",
                "true",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// Can bwrap also create a network namespace (filtered egress and
/// lockdown)?
pub fn bwrap_net_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        bwrap_available()
            && Command::new("bwrap")
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

/// The fixture requests need a host curl binary to drive HTTP traffic
/// through the proxy bridge; detect availability and skip when absent.
pub fn curl_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        Command::new("curl")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// macOS: can sandbox-exec apply a profile here? Fails when already
/// running inside a Seatbelt sandbox.
pub fn sandbox_exec_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        Command::new("sandbox-exec")
            .args(["-p", "(version 1)(allow default)", "/usr/bin/true"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    })
}

/// Lockdown mode clears the environment and sets PATH to standard FHS
/// directories (/usr/bin, /bin); on non-FHS systems (NixOS, etc.) guest
/// binaries like bash or curl are not present in those locations.
pub fn lockdown_cmd_available(cmd: &str) -> bool {
    const LOCKDOWN_PATH: &str =
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
    LOCKDOWN_PATH
        .split(':')
        .any(|dir| Path::new(dir).join(cmd).is_file())
}

/// Answer each connection with a fixed `ok` body, on its own thread.
pub fn serve_ok(listener: TcpListener) {
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

/// Minimal HTTP fixture on host loopback: one request in, a fixed
/// `ok` body out. Runs forever on its own thread.
pub fn http_fixture() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    serve_ok(listener);
    port
}

/// Panic unless the sandbox run succeeded; return its stdout.
pub fn assert_ok(output: &Output) -> String {
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "sandbox run failed: stdout={stdout:?} stderr={stderr:?}"
    );
    stdout
}

/// Per-request curl timeout for requests made from inside a sandbox.
/// No `--retry-connrefused`: the agent is exec'd only once every forward
/// bridge reports it is listening, so a refused first connect is a
/// regression, not a race to paper over.
pub const CURL_OPTS: &str = "--max-time 20";

/// A `curl` command line, to run inside the sandbox, for `url`. Proxy
/// settings are bypassed. `-g` disables URL globbing so `[::1]` works.
pub fn curl_url(url: &str) -> String {
    format!("curl -g --noproxy '*' -sS {CURL_OPTS} {url}")
}

/// `curl_url` for a fixture on the sandbox's own 127.0.0.1 `port`.
pub fn curl(port: u16) -> String {
    curl_url(&format!("http://127.0.0.1:{port}/"))
}

/// Run `bash -c <script>` in a sandbox with extra flags. `dir: None` runs
/// `--clean` with the test's cwd; `Some(dir)` runs from `dir` so its
/// project `.ai-jail` applies. The caller's proxy env is removed so only
/// ai-jail's own proxy settings can reach the sandbox.
pub fn run_in(dir: Option<&Path>, flags: &[&str], script: &str) -> Output {
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

/// A private audit-log fixture: a temp root with a `home/` whose
/// history log lives at the default XDG path. Removed on drop.
pub struct AuditFixture {
    pub root: PathBuf,
    pub home: PathBuf,
    pub log: PathBuf,
    subcommand: &'static str,
}

impl AuditFixture {
    /// `tag` names the temp dir; `subcommand` is the ai-jail flag to run
    /// (for example `--audit-show`).
    pub fn new(tag: &str, subcommand: &'static str) -> Self {
        static NEXT_ID: std::sync::atomic::AtomicUsize =
            std::sync::atomic::AtomicUsize::new(0);
        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("{tag}-{}-{id}", std::process::id()));
        let home = root.join("home");
        std::fs::create_dir_all(&home).unwrap();
        let log = home.join(".local/share/ai-jail/history.jsonl");
        Self {
            root,
            home,
            log,
            subcommand,
        }
    }

    /// Write the log with mode 0600.
    pub fn write(&self, content: impl AsRef<[u8]>) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir_all(self.log.parent().unwrap()).unwrap();
        std::fs::write(&self.log, content).unwrap();
        std::fs::set_permissions(
            &self.log,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(ai_jail());
        command
            .arg(self.subcommand)
            .env("HOME", &self.home)
            .current_dir(&self.root);
        command
    }

    pub fn run(&self) -> Output {
        self.command().output().unwrap()
    }
}

impl Drop for AuditFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Skip the test when the bwrap user-namespace probe fails. Expands to a
/// `return`, so it must be called directly in a `#[test]` body.
#[macro_export]
macro_rules! require_bwrap {
    () => {
        if !$crate::common::bwrap_available() {
            eprintln!(
                "SKIPPED: bwrap cannot create user namespaces \
                 on this system (AppArmor/kernel restriction)"
            );
            return;
        }
    };
}

/// Skip the test when bwrap cannot create network namespaces.
/// Expands to a `return`, so it must be called directly in a `#[test]`
/// body.
#[macro_export]
macro_rules! require_bwrap_net {
    () => {
        if !$crate::common::bwrap_net_available() {
            eprintln!(
                "SKIPPED: bwrap cannot create network namespaces \
                 on this system (AppArmor/kernel restriction)"
            );
            return;
        }
    };
}

/// Skip the test when no host curl binary is available. Expands to a
/// `return`, so it must be called directly in a `#[test]` body.
#[macro_export]
macro_rules! require_curl {
    () => {
        if !$crate::common::curl_available() {
            eprintln!("SKIPPED: curl not found in PATH");
            return;
        }
    };
}

/// Skip the test when any of the named commands is missing from the
/// lockdown PATH. Expands to a `return`, so it must be called directly
/// in a `#[test]` body.
#[macro_export]
macro_rules! require_lockdown_tools {
    ($($cmd:expr),+ $(,)?) => {
        $(
            if !$crate::common::lockdown_cmd_available($cmd) {
                eprintln!(
                    "SKIPPED: {} not found in lockdown PATH \
                     (non-FHS system / NixOS)",
                    $cmd
                );
                return;
            }
        )+
    };
}

/// [`run_in`], except that a `--lockdown` run skips the calling test when
/// `bash` is missing from the lockdown PATH. Expands to a `return`, so it
/// must be called directly in a `#[test]` body.
#[macro_export]
macro_rules! run_in_or_skip {
    ($dir:expr, $flags:expr, $script:expr $(,)?) => {{
        let flags: &[&str] = $flags;
        if flags.contains(&"--lockdown") {
            $crate::require_lockdown_tools!("bash");
        }
        $crate::common::run_in($dir, flags, $script)
    }};
}

/// Skip the test when the sandbox prerequisites are missing: bwrap
/// network namespaces plus a host curl binary. Expands to a `return`,
/// so it must be called directly in a `#[test]` body.
#[macro_export]
macro_rules! require_sandbox {
    () => {
        if !$crate::common::bwrap_net_available() {
            eprintln!(
                "SKIPPED: bwrap cannot create network namespaces \
                 on this system (AppArmor/kernel restriction)"
            );
            return;
        }
        if !$crate::common::curl_available() {
            eprintln!("SKIPPED: curl not found in PATH");
            return;
        }
    };
}

/// macOS counterpart of `require_sandbox!`: sandbox-exec plus curl.
/// Expands to a `return`, so it must be called directly in a `#[test]`
/// body.
#[macro_export]
macro_rules! require_sandbox_exec {
    () => {
        if !$crate::common::sandbox_exec_available() {
            eprintln!(
                "SKIPPED: sandbox-exec cannot apply a profile here \
                 (already sandboxed?)"
            );
            return;
        }
        if !$crate::common::curl_available() {
            eprintln!("SKIPPED: curl not found in PATH");
            return;
        }
    };
}
