// Integration tests that verify sandbox restrictions by
// attempting actual escape operations inside ai-jail.
//
// These tests are Linux-only (require bwrap) and compiled
// only on Linux via #![cfg(target_os = "linux")].
//
// Prerequisites (checked at runtime — tests skip gracefully
// when missing):
//   - Linux with kernel ≥ 5.13 (Landlock V1+)
//   - bwrap (bubblewrap) installed and able to create user
//     namespaces (some distros restrict this via AppArmor or
//     sysctl)
//   - C compiler (`cc`) for building the syscall test helper
//
// The tests compile a small C helper (tests/helpers/escape_helper.c)
// outside the sandbox, then run it inside ai-jail to verify that
// restricted syscalls return EPERM and filesystem writes are denied.
#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::OnceLock;

static COMPILE_HELPER: OnceLock<bool> = OnceLock::new();

// ── Runtime prerequisite checks ─────────────────
//
// bwrap needs unprivileged user namespaces which some kernels
// restrict (Ubuntu 24.04+ AppArmor policy, Debian hardened
// sysctl, etc.). Detect this at runtime so tests skip cleanly
// instead of failing with confusing bwrap errors.

/// Can bwrap create the namespaces needed for normal mode?
fn bwrap_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        Command::new("bwrap")
            .args([
                "--ro-bind",
                "/",
                "/",
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

/// Can bwrap also create a network namespace (lockdown mode)?
fn bwrap_net_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        bwrap_available()
            && Command::new("bwrap")
                .args([
                    "--ro-bind",
                    "/",
                    "/",
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

macro_rules! require_bwrap {
    () => {
        if !bwrap_available() {
            eprintln!(
                "SKIPPED: bwrap cannot create user namespaces \
                 on this system (AppArmor/kernel restriction)"
            );
            return;
        }
    };
}

macro_rules! require_bwrap_net {
    () => {
        if !bwrap_net_available() {
            eprintln!(
                "SKIPPED: bwrap cannot create network \
                 namespaces on this system \
                 (AppArmor/kernel restriction)"
            );
            return;
        }
    };
}

fn ai_jail() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ai-jail"))
}

fn helper_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
}

fn helper_bin() -> PathBuf {
    helper_dir().join("escape_helper")
}

/// Compile the C test helper once per test run.
/// Returns true if compilation succeeded, false otherwise.
fn compile_helper() -> bool {
    *COMPILE_HELPER.get_or_init(|| {
        let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("helpers")
            .join("escape_helper.c");
        let out = helper_bin();
        let _ = std::fs::create_dir_all(helper_dir());
        let Ok(result) = Command::new("cc")
            .args(["-O2", "-Wall", "-o"])
            .arg(&out)
            .arg(&src)
            .output()
        else {
            eprintln!(
                "SKIPPED: C compiler (cc) not found — \
                 cannot build escape_helper"
            );
            return false;
        };
        if !result.status.success() {
            eprintln!(
                "SKIPPED: escape_helper compilation failed: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            return false;
        }
        true
    })
}

macro_rules! require_helper {
    () => {
        if !compile_helper() {
            eprintln!(
                "SKIPPED: escape_helper binary not available \
                 (cc missing or compilation failed)"
            );
            return;
        }
    };
}

/// Run a command inside the sandbox (normal mode).
fn sandbox_run(args: &[&str]) -> Output {
    Command::new(ai_jail())
        .args(["--no-gpu", "--no-docker", "--no-display", "--no-status-bar"])
        .args(args)
        .output()
        .expect("failed to spawn ai-jail")
}

/// Run a command inside the sandbox (lockdown mode).
fn lockdown_run(args: &[&str]) -> Output {
    Command::new(ai_jail())
        .args(["--lockdown", "--no-status-bar"])
        .args(args)
        .output()
        .expect("failed to spawn ai-jail")
}

fn assert_blocked(output: &Output, test_name: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("BLOCKED"),
        "{test_name}: expected BLOCKED, got stdout={stdout:?} \
         stderr={stderr:?} exit={:?}",
        output.status.code()
    );
}

/// Helper: run the compiled C helper inside normal sandbox.
fn helper_normal(test_name: &str) -> Output {
    let bin = helper_bin();
    sandbox_run(&[bin.to_str().unwrap(), test_name])
}

/// Helper: run the compiled C helper inside lockdown sandbox.
fn helper_lockdown(test_name: &str) -> Output {
    let bin = helper_bin();
    lockdown_run(&[bin.to_str().unwrap(), test_name])
}

// ── Seccomp tests (normal mode) ─────────────────
//
// These syscalls normally succeed for unprivileged processes,
// so EPERM can only come from seccomp.

#[test]
fn seccomp_blocks_ptrace_traceme() {
    require_bwrap!();
    require_helper!();
    let out = helper_normal("ptrace");
    assert_blocked(&out, "ptrace(PTRACE_TRACEME)");
}

#[test]
fn seccomp_blocks_personality_read() {
    require_bwrap!();
    require_helper!();
    let out = helper_normal("personality");
    assert_blocked(&out, "personality(0xffffffff)");
}

#[test]
fn seccomp_blocks_io_uring_setup() {
    require_bwrap!();
    require_helper!();
    let out = helper_normal("io_uring");
    assert_blocked(&out, "io_uring_setup()");
}

#[test]
fn seccomp_blocks_bpf() {
    require_bwrap!();
    require_helper!();
    let out = helper_normal("bpf");
    assert_blocked(&out, "bpf(BPF_MAP_CREATE)");
}

#[test]
fn seccomp_blocks_clone3() {
    require_bwrap!();
    require_helper!();
    let out = helper_normal("clone3");
    assert_blocked(&out, "clone3(NULL)");
}

#[test]
fn seccomp_blocks_unshare() {
    require_bwrap!();
    require_helper!();
    let out = helper_normal("unshare");
    assert_blocked(&out, "unshare(CLONE_NEWUSER)");
}

#[test]
fn seccomp_blocks_mount() {
    require_bwrap!();
    require_helper!();
    let out = helper_normal("mount");
    assert_blocked(&out, "mount(tmpfs)");
}

#[test]
fn seccomp_blocks_init_module() {
    require_bwrap!();
    require_helper!();
    let out = helper_normal("init_module");
    assert_blocked(&out, "init_module(NULL)");
}

// ── Filesystem tests (normal mode) ──────────────

#[test]
fn sandbox_blocks_write_to_usr() {
    require_bwrap!();
    require_helper!();
    let out = helper_normal("write_sys");
    assert_blocked(&out, "write to /usr/");
}

#[test]
fn sandbox_blocks_write_to_etc() {
    require_bwrap!();
    let out = sandbox_run(&[
        "sh",
        "-c",
        "touch /etc/.sandbox_test 2>/dev/null && echo ALLOWED || echo BLOCKED",
    ]);
    assert_blocked(&out, "write to /etc/");
}

#[test]
fn sandbox_hides_ssh_dir() {
    require_bwrap!();
    // ~/.ssh is in DOTDIR_DENY and should not be bind-mounted.
    let out = sandbox_run(&[
        "sh",
        "-c",
        "test -d ~/.ssh && echo ALLOWED || echo BLOCKED",
    ]);
    assert_blocked(&out, "~/.ssh visibility");
}

#[test]
fn sandbox_hides_gnupg_dir() {
    require_bwrap!();
    // ~/.gnupg is in DOTDIR_DENY and should not be visible.
    let out = sandbox_run(&[
        "sh",
        "-c",
        "test -d ~/.gnupg && echo ALLOWED || echo BLOCKED",
    ]);
    assert_blocked(&out, "~/.gnupg visibility");
}

// ── Lockdown mode tests ─────────────────────────

#[test]
fn lockdown_blocks_network() {
    require_bwrap_net!();
    require_helper!();
    let out = helper_lockdown("network");
    assert_blocked(&out, "TCP connect in lockdown");
}

#[test]
fn lockdown_blocks_write_to_project() {
    require_bwrap_net!();
    // In lockdown, the project directory is read-only.
    let out = lockdown_run(&[
        "sh",
        "-c",
        "touch ./lockdown_test 2>/dev/null && echo ALLOWED || echo BLOCKED",
    ]);
    assert_blocked(&out, "write to project dir in lockdown");
}

#[test]
fn lockdown_seccomp_blocks_ptrace() {
    require_bwrap_net!();
    require_helper!();
    // Seccomp should be active in lockdown too.
    let out = helper_lockdown("ptrace");
    assert_blocked(&out, "ptrace in lockdown");
}

#[test]
fn lockdown_seccomp_blocks_io_uring() {
    require_bwrap_net!();
    require_helper!();
    let out = helper_lockdown("io_uring");
    assert_blocked(&out, "io_uring in lockdown");
}

#[test]
fn lockdown_blocks_write_to_usr() {
    require_bwrap_net!();
    require_helper!();
    let out = helper_lockdown("write_sys");
    assert_blocked(&out, "write to /usr/ in lockdown");
}
