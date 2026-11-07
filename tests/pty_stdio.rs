//! Redirected stdin must remain a pipe/file while terminal output is filtered.

#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::fs;
use std::io::Write;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

enum Input {
    Pipe,
    File,
    Null,
    Terminal,
}

struct TestTree(PathBuf);

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

unsafe fn slave_stdio(fd: i32) -> Stdio {
    let duplicated = unsafe { nix::libc::dup(fd) };
    assert!(duplicated >= 0);
    unsafe { Stdio::from_raw_fd(duplicated) }
}

fn read_available(fd: i32, transcript: &mut Vec<u8>) -> bool {
    let master = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut fds =
        [nix::poll::PollFd::new(master, nix::poll::PollFlags::POLLIN)];
    if nix::poll::poll(&mut fds, 50_u16).unwrap_or(0) == 0 {
        return false;
    }
    let mut buffer = [0_u8; 8192];
    match nix::unistd::read(fd, &mut buffer) {
        Ok(0) | Err(_) => false,
        Ok(count) => {
            transcript.extend_from_slice(&buffer[..count]);
            true
        }
    }
}

fn check_input(name: &str, input: Input) {
    #[cfg(target_os = "linux")]
    require_bwrap_net!();
    #[cfg(target_os = "macos")]
    if !common::sandbox_exec_available() {
        eprintln!("SKIPPED: sandbox-exec unavailable");
        return;
    }
    require_lockdown_tools!("sh", "cat");

    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("pty-stdio-{name}-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let tree = TestTree(root.canonicalize().unwrap());
    let home = tree.0.join("home");
    let project = tree.0.join("project");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&project).unwrap();
    let payload = "PAYLOAD-WITHOUT-NEWLINE";
    let input_path = tree.0.join("input");
    fs::write(&input_path, payload).unwrap();

    let size = nix::libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = nix::pty::openpty(Some(&size), None).unwrap();
    let original_mode = nix::sys::termios::tcgetattr(&pty.master).unwrap();
    let mut command = Command::new(common::ai_jail());
    command
        .args([
            "--clean",
            "--no-save-config",
            "--no-mise",
            "--no-toolchains",
            "--no-agent-state",
            "--no-network",
            "--no-status-bar",
            "/bin/sh",
            "-c",
            "if test -t 0; then printf STDIN_TTY; IFS= read -r data; \
             else printf STDIN_REDIRECTED; data=$(cat); fi; \
             printf '<%s>AFTER_EOF\\033]52;c;Y2xpcA==\\007FILTER_DONE\\n' \"$data\"",
        ])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin")
        .env("TERM", "xterm-256color")
        .current_dir(&project)
        .stdin(match input {
            Input::Pipe => Stdio::piped(),
            Input::File => fs::File::open(&input_path).unwrap().into(),
            Input::Null => Stdio::null(),
            Input::Terminal => unsafe { slave_stdio(pty.slave.as_raw_fd()) },
        });
    unsafe {
        command.stdout(slave_stdio(pty.slave.as_raw_fd()));
        command.stderr(slave_stdio(pty.slave.as_raw_fd()));
    }
    let mut child = command.spawn().unwrap();
    drop(pty.slave);
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(payload.as_bytes()).unwrap();
    }
    if matches!(input, Input::Terminal) {
        nix::unistd::write(&pty.master, format!("{payload}\n").as_bytes())
            .unwrap();
    }

    let mut transcript = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        read_available(pty.master.as_raw_fd(), &mut transcript);
        if let Some(status) = child.try_wait().unwrap() {
            while read_available(pty.master.as_raw_fd(), &mut transcript) {}
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("child did not reach EOF: {transcript:?}");
        }
    };
    let transcript = String::from_utf8_lossy(&transcript);
    assert!(status.success(), "{name}: {status}; {transcript}");
    let mode = if matches!(input, Input::Terminal) {
        "STDIN_TTY"
    } else {
        "STDIN_REDIRECTED"
    };
    assert!(transcript.contains(mode), "{name}: {transcript}");
    let expected = if matches!(input, Input::Null) {
        ""
    } else {
        payload
    };
    assert!(
        transcript.contains(&format!("<{expected}>AFTER_EOF")),
        "{name}: {transcript}"
    );
    assert!(transcript.contains("FILTER_DONE"), "{name}: {transcript}");
    assert!(
        !transcript.contains("]52;"),
        "terminal clipboard sequence was not filtered: {transcript}"
    );
    // PENDIN can be set by the kernel after restoring canonical mode;
    // compare the mode bits cfmakeraw changes, not transient input state.
    use nix::sys::termios::LocalFlags;
    let raw_mode_flags = LocalFlags::ECHO
        | LocalFlags::ECHONL
        | LocalFlags::ICANON
        | LocalFlags::ISIG
        | LocalFlags::IEXTEN;
    assert_eq!(
        nix::sys::termios::tcgetattr(&pty.master)
            .unwrap()
            .local_flags
            & raw_mode_flags,
        original_mode.local_flags & raw_mode_flags,
        "terminal mode was not restored"
    );
}

#[test]
fn piped_stdin_preserves_payload_and_eof_with_terminal_stdout() {
    check_input("pipe", Input::Pipe);
}

#[test]
fn file_stdin_preserves_payload_and_eof_with_terminal_stdout() {
    check_input("file", Input::File);
}

#[test]
fn null_stdin_reaches_eof_with_terminal_stdout() {
    check_input("null", Input::Null);
}

#[test]
fn terminal_stdin_still_forwards_input_and_restores_terminal_mode() {
    check_input("terminal", Input::Terminal);
}
