#![cfg(feature = "test-hooks")]

mod common;

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PTY_DEADLINE: Duration = Duration::from_secs(15);

unsafe fn slave_stdio(fd: i32) -> Stdio {
    let duplicated = unsafe { nix::libc::dup(fd) };
    assert!(duplicated >= 0);
    unsafe { Stdio::from_raw_fd(duplicated) }
}

fn read_once(fd: i32, transcript: &mut Vec<u8>, timeout_ms: u16) {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    use std::os::fd::BorrowedFd;

    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    let mut poll_fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
    if poll(&mut poll_fds, PollTimeout::from(timeout_ms)).unwrap_or(0) == 0 {
        return;
    }
    let mut buffer = [0_u8; 8192];
    if let Ok(count) = nix::unistd::read(fd, &mut buffer) {
        transcript.extend_from_slice(&buffer[..count]);
    }
}

fn run_pty(
    root: &std::path::Path,
    args: &[&str],
    exchanges: &[(&str, &[u8])],
    expected_code: i32,
) -> (String, bool) {
    let project = root.join("project");
    let home = root.join("home");
    let xdg = root.join("xdg");
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&home).unwrap();

    let pty = nix::pty::openpty(None, None).unwrap();
    let slave_fd = pty.slave.as_raw_fd();
    let mut command = Command::new(common::ai_jail());
    command
        .args(args)
        .current_dir(project)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", xdg)
        .env("NO_COLOR", "1")
        .env("TERM", "xterm");
    unsafe {
        command.stdin(slave_stdio(slave_fd));
        command.stdout(slave_stdio(slave_fd));
        command.stderr(slave_stdio(slave_fd));
    }
    use std::os::unix::process::CommandExt;
    unsafe {
        command.pre_exec(move || {
            nix::libc::setsid();
            nix::libc::ioctl(slave_fd, nix::libc::TIOCSCTTY as _, 0);
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let master_fd = pty.master.as_raw_fd();
    let mut transcript = Vec::new();
    for (prompt, input) in exchanges {
        let deadline = Instant::now() + PTY_DEADLINE;
        while !String::from_utf8_lossy(&transcript).contains(prompt) {
            assert!(
                Instant::now() < deadline,
                "missing {prompt:?}: {}",
                String::from_utf8_lossy(&transcript)
            );
            read_once(master_fd, &mut transcript, 50);
        }
        nix::unistd::write(&pty.master, input).unwrap();
    }
    let deadline = Instant::now() + PTY_DEADLINE;
    let status = loop {
        read_once(master_fd, &mut transcript, 20);
        if let Some(status) = child.try_wait().unwrap() {
            for _ in 0..5 {
                read_once(master_fd, &mut transcript, 20);
            }
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            break child.wait().unwrap();
        }
    };
    let mut termios = unsafe { std::mem::zeroed::<nix::libc::termios>() };
    assert_eq!(unsafe { nix::libc::tcgetattr(master_fd, &mut termios) }, 0);
    let echo = termios.c_lflag & nix::libc::ECHO != 0;
    assert_eq!(
        status.code(),
        Some(expected_code),
        "{}",
        String::from_utf8_lossy(&transcript)
    );
    (String::from_utf8(transcript).unwrap(), echo)
}

fn normalize(
    mut transcript: String,
    root: &std::path::Path,
    port: u16,
) -> String {
    transcript = transcript.replace('\r', "");
    transcript = transcript.replace(root.to_string_lossy().as_ref(), "<ROOT>");
    transcript = transcript.replace(
        &format!("http://127.0.0.1:{port}"),
        "https://gitlab.example",
    );
    while let Some(start) = transcript.find("forges/project-") {
        let relative_end = transcript[start..]
            .find(".toml")
            .expect("complete forge binding path");
        let end = start + relative_end + ".toml".len();
        transcript.replace_range(start..end, "forges/<PROJECT>.toml");
    }
    transcript
}

#[test]
fn actual_cli_forge_workflow_matches_documented_transcript() {
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("forge-pty-workflow-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        for expected in ["first-hidden-token", "rotated-hidden-token"] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                assert!(request.len() < 8192, "oversized verification request");
                let mut chunk = [0_u8; 1024];
                let count = stream.read(&mut chunk).unwrap();
                assert!(count > 0, "truncated verification request");
                request.extend_from_slice(&chunk[..count]);
            }
            let request = String::from_utf8_lossy(&request);
            assert!(
                request.contains(&format!("Authorization: Bearer {expected}"))
            );
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n{\"id\":42}").unwrap();
        }
    });
    let origin = format!("http://127.0.0.1:{port}");
    let setup_args = ["forge", "setup", "gitlab", &origin, "owner/repo"];
    let (setup, _) = run_pty(
        &root,
        &setup_args,
        &[
            ("comma-separated): ", b"read_repository\n"),
            ("or `never`): ", b"2027-01-31\n"),
            ("Repository token:", b"first-hidden-token\n"),
            ("Type OPEN to save this authority:", b"OPEN\n"),
        ],
        0,
    );
    let (status, _) = run_pty(&root, &["forge", "status"], &[], 0);
    let (rotate, _) = run_pty(
        &root,
        &setup_args,
        &[
            ("comma-separated): ", b"read_repository,write_repository\n"),
            ("or `never`): ", b"2027-06-30\n"),
            ("Repository token:", b"rotated-hidden-token\n"),
            ("Type OPEN to save this authority:", b"OPEN\n"),
        ],
        0,
    );
    let (remove, _) = run_pty(&root, &["forge", "remove"], &[], 0);
    server.join().unwrap();

    let transcript = normalize(
        format!(
            "AJ-FORGE-TRANSCRIPT-BEGIN actual CLI workflow\n{setup}{status}{rotate}{remove}AJ-FORGE-TRANSCRIPT-END actual CLI workflow\n"
        ),
        &root,
        port,
    );
    assert!(!transcript.contains("first-hidden-token"));
    assert!(!transcript.contains("rotated-hidden-token"));
    assert!(!transcript.contains("\x1b["));
    let fixture = include_str!("fixtures/forge/workflow.txt");
    assert_eq!(transcript, fixture);
    let fenced = format!("```text\n{fixture}```");
    assert!(include_str!("../docs/FORGE_AUTH.md").contains(&fenced));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn hidden_token_cancel_restores_terminal_echo() {
    for (label, cancel) in [
        ("ctrl-c", b"\x03".as_slice()),
        ("escape", b"\x1b".as_slice()),
    ] {
        let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("forge-pty-cancel-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let origin = "http://127.0.0.1:9";
        let (_, echo) = run_pty(
            &root,
            &["forge", "setup", "gitlab", origin, "owner/repo"],
            &[
                ("comma-separated): ", b"read_repository\n"),
                ("or `never`): ", b"never\n"),
                ("Repository token:", cancel),
            ],
            1,
        );
        assert!(echo, "terminal echo was not restored after {label}");
        let _ = fs::remove_dir_all(root);
    }
}
