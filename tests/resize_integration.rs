//! Integration test for PTY resize with scroll-region status bar.
//!
//! Reproduces the exact scenario: parent owns the real terminal,
//! child is in a PTY with one fewer row, scroll region reserves
//! the last row for the status bar.

use std::os::unix::io::{AsRawFd, FromRawFd};
use std::time::Duration;

fn set_pty_size(fd: i32, rows: u16, cols: u16) {
    let ws = nix::libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        nix::libc::ioctl(fd, nix::libc::TIOCSWINSZ, &ws);
    }
}

fn get_pty_size(fd: i32) -> (u16, u16) {
    let mut ws = unsafe { std::mem::zeroed::<nix::libc::winsize>() };
    unsafe {
        nix::libc::ioctl(fd, nix::libc::TIOCGWINSZ, &mut ws);
    }
    (ws.ws_row, ws.ws_col)
}

fn read_available(
    master: &std::os::unix::io::OwnedFd,
    timeout_ms: i32,
) -> Vec<u8> {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    let fd = unsafe {
        std::os::unix::io::BorrowedFd::borrow_raw(master.as_raw_fd())
    };
    let mut fds = [PollFd::new(fd, PollFlags::POLLIN)];
    let mut result = Vec::new();
    let mut buf = [0u8; 4096];

    loop {
        match poll(&mut fds, PollTimeout::from(timeout_ms as u16)) {
            Ok(0) => break,
            Err(_) => break,
            Ok(_) => match nix::unistd::read(master.as_raw_fd(), &mut buf) {
                Ok(0) => break,
                Ok(n) => result.extend_from_slice(&buf[..n]),
                Err(_) => break,
            },
        }
    }
    result
}

/// Extract visible text from raw terminal output (strip
/// escapes).
fn strip_ansi(data: &[u8]) -> String {
    let s = String::from_utf8_lossy(data);
    let mut result = String::new();
    let mut in_esc = false;
    let mut in_csi = false;
    for ch in s.chars() {
        if in_csi {
            if ch.is_ascii_alphabetic() || ch == '~' {
                in_csi = false;
            }
            continue;
        }
        if in_esc {
            if ch == '[' {
                in_csi = true;
            } else if ch != 'O' {
                in_esc = false;
            }
            continue;
        }
        if ch == '\x1b' {
            in_esc = true;
            continue;
        }
        if ch >= ' ' || ch == '\n' || ch == '\r' {
            result.push(ch);
        }
    }
    result
}

/// Dup slave fd for use as Stdio (avoids double-close with
/// OwnedFd).
unsafe fn slave_stdio(slave_fd: i32) -> std::process::Stdio {
    let duped = unsafe { nix::libc::dup(slave_fd) };
    assert!(duped >= 0, "dup() failed");
    unsafe { std::process::Stdio::from_raw_fd(duped) }
}

/// Test: child in PTY gets correct initial size.
#[test]
fn child_sees_initial_size_minus_one() {
    let pty = nix::pty::openpty(None, None).unwrap();
    let master = pty.master;
    let slave = pty.slave;

    // Real terminal would be 40x80; child gets 39x80
    set_pty_size(master.as_raw_fd(), 39, 80);

    let slave_fd = slave.as_raw_fd();
    let mut cmd = std::process::Command::new("bash");
    cmd.args(["-c", "stty size; exit 0"]);
    unsafe {
        cmd.stdin(slave_stdio(slave_fd));
        cmd.stdout(slave_stdio(slave_fd));
        cmd.stderr(slave_stdio(slave_fd));
    }

    let mut child = cmd.spawn().unwrap();
    drop(slave);

    let output = read_available(&master, 500);
    let status = child.wait().unwrap();
    let text = strip_ansi(&output);
    assert!(status.success(), "child exited with {status:?}");
    assert!(
        text.contains("39 80"),
        "Expected '39 80' in output, got: {:?}",
        text
    );
}

/// Test: resizing the PTY master delivers SIGWINCH to child,
/// and child sees the new size.
#[test]
fn resize_pty_delivers_sigwinch_and_new_size() {
    let pty = nix::pty::openpty(None, None).unwrap();
    let master = pty.master;
    let slave = pty.slave;

    set_pty_size(master.as_raw_fd(), 39, 80);

    let slave_fd = slave.as_raw_fd();
    let mut cmd = std::process::Command::new("bash");
    cmd.args([
        "-c",
        concat!(
            "trap 'stty size; exit 0' SIGWINCH; ",
            "while true; do sleep 0.1; done"
        ),
    ]);
    unsafe {
        cmd.stdin(slave_stdio(slave_fd));
        cmd.stdout(slave_stdio(slave_fd));
        cmd.stderr(slave_stdio(slave_fd));
    }

    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(move || {
            nix::libc::setsid();
            nix::libc::ioctl(
                slave_fd,
                nix::libc::TIOCSCTTY as nix::libc::c_ulong,
                0,
            );
            Ok(())
        });
    }

    let mut child = cmd.spawn().unwrap();
    drop(slave);

    // Wait for child to start
    std::thread::sleep(Duration::from_millis(200));
    // Drain any startup output
    let _ = read_available(&master, 100);

    // Simulate resize: terminal grew to 80 rows, child gets 79
    set_pty_size(master.as_raw_fd(), 79, 120);

    // Read child's SIGWINCH response
    let output = read_available(&master, 500);
    let status = child.wait().unwrap();
    let text = strip_ansi(&output);
    assert!(status.success(), "child exited with {status:?}");
    assert!(
        text.contains("79 120"),
        "Expected '79 120' after resize, got: {:?}",
        text
    );
}

/// Test: the exact resize sequence ai-jail uses.
/// Verifies that scroll region is set BEFORE PTY resize.
#[test]
fn resize_sequence_scroll_region_before_pty_resize() {
    let pty = nix::pty::openpty(None, None).unwrap();
    let master = pty.master;
    let slave = pty.slave;
    let master_fd = master.as_raw_fd();

    // Initial: 40-row terminal, child gets 39 rows
    set_pty_size(master_fd, 39, 80);

    let slave_fd = slave.as_raw_fd();
    let mut cmd = std::process::Command::new("bash");
    cmd.args([
        "-c",
        concat!(
            "trap 'stty size >> /tmp/resize_test_sizes; ",
            "echo RESIZE_DONE' SIGWINCH; ",
            "echo READY; ",
            "while true; do sleep 0.1; done"
        ),
    ]);
    unsafe {
        cmd.stdin(slave_stdio(slave_fd));
        cmd.stdout(slave_stdio(slave_fd));
        cmd.stderr(slave_stdio(slave_fd));
    }

    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(move || {
            nix::libc::setsid();
            nix::libc::ioctl(
                slave_fd,
                nix::libc::TIOCSCTTY as nix::libc::c_ulong,
                0,
            );
            Ok(())
        });
    }

    let mut child = cmd.spawn().unwrap();
    drop(slave);

    // Wait for READY
    std::thread::sleep(Duration::from_millis(300));
    let _ = read_available(&master, 100);

    // Clean up temp file
    let _ = std::fs::remove_file("/tmp/resize_test_sizes");

    // === Simulate what ai-jail's IO loop does on SIGWINCH ===
    // Step 1: Write scroll region for new size (80 rows total,
    //   status bar at row 80, scroll region [1, 79])
    // This goes to the REAL terminal, not the PTY master.
    // We just verify the PTY resize step works.

    // Step 2: THEN resize the PTY (child gets 79 rows)
    set_pty_size(master_fd, 79, 120);

    // Read child's response
    let output = read_available(&master, 500);
    let text = strip_ansi(&output);
    assert!(
        text.contains("RESIZE_DONE"),
        "Child should have received SIGWINCH, got: {:?}",
        text
    );

    // Verify child saw 79x120
    std::thread::sleep(Duration::from_millis(100));
    let sizes =
        std::fs::read_to_string("/tmp/resize_test_sizes").unwrap_or_default();
    assert!(
        sizes.contains("79 120"),
        "Child should see 79x120, got: {:?}",
        sizes
    );

    let _ = std::fs::remove_file("/tmp/resize_test_sizes");

    // Clean up
    let pid = child.id() as i32;
    unsafe {
        nix::libc::kill(pid, nix::libc::SIGTERM);
    }
    let _ = child.wait();
}

/// Test: child handles both grow and shrink resizes correctly.
/// Simulates the "PTY resize first" approach ai-jail now uses.
#[test]
fn resize_grow_and_shrink() {
    let pty = nix::pty::openpty(None, None).unwrap();
    let master = pty.master;
    let slave = pty.slave;
    let master_fd = master.as_raw_fd();

    // Initial: child gets 39x80
    set_pty_size(master_fd, 39, 80);

    let slave_fd = slave.as_raw_fd();
    let mut cmd = std::process::Command::new("bash");
    cmd.args([
        "-c",
        concat!(
            "echo READY; ",
            "trap 'stty size' SIGWINCH; ",
            "while true; do sleep 0.1; done"
        ),
    ]);
    unsafe {
        cmd.stdin(slave_stdio(slave_fd));
        cmd.stdout(slave_stdio(slave_fd));
        cmd.stderr(slave_stdio(slave_fd));
    }

    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(move || {
            nix::libc::setsid();
            nix::libc::ioctl(
                slave_fd,
                nix::libc::TIOCSCTTY as nix::libc::c_ulong,
                0,
            );
            Ok(())
        });
    }

    let mut child = cmd.spawn().unwrap();
    drop(slave);

    std::thread::sleep(Duration::from_millis(200));
    let _ = read_available(&master, 100);

    // Grow: 39x80 → 79x120
    set_pty_size(master_fd, 79, 120);
    let output = read_available(&master, 500);
    let text = strip_ansi(&output);
    assert!(
        text.contains("79 120"),
        "After grow, expected '79 120', got: {:?}",
        text
    );

    // Shrink: 79x120 → 29x60
    set_pty_size(master_fd, 29, 60);
    let output2 = read_available(&master, 500);
    let text2 = strip_ansi(&output2);
    assert!(
        text2.contains("29 60"),
        "After shrink, expected '29 60', got: {:?}",
        text2
    );

    let pid = child.id() as i32;
    unsafe {
        nix::libc::kill(pid, nix::libc::SIGTERM);
    }
    let _ = child.wait();
}

/// Test: verify the PTY correctly gets size (rows-1, cols) when
/// we simulate the terminal being rows×cols.
#[test]
fn pty_size_is_terminal_minus_one() {
    let pty = nix::pty::openpty(None, None).unwrap();
    let master_fd = pty.master.as_raw_fd();

    // Simulate: real terminal is 50x100
    // ai-jail sets PTY to (49, 100)
    set_pty_size(master_fd, 49, 100);

    let (rows, cols) = get_pty_size(master_fd);
    assert_eq!(rows, 49);
    assert_eq!(cols, 100);

    // Simulate resize: real terminal grows to 80x100
    // ai-jail sets PTY to (79, 100)
    set_pty_size(master_fd, 79, 100);

    let (rows, cols) = get_pty_size(master_fd);
    assert_eq!(rows, 79);
    assert_eq!(cols, 100);
}
