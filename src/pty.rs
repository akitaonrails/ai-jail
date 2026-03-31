//! PTY proxy with virtual terminal for persistent status bar.
//!
//! When the status bar is enabled, ai-jail interposes a PTY between
//! itself and the sandbox child. The child writes to the PTY slave
//! while ai-jail owns the real terminal.
//!
//! Rendering uses a hybrid approach:
//!   - **Primary screen**: raw pass-through with a scroll region
//!     protecting the status bar. This preserves natural terminal
//!     scrollback. vt100 processes the output in parallel for
//!     resize recovery.
//!   - **Alternate screen** (vim, less, etc.): cursor-addressed
//!     diff-rendering via vt100::state_diff. No scrollback needed.
//!
//! On resize, the vt100 virtual terminal is resized first, then
//! its state is re-rendered to the real terminal, giving ai-jail
//! full control over screen recovery.

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::termios::{self, SetArg, Termios};
use std::os::unix::io::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

/// Stored master raw FD for async-signal-safe resize from SIGWINCH.
static MASTER_FD: AtomicI32 = AtomicI32::new(-1);

/// Set by signal handler; IO loop clears screen + redraws status bar
/// BEFORE forwarding SIGWINCH to the child, preventing ghost bars.
static SIGWINCH_PENDING: AtomicBool = AtomicBool::new(false);

/// Mark a SIGWINCH as pending. Called from the signal handler.
pub fn set_sigwinch_pending() {
    SIGWINCH_PENDING.store(true, Ordering::SeqCst);
}

/// Resize the PTY slave to match the real terminal (minus one row
/// for the status bar). Async-signal-safe: only uses ioctl + atomics.
pub fn resize_pty() {
    let master = MASTER_FD.load(Ordering::SeqCst);
    if master < 0 {
        return;
    }
    let mut ws = unsafe { std::mem::zeroed::<nix::libc::winsize>() };
    let ret = unsafe {
        nix::libc::ioctl(
            nix::libc::STDOUT_FILENO,
            nix::libc::TIOCGWINSZ,
            &mut ws,
        )
    };
    if ret != 0 || ws.ws_row < 2 || ws.ws_col == 0 {
        return;
    }
    ws.ws_row -= 1;
    unsafe {
        nix::libc::ioctl(master, nix::libc::TIOCSWINSZ, &ws);
    }
}

/// Explicitly send SIGWINCH to the PTY foreground process group.
/// TIOCSWINSZ should do this via the kernel, but bwrap's PID
/// namespace can prevent delivery. This is the reliable fallback.
fn forward_sigwinch() {
    let master = MASTER_FD.load(Ordering::SeqCst);
    if master < 0 {
        return;
    }
    let mut pgrp: nix::libc::pid_t = 0;
    let ret =
        unsafe { nix::libc::ioctl(master, nix::libc::TIOCGPGRP, &mut pgrp) };
    if ret == 0 && pgrp > 0 {
        unsafe {
            nix::libc::kill(-pgrp, nix::libc::SIGWINCH);
        }
    }
}

fn enter_raw_mode() -> Result<Termios, String> {
    let stdin = std::io::stdin();
    let saved =
        termios::tcgetattr(&stdin).map_err(|e| format!("tcgetattr: {e}"))?;
    let mut raw = saved.clone();
    termios::cfmakeraw(&mut raw);
    termios::tcsetattr(&stdin, SetArg::TCSANOW, &raw)
        .map_err(|e| format!("tcsetattr raw: {e}"))?;
    Ok(saved)
}

fn restore_mode(saved: &Termios) {
    let stdin = std::io::stdin();
    let _ = termios::tcsetattr(&stdin, SetArg::TCSANOW, saved);
}

struct RawModeGuard(Option<Termios>);

impl RawModeGuard {
    fn new(saved: Termios) -> Self {
        Self(Some(saved))
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if let Some(saved) = self.0.take() {
            restore_mode(&saved);
        }
    }
}

fn set_initial_size(fd: &OwnedFd, rows: u16, cols: u16) {
    let ws = nix::libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    unsafe {
        nix::libc::ioctl(fd.as_raw_fd(), nix::libc::TIOCSWINSZ, &ws);
    }
}

/// Set terminal scroll region to rows 1..content_rows (1-based).
/// Status bar lives on row content_rows+1, outside the region.
fn set_scroll_region(fd: i32, content_rows: u16) {
    let seq = format!("\x1b[1;{}r", content_rows);
    write_all_raw(fd, seq.as_bytes());
}

/// Sync the vt100 cursor position into the status bar module
/// so that `draw()` can restore the cursor via CUP.
fn sync_statusbar_cursor(parser: &vt100::Parser) {
    let (row, col) = parser.screen().cursor_position();
    crate::statusbar::set_cursor_position(row + 1, col + 1);
}

fn io_loop(master: &OwnedFd, init_rows: u16, init_cols: u16) {
    let stdin_fd = std::io::stdin().as_raw_fd();
    let master_raw = master.as_raw_fd();
    let stdin_bfd = unsafe { BorrowedFd::borrow_raw(stdin_fd) };
    let master_bfd = unsafe { BorrowedFd::borrow_raw(master_raw) };
    let mut buf = [0u8; 8192];
    let stdout = nix::libc::STDOUT_FILENO;

    // Track content area size (updated on SIGWINCH)
    let mut content_rows = init_rows - 1;
    let mut content_cols = init_cols;

    // Virtual terminal for resize recovery and alt-screen
    // diff rendering. Scrollback of 0 is fine — the real
    // terminal handles scrollback via raw pass-through.
    let mut parser = vt100::Parser::new(content_rows, content_cols, 0);
    let mut prev_screen = parser.screen().clone();
    let mut pending_redraw = false;
    let mut was_alt_screen = false;

    // Push existing terminal content into scrollback so the
    // child starts on a clean canvas without losing history.
    // Move cursor to bottom of screen and emit newlines.
    let pos = format!("\x1b[{};1H", init_rows);
    write_all_raw(stdout, pos.as_bytes());
    for _ in 0..content_rows {
        write_all_raw(stdout, b"\n");
    }
    // Clear visible area and set scroll region
    write_all_raw(stdout, b"\x1b[H\x1b[J");
    set_scroll_region(stdout, content_rows);

    loop {
        // Handle pending SIGWINCH before anything else.
        // Order: resize vt100 FIRST, then re-render, then
        // resize PTY (which delivers SIGWINCH to child).
        if SIGWINCH_PENDING.swap(false, Ordering::SeqCst) {
            let (rows, cols) =
                real_term_size().unwrap_or((init_rows, init_cols));
            if rows >= 2 {
                content_rows = rows - 1;
                content_cols = cols;
                parser.screen_mut().set_size(content_rows, content_cols);

                let screen = parser.screen();
                let on_alt = screen.alternate_screen();

                // Reset scroll region and clear screen
                write_all_raw(stdout, b"\x1b[r\x1b[H\x1b[J");

                if on_alt {
                    // Alt screen: re-render from vt100 state
                    // (child will overwrite with its own redraw)
                    let output = screen.state_formatted();
                    write_all_raw(stdout, &output);
                } else {
                    // Primary screen: just set scroll region
                    // and let the child redraw at the new size.
                    // Don't re-render stale vt100 content.
                    set_scroll_region(stdout, content_rows);
                }

                prev_screen = screen.clone();
                was_alt_screen = on_alt;

                // Redraw status bar, then notify child
                sync_statusbar_cursor(&parser);
                crate::statusbar::redraw();
                resize_pty();
                forward_sigwinch();

                let _ = crate::statusbar::take_requests();
                pending_redraw = false;
            }
        }

        let mut fds = [
            PollFd::new(stdin_bfd, PollFlags::POLLIN),
            PollFd::new(master_bfd, PollFlags::POLLIN),
        ];

        if crate::statusbar::take_requests() {
            pending_redraw = true;
        }

        match poll(&mut fds, PollTimeout::from(100_u16)) {
            Ok(0) => {
                if pending_redraw {
                    sync_statusbar_cursor(&parser);
                    crate::statusbar::redraw();
                    pending_redraw = false;
                }
                continue;
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
            Ok(_) => {}
        }

        // Check master (child output) first for responsiveness
        if let Some(revents) = fds[1].revents() {
            if revents.contains(PollFlags::POLLIN) {
                match nix::unistd::read(master_raw, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        // Always process through vt100 for resize
                        // recovery and alt-screen tracking.
                        parser.process(&buf[..n]);
                        let screen = parser.screen();
                        let now_alt = screen.alternate_screen();

                        // Forward kitty keyboard protocol
                        // sequences that vt100 silently drops.
                        // Only needed on alt screen paths —
                        // primary screen uses raw pass-through.
                        if now_alt || now_alt != was_alt_screen {
                            forward_keyboard_protocol(stdout, &buf[..n]);
                        }

                        if now_alt != was_alt_screen {
                            // Alt screen transition: full re-render
                            if now_alt {
                                // Entering alt: remove scroll region
                                write_all_raw(stdout, b"\x1b[r");
                            } else {
                                // Leaving alt: restore scroll region
                                set_scroll_region(stdout, content_rows);
                            }
                            write_all_raw(stdout, b"\x1b[H\x1b[J");
                            let output = screen.state_formatted();
                            write_all_raw(stdout, &output);
                            was_alt_screen = now_alt;
                        } else if now_alt {
                            // Alt screen: cursor-addressed diff
                            let diff = screen.state_diff(&prev_screen);
                            write_all_raw(stdout, &diff);
                        } else {
                            // Primary screen: raw pass-through
                            // for natural scrollback.
                            write_all_raw(stdout, &buf[..n]);
                            // Re-establish scroll region in case
                            // child output contained a reset.
                            // Only inject when the output ends at
                            // ground state — if we're mid-escape
                            // sequence, our injected escapes would
                            // corrupt the child's incomplete CSI
                            // (causes color bleeding).
                            //
                            // DECSTBM (\x1b[1;Nr) moves the cursor
                            // to home as a side effect. Restore it
                            // via absolute CUP (\x1b[row;colH) using
                            // the position tracked by the vt100
                            // model — avoids DECSC/DECRC (\x1b7/\x1b8)
                            // which on macOS terminals also saves/
                            // restores scroll margins, undoing the
                            // repair we just applied.
                            if ends_at_ground_state(&buf[..n]) {
                                let (row, col) =
                                    parser.screen().cursor_position();
                                set_scroll_region(stdout, content_rows);
                                let seq =
                                    format!("\x1b[{};{}H", row + 1, col + 1);
                                write_all_raw(stdout, seq.as_bytes());
                            }
                        }

                        prev_screen = screen.clone();
                        pending_redraw = true;
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(nix::errno::Errno::EIO) => break,
                    Err(_) => break,
                }
            }
            if revents.contains(PollFlags::POLLHUP)
                || revents.contains(PollFlags::POLLERR)
            {
                loop {
                    match nix::unistd::read(master_raw, &mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            parser.process(&buf[..n]);
                        }
                    }
                }
                let screen = parser.screen();
                let diff = screen.state_diff(&prev_screen);
                write_all_raw(stdout, &diff);
                // Reset scroll region before exit
                write_all_raw(stdout, b"\x1b[r");
                sync_statusbar_cursor(&parser);
                crate::statusbar::redraw();
                break;
            }
        }

        // Redraw status bar when child is quiet
        if !matches!(
            fds[1].revents(),
            Some(r) if r.contains(PollFlags::POLLIN)
        ) && pending_redraw
        {
            sync_statusbar_cursor(&parser);
            crate::statusbar::redraw();
            pending_redraw = false;
        }

        // Check stdin (user input) — forward directly to PTY
        if let Some(revents) = fds[0].revents() {
            if revents.contains(PollFlags::POLLIN) {
                match nix::unistd::read(stdin_fd, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        write_all_raw(master_raw, &buf[..n]);
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(_) => break,
                }
            }
        }
    }

    // Clean up: reset scroll region so terminal is in a
    // known state after ai-jail exits.
    write_all_raw(stdout, b"\x1b[r");
}

/// Scan child output for kitty keyboard protocol sequences and
/// forward them to the real terminal.  The vt100 crate does not
/// understand these, so `state_diff()` / `state_formatted()` will
/// silently drop them.  Without forwarding, the real terminal
/// never enables the protocol and modifier keys (Shift+Enter,
/// Ctrl+i vs Tab, etc.) are lost.
///
/// Recognised sequences (CSI with `>`, `<`, or `?` prefix,
/// final byte `u`):
///   - `\x1b[>flags u`  — push keyboard mode
///   - `\x1b[<u`        — pop keyboard mode
///   - `\x1b[?u`        — query keyboard mode
fn forward_keyboard_protocol(fd: i32, data: &[u8]) {
    // Tiny state machine:  0=ground  1=ESC  2=CSI-start  3=params
    let mut st: u8 = 0;
    let mut start: usize = 0;
    let mut is_kbd = false;
    for (i, &b) in data.iter().enumerate() {
        match st {
            0 => {
                if b == 0x1b {
                    start = i;
                    is_kbd = false;
                    st = 1;
                }
            }
            1 => {
                if b == b'[' {
                    st = 2;
                } else {
                    st = 0;
                }
            }
            2 => {
                // First byte after CSI — check for > < ?
                if b == b'>' || b == b'<' || b == b'?' {
                    is_kbd = true;
                    st = 3;
                } else if (0x40..=0x7e).contains(&b) {
                    st = 0; // final byte, not ours
                } else {
                    st = 3; // params
                }
            }
            3 => {
                if (0x40..=0x7e).contains(&b) {
                    // Final byte
                    if is_kbd && b == b'u' {
                        write_all_raw(fd, &data[start..=i]);
                    }
                    st = 0;
                }
                // else: still in params
            }
            _ => st = 0,
        }
    }
}

/// Check whether raw output ends at the ground state of the VT
/// escape parser.  If `false`, the buffer ends mid-sequence and
/// injecting our own escape codes would corrupt the child's
/// incomplete CSI/OSC/DCS.
fn ends_at_ground_state(data: &[u8]) -> bool {
    // 0 = ground, 1 = ESC, 2 = CSI params, 3 = string (OSC/DCS)
    let mut st: u8 = 0;
    for &b in data {
        st = match st {
            0 => {
                if b == 0x1b {
                    1
                } else {
                    0
                }
            }
            1 => match b {
                b'[' => 2,
                b']' | b'P' | b'X' | b'^' | b'_' => 3,
                0x20..=0x2f => 1, // intermediates
                _ => 0,           // single-char escape done
            },
            2 => {
                if (0x40..=0x7e).contains(&b) {
                    0 // CSI final byte
                } else {
                    2 // params / intermediates
                }
            }
            3 => {
                if b == 0x07 {
                    0 // BEL terminates OSC
                } else if b == 0x1b {
                    1 // possible ST (ESC \)
                } else {
                    3
                }
            }
            _ => 0,
        };
    }
    st == 0
}

/// Write all bytes to a raw fd using libc::write (works in all
/// contexts including pre_exec).
fn write_all_raw(fd: i32, data: &[u8]) {
    let mut off = 0;
    while off < data.len() {
        let n = unsafe {
            nix::libc::write(
                fd,
                data[off..].as_ptr() as *const nix::libc::c_void,
                data.len() - off,
            )
        };
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
}

/// Run the command through a PTY proxy with virtual terminal.
/// Creates PTY pair, enters raw mode, spawns child with PTY slave
/// as stdio, runs IO loop with hybrid rendering, waits for
/// child, restores terminal. Returns exit code.
pub fn run(cmd: &mut std::process::Command) -> Result<i32, String> {
    use std::os::unix::process::CommandExt;

    let (rows, cols) = real_term_size().unwrap_or((24, 80));
    if rows < 2 {
        return Err("Terminal too small for status bar".into());
    }

    // Create PTY pair
    let pty =
        nix::pty::openpty(None, None).map_err(|e| format!("openpty: {e}"))?;
    let master = pty.master;
    let slave = pty.slave;

    // Set FD_CLOEXEC on master so child doesn't inherit it
    let master_raw = master.as_raw_fd();
    unsafe {
        let flags = nix::libc::fcntl(master_raw, nix::libc::F_GETFD);
        nix::libc::fcntl(
            master_raw,
            nix::libc::F_SETFD,
            flags | nix::libc::FD_CLOEXEC,
        );
    }

    // Set initial PTY size (rows-1 for status bar)
    set_initial_size(&master, rows - 1, cols);

    // Enter raw mode on real stdin
    let saved = enter_raw_mode()?;
    let raw_mode_guard = RawModeGuard::new(saved);

    // Configure child to use PTY slave as stdin/stdout/stderr
    let slave_raw = slave.as_raw_fd();
    unsafe {
        cmd.pre_exec(move || {
            if nix::libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if nix::libc::ioctl(
                slave_raw,
                nix::libc::TIOCSCTTY as nix::libc::c_ulong,
                0,
            ) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            nix::libc::dup2(slave_raw, 0);
            nix::libc::dup2(slave_raw, 1);
            nix::libc::dup2(slave_raw, 2);
            if slave_raw > 2 {
                nix::libc::close(slave_raw);
            }
            Ok(())
        });
    }

    // Spawn child
    let child = cmd
        .spawn()
        .map_err(|e| format!("Failed to start sandbox: {e}"))?;

    let pid = child.id() as i32;
    crate::signals::set_child_pid(pid);
    MASTER_FD.store(master_raw, Ordering::SeqCst);

    // Close slave in parent — child has its own copy
    drop(slave);

    // Run IO loop (blocks until child exits / master HUP)
    io_loop(&master, rows, cols);

    // Clean up
    MASTER_FD.store(-1, Ordering::SeqCst);
    drop(master);
    drop(raw_mode_guard);

    // Wait for child
    let exit_code = crate::signals::wait_child(pid);

    // Prevent double-wait
    std::mem::forget(child);

    Ok(exit_code)
}

fn real_term_size() -> Option<(u16, u16)> {
    let mut ws = unsafe { std::mem::zeroed::<nix::libc::winsize>() };
    let ret = unsafe {
        nix::libc::ioctl(
            nix::libc::STDOUT_FILENO,
            nix::libc::TIOCGWINSZ,
            &mut ws,
        )
    };
    if ret == 0 && ws.ws_row > 0 && ws.ws_col > 0 {
        Some((ws.ws_row, ws.ws_col))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn vt100_screen_tracks_content() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"Hello, world!");
        let screen = parser.screen();
        let row = screen.rows(0, 80).next().unwrap();
        assert!(row.starts_with("Hello, world!"));
    }

    #[test]
    fn vt100_diff_produces_output() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        let prev = parser.screen().clone();
        parser.process(b"test output");
        let diff = parser.screen().contents_diff(&prev);
        assert!(!diff.is_empty());
    }

    #[test]
    fn vt100_resize_preserves_content() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"line1\r\nline2\r\nline3");
        parser.screen_mut().set_size(30, 100);
        let screen = parser.screen();
        let row0 = screen.rows(0, 100).next().unwrap();
        assert!(row0.starts_with("line1"));
    }

    #[test]
    fn vt100_state_diff_includes_mode_changes() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        let prev = parser.screen().clone();
        // Enable bracketed paste mode
        parser.process(b"\x1b[?2004h");
        let diff = parser.screen().state_diff(&prev);
        // state_diff includes both content and mode changes
        assert!(parser.screen().bracketed_paste());
        assert!(!prev.bracketed_paste());
        // Diff should contain the mode change sequence
        assert!(!diff.is_empty());
    }

    #[test]
    fn vt100_alt_screen_tracking() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        assert!(!parser.screen().alternate_screen());
        parser.process(b"\x1b[?1049h");
        assert!(parser.screen().alternate_screen());
        parser.process(b"\x1b[?1049l");
        assert!(!parser.screen().alternate_screen());
    }

    #[test]
    fn vt100_mouse_mode_tracking() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        assert_eq!(
            parser.screen().mouse_protocol_mode(),
            vt100::MouseProtocolMode::None
        );
        parser.process(b"\x1b[?1003h");
        assert_eq!(
            parser.screen().mouse_protocol_mode(),
            vt100::MouseProtocolMode::AnyMotion
        );
    }

    #[test]
    fn vt100_cursor_visibility() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        assert!(!parser.screen().hide_cursor());
        parser.process(b"\x1b[?25l");
        assert!(parser.screen().hide_cursor());
        parser.process(b"\x1b[?25h");
        assert!(!parser.screen().hide_cursor());
    }

    use super::ends_at_ground_state;
    use super::forward_keyboard_protocol;
    use std::os::unix::io::AsRawFd;

    fn capture_kbd_forward(data: &[u8]) -> Vec<u8> {
        let (r, w) = nix::unistd::pipe().unwrap();
        forward_keyboard_protocol(w.as_raw_fd(), data);
        drop(w);
        let mut out = vec![0u8; 256];
        let n = nix::unistd::read(r.as_raw_fd(), &mut out).unwrap_or(0);
        out.truncate(n);
        out
    }

    #[test]
    fn kbd_push_mode_forwarded() {
        // CSI > 1 u  — push keyboard mode flags=1
        let out = capture_kbd_forward(b"\x1b[>1u");
        assert_eq!(out, b"\x1b[>1u");
    }

    #[test]
    fn kbd_pop_mode_forwarded() {
        // CSI < u  — pop keyboard mode
        let out = capture_kbd_forward(b"\x1b[<u");
        assert_eq!(out, b"\x1b[<u");
    }

    #[test]
    fn kbd_query_mode_forwarded() {
        // CSI ? u  — query keyboard mode
        let out = capture_kbd_forward(b"\x1b[?u");
        assert_eq!(out, b"\x1b[?u");
    }

    #[test]
    fn kbd_mixed_with_other_csi() {
        // SGR + keyboard push + cursor move
        let data = b"\x1b[31m\x1b[>1u\x1b[H";
        let out = capture_kbd_forward(data);
        assert_eq!(out, b"\x1b[>1u");
    }

    #[test]
    fn kbd_no_false_positives() {
        // Regular CSI sequences should not be forwarded
        let out = capture_kbd_forward(b"\x1b[31m\x1b[H\x1b[J");
        assert!(out.is_empty());
    }

    #[test]
    fn kbd_plain_text_ignored() {
        let out = capture_kbd_forward(b"hello world");
        assert!(out.is_empty());
    }

    #[test]
    fn ground_state_plain_text() {
        assert!(ends_at_ground_state(b"hello world"));
    }

    #[test]
    fn ground_state_complete_csi() {
        // Complete SGR: \x1b[31m
        assert!(ends_at_ground_state(b"\x1b[31m"));
        // Complete 24-bit color
        assert!(ends_at_ground_state(b"\x1b[38;2;255;0;0mRed"));
    }

    #[test]
    fn ground_state_incomplete_csi() {
        // Ends mid-CSI (no final byte yet)
        assert!(!ends_at_ground_state(b"\x1b[38;2;255"));
        // Just ESC [
        assert!(!ends_at_ground_state(b"\x1b["));
        // Just ESC
        assert!(!ends_at_ground_state(b"\x1b"));
    }

    #[test]
    fn ground_state_text_then_incomplete() {
        assert!(!ends_at_ground_state(b"hello\x1b[31"));
    }

    #[test]
    fn ground_state_osc_complete() {
        // OSC terminated by BEL
        assert!(ends_at_ground_state(b"\x1b]0;title\x07"));
        // OSC terminated by ST (ESC \)
        assert!(ends_at_ground_state(b"\x1b]0;title\x1b\\"));
    }

    #[test]
    fn ground_state_osc_incomplete() {
        assert!(!ends_at_ground_state(b"\x1b]0;title"));
    }

    #[test]
    fn ground_state_empty() {
        assert!(ends_at_ground_state(b""));
    }

    #[test]
    fn ground_state_single_char_escape() {
        // ESC 7 (DECSC) is a complete single-char escape
        assert!(ends_at_ground_state(b"\x1b7"));
    }

    #[test]
    fn ground_state_scroll_region_reset() {
        // \x1b[r resets scroll margins — full CSI, ends at ground
        assert!(ends_at_ground_state(b"\x1b[r"));
        // Table border followed by scroll region reset
        assert!(ends_at_ground_state(
            b"\xe2\x94\x80\xe2\x94\x80\xe2\x94\x80\x1b[r"
        ));
    }

    #[test]
    fn ground_state_cup_sequence() {
        // CUP (\x1b[row;colH) used to restore cursor position
        // after set_scroll_region — complete CSI, ends at ground.
        assert!(ends_at_ground_state(b"\x1b[12;1H"));
        assert!(ends_at_ground_state(b"\x1b[1;80H"));
    }
}
