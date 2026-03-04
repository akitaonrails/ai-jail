//! PTY proxy for persistent status bar.
//!
//! When the status bar is enabled, ai-jail interposes a PTY between
//! itself and the sandbox child. The child writes to the PTY slave
//! while ai-jail owns the real terminal, allowing the status bar to
//! persist regardless of what the child does (clear, reset, vim, etc).
//!
//! All bytes are forwarded verbatim. The only post-processing is
//! detecting sequences that reset the scroll region (alt screen
//! switches, RIS, bare DECSTBM reset) and re-asserting the status
//! bar afterward.

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::termios::{self, SetArg, Termios};
use std::os::unix::io::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicI32, Ordering};

/// Stored master raw FD for async-signal-safe resize from SIGWINCH.
static MASTER_FD: AtomicI32 = AtomicI32::new(-1);

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

/// Forward SIGWINCH to the PTY foreground process group.
/// Returns true if forwarding was attempted.
pub fn forward_sigwinch() -> bool {
    let master = MASTER_FD.load(Ordering::SeqCst);
    if master < 0 {
        return false;
    }

    let mut pgrp: nix::libc::pid_t = 0;
    let ret =
        unsafe { nix::libc::ioctl(master, nix::libc::TIOCGPGRP, &mut pgrp) };
    if ret != 0 || pgrp <= 0 {
        return false;
    }

    unsafe {
        nix::libc::kill(-pgrp, nix::libc::SIGWINCH);
    }
    true
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ResetEvent {
    None,
    Redraw,
    RedrawAndClamp,
}

impl ResetEvent {
    fn merge(self, other: Self) -> Self {
        match (self, other) {
            (ResetEvent::RedrawAndClamp, _)
            | (_, ResetEvent::RedrawAndClamp) => ResetEvent::RedrawAndClamp,
            (ResetEvent::Redraw, _) | (_, ResetEvent::Redraw) => {
                ResetEvent::Redraw
            }
            _ => ResetEvent::None,
        }
    }
}

#[derive(Clone, Copy)]
enum ResetScanState {
    Normal,
    Esc,
    Csi,
    CsiInter,
}

/// Incremental scanner for sequences that reset scroll region state.
struct ResetDetector {
    state: ResetScanState,
    params: [u8; 64],
    params_len: usize,
    params_overflow: bool,
}

impl ResetDetector {
    fn new() -> Self {
        Self {
            state: ResetScanState::Normal,
            params: [0u8; 64],
            params_len: 0,
            params_overflow: false,
        }
    }

    fn push_param(&mut self, b: u8) {
        if self.params_len < self.params.len() {
            self.params[self.params_len] = b;
            self.params_len += 1;
        } else {
            self.params_overflow = true;
        }
    }

    fn finish_csi(&self, fin: u8) -> ResetEvent {
        if self.params_overflow {
            return ResetEvent::None;
        }
        let params = &self.params[..self.params_len];

        // Bare DECSTBM reset: \x1b[r or \x1b[;r
        if fin == b'r' && (params.is_empty() || params == b";") {
            return ResetEvent::RedrawAndClamp;
        }

        // Alt-screen modes:
        //   ...h = enter alt-screen (needs redraw)
        //   ...l = leave alt-screen (needs redraw + clamp cursor)
        if (fin == b'h' || fin == b'l') && params.first() == Some(&b'?') {
            let mut found = false;
            for part in params[1..].split(|&b| b == b';') {
                if part == b"1049" || part == b"47" || part == b"1047" {
                    found = true;
                    break;
                }
            }
            if found {
                return if fin == b'l' {
                    ResetEvent::RedrawAndClamp
                } else {
                    ResetEvent::Redraw
                };
            }
        }

        ResetEvent::None
    }

    /// Scan output bytes and report whether we should redraw/reclamp.
    fn scan(&mut self, data: &[u8]) -> ResetEvent {
        let mut ev = ResetEvent::None;
        for &b in data {
            match self.state {
                ResetScanState::Normal => {
                    if b == 0x1b {
                        self.state = ResetScanState::Esc;
                    }
                }
                ResetScanState::Esc => match b {
                    b'c' => {
                        ev = ev.merge(ResetEvent::RedrawAndClamp);
                        self.state = ResetScanState::Normal;
                    }
                    b'[' => {
                        self.state = ResetScanState::Csi;
                        self.params_len = 0;
                        self.params_overflow = false;
                    }
                    0x20..=0x2f => {}
                    0x1b => {}
                    _ => {
                        self.state = ResetScanState::Normal;
                    }
                },
                ResetScanState::Csi => match b {
                    0x30..=0x3f => self.push_param(b),
                    0x20..=0x2f => self.state = ResetScanState::CsiInter,
                    0x40..=0x7e => {
                        ev = ev.merge(self.finish_csi(b));
                        self.state = ResetScanState::Normal;
                    }
                    0x1b => self.state = ResetScanState::Esc,
                    _ => self.state = ResetScanState::Normal,
                },
                ResetScanState::CsiInter => match b {
                    0x20..=0x2f => {}
                    0x40..=0x7e => {
                        ev = ev.merge(self.finish_csi(b));
                        self.state = ResetScanState::Normal;
                    }
                    0x1b => self.state = ResetScanState::Esc,
                    _ => self.state = ResetScanState::Normal,
                },
            }
        }
        ev
    }
}

#[cfg(test)]
fn contains_scroll_reset(data: &[u8]) -> bool {
    let mut detector = ResetDetector::new();
    !matches!(detector.scan(data), ResetEvent::None)
}

#[derive(Clone, Copy)]
enum ControlState {
    Normal,
    Esc,
    Csi,
    Osc,
    OscEsc,
    Dcs,
    DcsEsc,
    Apc,
    ApcEsc,
    Pm,
    PmEsc,
    Sos,
    SosEsc,
}

/// Tracks whether it is safe to inject status-bar control bytes:
/// only when we're at a control-sequence boundary and not mid UTF-8.
struct StreamState {
    ctl: ControlState,
    utf8_cont: u8,
}

impl StreamState {
    fn new() -> Self {
        Self {
            ctl: ControlState::Normal,
            utf8_cont: 0,
        }
    }

    fn can_inject(&self) -> bool {
        matches!(self.ctl, ControlState::Normal) && self.utf8_cont == 0
    }

    fn update_utf8(&mut self, b: u8) {
        if self.utf8_cont > 0 {
            if (0x80..=0xbf).contains(&b) {
                self.utf8_cont -= 1;
                return;
            }
            self.utf8_cont = 0;
        }
        self.utf8_cont = match b {
            0xc2..=0xdf => 1,
            0xe0..=0xef => 2,
            0xf0..=0xf4 => 3,
            _ => 0,
        };
    }

    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.ctl = match self.ctl {
                ControlState::Normal => {
                    if b == 0x1b {
                        ControlState::Esc
                    } else {
                        self.update_utf8(b);
                        ControlState::Normal
                    }
                }
                ControlState::Esc => match b {
                    b'[' => ControlState::Csi,
                    b']' => ControlState::Osc,
                    b'P' => ControlState::Dcs,
                    b'_' => ControlState::Apc,
                    b'^' => ControlState::Pm,
                    b'X' => ControlState::Sos,
                    0x20..=0x2f => ControlState::Esc,
                    0x1b => ControlState::Esc,
                    _ => ControlState::Normal,
                },
                ControlState::Csi => match b {
                    0x20..=0x3f => ControlState::Csi,
                    0x1b => ControlState::Esc,
                    _ => ControlState::Normal,
                },
                // OSC: BEL or ST (ESC \)
                ControlState::Osc => match b {
                    0x07 => ControlState::Normal,
                    0x1b => ControlState::OscEsc,
                    _ => ControlState::Osc,
                },
                ControlState::OscEsc => {
                    if b == b'\\' {
                        ControlState::Normal
                    } else {
                        ControlState::Osc
                    }
                }
                // DCS/APC/PM/SOS: ST (ESC \)
                ControlState::Dcs => {
                    if b == 0x1b {
                        ControlState::DcsEsc
                    } else {
                        ControlState::Dcs
                    }
                }
                ControlState::DcsEsc => {
                    if b == b'\\' {
                        ControlState::Normal
                    } else {
                        ControlState::Dcs
                    }
                }
                ControlState::Apc => {
                    if b == 0x1b {
                        ControlState::ApcEsc
                    } else {
                        ControlState::Apc
                    }
                }
                ControlState::ApcEsc => {
                    if b == b'\\' {
                        ControlState::Normal
                    } else {
                        ControlState::Apc
                    }
                }
                ControlState::Pm => {
                    if b == 0x1b {
                        ControlState::PmEsc
                    } else {
                        ControlState::Pm
                    }
                }
                ControlState::PmEsc => {
                    if b == b'\\' {
                        ControlState::Normal
                    } else {
                        ControlState::Pm
                    }
                }
                ControlState::Sos => {
                    if b == 0x1b {
                        ControlState::SosEsc
                    } else {
                        ControlState::Sos
                    }
                }
                ControlState::SosEsc => {
                    if b == b'\\' {
                        ControlState::Normal
                    } else {
                        ControlState::Sos
                    }
                }
            };
        }
    }
}

fn flush_statusbar_if_safe(
    stream: &StreamState,
    pending_redraw: &mut bool,
    pending_clamp: &mut bool,
) {
    if !*pending_redraw || !stream.can_inject() {
        return;
    }
    crate::statusbar::redraw();
    if *pending_clamp {
        crate::statusbar::clamp_cursor();
        *pending_clamp = false;
    }
    *pending_redraw = false;
}

fn io_loop(master: &OwnedFd) {
    let stdin_fd = std::io::stdin().as_raw_fd();
    let master_raw = master.as_raw_fd();
    let stdin_bfd = unsafe { BorrowedFd::borrow_raw(stdin_fd) };
    let master_bfd = unsafe { BorrowedFd::borrow_raw(master_raw) };
    let mut buf = [0u8; 8192];
    let mut stream = StreamState::new();
    let mut reset = ResetDetector::new();
    let mut pending_redraw = false;
    let mut pending_clamp = false;

    loop {
        let mut fds = [
            PollFd::new(stdin_bfd, PollFlags::POLLIN),
            PollFd::new(master_bfd, PollFlags::POLLIN),
        ];

        let (req_redraw, req_clamp) = crate::statusbar::take_requests();
        if req_redraw {
            pending_redraw = true;
        }
        if req_clamp {
            pending_clamp = true;
            pending_redraw = true;
        }

        match poll(&mut fds, PollTimeout::from(100_u16)) {
            Ok(0) => {
                // Timeout: if a redraw is pending, force it
                // regardless of stream state. After 100ms of
                // silence any partial escape sequence is stale.
                if pending_redraw {
                    stream = StreamState::new();
                    crate::statusbar::redraw();
                    if pending_clamp {
                        crate::statusbar::clamp_cursor();
                        pending_clamp = false;
                    }
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
                        write_all_raw(nix::libc::STDOUT_FILENO, &buf[..n]);
                        if matches!(
                            reset.scan(&buf[..n]),
                            ResetEvent::RedrawAndClamp
                        ) {
                            pending_clamp = true;
                        }
                        stream.update(&buf[..n]);
                        // Any child output may have overwritten
                        // the status bar row; always refresh once
                        // the child goes quiet.
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
                            write_all_raw(nix::libc::STDOUT_FILENO, &buf[..n]);
                            if matches!(
                                reset.scan(&buf[..n]),
                                ResetEvent::RedrawAndClamp
                            ) {
                                pending_clamp = true;
                            }
                            stream.update(&buf[..n]);
                            pending_redraw = true;
                        }
                    }
                }
                flush_statusbar_if_safe(
                    &stream,
                    &mut pending_redraw,
                    &mut pending_clamp,
                );
                break;
            }
        }

        // If child is currently quiet and we're at a safe stream boundary,
        // apply any pending redraw now.
        if !matches!(fds[1].revents(), Some(r) if r.contains(PollFlags::POLLIN))
        {
            flush_statusbar_if_safe(
                &stream,
                &mut pending_redraw,
                &mut pending_clamp,
            );
        }

        // Check stdin (user input)
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

/// Run the command through a PTY proxy. Creates PTY pair, enters
/// raw mode, spawns child with PTY slave as stdio, runs IO loop,
/// waits for child, restores terminal. Returns exit code.
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
    io_loop(&master);

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
    use super::*;

    #[test]
    fn detect_bare_decstbm_reset() {
        assert!(contains_scroll_reset(b"\x1b[r"));
    }

    #[test]
    fn detect_semicolon_decstbm_reset() {
        assert!(contains_scroll_reset(b"\x1b[;r"));
    }

    #[test]
    fn ignore_parameterized_decstbm() {
        assert!(!contains_scroll_reset(b"\x1b[1;24r"));
    }

    #[test]
    fn detect_ris() {
        assert!(contains_scroll_reset(b"\x1bc"));
    }

    #[test]
    fn detect_alt_screen_1049h() {
        assert!(contains_scroll_reset(b"\x1b[?1049h"));
    }

    #[test]
    fn detect_alt_screen_1049l() {
        assert!(contains_scroll_reset(b"\x1b[?1049l"));
    }

    #[test]
    fn detect_alt_screen_47h() {
        assert!(contains_scroll_reset(b"\x1b[?47h"));
    }

    #[test]
    fn detect_alt_screen_1047l() {
        assert!(contains_scroll_reset(b"\x1b[?1047l"));
    }

    #[test]
    fn ignore_show_cursor() {
        assert!(!contains_scroll_reset(b"\x1b[?25h"));
    }

    #[test]
    fn ignore_sgr_color() {
        assert!(!contains_scroll_reset(b"\x1b[38;2;255;100;0m"));
    }

    #[test]
    fn ignore_clear_screen() {
        assert!(!contains_scroll_reset(b"\x1b[2J"));
    }

    #[test]
    fn detect_embedded_in_output() {
        let data = b"hello\x1b[?1049hworld";
        assert!(contains_scroll_reset(data));
    }

    #[test]
    fn no_false_positive_plain_text() {
        assert!(!contains_scroll_reset(b"just plain text\n"));
    }

    #[test]
    fn detect_alt_screen_combined_modes() {
        // Some programs set multiple modes at once
        assert!(contains_scroll_reset(b"\x1b[?1049;2004h"));
    }

    #[test]
    fn detect_split_alt_screen_exit_across_chunks() {
        let mut detector = ResetDetector::new();
        assert!(matches!(detector.scan(b"\x1b[?1049"), ResetEvent::None));
        assert!(matches!(detector.scan(b"l"), ResetEvent::RedrawAndClamp));
    }

    #[test]
    fn stream_state_blocks_mid_utf8() {
        let mut s = StreamState::new();
        s.update(&[0xe2]); // start of 3-byte sequence
        assert!(!s.can_inject());
        s.update(&[0x94, 0x80]); // finish "─"
        assert!(s.can_inject());
    }

    #[test]
    fn stream_state_blocks_inside_dcs_until_st() {
        let mut s = StreamState::new();
        s.update(b"\x1bP");
        assert!(!s.can_inject());
        s.update(b"abc");
        assert!(!s.can_inject());
        s.update(b"\x1b\\");
        assert!(s.can_inject());
    }

    #[test]
    fn stream_state_blocks_inside_osc_until_bel() {
        let mut s = StreamState::new();
        s.update(b"\x1b]0;title");
        assert!(!s.can_inject());
        s.update(&[0x07]);
        assert!(s.can_inject());
    }
}
