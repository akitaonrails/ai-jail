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

use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::termios::{self, SetArg, Termios};
use std::os::unix::io::{AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant};

/// Stored master raw FD for async-signal-safe resize from SIGWINCH.
static MASTER_FD: AtomicI32 = AtomicI32::new(-1);

/// Set by signal handler; IO loop clears screen + redraws status bar
/// BEFORE forwarding SIGWINCH to the child, preventing ghost bars.
static SIGWINCH_PENDING: AtomicBool = AtomicBool::new(false);
const RESIZE_REDRAW_DELAY: Duration = Duration::from_millis(75);

/// Mark a SIGWINCH as pending. Called from the signal handler.
pub fn set_sigwinch_pending() {
    SIGWINCH_PENDING.store(true, Ordering::SeqCst);
}

/// Read-and-clear the SIGWINCH pending flag. Test-only — production
/// callers do this implicitly via `SIGWINCH_PENDING.swap(false, ...)`
/// inside the IO loop's `handle_sigwinch` method.
#[cfg(test)]
pub(crate) fn take_sigwinch_pending_for_test() -> bool {
    SIGWINCH_PENDING.swap(false, Ordering::SeqCst)
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
    let seq = format!("\x1b[1;{content_rows}r");
    write_all_raw(fd, seq.as_bytes());
}

pub fn parse_resize_redraw_key(spec: &str) -> Result<Option<Vec<u8>>, String> {
    let normalized = spec
        .trim()
        .to_ascii_lowercase()
        .replace(['_', '+', ' '], "-");
    if normalized.is_empty()
        || matches!(normalized.as_str(), "off" | "none" | "disabled")
    {
        return Ok(None);
    }

    let parts: Vec<&str> =
        normalized.split('-').filter(|p| !p.is_empty()).collect();
    if parts.len() < 2 {
        return Err("expected values like ctrl-l or disabled".into());
    }

    let mut has_ctrl = false;
    let mut has_shift = false;
    let mut key = None;
    for part in parts {
        match part {
            "ctrl" | "control" => has_ctrl = true,
            "shift" => has_shift = true,
            k if k.len() == 1 && k.as_bytes()[0].is_ascii_alphabetic() => {
                key = Some(k.as_bytes()[0].to_ascii_uppercase());
            }
            other => {
                return Err(format!("unsupported modifier or key {other:?}"));
            }
        }
    }

    if !has_ctrl {
        return Err("only ctrl-based redraw keys are supported".into());
    }
    let Some(key) = key else {
        return Err("missing final letter key".into());
    };
    if has_shift {
        // Shift is accepted for config ergonomics, but terminals
        // collapse Ctrl+Shift+<letter> to the same control byte as
        // Ctrl+<letter>, so both spellings send the same sequence.
    }
    Ok(Some(vec![key & 0x1f]))
}

/// Mutable state shared across one run of the PTY IO loop.
///
/// Bundled into one struct so the per-section helpers can take a
/// single `&mut IoLoop<'_>` instead of half a dozen mutable refs.
struct IoLoop<'a> {
    parser: vt100::Parser,
    prev_screen: vt100::Screen,
    content_rows: u16,
    content_cols: u16,
    pending_redraw: bool,
    pending_resize_redraw_at: Option<Instant>,
    was_alt_screen: bool,
    /// Raw stdout fd. Owned by the process; we just use it for writes.
    stdout: i32,
    /// PTY master fd. Lifetime tied to the parent `pty::run` scope.
    master_raw: i32,
    /// Initial terminal size. Used as fallback when `real_term_size()`
    /// fails inside a SIGWINCH handler.
    init_rows: u16,
    init_cols: u16,
    /// Optional control sequence to inject after the child has had a
    /// chance to process SIGWINCH. None when disabled.
    resize_redraw_key: Option<&'a [u8]>,
}

impl<'a> IoLoop<'a> {
    fn new(
        master_raw: i32,
        init_rows: u16,
        init_cols: u16,
        resize_redraw_key: Option<&'a [u8]>,
    ) -> Self {
        let content_rows = init_rows - 1;
        let content_cols = init_cols;
        let parser = vt100::Parser::new(content_rows, content_cols, 0);
        let prev_screen = parser.screen().clone();
        Self {
            parser,
            prev_screen,
            content_rows,
            content_cols,
            pending_redraw: false,
            pending_resize_redraw_at: None,
            was_alt_screen: false,
            stdout: nix::libc::STDOUT_FILENO,
            master_raw,
            init_rows,
            init_cols,
            resize_redraw_key,
        }
    }

    /// Push existing terminal content into scrollback, clear the
    /// visible area, and set the scroll region so the status bar
    /// row stays untouched by child output.
    fn prime_terminal(&self) {
        let pos = format!("\x1b[{};1H", self.init_rows);
        write_all_raw(self.stdout, pos.as_bytes());
        for _ in 0..self.content_rows {
            write_all_raw(self.stdout, b"\n");
        }
        write_all_raw(self.stdout, b"\x1b[H\x1b[J");
        set_scroll_region(self.stdout, self.content_rows);
    }

    /// Drain a pending SIGWINCH: resize vt100 first, repaint the
    /// real terminal, then resize the PTY and forward SIGWINCH to
    /// the child. Doing it in this order avoids a ghost status-bar
    /// row when the user maximises and avoids a blank flash on the
    /// primary screen.
    fn handle_sigwinch(&mut self) {
        if !SIGWINCH_PENDING.swap(false, Ordering::SeqCst) {
            return;
        }
        let (rows, cols) =
            real_term_size().unwrap_or((self.init_rows, self.init_cols));
        if rows < 2 {
            return;
        }
        let old_content_rows = self.content_rows;
        self.content_rows = rows - 1;
        self.content_cols = cols;
        self.parser
            .screen_mut()
            .set_size(self.content_rows, self.content_cols);

        let screen = self.parser.screen();
        let on_alt = screen.alternate_screen();
        if on_alt {
            // Alt screen: full clear + repaint from vt100 so
            // prev_screen matches the real terminal for subsequent
            // state_diff rendering.
            write_all_raw(self.stdout, b"\x1b[r\x1b[H\x1b[J");
            let output = screen.state_formatted();
            write_all_raw(self.stdout, &output);
        } else {
            // Primary screen: preserve visible content (avoid a blank
            // flash on maximize). Reset the scroll region and clean up
            // the old status-bar ghost row, then let the child repaint
            // on its own after SIGWINCH.
            write_all_raw(self.stdout, b"\x1b[r");
            if old_content_rows < self.content_rows {
                let seq = format!("\x1b[{};1H\x1b[2K", old_content_rows + 1);
                write_all_raw(self.stdout, seq.as_bytes());
            }
            set_scroll_region(self.stdout, self.content_rows);
            let (row, col) = screen.cursor_position();
            let seq = format!("\x1b[{};{}H", row + 1, col + 1);
            write_all_raw(self.stdout, seq.as_bytes());
        }

        self.prev_screen = screen.clone();
        self.was_alt_screen = on_alt;
        crate::statusbar::update_terminal_state(screen);
        crate::statusbar::redraw();
        resize_pty();
        forward_sigwinch();
        if !on_alt && self.resize_redraw_key.is_some() {
            // Let the child process SIGWINCH first, then nudge it to
            // repaint once the terminal goes quiet.
            self.pending_resize_redraw_at =
                Some(Instant::now() + RESIZE_REDRAW_DELAY);
        }
        let _ = crate::statusbar::take_requests();
        self.pending_redraw = false;
    }

    /// One read from the PTY master: hybrid rendering depending on
    /// alt-screen state and screen transitions. Returns
    /// `ControlFlow::Break(())` when the loop should exit (child
    /// closed the PTY).
    fn handle_master_read(&mut self, buf: &[u8]) -> std::ops::ControlFlow<()> {
        self.parser.process(buf);
        let screen = self.parser.screen();
        let now_alt = screen.alternate_screen();

        // Forward kitty keyboard protocol sequences that vt100
        // silently drops. Only needed on alt screen paths — the
        // primary screen uses raw pass-through anyway.
        if now_alt || now_alt != self.was_alt_screen {
            forward_keyboard_protocol(self.stdout, buf);
        }

        if now_alt != self.was_alt_screen {
            // Alt screen transition: full re-render.
            if now_alt {
                write_all_raw(self.stdout, b"\x1b[r");
            } else {
                set_scroll_region(self.stdout, self.content_rows);
            }
            write_all_raw(self.stdout, b"\x1b[H\x1b[J");
            let output = screen.state_formatted();
            write_all_raw(self.stdout, &output);
            self.was_alt_screen = now_alt;
        } else if now_alt {
            // Alt screen: cursor-addressed diff.
            let diff = screen.state_diff(&self.prev_screen);
            write_all_raw(self.stdout, &diff);
        } else {
            // Primary screen: raw pass-through for natural scrollback.
            write_all_raw(self.stdout, buf);
            // Re-establish scroll region in case child output contained
            // a reset. Only inject when the output ends at ground state
            // — otherwise our escapes corrupt an in-progress CSI/OSC.
            // DECSTBM (\x1b[1;Nr) moves the cursor home as a side
            // effect; restore via absolute CUP, NOT DECSC/DECRC (which
            // on macOS also save/restore scroll margins and would undo
            // the repair).
            if ends_at_ground_state(buf) {
                let (row, col) = self.parser.screen().cursor_position();
                set_scroll_region(self.stdout, self.content_rows);
                let seq = format!("\x1b[{};{}H", row + 1, col + 1);
                write_all_raw(self.stdout, seq.as_bytes());
            }
        }

        self.prev_screen = screen.clone();
        crate::statusbar::update_terminal_state(screen);
        self.pending_redraw = true;
        if self.resize_redraw_key.is_some()
            && self.pending_resize_redraw_at.is_some()
        {
            // Child is still talking — push the redraw-key injection
            // out so we don't fire while the screen is actively
            // changing.
            self.pending_resize_redraw_at =
                Some(Instant::now() + RESIZE_REDRAW_DELAY);
        }
        std::ops::ControlFlow::Continue(())
    }

    /// Drain any remaining bytes on POLLHUP/POLLERR, render the final
    /// state, and reset the scroll region. The loop exits after this.
    fn drain_on_hup(&mut self, buf: &mut [u8]) {
        loop {
            match nix::unistd::read(self.master_raw, buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    self.parser.process(&buf[..n]);
                }
            }
        }
        let screen = self.parser.screen();
        let diff = screen.state_diff(&self.prev_screen);
        write_all_raw(self.stdout, &diff);
        write_all_raw(self.stdout, b"\x1b[r");
        crate::statusbar::redraw();
    }

    /// Status bar / pending redraw-key flush, run when the child is
    /// quiet (no POLLIN on master).
    fn flush_when_idle(&mut self) {
        if self.pending_redraw {
            crate::statusbar::redraw();
            self.pending_redraw = false;
        }
        self.maybe_inject_resize_key();
    }

    /// Fire the pending resize-redraw key if its deadline has passed.
    fn maybe_inject_resize_key(&mut self) {
        if let Some(deadline) = self.pending_resize_redraw_at
            && Instant::now() >= deadline
        {
            if let Some(key) = self.resize_redraw_key {
                write_all_raw(self.master_raw, key);
            }
            self.pending_resize_redraw_at = None;
        }
    }
}

fn io_loop(
    master: &OwnedFd,
    init_rows: u16,
    init_cols: u16,
    resize_redraw_key: Option<&[u8]>,
) {
    let stdin_fd = std::io::stdin().as_raw_fd();
    let master_raw = master.as_raw_fd();
    let stdin_bfd = unsafe { BorrowedFd::borrow_raw(stdin_fd) };
    let master_bfd = unsafe { BorrowedFd::borrow_raw(master_raw) };
    let mut buf = [0u8; 8192];

    let mut state =
        IoLoop::new(master_raw, init_rows, init_cols, resize_redraw_key);
    crate::statusbar::update_terminal_state(state.parser.screen());
    state.prime_terminal();

    loop {
        state.handle_sigwinch();

        let mut fds = [
            PollFd::new(stdin_bfd, PollFlags::POLLIN),
            PollFd::new(master_bfd, PollFlags::POLLIN),
        ];
        if crate::statusbar::take_requests() {
            state.pending_redraw = true;
        }

        match poll(&mut fds, PollTimeout::from(100_u16)) {
            Ok(0) => {
                state.flush_when_idle();
                continue;
            }
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => break,
            Ok(_) => {}
        }

        // Check master (child output) first for responsiveness.
        let mut should_break = false;
        if let Some(revents) = fds[1].revents() {
            if revents.contains(PollFlags::POLLIN) {
                match nix::unistd::read(master_raw, &mut buf) {
                    Ok(0) => {
                        should_break = true;
                    }
                    Ok(n) => {
                        let _ = state.handle_master_read(&buf[..n]);
                    }
                    Err(nix::errno::Errno::EINTR) => {}
                    Err(nix::errno::Errno::EIO) => should_break = true,
                    Err(_) => should_break = true,
                }
            }
            if !should_break
                && (revents.contains(PollFlags::POLLHUP)
                    || revents.contains(PollFlags::POLLERR))
            {
                state.drain_on_hup(&mut buf);
                should_break = true;
            }
        }
        if should_break {
            break;
        }

        // Status bar / resize-key flush when child is quiet.
        let child_quiet = !matches!(
            fds[1].revents(),
            Some(r) if r.contains(PollFlags::POLLIN)
        );
        if child_quiet {
            state.flush_when_idle();
        }

        // stdin (user input) → PTY master.
        if let Some(revents) = fds[0].revents()
            && revents.contains(PollFlags::POLLIN)
        {
            match nix::unistd::read(stdin_fd, &mut buf) {
                Ok(0) => break,
                Ok(n) => write_all_raw(master_raw, &buf[..n]),
                Err(nix::errno::Errno::EINTR) => {}
                Err(_) => break,
            }
        }
    }

    // Defensive terminal-mode reset (issue #40). The raw-mode guard
    // restores termios separately on Drop.
    crate::output::terminal_reset();
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
        st = match (st, b) {
            (0, 0x1b) => 1,
            (0, _) => 0,
            (1, b'[') => 2,
            (1, b']' | b'P' | b'X' | b'^' | b'_') => 3,
            (1, 0x20..=0x2f) => 1, // intermediates
            (1, _) => 0,           // single-char escape done
            (2, 0x40..=0x7e) => 0, // CSI final byte
            (2, _) => 2,           // params / intermediates
            (3, 0x07) => 0,        // BEL terminates OSC
            (3, 0x1b) => 1,        // possible ST (ESC \)
            (3, _) => 3,
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
                data[off..].as_ptr().cast::<nix::libc::c_void>(),
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
pub fn run(
    cmd: &mut std::process::Command,
    resize_redraw_key: Option<&[u8]>,
) -> Result<i32, String> {
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
    io_loop(&master, rows, cols, resize_redraw_key);

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
    fn vt100_primary_screen_repaint_after_resize_contains_content() {
        let mut parser = vt100::Parser::new(4, 20, 0);
        parser.process(b"line1\r\nline2\r\nline3");
        parser.screen_mut().set_size(6, 30);

        let output = parser.screen().state_formatted();

        assert!(!parser.screen().alternate_screen());
        assert!(!output.is_empty());
        assert!(String::from_utf8_lossy(&output).contains("line1"));
        assert!(String::from_utf8_lossy(&output).contains("line2"));
    }

    #[test]
    fn parse_resize_redraw_key_ctrl_l() {
        assert_eq!(
            super::parse_resize_redraw_key("ctrl-l").unwrap(),
            Some(vec![0x0c])
        );
    }

    #[test]
    fn parse_resize_redraw_key_ctrl_shift_l_aliases_ctrl_l() {
        assert_eq!(
            super::parse_resize_redraw_key("ctrl-shift-l").unwrap(),
            Some(vec![0x0c])
        );
    }

    #[test]
    fn parse_resize_redraw_key_disabled() {
        assert_eq!(super::parse_resize_redraw_key("disabled").unwrap(), None);
    }

    #[test]
    fn parse_resize_redraw_key_rejects_unknown() {
        assert!(super::parse_resize_redraw_key("alt-l").is_err());
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
