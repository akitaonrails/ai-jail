use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// When set, suppress info/warn/verbose output (--exec mode).
static QUIET: AtomicBool = AtomicBool::new(false);

pub fn set_quiet(q: bool) {
    QUIET.store(q, Ordering::SeqCst);
}

pub fn is_quiet() -> bool {
    QUIET.load(Ordering::SeqCst)
}

fn is_tty() -> bool {
    io::stderr().is_terminal()
}

const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const GREEN: &str = "\x1b[32m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const CYAN: &str = "\x1b[36m";
const DIM: &str = "\x1b[2m";

pub fn info(msg: &str) {
    if QUIET.load(Ordering::SeqCst) {
        return;
    }
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{GREEN}▸{RESET} {msg}");
    } else {
        let _ = writeln!(out, "▸ {msg}");
    }
}

pub fn warn(msg: &str) {
    if QUIET.load(Ordering::SeqCst) {
        return;
    }
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{YELLOW}⚠{RESET} {msg}");
    } else {
        let _ = writeln!(out, "⚠ {msg}");
    }
}

pub fn error(msg: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{RED}✗{RESET} {msg}");
    } else {
        let _ = writeln!(out, "✗ {msg}");
    }
}

pub fn ok(msg: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{GREEN}✓{RESET} {msg}");
    } else {
        let _ = writeln!(out, "✓ {msg}");
    }
}

pub fn verbose(msg: &str) {
    if QUIET.load(Ordering::SeqCst) {
        return;
    }
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{DIM}  {msg}{RESET}");
    } else {
        let _ = writeln!(out, "  {msg}");
    }
}

pub fn status_header(label: &str, value: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{CYAN}{label}{RESET}: {value}");
    } else {
        let _ = writeln!(out, "{label}: {value}");
    }
}

pub fn dry_run_line(line: &str) {
    let out = io::stdout();
    let mut out = out.lock();
    let _ = writeln!(out, "{line}");
}

/// Defensive terminal-mode reset emitted after the sandbox child
/// exits. Children that crash or fail to clean up can leave the real
/// terminal in an unusable state (mouse-tracking on, bracketed paste
/// on, alt-screen retained, kitty kbd protocol pushed, etc.) — the
/// symptom is "mouse movement produces random characters" and
/// "previous escape sequences keep replaying" (see issue #40).
///
/// The sequence takes the terminal back to a sane state without
/// clearing the screen or scrollback.
const TERMINAL_RESET_SEQ: &str = concat!(
    // Exit alt-screen (no-op if not on it; also restores main).
    "\x1b[?1049l",
    // Disable bracketed paste.
    "\x1b[?2004l",
    // Disable mouse tracking modes (X10, highlight, cell, all-motion,
    // focus, UTF-8, SGR, urxvt).
    "\x1b[?1000l\x1b[?1001l\x1b[?1002l\x1b[?1003l\x1b[?1004l",
    "\x1b[?1005l\x1b[?1006l\x1b[?1015l",
    // Pop kitty keyboard protocol (no-op if not pushed).
    "\x1b[<u",
    // Make the cursor visible again.
    "\x1b[?25h",
    // Reset SGR (colors/attrs).
    "\x1b[0m",
    // Reset scroll region.
    "\x1b[r",
);

/// Write the terminal reset sequence to stdout. No-op when stdout
/// isn't a TTY (output is being captured/redirected) or in `--exec`
/// quiet mode.
pub fn terminal_reset() {
    if QUIET.load(Ordering::SeqCst) {
        return;
    }
    if !io::stdout().is_terminal() {
        return;
    }
    let mut out = io::stdout();
    let _ = out.write_all(TERMINAL_RESET_SEQ.as_bytes());
    let _ = out.flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_reset_seq_covers_mouse_modes() {
        for mode in ["?1000", "?1002", "?1003", "?1006"] {
            assert!(
                TERMINAL_RESET_SEQ.contains(&format!("\x1b[{mode}l")),
                "reset sequence should disable mouse mode {mode}"
            );
        }
    }

    #[test]
    fn terminal_reset_seq_disables_bracketed_paste() {
        assert!(TERMINAL_RESET_SEQ.contains("\x1b[?2004l"));
    }

    #[test]
    fn terminal_reset_seq_exits_alt_screen() {
        assert!(TERMINAL_RESET_SEQ.contains("\x1b[?1049l"));
    }

    #[test]
    fn terminal_reset_seq_pops_kitty_kbd_protocol() {
        assert!(TERMINAL_RESET_SEQ.contains("\x1b[<u"));
    }

    #[test]
    fn terminal_reset_seq_restores_cursor_visibility_and_sgr() {
        assert!(TERMINAL_RESET_SEQ.contains("\x1b[?25h"));
        assert!(TERMINAL_RESET_SEQ.contains("\x1b[0m"));
    }
}
