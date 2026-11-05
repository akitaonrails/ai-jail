use std::io::{self, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};

/// When set, suppress info/warn/verbose output (--exec mode).
static QUIET: AtomicBool = AtomicBool::new(false);

pub fn set_quiet(q: bool) {
    QUIET.store(q, Ordering::SeqCst);
}

#[cfg_attr(target_os = "macos", allow(dead_code))]
pub fn is_quiet() -> bool {
    QUIET.load(Ordering::SeqCst)
}

fn is_tty() -> bool {
    colors_enabled(
        io::stderr().is_terminal(),
        std::env::var_os("NO_COLOR").is_some(),
    )
}

fn colors_enabled(is_terminal: bool, no_color: bool) -> bool {
    is_terminal && !no_color
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
        let _ = writeln!(
            out,
            "{BOLD}{GREEN}▸{RESET} {}",
            escape_control_bytes(msg)
        );
    } else {
        let _ = writeln!(out, "▸ {}", escape_control_bytes(msg));
    }
}

pub fn warn(msg: &str) {
    emit_warning(msg, true);
}

/// Print a security-relevant warning even in quiet (`--exec`) mode.
pub fn security_warn(msg: &str) {
    emit_warning(msg, false);
}

fn emit_warning(msg: &str, respect_quiet: bool) {
    if !warning_should_emit(respect_quiet) {
        return;
    }
    let mut out = io::stderr().lock();
    let msg = escape_control_bytes(msg);
    if is_tty() {
        let _ = writeln!(out, "{BOLD}{YELLOW}⚠{RESET} {msg}");
    } else {
        let _ = writeln!(out, "⚠ {msg}");
    }
}

fn warning_should_emit(respect_quiet: bool) -> bool {
    !respect_quiet || !QUIET.load(Ordering::SeqCst)
}

pub fn error(msg: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ =
            writeln!(out, "{BOLD}{RED}✗{RESET} {}", escape_control_bytes(msg));
    } else {
        let _ = writeln!(out, "✗ {}", escape_control_bytes(msg));
    }
}

pub fn ok(msg: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(
            out,
            "{BOLD}{GREEN}✓{RESET} {}",
            escape_control_bytes(msg)
        );
    } else {
        let _ = writeln!(out, "✓ {}", escape_control_bytes(msg));
    }
}

/// Security-sensitive migration result. Stable IDs make docs and support
/// transcripts robust while the explanatory copy evolves.
pub fn migration_notice(id: &str, msg: &str, warning: bool) {
    let mut out = io::stderr().lock();
    let rendered = render_migration_notice(id, msg, warning, is_tty());
    let _ = writeln!(out, "{rendered}");
}

fn render_migration_notice(
    id: &str,
    msg: &str,
    warning: bool,
    ansi: bool,
) -> String {
    let id = escape_control_bytes(id);
    let msg = escape_control_bytes(msg);
    if warning && ansi {
        format!("{BOLD}{YELLOW}⚠ {id}{RESET} {msg}")
    } else if warning {
        format!("⚠ {id} {msg}")
    } else if ansi {
        format!("{BOLD}{CYAN}✓ {id}{RESET} {msg}")
    } else {
        format!("✓ {id} {msg}")
    }
}

pub fn verbose(msg: &str) {
    if QUIET.load(Ordering::SeqCst) {
        return;
    }
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(out, "{DIM}  {}{RESET}", escape_control_bytes(msg));
    } else {
        let _ = writeln!(out, "  {}", escape_control_bytes(msg));
    }
}

pub fn status_header(label: &str, value: &str) {
    let mut out = io::stderr().lock();
    if is_tty() {
        let _ = writeln!(
            out,
            "{BOLD}{CYAN}{}{RESET}: {}",
            escape_control_bytes(label),
            escape_control_bytes(value)
        );
    } else {
        let _ = writeln!(
            out,
            "{}: {}",
            escape_control_bytes(label),
            escape_control_bytes(value)
        );
    }
}

pub fn dry_run_line(line: &str) {
    let out = io::stdout();
    let mut out = out.lock();
    let _ = writeln!(out, "{}", escape_control_bytes(line));
}

/// Replace terminal control bytes in untrusted text with a visible-safe
/// placeholder. This renderer is for values interpolated into one terminal
/// line, so every control character, including line breaks and tabs, is unsafe.
pub fn escape_control_bytes(s: &str) -> String {
    s.chars()
        .map(|ch| match ch {
            '\u{2028}'
            | '\u{2029}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}' => '?',
            '\u{20}'..='\u{7e}' | '\u{a0}'.. => ch,
            _ => '?',
        })
        .collect()
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
    fn escape_control_bytes_removes_terminal_escapes() {
        assert_eq!(
            escape_control_bytes("ok\x1b]52;secret\x07"),
            "ok?]52;secret?"
        );
        assert_eq!(escape_control_bytes("a\u{202e}b\u{2028}c"), "a?b?c");
        assert_eq!(
            escape_control_bytes("line\ncarriage\rtab\t\u{0085}end"),
            "line?carriage?tab??end"
        );
    }

    #[test]
    fn security_warning_bypasses_quiet_mode() {
        set_quiet(true);
        assert!(warning_should_emit(false));
        assert!(!warning_should_emit(true));
        set_quiet(false);
    }

    #[test]
    fn no_color_disables_ansi_on_terminals() {
        assert!(colors_enabled(true, false));
        assert!(!colors_enabled(true, true));
        assert!(!colors_enabled(false, false));
    }

    #[test]
    fn migration_warning_has_exact_plain_and_ansi_rendering() {
        assert_eq!(
            render_migration_notice("AJ-MIG-003", "reapprove", true, false),
            "⚠ AJ-MIG-003 reapprove"
        );
        assert_eq!(
            render_migration_notice("AJ-MIG-003", "reapprove", true, true),
            "\x1b[1m\x1b[33m⚠ AJ-MIG-003\x1b[0m reapprove"
        );
        assert!(
            !render_migration_notice("AJ-MIG-003", "x", true, false)
                .contains('✓')
        );
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
