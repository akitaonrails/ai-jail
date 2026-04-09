//! Persistent terminal status bar overlay.
//!
//! Layout: ` /path | command            ai-jail ⚿ 0.4.5 `
//!
//! With the vt100 virtual terminal, the status bar is drawn as a
//! simple overlay on the real terminal's last row — no scroll
//! regions needed. The virtual terminal is sized rows-1, so child
//! output never reaches the last row.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

static ACTIVE: AtomicBool = AtomicBool::new(false);
static STYLE_DARK: AtomicBool = AtomicBool::new(true);
static STYLE_PASTEL: AtomicBool = AtomicBool::new(false);
static DIRTY: AtomicBool = AtomicBool::new(false);

// SGR sequence for the active pastel palette, picked at setup().
// Form: "\x1b[38;5;{fg};48;5;{bg}m" — at most ~20 bytes.
const MAX_PASTEL_SGR: usize = 32;
static mut PASTEL_SGR_BUF: [u8; MAX_PASTEL_SGR] = [0u8; MAX_PASTEL_SGR];
static PASTEL_SGR_LEN: AtomicUsize = AtomicUsize::new(0);

/// Pastel (bg, fg) pairs in xterm-256 indices. Each background is a
/// soft pastel and the matching foreground is a deep tone of the same
/// hue family — contrast is high enough to read on every entry.
const PASTEL_PALETTE: &[(u8, u8)] = &[
    (224, 52),  // mistyrose / dark red
    (223, 94),  // wheat / dark orange
    (230, 94),  // cornsilk / dark orange
    (194, 22),  // honeydew / dark green
    (195, 23),  // lightcyan / dark teal
    (189, 54),  // lavender / dark purple
    (218, 53),  // pink / dark magenta
    (255, 235), // off-white / near-black
];

const MAX_DIR: usize = 4096;
static mut DIR_BUF: [u8; MAX_DIR] = [0u8; MAX_DIR];
static DIR_LEN: AtomicUsize = AtomicUsize::new(0);

const MAX_CMD: usize = 1024;
static mut CMD_BUF: [u8; MAX_CMD] = [0u8; MAX_CMD];
static CMD_LEN: AtomicUsize = AtomicUsize::new(0);

static UPDATE_AVAILABLE: AtomicBool = AtomicBool::new(false);

const VERSION: &str = env!("CARGO_PKG_VERSION");

const MAX_CURSOR_STATE: usize = 4096;
static mut CURSOR_STATE_BUF: [u8; MAX_CURSOR_STATE] = [0u8; MAX_CURSOR_STATE];
static CURSOR_STATE_LEN: AtomicUsize = AtomicUsize::new(0);

const MAX_ATTR_STATE: usize = 512;
static mut ATTR_STATE_BUF: [u8; MAX_ATTR_STATE] = [0u8; MAX_ATTR_STATE];
static ATTR_STATE_LEN: AtomicUsize = AtomicUsize::new(0);

// U+2026 HORIZONTAL ELLIPSIS: 3 UTF-8 bytes, 1 visible column
const ELLIPSIS: [u8; 3] = [0xe2, 0x80, 0xa6];
// U+2191 UPWARDS ARROW: 3 UTF-8 bytes, 1 visible column
const UP_ARROW: [u8; 3] = [0xe2, 0x86, 0x91];
// U+26BF SQUARED KEY: 3 UTF-8 bytes, East Asian Width "Ambiguous"
// Renders as 2 columns on macOS terminals; counted as 2 here.
const JAIL_ICON: [u8; 3] = [0xe2, 0x9a, 0xbf];
const JAIL_ICON_COLS: usize = 2;

fn term_size() -> Option<(u16, u16)> {
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

/// Pick a random pastel palette entry and serialize its SGR escape
/// into PASTEL_SGR_BUF. Called once per session from setup(), so the
/// color stays stable for the whole run but rotates between sessions.
fn pick_pastel_palette() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as usize)
        .unwrap_or(0);
    let (bg, fg) = PASTEL_PALETTE[nanos % PASTEL_PALETTE.len()];

    // Format: "\x1b[38;5;{fg};48;5;{bg}m"
    let mut buf = [0u8; MAX_PASTEL_SGR];
    let mut pos = 0;
    let prefix = b"\x1b[38;5;";
    buf[pos..pos + prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += write_u16(fg as u16, &mut buf[pos..]);
    let mid = b";48;5;";
    buf[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += write_u16(bg as u16, &mut buf[pos..]);
    buf[pos] = b'm';
    pos += 1;

    unsafe {
        PASTEL_SGR_BUF[..pos].copy_from_slice(&buf[..pos]);
    }
    PASTEL_SGR_LEN.store(pos, Ordering::SeqCst);
}

/// Return the active SGR sequence for the status bar background.
/// Async-signal-safe.
fn style_sgr() -> &'static [u8] {
    if STYLE_PASTEL.load(Ordering::SeqCst) {
        let len = PASTEL_SGR_LEN.load(Ordering::SeqCst);
        unsafe { &PASTEL_SGR_BUF[..len] }
    } else if STYLE_DARK.load(Ordering::SeqCst) {
        b"\x1b[37;40m"
    } else {
        b"\x1b[90;107m"
    }
}

/// Async-signal-safe write to stdout.
fn raw_write(bytes: &[u8]) {
    let mut off = 0;
    while off < bytes.len() {
        let n = unsafe {
            nix::libc::write(
                nix::libc::STDOUT_FILENO,
                bytes[off..].as_ptr() as *const nix::libc::c_void,
                bytes.len() - off,
            )
        };
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
}

/// Write a u16 as decimal digits into `buf`. Returns byte count.
fn write_u16(n: u16, buf: &mut [u8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut digits = [0u8; 5];
    let mut len = 0;
    let mut v = n;
    while v > 0 {
        digits[len] = b'0' + (v % 10) as u8;
        len += 1;
        v /= 10;
    }
    for i in 0..len {
        buf[i] = digits[len - 1 - i];
    }
    len
}

fn write_move_clear_row(row: u16, buf: &mut [u8], pos: &mut usize) {
    buf[*pos..*pos + 2].copy_from_slice(b"\x1b[");
    *pos += 2;
    *pos += write_u16(row, &mut buf[*pos..]);
    buf[*pos..*pos + 3].copy_from_slice(b";1H");
    *pos += 3;
    buf[*pos..*pos + 4].copy_from_slice(b"\x1b[2K");
    *pos += 4;
}

fn store_terminal_state(cursor_state: &[u8], attr_state: &[u8]) {
    let cursor_len = cursor_state.len().min(MAX_CURSOR_STATE);
    unsafe {
        CURSOR_STATE_BUF[..cursor_len]
            .copy_from_slice(&cursor_state[..cursor_len]);
    }
    CURSOR_STATE_LEN.store(cursor_len, Ordering::SeqCst);

    let attr_len = attr_state.len().min(MAX_ATTR_STATE);
    unsafe {
        ATTR_STATE_BUF[..attr_len].copy_from_slice(&attr_state[..attr_len]);
    }
    ATTR_STATE_LEN.store(attr_len, Ordering::SeqCst);
}

pub fn update_terminal_state(screen: &vt100::Screen) {
    let cursor_state = screen.cursor_state_formatted();
    let attr_state = screen.attributes_formatted();
    store_terminal_state(&cursor_state, &attr_state);
}

/// Set up the status bar. Call before spawning the child.
/// `style` must be `"dark"`, `"light"`, or `"pastel"`.
pub fn setup(project_dir: &std::path::Path, command: &[String], style: &str) {
    use std::os::unix::ffi::OsStrExt;

    STYLE_DARK.store(style == "dark", Ordering::SeqCst);
    let pastel = style == "pastel";
    STYLE_PASTEL.store(pastel, Ordering::SeqCst);
    if pastel {
        pick_pastel_palette();
    }

    let dir_bytes = project_dir.as_os_str().as_bytes();
    let len = dir_bytes.len().min(MAX_DIR);

    // SAFETY: single-threaded at this point (before child spawn).
    unsafe {
        DIR_BUF[..len].copy_from_slice(&dir_bytes[..len]);
    }
    DIR_LEN.store(len, Ordering::SeqCst);

    // Store command as joined string
    let mut cmd_pos = 0;
    for (i, arg) in command.iter().enumerate() {
        if i > 0 && cmd_pos < MAX_CMD {
            // SAFETY: single-threaded, same as DIR_BUF.
            unsafe {
                CMD_BUF[cmd_pos] = b' ';
            }
            cmd_pos += 1;
        }
        let bytes = arg.as_bytes();
        let n = bytes.len().min(MAX_CMD - cmd_pos);
        unsafe {
            CMD_BUF[cmd_pos..cmd_pos + n].copy_from_slice(&bytes[..n]);
        }
        cmd_pos += n;
    }
    CMD_LEN.store(cmd_pos, Ordering::SeqCst);

    store_terminal_state(b"\x1b[1;1H", b"\x1b[0m");

    let Some((rows, cols)) = term_size() else {
        return;
    };
    if rows < 2 {
        return;
    }

    ACTIVE.store(true, Ordering::SeqCst);
    DIRTY.store(false, Ordering::SeqCst);
    draw(rows, cols);
}

/// Signal that a newer version is available. Triggers redraw.
pub fn set_update_available() {
    UPDATE_AVAILABLE.store(true, Ordering::SeqCst);
    request_redraw();
}

/// Whether the status bar is currently active.
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::SeqCst)
}

/// Request a redraw from async contexts.
pub fn request_redraw() {
    DIRTY.store(true, Ordering::SeqCst);
}

/// Consume and clear pending redraw request.
pub fn take_requests() -> bool {
    DIRTY.swap(false, Ordering::SeqCst)
}

/// Spawn a background thread to check GitHub for a newer release.
/// Fire-and-forget; any error is silently ignored.
pub fn check_update_background() {
    std::thread::spawn(|| {
        let output = match std::process::Command::new("curl")
            .args([
                "-sL",
                "-m",
                "5",
                "-H",
                "Accept: application/vnd.github.v3+json",
                "https://api.github.com/repos/akitaonrails/ai-jail/releases/latest",
            ])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
        {
            Ok(o) if o.status.success() => o.stdout,
            _ => return,
        };

        let json: serde_json::Value = match serde_json::from_slice(&output) {
            Ok(v) => v,
            _ => return,
        };

        let tag = match json.get("tag_name").and_then(|v| v.as_str()) {
            Some(t) => t.trim_start_matches('v'),
            None => return,
        };

        if is_newer(tag, VERSION) {
            set_update_available();
        }
    });
}

/// Simple semver comparison: is `remote` newer than `local`?
fn is_newer(remote: &str, local: &str) -> bool {
    let parse = |s: &str| -> (u32, u32, u32) {
        let mut parts = s.split('.');
        let ma = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        let mi = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        let pa = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
        (ma, mi, pa)
    };
    parse(remote) > parse(local)
}

/// Tear down the status bar. Call after child exits.
pub fn teardown() {
    if !ACTIVE.load(Ordering::SeqCst) {
        return;
    }
    ACTIVE.store(false, Ordering::SeqCst);
    DIRTY.store(false, Ordering::SeqCst);

    let rows = term_size().map(|(r, _)| r).unwrap_or(24);

    // Just clear the last row where the status bar was drawn.
    let mut buf = [0u8; 32];
    let mut pos = 0;
    write_move_clear_row(rows, &mut buf, &mut pos);

    raw_write(&buf[..pos]);
}

/// Redraw on resize. Async-signal-safe.
pub fn redraw() {
    if !ACTIVE.load(Ordering::SeqCst) {
        return;
    }
    let Some((rows, cols)) = term_size() else {
        return;
    };
    if rows < 2 {
        return;
    }
    draw(rows, cols);
}

/// Render status bar overlay on the last row. Async-signal-safe.
fn draw(rows: u16, cols: u16) {
    let dir_len = DIR_LEN.load(Ordering::SeqCst);
    let cmd_len = CMD_LEN.load(Ordering::SeqCst);
    let has_update = UPDATE_AVAILABLE.load(Ordering::SeqCst);
    let style_seq = style_sgr();
    let cols = cols as usize;
    let usable_cols = cols.saturating_sub(1);

    let mut buf = [0u8; 8192];
    let mut pos = 0;

    macro_rules! put {
        ($b:expr) => {{
            let b: &[u8] = $b;
            let end = (pos + b.len()).min(buf.len());
            buf[pos..end].copy_from_slice(&b[..end - pos]);
            pos = end;
        }};
    }

    // Move to last row + clear it: \x1b[{rows};1H\x1b[2K
    put!(b"\x1b[");
    pos += write_u16(rows, &mut buf[pos..]);
    put!(b";1H");
    put!(b"\x1b[2K");

    // Status-bar background style (dark / light / pastel).
    put!(style_seq);

    // 5. Compute layout widths
    let ver = VERSION.as_bytes();
    // "ai-jail " (8) + ⚿ (JAIL_ICON_COLS) + " " (1) + VERSION + optional " ↑" (2)
    let right_vis =
        8 + JAIL_ICON_COLS + 1 + ver.len() + if has_update { 2 } else { 0 };
    let show_right = usable_cols >= right_vis + 2;
    let eff_right = if show_right { right_vis } else { 0 };

    // Leave the final terminal column blank to avoid wrap-pending
    // artifacts when terminals redraw during resize.
    // Left budget: usable_cols - 1(leading) - eff_right - 1(min gap)
    let left_budget = if show_right {
        usable_cols.saturating_sub(eff_right + 2)
    } else {
        usable_cols.saturating_sub(1)
    };

    let mut vis = 0;

    // Leading space
    if cols > 0 {
        put!(b" ");
        vis += 1;
    }

    // --- PWD ---
    let dir_bytes = unsafe { &DIR_BUF[..dir_len] };
    let pwd_avail = left_budget;
    let pwd_vis;

    if dir_len == 0 || pwd_avail == 0 {
        pwd_vis = 0;
    } else if dir_len <= pwd_avail {
        put!(dir_bytes);
        pwd_vis = dir_len;
    } else {
        // Truncate: find last '/' for smart truncation
        let mut last_slash = None;
        for i in (0..dir_len).rev() {
            if dir_bytes[i] == b'/' {
                last_slash = Some(i);
                break;
            }
        }
        if let Some(sp) = last_slash {
            let seg = &dir_bytes[sp + 1..dir_len];
            // "…/" (2 vis cols) + segment
            if seg.len() + 2 <= pwd_avail {
                put!(&ELLIPSIS);
                put!(b"/");
                put!(seg);
                pwd_vis = seg.len() + 2;
            } else if pwd_avail > 1 {
                // "…" + truncated segment
                put!(&ELLIPSIS);
                let n = pwd_avail - 1;
                put!(&seg[..n]);
                pwd_vis = pwd_avail;
            } else {
                put!(&ELLIPSIS);
                pwd_vis = 1;
            }
        } else if pwd_avail > 1 {
            // No slash: "…" + tail of path
            put!(&ELLIPSIS);
            let n = pwd_avail - 1;
            put!(&dir_bytes[dir_len - n..]);
            pwd_vis = pwd_avail;
        } else {
            put!(&ELLIPSIS);
            pwd_vis = 1;
        }
    }
    vis += pwd_vis;

    // --- Separator + Command ---
    let remaining = left_budget.saturating_sub(pwd_vis);
    let cmd_bytes = unsafe { &CMD_BUF[..cmd_len] };

    if remaining >= 4 && cmd_len > 0 {
        put!(b" | ");
        vis += 3;

        let cmd_avail = remaining - 3;
        if cmd_len <= cmd_avail {
            put!(cmd_bytes);
            vis += cmd_len;
        } else if cmd_avail > 1 {
            put!(&cmd_bytes[..cmd_avail - 1]);
            put!(&ELLIPSIS);
            vis += cmd_avail;
        } else {
            put!(&ELLIPSIS);
            vis += 1;
        }
    }

    // --- Space fill ---
    let target = if show_right {
        usable_cols - eff_right
    } else {
        usable_cols
    };
    while vis < target {
        put!(b" ");
        vis += 1;
    }

    // --- Right section ---
    if show_right {
        put!(b"ai-jail ");
        put!(&JAIL_ICON);
        put!(b" ");
        put!(ver);
        vis += 8 + JAIL_ICON_COLS + 1 + ver.len();

        if has_update {
            put!(b" \x1b[32m"); // space + green
            put!(&UP_ARROW);
            put!(style_seq);
            vis += 2;
        }
    }

    // Safety fill
    while vis < usable_cols {
        put!(b" ");
        vis += 1;
    }

    // 6. Reset attributes
    put!(b"\x1b[0m");

    // Restore child terminal state without touching the terminal's
    // save/restore cursor slot, which many TUIs also use.
    let cursor_len = CURSOR_STATE_LEN.load(Ordering::SeqCst);
    if cursor_len > 0 {
        let cursor_state = unsafe { &CURSOR_STATE_BUF[..cursor_len] };
        put!(cursor_state);
    }
    let attr_len = ATTR_STATE_LEN.load(Ordering::SeqCst);
    if attr_len > 0 {
        let attr_state = unsafe { &ATTR_STATE_BUF[..attr_len] };
        put!(attr_state);
    }

    raw_write(&buf[..pos]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_u16_zero() {
        let mut buf = [0u8; 5];
        let n = write_u16(0, &mut buf);
        assert_eq!(&buf[..n], b"0");
    }

    #[test]
    fn write_u16_single_digit() {
        let mut buf = [0u8; 5];
        let n = write_u16(7, &mut buf);
        assert_eq!(&buf[..n], b"7");
    }

    #[test]
    fn write_u16_multi_digit() {
        let mut buf = [0u8; 5];
        let n = write_u16(1024, &mut buf);
        assert_eq!(&buf[..n], b"1024");
    }

    #[test]
    fn write_u16_max() {
        let mut buf = [0u8; 5];
        let n = write_u16(65535, &mut buf);
        assert_eq!(&buf[..n], b"65535");
    }

    #[test]
    fn active_default_false() {
        assert!(!ACTIVE.load(Ordering::SeqCst));
    }

    #[test]
    fn is_newer_basic() {
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(is_newer("0.5.0", "0.4.5"));
        assert!(is_newer("0.4.6", "0.4.5"));
        assert!(!is_newer("0.4.5", "0.4.5"));
        assert!(!is_newer("0.4.4", "0.4.5"));
        assert!(!is_newer("0.3.0", "0.4.5"));
    }

    #[test]
    fn is_newer_partial_version() {
        assert!(is_newer("1.0", "0.9.9"));
        assert!(!is_newer("0.4", "0.4.5"));
    }

    #[test]
    fn update_available_default_false() {
        assert!(!UPDATE_AVAILABLE.load(Ordering::SeqCst));
    }

    #[test]
    fn request_redraw_sets_dirty() {
        DIRTY.store(false, Ordering::SeqCst);
        request_redraw();
        assert!(take_requests());
        assert!(!take_requests());
    }

    #[test]
    fn update_terminal_state_restores_cursor_without_decsc() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"\x1b[31mhello\x1b[5;10H");
        update_terminal_state(parser.screen());

        let cursor_len = CURSOR_STATE_LEN.load(Ordering::SeqCst);
        let attr_len = ATTR_STATE_LEN.load(Ordering::SeqCst);

        let cursor_state = unsafe { &CURSOR_STATE_BUF[..cursor_len] };
        let attr_state = unsafe { &ATTR_STATE_BUF[..attr_len] };

        assert!(!cursor_state.windows(2).any(|w| w == b"\x1b7"));
        assert!(!cursor_state.windows(2).any(|w| w == b"\x1b8"));
        assert!(cursor_state.windows(6).any(|w| w == b"\x1b[5;10"));
        assert!(!attr_state.is_empty());
        assert_eq!(attr_state[0], 0x1b);
        assert!(attr_state.ends_with(b"m"));
    }
}
