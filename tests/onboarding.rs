mod common;

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

struct PtyStep<'a> {
    wait_for: &'a str,
    input: &'a [u8],
}

enum PtyInput<'a> {
    Immediate(&'a [u8]),
    Split { input: &'a [u8], at: usize },
    Steps(&'a [PtyStep<'a>]),
}

#[test]
fn noninteractive_configure_fails_without_writing_policy() {
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("onboarding-nontty-{}", std::process::id()));
    let project = root.join("project");
    let home = root.join("home");
    let xdg = root.join("xdg");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&home).unwrap();
    let output = Command::new(common::ai_jail())
        .args(["configure", "claude"])
        .current_dir(&project)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No configuration was changed"), "{stderr}");
    assert!(!stderr.contains("AJ-"), "{stderr}");
    assert!(!xdg.exists());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn noninteractive_first_run_renders_complete_effective_access() {
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("onboarding-nontty-first-{}", std::process::id()));
    let project = root.join("project");
    let home = root.join("home");
    let xdg = root.join("xdg");
    let empty_path = root.join("empty-path");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&empty_path).unwrap();

    let output = Command::new(common::ai_jail())
        .arg("claude")
        .current_dir(&project)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("PATH", &empty_path)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Complete effective access"), "{stderr}");
    assert!(!stderr.contains("AJ-"), "{stderr}");
    assert!(stderr.contains("no_mise = true"), "{stderr}");
    assert!(stderr.contains("no_toolchains = true"), "{stderr}");
    let projects = xdg.join("ai-jail/projects");
    assert!(
        !projects.exists() || fs::read_dir(projects).unwrap().next().is_none()
    );
    let _ = fs::remove_dir_all(root);
}

unsafe fn slave_stdio(fd: i32) -> Stdio {
    let duplicated = unsafe { nix::libc::dup(fd) };
    assert!(duplicated >= 0);
    unsafe { Stdio::from_raw_fd(duplicated) }
}

fn scripted_pty(
    label: &str,
    input: &[u8],
    extra_env: &[(&str, &str)],
    term: &str,
    expected_code: i32,
    delayed_split: Option<usize>,
) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let input = match delayed_split {
        Some(at) => PtyInput::Split { input, at },
        None => PtyInput::Immediate(input),
    };
    scripted_pty_driver(label, input, extra_env, term, expected_code)
}

fn scripted_pty_steps(
    label: &str,
    steps: &[PtyStep<'_>],
    extra_env: &[(&str, &str)],
    term: &str,
    expected_code: i32,
) -> (std::path::PathBuf, std::path::PathBuf, String) {
    scripted_pty_driver(
        label,
        PtyInput::Steps(steps),
        extra_env,
        term,
        expected_code,
    )
}

fn scripted_pty_driver(
    label: &str,
    input: PtyInput<'_>,
    extra_env: &[(&str, &str)],
    term: &str,
    expected_code: i32,
) -> (std::path::PathBuf, std::path::PathBuf, String) {
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("onboarding-{label}-{}", std::process::id()));
    let project = root.join("project");
    let home = root.join("home");
    let xdg = root.join("xdg");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&home).unwrap();
    if matches!(label, "pty-forge-open" | "pty-forge-allowed") {
        install_forge_binding_without_credential(
            &project,
            &xdg,
            label == "pty-forge-allowed",
        );
    }
    if label == "pty-utf8-tab" {
        fs::create_dir_all(root.join("share-café")).unwrap();
    }
    if label == "pty-restricted-ssh" {
        let ssh = home.join(".ssh");
        let tools = root.join("ssh-tools");
        fs::create_dir_all(&ssh).unwrap();
        fs::create_dir_all(&tools).unwrap();
        fs::write(ssh.join("id_test"), "private test fixture").unwrap();
        fs::write(
            ssh.join("id_test.pub"),
            "ssh-ed25519 AAAATEST alice@example\n",
        )
        .unwrap();
        fs::write(ssh.join("known_hosts"), "github.com ssh-ed25519 AAAAHOST\n")
            .unwrap();
        fs::write(
            tools.join("ssh-keygen"),
            "#!/bin/sh\nprintf '256 SHA256:EXAMPLE alice@example (ED25519)\\n'\n",
        )
        .unwrap();
        fs::set_permissions(
            tools.join("ssh-keygen"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        for name in ["ssh-agent", "ssh-add", "ssh"] {
            fs::write(tools.join(name), "#!/bin/sh\nexit 0\n").unwrap();
            fs::set_permissions(
                tools.join(name),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
    }

    let window = nix::pty::Winsize {
        ws_row: 32,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = nix::pty::openpty(Some(&window), None).unwrap();
    let slave_fd = pty.slave.as_raw_fd();
    let mut command = Command::new(common::ai_jail());
    command
        .args(["configure", "claude"])
        .current_dir(&project)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("NO_COLOR", "")
        .env("TERM", term)
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("OPENAI_API_KEY")
        .env_remove("GEMINI_API_KEY")
        .env_remove("GOOGLE_API_KEY")
        .env_remove("XAI_API_KEY")
        .env_remove("MOONSHOT_API_KEY");
    if label == "pty-restricted-ssh" {
        command.env("AI_JAIL_TEST_SSH_TOOL_DIR", root.join("ssh-tools"));
    }
    for (name, value) in extra_env {
        command.env(name, value);
    }
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
    drop(pty.slave);
    let reader_fd = unsafe { nix::libc::dup(pty.master.as_raw_fd()) };
    assert!(reader_fd >= 0);
    let transcript = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let reader_transcript = transcript.clone();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_done = done.clone();
    let reader = std::thread::spawn(move || {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::os::fd::BorrowedFd;
        use std::sync::atomic::Ordering;

        let reader = unsafe { std::os::fd::OwnedFd::from_raw_fd(reader_fd) };
        let mut buffer = [0u8; 8192];
        loop {
            let borrowed =
                unsafe { BorrowedFd::borrow_raw(reader.as_raw_fd()) };
            let mut poll_fds = [PollFd::new(borrowed, PollFlags::POLLIN)];
            if poll(&mut poll_fds, PollTimeout::from(100u16)).unwrap_or(0) == 0
            {
                if reader_done.load(Ordering::SeqCst) {
                    break;
                }
                continue;
            }
            match nix::unistd::read(reader.as_raw_fd(), &mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => reader_transcript
                    .lock()
                    .unwrap()
                    .extend_from_slice(&buffer[..count]),
            }
        }
    });
    match input {
        PtyInput::Immediate(input) => {
            nix::unistd::write(&pty.master, input).unwrap();
        }
        PtyInput::Split { input, at } => {
            nix::unistd::write(&pty.master, &input[..at]).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(150));
            nix::unistd::write(&pty.master, &input[at..]).unwrap();
        }
        PtyInput::Steps(steps) => {
            let mut cursor = 0;
            for step in steps {
                wait_for_transcript(&transcript, step.wait_for, cursor);
                cursor = transcript.lock().unwrap().len();
                nix::unistd::write(&pty.master, step.input).unwrap();
            }
        }
    }
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            child.kill().unwrap();
            break child.wait().unwrap();
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    done.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(pty.master);
    reader.join().unwrap();
    let bytes = transcript.lock().unwrap().clone();
    let transcript = String::from_utf8_lossy(&bytes);
    assert_eq!(status.code(), Some(expected_code), "{transcript}");
    (root, xdg, transcript.into_owned())
}

fn install_forge_binding_without_credential(
    project: &std::path::Path,
    xdg: &std::path::Path,
    scope_verified: bool,
) {
    let canonical = fs::canonicalize(project).unwrap();
    let digest =
        format!("{:x}", Sha256::digest(canonical.as_os_str().as_bytes()));
    let base = canonical
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap();
    let project_key = format!("{base}-{}", &digest[..20]);
    let store = xdg.join("ai-jail");
    let forges = store.join("forges");
    fs::create_dir_all(&forges).unwrap();
    for directory in [&store, &forges] {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .unwrap();
    }
    let repository = if scope_verified {
        "owner/allowed-review"
    } else {
        "owner/open-review"
    };
    let binding = format!(
        "schema_version = 1\nprovider = \"gitlab_project\"\nrepository_id = 42\nrepository = \"{repository}\"\ncredential_id = \"missing-review-only-credential\"\nallow_private = false\nscope_verified = {scope_verified}\nscopes = [\"read_repository\"]\nexpires_at = \"2099-01-01\"\nopen_approved = true\n\n[origin]\nhost = \"gitlab.example\"\nport = 443\ntest_http = false\n"
    );
    let binding_path = forges.join(format!("{project_key}.toml"));
    fs::write(&binding_path, binding).unwrap();
    fs::set_permissions(binding_path, fs::Permissions::from_mode(0o600))
        .unwrap();
}

/// One terminal cell: the character drawn there and the byte offset it was
/// written at. The offset keeps the step cursor meaningful while matching
/// what a user actually sees.
type ScreenCell = Option<(char, usize)>;

const SCREEN_ROWS: usize = 64;
const SCREEN_COLS: usize = 256;

/// Replay a ratatui byte stream into a character grid.
///
/// The onboarding UI redraws incrementally: a dialog's label is written as
/// separate runs positioned with cursor moves, so its text never appears as
/// one contiguous slice of the raw stream. Matching the rendered grid is what
/// a user (and a keystroke) is actually responding to.
fn render_screen(bytes: &[u8]) -> Vec<Vec<ScreenCell>> {
    let mut screen = vec![vec![None; SCREEN_COLS]; SCREEN_ROWS];
    let mut row = 0usize;
    let mut col = 0usize;
    let text = String::from_utf8_lossy(bytes);
    let mut chars = text.char_indices().peekable();
    while let Some((offset, ch)) = chars.next() {
        match ch {
            '\x1b' => {
                let Some((_, '[')) = chars.next() else {
                    // OSC and other strings: skip to BEL or ST.
                    for (_, next) in chars.by_ref() {
                        if next == '\x07' {
                            break;
                        }
                    }
                    continue;
                };
                let mut params = String::new();
                let mut final_byte = None;
                for (_, next) in chars.by_ref() {
                    if next.is_ascii_digit() || next == ';' || next == '?' {
                        params.push(next);
                    } else {
                        final_byte = Some(next);
                        break;
                    }
                }
                let numbers: Vec<usize> = params
                    .trim_start_matches('?')
                    .split(';')
                    .map(|part| part.parse().unwrap_or(0))
                    .collect();
                match final_byte {
                    Some('H') | Some('f') => {
                        row = numbers
                            .first()
                            .copied()
                            .filter(|value| *value > 0)
                            .unwrap_or(1)
                            .saturating_sub(1);
                        col = numbers
                            .get(1)
                            .copied()
                            .filter(|value| *value > 0)
                            .unwrap_or(1)
                            .saturating_sub(1);
                    }
                    Some('J') => match numbers.first().copied().unwrap_or(0) {
                        2 | 3 => {
                            for line in screen.iter_mut() {
                                line.fill(None);
                            }
                            row = 0;
                            col = 0;
                        }
                        _ => {
                            if let Some(line) = screen.get_mut(row) {
                                for cell in line.iter_mut().skip(col) {
                                    *cell = None;
                                }
                            }
                            for line in screen.iter_mut().skip(row + 1) {
                                line.fill(None);
                            }
                        }
                    },
                    Some('K') => {
                        if let Some(line) = screen.get_mut(row) {
                            match numbers.first().copied().unwrap_or(0) {
                                2 => line.fill(None),
                                _ => {
                                    for cell in line.iter_mut().skip(col) {
                                        *cell = None;
                                    }
                                }
                            }
                        }
                    }
                    // Entering or leaving the alternate screen starts a
                    // fresh picture, so earlier frames must not match.
                    Some('h') | Some('l') if params.contains("1049") => {
                        for line in screen.iter_mut() {
                            line.fill(None);
                        }
                        row = 0;
                        col = 0;
                    }
                    _ => {}
                }
            }
            '\r' => col = 0,
            '\n' => {
                row = row.saturating_add(1);
                col = 0;
            }
            ch if ch.is_control() => {}
            ch => {
                if let Some(cell) =
                    screen.get_mut(row).and_then(|line| line.get_mut(col))
                {
                    *cell = Some((ch, offset));
                }
                col = col.saturating_add(1);
            }
        }
    }
    screen
}

/// Find `needle` as contiguous text on one rendered row, ignoring cells that
/// were written before `after`. Returns the byte offset just past the match.
fn find_on_screen(bytes: &[u8], needle: &str, after: usize) -> Option<usize> {
    let needle: Vec<char> = needle.chars().collect();
    if needle.is_empty() {
        return Some(after);
    }
    for line in render_screen(bytes) {
        let cells: Vec<Option<(char, usize)>> = line;
        for start in 0..cells.len().saturating_sub(needle.len() - 1) {
            let window = &cells[start..start + needle.len()];
            let matches = window.iter().zip(&needle).all(
                |(cell, wanted)| matches!(cell, Some((ch, _)) if ch == wanted),
            );
            if !matches {
                continue;
            }
            let last = window.last().and_then(|cell| cell.map(|(_, at)| at))?;
            if last + 1 > after {
                return Some(last + 1);
            }
        }
    }
    None
}

fn wait_for_transcript(
    transcript: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    needle: &str,
    after: usize,
) -> usize {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let bytes = transcript.lock().unwrap();
        // Raw control sequences (e.g. a cursor-hide marker) are matched on
        // the stream; user-visible text is matched on the rendered screen.
        let raw = String::from_utf8_lossy(&bytes[after.min(bytes.len())..]);
        let found = raw
            .find(needle)
            .map(|relative| after + relative + needle.len())
            .or_else(|| find_on_screen(&bytes, needle, after));
        if let Some(position) = found {
            return position;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for {needle:?}; transcript:\n{}",
            String::from_utf8_lossy(&bytes)
        );
        drop(bytes);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn assert_tui_terminal_restored(transcript: &str) {
    assert_eq!(
        transcript.matches("\x1b[?1049h").count(),
        1,
        "onboarding must use one alternate-screen session:\n{transcript}"
    );
    assert_eq!(
        transcript.matches("\x1b[?1049l").count(),
        1,
        "onboarding must leave the alternate screen exactly once:\n{transcript}"
    );
    let enter = transcript
        .find("\x1b[?1049h")
        .expect("TUI must enter the alternate screen");
    let leave = transcript
        .rfind("\x1b[?1049l")
        .expect("TUI must leave the alternate screen");
    assert!(
        leave > enter,
        "alternate screen was not restored:\n{transcript}"
    );

    let hide = transcript
        .find("\x1b[?25l")
        .expect("TUI must hide the cursor while drawing");
    let show = transcript
        .rfind("\x1b[?25h")
        .expect("TUI must restore the cursor");
    assert!(show > hide, "cursor was not restored:\n{transcript}");
}

#[test]
fn scripted_pty_confirms_recommended_github_and_saves_without_final_review() {
    let steps = [
        PtyStep {
            wait_for: "AI-JAIL",
            input: b"s",
        },
        PtyStep {
            wait_for: "Save with OPEN GitHub",
            input: b"\t\r",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty", &steps, &[], "xterm", 0);
    assert!(
        !transcript.contains("Complete effective access"),
        "{transcript}"
    );
    assert!(transcript.contains("Configuration saved"), "{transcript}");
    assert!(transcript.contains("Review later:"), "{transcript}");
    assert!(transcript.contains("api.anthropic.com"), "{transcript}");
    assert!(!transcript.contains("AJ-"), "{transcript}");
    assert_tui_terminal_restored(&transcript);
    assert!(xdg.join("ai-jail/projects").is_dir());
    let policy_path = fs::read_dir(xdg.join("ai-jail/projects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let policy = fs::read_to_string(policy_path).unwrap();
    assert!(policy.contains("github = true"), "{policy}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn scripted_pty_quit_with_changes_can_save_without_launching() {
    let steps = [
        PtyStep {
            wait_for: "AI-JAIL",
            input: b"q",
        },
        PtyStep {
            wait_for: "Keep editing",
            input: b"s",
        },
        PtyStep {
            wait_for: "Save with OPEN GitHub",
            input: b"\t\r",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty-exit-save", &steps, &[], "xterm", 0);
    assert!(transcript.contains("Configuration saved"), "{transcript}");
    assert!(transcript.contains("Review later:"), "{transcript}");
    assert!(!transcript.contains("AJ-"), "{transcript}");
    assert_tui_terminal_restored(&transcript);
    let policy_path = fs::read_dir(xdg.join("ai-jail/projects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let policy = fs::read_to_string(policy_path).unwrap();
    assert!(policy.contains("github = true"), "{policy}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn scripted_pty_environment_checklist_never_displays_or_saves_values() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"e/CUSTOM_MODE\r ",
        },
        PtyStep {
            wait_for: "Consequence:",
            input: b"\x1b[F",
        },
        PtyStep {
            wait_for: "Authority:",
            input: b"\r",
        },
        PtyStep {
            wait_for: "Share this environment value?",
            input: b"\x1b[F",
        },
        PtyStep {
            wait_for: "\x1b[?25l",
            input: b"\t\r",
        },
        PtyStep {
            wait_for: "Selected",
            input: b"\x1b",
        },
        PtyStep {
            // Clearing the search must not depend on whichever unrelated
            // variables happen to exist in the build host environment.
            wait_for: "Search cleared.",
            input: b"\x1b",
        },
        PtyStep {
            wait_for: "separately.",
            input: b"s",
        },
        PtyStep {
            wait_for: "Save with OPEN GitHub",
            input: b"\t\r",
        },
    ];
    let (root, xdg, transcript) = scripted_pty_steps(
        "pty-env",
        &steps,
        &[("CUSTOM_MODE", "secret-value-that-must-never-appear")],
        "xterm",
        0,
    );
    assert!(transcript.contains("CUSTOM_MODE"), "{transcript}");
    assert!(!transcript.contains("AJ-"), "{transcript}");
    assert!(!transcript.contains("secret-value-that-must-never-appear"));
    assert_tui_terminal_restored(&transcript);

    let policies = fs::read_dir(xdg.join("ai-jail/projects")).unwrap();
    let policy_path = policies.into_iter().next().unwrap().unwrap().path();
    let policy = fs::read_to_string(policy_path).unwrap();
    assert!(policy.contains("CUSTOM_MODE"));
    assert!(!policy.contains("secret-value-that-must-never-appear"));
    let _ = fs::remove_dir_all(root);
}

#[cfg(feature = "test-hooks")]
#[test]
fn scripted_pty_configures_and_saves_destination_constrained_ssh() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"k ",
        },
        PtyStep {
            // Ratatui may redraw the status line in fragments, with cursor
            // movement between "Identity" and this stable suffix.
            wait_for: "selected.",
            input: b"\t\tagit@github.com\r",
        },
        PtyStep {
            wait_for: "READY — selected-key SSH is destination constrained",
            input: b"\x1b",
        },
        PtyStep {
            wait_for: "Selected SSH keys (fresh agent)",
            input: b"6",
        },
        PtyStep {
            wait_for: "Enable OPEN access",
            input: b"\t\r",
        },
        PtyStep {
            wait_for: "OPEN grant",
            input: b"s",
        },
        PtyStep {
            wait_for: "Save with OPEN GitHub",
            input: b"\t\r",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty-restricted-ssh", &steps, &[], "xterm", 0);
    assert!(transcript.contains("SHA256:EXAMPLE"), "{transcript}");
    assert!(transcript.contains("git@github.com"), "{transcript}");
    assert!(!transcript.contains("AJ-"), "{transcript}");
    assert!(!transcript.contains("private test fixture"), "{transcript}");
    assert_tui_terminal_restored(&transcript);
    let policy_path = fs::read_dir(xdg.join("ai-jail/projects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let policy = fs::read_to_string(policy_path).unwrap();
    assert!(policy.contains("restricted_ssh"));
    assert!(policy.contains("git@github.com"));
    assert!(policy.contains("network = true"));
    assert!(!policy.contains("private test fixture"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn scripted_pty_arrows_move_the_highlighted_row_and_cancel_restores_terminal() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"\x1b[B",
        },
        PtyStep {
            wait_for: "login/state",
            input: b"q",
        },
        PtyStep {
            wait_for: "Keep editing",
            input: b"d",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty-arrows", &steps, &[], "xterm", 130);
    assert!(transcript.contains("choices"), "{transcript}");
    assert!(transcript.contains("login/state"), "{transcript}");
    assert!(
        transcript.contains("Filtered model API access"),
        "{transcript}"
    );
    assert!(
        !transcript.contains("Selected:"),
        "the highlighted list row must be the only selection indicator:\n{transcript}"
    );
    assert!(
        transcript.matches(";7m").count() >= 2
            || transcript.matches("\x1b[7m").count() >= 2,
        "initial and moved rows must both render highlighted:\n{transcript}"
    );
    assert_tui_terminal_restored(&transcript);
    let projects = xdg.join("ai-jail/projects");
    assert!(
        !projects.exists() || fs::read_dir(projects).unwrap().next().is_none()
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn term_dumb_q_cancels_at_the_first_prompt() {
    let (root, xdg, transcript) =
        scripted_pty("pty-dumb-q", b"q\n", &[], "dumb", 130, None);
    assert!(transcript.contains("Plain-terminal mode"));
    assert!(transcript.contains("Onboarding cancelled"));
    assert!(!transcript.contains("AJ-"));
    let projects = xdg.join("ai-jail/projects");
    assert!(
        !projects.exists() || fs::read_dir(projects).unwrap().next().is_none()
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn escape_at_access_overview_prompts_before_discarding_unsaved_changes() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"\x1b",
        },
        PtyStep {
            wait_for: "Keep editing",
            input: b"d",
        },
    ];
    let (root, _xdg, transcript) =
        scripted_pty_steps("pty-lone-escape", &steps, &[], "xterm", 130);
    assert!(transcript.contains("Keep editing"), "{transcript}");
    assert_eq!(transcript.matches("\x1b[?1049h").count(), 1);
    assert_tui_terminal_restored(&transcript);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn discarding_unsaved_exit_does_not_save() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"5q",
        },
        PtyStep {
            wait_for: "Save changes",
            input: b"d",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty-discard", &steps, &[], "xterm", 130);
    assert!(transcript.contains("Onboarding cancelled"), "{transcript}");
    assert!(!transcript.contains("Configuration saved"), "{transcript}");
    assert_tui_terminal_restored(&transcript);
    let projects = xdg.join("ai-jail/projects");
    assert!(
        !projects.exists() || fs::read_dir(projects).unwrap().next().is_none()
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn directory_browser_accepts_utf8_paths() {
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("onboarding-pty-utf8-tab-{}", std::process::id()));
    let tui_input = format!("dg{}/share-café\r ", root.to_string_lossy());
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: tui_input.as_bytes(),
        },
        PtyStep {
            wait_for: "Added READ-ONLY",
            input: b"\t",
        },
        PtyStep {
            wait_for: "Selected directories",
            input: b"m",
        },
        PtyStep {
            wait_for: "Set READ/WRITE",
            input: b"m",
        },
        PtyStep {
            // Ratatui updates only the changed mode suffix on this row.
            wait_for: "-ONLY ac",
            input: b" ",
        },
        PtyStep {
            wait_for: "moved directory access",
            input: b" ",
        },
        PtyStep {
            wait_for: "Added READ-ONLY",
            input: b"\x1b",
        },
        PtyStep {
            wait_for: "Directory access",
            input: b"s",
        },
        PtyStep {
            wait_for: "Save with OPEN GitHub",
            input: b"\t\r",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty-utf8-tab", &steps, &[], "xterm", 0);
    assert!(transcript.contains("share-café"), "{transcript}");
    assert!(transcript.contains("Selected directories"), "{transcript}");
    assert!(transcript.contains("Set READ/WRITE"), "{transcript}");
    assert!(
        transcript.contains("moved directory access"),
        "{transcript}"
    );
    assert!(!transcript.contains("AJ-"), "{transcript}");
    assert_tui_terminal_restored(&transcript);
    let policy_path = fs::read_dir(xdg.join("ai-jail/projects"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let policy = fs::read_to_string(policy_path).unwrap();
    assert!(policy.contains("share-café"), "{policy}");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn forge_open_binding_is_finalized_without_reading_a_credential() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"s",
        },
        PtyStep {
            wait_for: "Save with OPEN GitHub",
            input: b"\t\r",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty-forge-open", &steps, &[], "xterm", 0);
    assert!(!transcript.contains("Type OPEN"), "{transcript}");
    assert!(transcript.contains("Configuration saved"), "{transcript}");
    assert!(
        !transcript.contains("missing-review-only-credential"),
        "credential identifiers are not review content:\n{transcript}"
    );
    assert_tui_terminal_restored(&transcript);
    assert!(xdg.join("ai-jail/projects").is_dir());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn forge_scoped_binding_saves_without_a_final_review() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"s",
        },
        PtyStep {
            wait_for: "Save with OPEN GitHub",
            input: b"\t\r",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty-forge-allowed", &steps, &[], "xterm", 0);
    assert!(transcript.contains("Configuration saved"), "{transcript}");
    assert!(
        !transcript.contains("Final effective access contains OPEN authority."),
        "scoped forge metadata must not cause OPEN confirmation:\n{transcript}"
    );
    assert!(
        !transcript.contains("missing-review-only-credential"),
        "credential identifiers are not review content:\n{transcript}"
    );
    assert_tui_terminal_restored(&transcript);
    assert!(xdg.join("ai-jail/projects").is_dir());
    let _ = fs::remove_dir_all(root);
}
