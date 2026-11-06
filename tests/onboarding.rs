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

fn wait_for_transcript(
    transcript: &std::sync::Arc<std::sync::Mutex<Vec<u8>>>,
    needle: &str,
    after: usize,
) -> usize {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let bytes = transcript.lock().unwrap();
        let text = String::from_utf8_lossy(&bytes[after.min(bytes.len())..]);
        if let Some(relative) = text.find(needle) {
            return after + relative + needle.len();
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
fn scripted_pty_can_review_and_save_recommended_baseline() {
    let steps = [
        PtyStep {
            wait_for: "For developers applied",
            input: b"s",
        },
        PtyStep {
            wait_for: "choosing a final",
            input: b"\x1b[F",
        },
        PtyStep {
            wait_for: "\x1b[?25l",
            input: b"s",
        },
        PtyStep {
            wait_for: "Continue with OPEN authority?",
            input: b"\t\r",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty", &steps, &[], "xterm", 0);
    assert!(transcript.contains("choosing a final"), "{transcript}");
    assert!(transcript.contains("Configuration saved"), "{transcript}");
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
            wait_for: "\x1b[?25l",
            input: b"\r",
        },
        PtyStep {
            wait_for: "Share this environment value?",
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
            wait_for: "Review complete",
            input: b"s",
        },
        PtyStep {
            wait_for: "choosing a final",
            input: b"\x1b[F",
        },
        PtyStep {
            wait_for: "\x1b[?25l",
            input: b"s",
        },
        PtyStep {
            wait_for: "Continue with OPEN authority?",
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
            wait_for: "Open this boundary?",
            input: b"\t\r",
        },
        PtyStep {
            wait_for: "OPEN grant",
            input: b"s",
        },
        PtyStep {
            wait_for: "choosing a final",
            input: b"\x1b[F",
        },
        PtyStep {
            wait_for: "\x1b[?25l",
            input: b"s",
        },
        PtyStep {
            wait_for: "Continue with OPEN authority?",
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
fn term_dumb_q_cancels_at_the_first_review_prompt() {
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
fn escape_at_access_overview_explains_how_to_cancel() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"\x1b",
        },
        PtyStep {
            wait_for: "q cancels setup.",
            input: b"q",
        },
    ];
    let (root, _xdg, transcript) =
        scripted_pty_steps("pty-lone-escape", &steps, &[], "xterm", 130);
    assert!(transcript.contains("q cancels setup."), "{transcript}");
    assert_eq!(transcript.matches("\x1b[?1049h").count(), 1);
    assert_tui_terminal_restored(&transcript);
    let _ = fs::remove_dir_all(root);
}

#[test]
fn backing_out_of_final_review_then_cancelling_does_not_save() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"5s",
        },
        PtyStep {
            wait_for: "choosing a final",
            input: b"b",
        },
        PtyStep {
            wait_for: "Review complete access",
            input: b"q",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty-review-back", &steps, &[], "xterm", 130);
    assert!(
        transcript.contains("Review draft discarded"),
        "{transcript}"
    );
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
            wait_for: "choosing a final",
            input: b"\x1b[F",
        },
        PtyStep {
            wait_for: "\x1b[?25l",
            input: b"s",
        },
        PtyStep {
            wait_for: "Continue with OPEN authority?",
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
fn forge_open_metadata_is_reviewed_without_reading_a_credential() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"5s",
        },
        PtyStep {
            wait_for: "choosing a final",
            input: b"\x1b[F",
        },
        PtyStep {
            wait_for: "owner/open-review",
            input: b"s",
        },
        PtyStep {
            wait_for: "Continue with OPEN authority?",
            input: b"\r",
        },
        PtyStep {
            wait_for: "cancelled.",
            input: b"s",
        },
        PtyStep {
            wait_for: "Continue with OPEN authority?",
            input: b"\t\r",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty-forge-open", &steps, &[], "xterm", 0);
    assert!(transcript.contains("cancelled."), "{transcript}");
    assert!(!transcript.contains("Type OPEN"), "{transcript}");
    assert!(transcript.contains("USER-ASSERTED"), "{transcript}");
    assert!(transcript.contains("PERSISTENT"), "{transcript}");
    assert!(transcript.contains("owner/open-review"), "{transcript}");
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
fn forge_scoped_metadata_is_allowed_without_open_confirmation() {
    let steps = [
        PtyStep {
            wait_for: "separately.",
            input: b"5s",
        },
        PtyStep {
            wait_for: "choosing a final",
            input: b"\x1b[F",
        },
        PtyStep {
            wait_for: "owner/allowed-review",
            input: b"s",
        },
    ];
    let (root, xdg, transcript) =
        scripted_pty_steps("pty-forge-allowed", &steps, &[], "xterm", 0);
    assert!(transcript.contains("[WARN] ALLOWED"), "{transcript}");
    assert!(transcript.contains("SCOPED"), "{transcript}");
    assert!(transcript.contains("PERSISTENT"), "{transcript}");
    assert!(transcript.contains("owner/allowed-review"), "{transcript}");
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
