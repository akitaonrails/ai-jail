mod common;

use std::fs;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Stdio};

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
    assert!(stderr.contains("AJ-NONTTY-002"), "{stderr}");
    assert!(stderr.contains("No configuration was changed"), "{stderr}");
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
    assert!(stderr.contains("AJ-NONTTY-001"), "{stderr}");
    assert!(
        stderr.contains("AJ-FINAL-001 Complete effective access"),
        "{stderr}"
    );
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
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("onboarding-{label}-{}", std::process::id()));
    let project = root.join("project");
    let home = root.join("home");
    let xdg = root.join("xdg");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&project).unwrap();
    fs::create_dir_all(&home).unwrap();
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

    let pty = nix::pty::openpty(None, None).unwrap();
    let slave_fd = pty.slave.as_raw_fd();
    let mut command = Command::new(common::ai_jail());
    command
        .args(["configure", "claude"])
        .current_dir(&project)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("NO_COLOR", "")
        .env("TERM", term);
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
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader_done = done.clone();
    let reader = std::thread::spawn(move || {
        use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
        use std::os::fd::BorrowedFd;
        use std::sync::atomic::Ordering;

        let reader = unsafe { std::os::fd::OwnedFd::from_raw_fd(reader_fd) };
        let mut bytes = Vec::new();
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
                Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            }
        }
        bytes
    });
    if let Some(split) = delayed_split {
        nix::unistd::write(&pty.master, &input[..split]).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(150));
        nix::unistd::write(&pty.master, &input[split..]).unwrap();
    } else {
        nix::unistd::write(&pty.master, input).unwrap();
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
    let bytes = reader.join().unwrap();
    let transcript = String::from_utf8_lossy(&bytes);
    assert_eq!(status.code(), Some(expected_code), "{transcript}");
    (root, xdg, transcript.into_owned())
}

#[test]
fn scripted_pty_can_select_api_review_and_save() {
    let (root, xdg, transcript) =
        scripted_pty("pty", b"1y\nsy\n", &[], "xterm", 0, None);
    for expected in
        ["AJ-ONB-001", "AJ-GRANT-001", "AJ-FINAL-001", "AJ-SAVE-001"]
    {
        assert!(transcript.contains(expected), "{transcript}");
    }
    assert!(!transcript.contains("\x1b["), "NO_COLOR must disable ANSI");
    let mut normalized = transcript.replace('\r', "");
    normalized =
        normalized.replace(&root.to_string_lossy().to_string(), "<ROOT>");
    if let Some(start) = normalized.find("projects/project-")
        && let Some(relative_end) = normalized[start..].find(".toml")
    {
        let end = start + relative_end + ".toml".len();
        normalized.replace_range(start..end, "projects/<POLICY>.toml");
    }
    let fixture = include_str!("fixtures/onboarding/pty-secure-save.txt");
    assert_eq!(normalized, fixture);
    assert!(include_str!("../docs/USER_GUIDE.md").contains(fixture));
    assert!(xdg.join("ai-jail/projects").is_dir());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn scripted_pty_environment_checklist_never_displays_or_saves_values() {
    let (root, xdg, transcript) = scripted_pty(
        "pty-env",
        b"eCUSTOM_MODE\nOPEN\nsOPEN\ny\n",
        &[("CUSTOM_MODE", "secret-value-that-must-never-appear")],
        "xterm",
        0,
        None,
    );
    assert!(transcript.contains("AJ-ENV-001"), "{transcript}");
    assert!(transcript.contains("CUSTOM_MODE"), "{transcript}");
    assert!(transcript.contains("value hidden"), "{transcript}");
    assert!(!transcript.contains("secret-value-that-must-never-appear"));

    let policies = fs::read_dir(xdg.join("ai-jail/projects")).unwrap();
    let policy_path = policies.into_iter().next().unwrap().unwrap().path();
    let policy = fs::read_to_string(policy_path).unwrap();
    assert!(policy.contains("CUSTOM_MODE"));
    assert!(!policy.contains("secret-value-that-must-never-appear"));
    let _ = fs::remove_dir_all(root);
}

#[cfg(feature = "test-hooks")]
#[test]
fn scripted_pty_adds_removes_constrains_and_saves_restricted_ssh() {
    let input = b"ka\n1\nkr\n1\nka\n1\nkh\ngit@github.com\n6OPEN\nsOPEN\ny\n";
    let (root, xdg, transcript) =
        scripted_pty("pty-restricted-ssh", input, &[], "xterm", 0, None);
    let root_text = root.to_string_lossy();
    let mut normalized = transcript
        .replace('\r', "")
        .replace(root_text.as_ref(), "<ROOT>");
    if let Some(start) = normalized.find("projects/project-")
        && let Some(relative_end) = normalized[start..].find(".toml")
    {
        let end = start + relative_end + ".toml".len();
        normalized.replace_range(start..end, "projects/<POLICY>.toml");
    }
    let begin = normalized
        .find("AJ-SSH-TRANSCRIPT-BEGIN")
        .expect("production transcript begin marker");
    let end_marker = "AJ-SSH-TRANSCRIPT-END selected-key SSH interaction";
    let end = normalized[begin..]
        .find(end_marker)
        .map(|offset| begin + offset + end_marker.len())
        .expect("production transcript end marker");
    let security_transcript = format!("{}\n", &normalized[begin..end]);
    let fixture = include_str!("fixtures/onboarding/pty-restricted-ssh.txt");
    assert_eq!(security_transcript, fixture);
    let fenced = format!("```text\n{fixture}```");
    assert!(include_str!("../docs/USER_GUIDE.md").contains(&fenced));
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
fn scripted_pty_arrows_and_space_select_the_highlighted_row() {
    let (root, xdg, transcript) = scripted_pty(
        "pty-arrows",
        b"\x1b[B\x1b[A y\nsy\n",
        &[],
        "xterm",
        0,
        None,
    );
    assert!(
        transcript.contains("[OK] Selected: host harness state"),
        "{transcript}"
    );
    assert!(
        transcript.contains("[OK] Selected: filtered model API"),
        "{transcript}"
    );
    assert!(transcript.contains("api.anthropic.com"));
    assert!(xdg.join("ai-jail/projects").is_dir());
    let _ = fs::remove_dir_all(root);
}

#[test]
fn term_dumb_q_cancels_at_the_first_review_prompt() {
    let (root, xdg, transcript) =
        scripted_pty("pty-dumb-q", b"q\n", &[], "dumb", 130, None);
    assert!(transcript.contains("Plain-terminal mode"));
    assert!(transcript.contains("AJ-CANCEL-001"));
    let projects = xdg.join("ai-jail/projects");
    assert!(
        !projects.exists() || fs::read_dir(projects).unwrap().next().is_none()
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn lone_escape_returns_without_waiting_for_an_arrow_sequence() {
    let (root, _xdg, transcript) =
        scripted_pty("pty-lone-escape", b"\x1bq", &[], "xterm", 130, Some(1));
    assert!(transcript.matches("AJ-CHOICE-001 Access choices").count() >= 2);
    assert!(transcript.contains("AJ-CANCEL-001"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn directory_tab_completion_accepts_utf8_paths() {
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("onboarding-pty-utf8-tab-{}", std::process::id()));
    let input = format!("r{}/share-caf\t\ny\nsy\n", root.to_string_lossy());
    let (root, xdg, transcript) =
        scripted_pty("pty-utf8-tab", input.as_bytes(), &[], "xterm", 0, None);
    assert!(transcript.contains("share-café"), "{transcript}");
    assert!(xdg.join("ai-jail/projects").is_dir());
    let _ = fs::remove_dir_all(root);
}
