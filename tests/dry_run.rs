//! A dry run renders the planned launch without creating persistent state.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::path::PathBuf;
use std::process::{Command, Output};

struct TestTree {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl TestTree {
    fn new(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("dry-run-{name}-{}", std::process::id()));
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        Self {
            root,
            home,
            project,
        }
    }

    fn run(&self, args: &[&str]) -> (Output, u32) {
        let child = Command::new(env!("CARGO_BIN_EXE_ai-jail"))
            .args([
                "--dry-run",
                "--no-mise",
                "--no-toolchains",
                "--no-agent-state",
                "--no-network",
            ])
            .args(args)
            .env("HOME", &self.home)
            .env_remove("AI_JAIL_QUIET")
            .current_dir(&self.project)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "{output:?}");
        (output, pid)
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn audit_dry_run_does_not_create_history() {
    let tree = TestTree::new("audit");
    let _ = tree.run(&["--audit-log", "/usr/bin/true"]);
    assert!(
        !tree.home.join(".local").exists(),
        "a dry run must not create audit storage"
    );
    assert!(!tree.project.join(".ai-jail").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn macos_dry_run_does_not_create_profile_directories() {
    for (name, args) in [
        ("ordinary", vec!["/usr/bin/true"]),
        ("browser", vec!["--browser=soft", "chromium"]),
    ] {
        let tree = TestTree::new(name);
        let (output, pid) = tree.run(&args);
        let stdout = String::from_utf8(output.stdout).unwrap();
        // The profile must still name the planned session directory even
        // though no launch has created it. Darwin's temp path has no quotes.
        let suffix = format!("/ai-jail-{pid}\"");
        let session_rule = stdout
            .lines()
            .find(|line| line.contains(&suffix))
            .expect("the dry-run profile must include its session temp path");
        let session = PathBuf::from(session_rule.split('"').nth(1).unwrap());
        let created = session.exists();
        // Clean up the regression's empty directory before reporting it.
        let _ = std::fs::remove_dir(&session);
        assert!(!created, "{name}: dry run created {}", session.display());
        assert!(
            !tree.home.join(".local").exists(),
            "a browser dry run must not create persistent profile storage"
        );
        if name == "browser" {
            assert!(stdout.contains("/browsers/chromium"));
            assert!(stdout.contains("--user-data-dir="));
        }
    }
}
