//! Command discovery must follow relative launch paths out of the project.
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

struct Fixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("relative-command-{name}-{}", std::process::id()));
        let home = root.join("home");
        let project = home.join("project");
        let tools = home.join("tools");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&tools).unwrap();
        let target = tools.join("fixture-agent");
        std::fs::write(&target, "#!/bin/sh\nprintf 'agent-ok\\n'\n").unwrap();
        std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        symlink("../tools/fixture-agent", project.join("agent-link")).unwrap();
        Self {
            root,
            home,
            project,
        }
    }

    fn run(&self, executable: &str, path: &str) -> String {
        common::assert_ok(
            &Command::new(common::ai_jail())
                .args([
                    "--clean",
                    "--exec",
                    "--no-mise",
                    "--no-toolchains",
                    "--no-agent-state",
                    "--no-network",
                    "--no-save-config",
                    "--no-status-bar",
                    executable,
                ])
                .current_dir(&self.project)
                .env_clear()
                .env("HOME", &self.home)
                .env("PATH", path)
                .output()
                .unwrap(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn available() -> bool {
    if !Path::new("/bin/sh").is_file() {
        eprintln!("SKIPPED: /bin/sh unavailable");
        return false;
    }
    #[cfg(target_os = "linux")]
    let available = common::bwrap_net_available();
    #[cfg(target_os = "macos")]
    let available = common::sandbox_exec_available();
    if !available {
        eprintln!("SKIPPED: sandbox backend unavailable");
    }
    available
}

#[test]
fn relative_commands_can_reach_their_install_directory() {
    if !available() {
        return;
    }
    let fixture = Fixture::new("explicit");
    for executable in ["./agent-link", "../tools/fixture-agent"] {
        assert_eq!(fixture.run(executable, "/usr/bin:/bin"), "agent-ok\n");
    }
}

#[test]
fn relative_path_entries_can_reach_their_install_directory() {
    if !available() {
        return;
    }
    let fixture = Fixture::new("path");
    assert_eq!(
        fixture.run("fixture-agent", "../tools:/usr/bin:/bin"),
        "agent-ok\n"
    );
}

#[test]
fn empty_path_entry_resolves_against_the_project() {
    if !available() {
        return;
    }
    let fixture = Fixture::new("empty-path");
    assert_eq!(fixture.run("agent-link", ":/usr/bin:/bin"), "agent-ok\n");
}
