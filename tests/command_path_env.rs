//! Discovery must select the executable named by the child's PATH.
#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn explicit_path_selects_the_requested_binary() {
    if !Path::new("/bin/sh").is_file() {
        eprintln!("SKIPPED: /bin/sh unavailable");
        return;
    }
    #[cfg(target_os = "linux")]
    if !common::bwrap_net_available() {
        return;
    }
    #[cfg(target_os = "macos")]
    if !common::sandbox_exec_available() {
        return;
    }

    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let fixture = Fixture(
        PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("command-path-env-{}", std::process::id())),
    );
    let home = fixture.0.join("home");
    let project = home.join("project");
    let old = home.join("old-bin");
    let selected = home.join("selected-bin");
    for dir in [&project, &old, &selected] {
        std::fs::create_dir_all(dir).unwrap();
    }
    for (dir, marker) in [(&old, "OLD"), (&selected, "SELECTED")] {
        let binary = dir.join("fixture-agent");
        std::fs::write(&binary, format!("#!/bin/sh\nprintf '{marker}\\n'\n"))
            .unwrap();
        std::fs::set_permissions(
            &binary,
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
    }
    let host_path = format!("{}:/usr/bin:/bin", old.display());
    let child_path = format!("{}:{host_path}", selected.display());
    let env_file = fixture.0.join("child.env");
    std::fs::write(&env_file, format!("PATH={child_path}\n")).unwrap();
    std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o600))
        .unwrap();

    for from_file in [false, true] {
        let mut command = Command::new(common::ai_jail());
        command.args([
            "--clean",
            "--exec",
            "--no-mise",
            "--no-toolchains",
            "--no-agent-state",
            "--no-network",
            "--no-save-config",
            "--no-status-bar",
        ]);
        if from_file {
            command.arg("--env-from-file").arg(&env_file);
        } else {
            command.arg("--env").arg(format!("PATH={child_path}"));
        }
        let output = command
            .arg("fixture-agent")
            .current_dir(&project)
            .env_clear()
            .env("HOME", &home)
            .env("PATH", &host_path)
            .output()
            .unwrap();
        assert_eq!(
            common::assert_ok(&output),
            "SELECTED\n",
            "from_file={from_file}"
        );
    }
}
