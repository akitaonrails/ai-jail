//! Command selection through the real CLI, with isolated project/global config.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::path::PathBuf;
use std::process::Command;

mod common;

struct TestTree {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
}

impl TestTree {
    fn new(name: &str, trusted: bool, project_command: bool) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("config-command-{name}-{}", std::process::id()));
        let home = root.join("home");
        let project = root.join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let mut global =
            String::from("command = [\"/usr/bin/printf\", \"GLOBAL\"]\n");
        if trusted {
            global.push_str(&format!(
                "trust_project_config = [{}]\n",
                toml::Value::String(project.to_str().unwrap().into())
            ));
        }
        // The CLI command selects its global table before the project merge.
        global.push_str(
            "[commands.\"/bin/sh\"]\n\
             env_pass = [\"COMMAND_PREFERENCE=CLI\"]\n",
        );
        std::fs::write(home.join(".ai-jail"), global).unwrap();
        std::fs::write(
            project.join(".ai-jail"),
            if project_command {
                "command = [\"/usr/bin/printf\", \"PROJECT\"]\n"
            } else {
                ""
            },
        )
        .unwrap();
        Self {
            root,
            home,
            project,
        }
    }

    fn run(&self, command: &[&str]) -> String {
        let output = Command::new(common::ai_jail())
            .args([
                "--exec",
                "--no-save-config",
                "--no-mise",
                "--no-toolchains",
                "--no-agent-state",
                "--no-network",
            ])
            .args(command)
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .current_dir(&self.project)
            .output()
            .unwrap();
        common::assert_ok(&output)
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn sandbox_available() -> bool {
    if !std::path::Path::new("/usr/bin/printf").is_file()
        || !std::path::Path::new("/bin/sh").is_file()
    {
        eprintln!(
            "SKIPPED: command fixtures require /usr/bin/printf and /bin/sh"
        );
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
fn cli_command_overrides_trusted_and_untrusted_project_commands() {
    if !sandbox_available() {
        return;
    }
    for trusted in [false, true] {
        let tree = TestTree::new("explicit", trusted, true);
        assert_eq!(
            tree.run(&["/usr/bin/printf", "CLI"]),
            "CLI",
            "project trusted: {trusted}"
        );
    }
}

#[test]
fn no_cli_command_keeps_project_then_global_fallbacks() {
    if !sandbox_available() {
        return;
    }
    for trusted in [false, true] {
        for project_command in [false, true] {
            let tree = TestTree::new("fallback", trusted, project_command);
            assert_eq!(
                tree.run(&[]),
                if project_command { "PROJECT" } else { "GLOBAL" },
                "project trusted: {trusted}, command: {project_command}"
            );
        }
    }
}

#[test]
fn cli_command_keeps_its_global_command_preferences() {
    if !sandbox_available() {
        return;
    }
    let tree = TestTree::new("preferences", true, true);
    assert_eq!(
        tree.run(&["/bin/sh", "-c", "printf '%s' \"$COMMAND_PREFERENCE\""]),
        "CLI"
    );
}
