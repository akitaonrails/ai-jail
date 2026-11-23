#![cfg(target_os = "linux")]
//! A limit no launch can honour is caught before anything is written or
//! reported ready. The maintainer's review of #229 found a syntactically
//! valid but unavailable CPU set saved by `--init`, refusing every later
//! start, while `status --json` still reported readiness.

mod common;

use common::ai_jail;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

struct Tree {
    root: PathBuf,
    project: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "limits-preflight-{name}-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        let home = root.join("home");
        let xdg = root.join("xdg");
        for dir in [&project, &home, &xdg] {
            std::fs::create_dir_all(dir).unwrap();
        }
        Self {
            root,
            project,
            home,
            xdg,
        }
    }

    fn write_global(&self, text: &str) {
        let store = self.xdg.join("ai-jail");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(
            &store,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let path = store.join("config.toml");
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    /// Every project policy document in the trusted store.
    fn saved_policies(&self) -> Vec<PathBuf> {
        std::fs::read_dir(self.xdg.join("ai-jail/projects"))
            .map(|entries| {
                entries.filter_map(Result::ok).map(|e| e.path()).collect()
            })
            .unwrap_or_default()
    }

    fn run(&self, args: &[&str]) -> Output {
        let _lock = common::SANDBOX_RUN_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Command::new(ai_jail())
            .args(args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env_remove("AI_JAIL_QUIET")
            .env_remove("NO_COLOR")
            .stdin(Stdio::null())
            .output()
            .expect("failed to run ai-jail")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// A CPU number the parser accepts but this process may not use.
fn unavailable_cpu() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let list = status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .expect("Cpus_allowed_list")
        .trim();
    let highest = list
        .split(',')
        .map(|part| part.rsplit('-').next().unwrap().parse::<usize>().unwrap())
        .max()
        .unwrap();
    (highest + 1).to_string()
}

fn available_cpu() -> String {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .expect("Cpus_allowed_list")
        .trim()
        .split([',', '-'])
        .next()
        .unwrap()
        .to_string()
}

fn blocker_codes(out: &Output) -> Vec<String> {
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| {
            panic!("status --json: {e}: {}", text(&out.stdout))
        });
    json["blockers"]
        .as_array()
        .expect("blockers array")
        .iter()
        .map(|b| b["code"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn status_json_reports_an_unavailable_cpu_set_as_a_blocker() {
    let tree = Tree::new("status-cli");
    let out = tree.run(&["--cpus", &unavailable_cpu(), "status", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        blocker_codes(&out)
            .iter()
            .any(|c| c == "limits_unavailable"),
        "{}",
        text(&out.stdout)
    );

    // The control: an available CPU is not a blocker.
    let out = tree.run(&["--cpus", &available_cpu(), "status", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        !blocker_codes(&out)
            .iter()
            .any(|c| c == "limits_unavailable"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn status_json_reports_a_global_unavailable_cpu_set_as_a_blocker() {
    let tree = Tree::new("status-global");
    tree.write_global(&format!("cpus = \"{}\"\n", unavailable_cpu()));
    let out = tree.run(&["status", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        blocker_codes(&out)
            .iter()
            .any(|c| c == "limits_unavailable"),
        "{}",
        text(&out.stdout)
    );
}

#[test]
fn plain_status_warns_that_a_launch_would_be_refused() {
    let tree = Tree::new("status-plain");
    let out = tree.run(&["--cpus", &unavailable_cpu(), "status"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        text(&out.stderr).contains("a launch would be refused"),
        "{}",
        text(&out.stderr)
    );
}

#[test]
fn init_refuses_an_unavailable_cpu_set_and_writes_no_policy() {
    for source in ["cli", "global"] {
        let tree = Tree::new(&format!("init-{source}"));
        let cpu = unavailable_cpu();
        let out = if source == "global" {
            tree.write_global(&format!("cpus = \"{cpu}\"\n"));
            tree.run(&["--init", "sh"])
        } else {
            tree.run(&["--cpus", &cpu, "--init", "sh"])
        };
        assert!(!out.status.success(), "{source}: --init must be refused");
        // `--cpus` for the flag, `global config cpus` for the config.
        assert!(
            text(&out.stderr).contains("cpus"),
            "{source}: names the cause: {}",
            text(&out.stderr)
        );
        assert!(
            tree.saved_policies().is_empty(),
            "{source}: nothing may be saved: {:?}",
            tree.saved_policies()
        );
    }
}

#[test]
fn a_refused_launch_auto_saves_no_policy() {
    let tree = Tree::new("auto-save");
    let out = tree.run(&[
        "--no-status-bar",
        "--cpus",
        &unavailable_cpu(),
        "sh",
        "-c",
        "true",
    ]);
    assert!(!out.status.success(), "the launch must be refused");
    assert!(
        tree.saved_policies().is_empty(),
        "auto-save ran before the refusal: {:?}",
        tree.saved_policies()
    );
}
