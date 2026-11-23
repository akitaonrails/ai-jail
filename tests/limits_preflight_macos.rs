#![cfg(target_os = "macos")]
//! An explicit `--rlimit` is Linux only, and that refusal comes before
//! anything is written or reported ready. The maintainer's review of #229
//! found the platform check running after the `--init` and
//! `status --json` return paths, so a limit no later launch could honour
//! was saved while status still reported readiness. macOS is the platform
//! where this refusal fires, so the test runs there.

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
        // The trusted store refuses a symlink anywhere in its path, and a
        // macOS temp dir can sit under /var -> /private/var: resolve first.
        let tmp = std::fs::canonicalize(env!("CARGO_TARGET_TMPDIR"))
            .expect("target tmp dir resolves");
        let root = tmp.join(format!(
            "limits-preflight-macos-{name}-{}-{id}",
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
fn status_json_reports_an_explicit_rlimit_as_a_blocker() {
    let tree = Tree::new("status-cli");
    let out = tree.run(&["--rlimit", "nofile=1024", "status", "--json"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(
        blocker_codes(&out)
            .iter()
            .any(|c| c == "limits_unavailable"),
        "{}",
        text(&out.stdout)
    );

    // The control: no explicit limit, no such blocker.
    let out = tree.run(&["status", "--json"]);
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
fn status_json_reports_a_global_rlimit_as_a_blocker() {
    let tree = Tree::new("status-global");
    tree.write_global("[rlimit]\nnofile = 1024\n");
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
fn init_refuses_an_explicit_rlimit_and_writes_no_policy() {
    for source in ["cli", "global"] {
        let tree = Tree::new(&format!("init-{source}"));
        let out = if source == "global" {
            tree.write_global("[rlimit]\nnofile = 1024\n");
            tree.run(&["--init", "sh"])
        } else {
            tree.run(&["--rlimit", "nofile=1024", "--init", "sh"])
        };
        assert!(!out.status.success(), "{source}: --init must be refused");
        assert!(
            text(&out.stderr).contains("rlimit"),
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
