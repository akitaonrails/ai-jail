// Through the built binary: a profile's widening lines print under
// `--exec`, where ordinary warnings are quiet; a mistyped `env_pass`
// refuses the launch without its value reaching stderr; and a stray
// non-table `[profiles]` entry leaves a launch that names no profile
// untouched, while selecting it is refused by name. Each test gets a
// temporary HOME, XDG_CONFIG_HOME and project; the global config is
// `$XDG_CONFIG_HOME/ai-jail/config.toml`, dir 0700, file 0600. Dry runs
// need no sandbox; the real launch skips when bwrap with network
// namespaces is unavailable.
#![cfg(target_os = "linux")]

mod common;

use common::ai_jail;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

const WIDE: &str = "\
[profiles.wide]
profile_version = 1
allow_hosts = [\"registry.npmjs.org\", \"api.example.com\"]
pictures = true
";

struct Tree {
    root: PathBuf,
    project: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
}

impl Tree {
    fn new(name: &str, global: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("aj-prof-trust-{name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        let home = root.join("home");
        let xdg = root.join("xdg");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(home.join("Pictures")).unwrap();
        let store = xdg.join("ai-jail");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(
            &store,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let config = store.join("config.toml");
        std::fs::write(&config, global).unwrap();
        std::fs::set_permissions(
            &config,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Self {
            root,
            project,
            home,
            xdg,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(ai_jail())
            .args(args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env_remove("AI_JAIL_QUIET")
            .stdin(Stdio::null())
            .output()
            .expect("failed to run ai-jail")
    }

    fn dry_run(&self, flags: &[&str]) -> Output {
        let mut args = vec!["--no-status-bar", "--no-save-config"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["--dry-run", "bash"]);
        self.run(&args)
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn assert_ok(o: &Output) {
    assert!(
        o.status.success(),
        "ai-jail failed: {:?}\nstdout={}\nstderr={}",
        o.status,
        String::from_utf8_lossy(&o.stdout),
        stderr(o)
    );
}

fn assert_refused(o: &Output) -> String {
    assert!(
        !o.status.success(),
        "launch must be refused\nstderr={}",
        stderr(o)
    );
    stderr(o)
}

/// The widening lines for `name`: `profile=<name> widens=<field> ...`.
fn widening_fields(o: &Output, name: &str) -> Vec<String> {
    let needle = format!("profile={name} widens=");
    stderr(o)
        .lines()
        .filter_map(|l| l.find(&needle).map(|at| &l[at + needle.len()..]))
        .map(|rest| rest.split(' ').next().unwrap_or("").to_string())
        .collect()
}

// ── Widenings are never quiet ─────────────────────────────────

#[test]
fn widening_lines_print_under_exec_dry_run() {
    let tree = Tree::new("exec-dry", WIDE);
    // Premise: the same profile prints its lines without --exec.
    let plain = tree.dry_run(&["--profile", "wide"]);
    assert_ok(&plain);
    let expected = widening_fields(&plain, "wide");
    assert!(
        expected.contains(&"allow_hosts".to_string()),
        "{expected:?}"
    );
    let exec = tree.dry_run(&["--exec", "--profile", "wide"]);
    assert_ok(&exec);
    assert_eq!(
        widening_fields(&exec, "wide"),
        expected,
        "--exec hid widening lines: {}",
        stderr(&exec)
    );
}

#[test]
fn widening_lines_print_under_exec_real_launch() {
    require_bwrap_net!();
    let tree = Tree::new("exec-real", WIDE);
    let _lock = common::SANDBOX_RUN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let out = tree.run(&[
        "--no-status-bar",
        "--no-save-config",
        "--exec",
        "--profile",
        "wide",
        "bash",
        "-c",
        "true",
    ]);
    assert_ok(&out);
    let got = widening_fields(&out, "wide");
    for field in ["allow_hosts", "pictures"] {
        assert!(
            got.contains(&field.to_string()),
            "{field} missing under --exec: {}",
            stderr(&out)
        );
    }
}

// ── A mistyped secret field never echoes ───────────────

#[test]
fn mistyped_env_pass_is_refused_without_the_secret_on_stderr() {
    let tree = Tree::new(
        "env-pass-type",
        "[profiles.p]\nprofile_version = 1\nenv_pass = \"API_KEY=sk-live-TOPSECRET\"\n",
    );
    let out = tree.dry_run(&["--profile", "p"]);
    let err = assert_refused(&out);
    for fragment in ["API_KEY", "sk-live", "TOPSECRET"] {
        assert!(!err.contains(fragment), "{fragment:?} echoed: {err}");
    }
    assert!(
        String::from_utf8_lossy(&out.stdout).is_empty(),
        "nothing may be printed as a launch"
    );
    assert!(err.contains("'p'") && err.contains("env_pass"), "{err}");
}

// ── A stray [profiles] entry ──────────────────────────

#[test]
fn plain_launch_with_a_stray_profiles_entry_succeeds() {
    let global = format!("[profiles]\ndefault = \"wide\"\n\n{WIDE}");
    let tree = Tree::new("stray", &global);
    let out = tree.dry_run(&[]);
    assert_ok(&out);
    assert!(widening_fields(&out, "wide").is_empty(), "{}", stderr(&out));
    // The sibling table still selects ...
    let wide = tree.dry_run(&["--profile", "wide"]);
    assert_ok(&wide);
    assert!(!widening_fields(&wide, "wide").is_empty());
    // ... and the stray entry, once selected, is refused by name.
    let err = assert_refused(&tree.dry_run(&["--profile", "default"]));
    assert!(err.contains("default"), "{err}");
}
