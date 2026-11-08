// Story 047 — `--profile NAME` through the built binary (Tasks 3.2, 3.3,
// 3.4): the widening lines, refusals at launch, the project file's
// inability to select a profile, saving, and the audit record.
//
// Each test gets a temporary HOME, XDG_CONFIG_HOME and project directory
// under CARGO_TARGET_TMPDIR. The `[profiles.*]` tables live in the trusted
// global config `$XDG_CONFIG_HOME/ai-jail/config.toml` (upstream v3.3.0;
// `~/.ai-jail` is only the legacy file it migrates), and the project
// policy that `--init` and auto-save write is the per-project document
// under `$XDG_CONFIG_HOME/ai-jail/projects/`. --dry-run tests need no
// sandbox; real launches need bwrap with network namespaces and skip with
// a message when it is unavailable (`require_bwrap_net!` from
// `tests/common/mod.rs`). Fixtures use only keys upstream/master knows
// (no cpus/rlimit), so this suite stands alone on feat/profiles.
#![cfg(target_os = "linux")]

mod common;

use common::ai_jail;
use std::collections::BTreeSet;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

/// A profile that widens (filtered-egress hosts, a capability, a secret
/// env entry) and also tightens (no_gpu).
const WIDE: &str = "\
[profiles.wide]
profile_version = 1
allow_hosts = [\"registry.npmjs.org\", \"api.example.com\"]
pictures = true
no_gpu = true
env_pass = [\"AJ047_SECRET=topsecret-value\"]
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
            .join(format!("aj047-prof-{name}-{}-{id}", std::process::id()));
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

    fn launch(&self, flags: &[&str], script: &str) -> Output {
        let _lock = common::SANDBOX_RUN_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut args = vec!["--no-status-bar", "--no-save-config"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["bash", "-c", script]);
        self.run(&args)
    }

    /// Every project policy this launch could have written: the per-project
    /// documents of the store and the legacy project `.ai-jail`, joined.
    /// A store document's `[project]` table is identity metadata (the
    /// canonical path and key), not policy, and is dropped: the checkout
    /// path may itself contain a word such as `profiles`.
    fn saved_project_policy(&self) -> String {
        let mut body = String::new();
        if let Ok(entries) =
            std::fs::read_dir(self.xdg.join("ai-jail/projects"))
        {
            for entry in entries.filter_map(Result::ok) {
                let text =
                    std::fs::read_to_string(entry.path()).unwrap_or_default();
                let mut doc: toml::Table =
                    text.parse().expect("project document is TOML");
                doc.remove("project");
                body.push_str(&toml::to_string(&doc).unwrap());
            }
        }
        body.push_str(
            &std::fs::read_to_string(self.project.join(".ai-jail"))
                .unwrap_or_default(),
        );
        body
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

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn assert_ok(o: &Output) {
    assert!(
        o.status.success(),
        "ai-jail failed: {:?}\nstdout={}\nstderr={}",
        o.status,
        stdout(o),
        stderr(o)
    );
}

fn assert_refused(o: &Output) -> String {
    assert!(
        !o.status.success(),
        "launch must be refused\nstdout={}\nstderr={}",
        stdout(o),
        stderr(o)
    );
    stderr(o)
}

/// The `profile=<name> widens=...` lines of stderr, with any warning glyph
/// in front stripped.
fn widening_lines(o: &Output, name: &str) -> BTreeSet<String> {
    let needle = format!("profile={name} ");
    stderr(o)
        .lines()
        .filter_map(|l| l.find(&needle).map(|at| l[at..].trim().to_string()))
        .filter(|l| l.contains("widens="))
        .collect()
}

fn line_for<'a>(
    lines: &'a BTreeSet<String>,
    field: &str,
) -> Option<&'a String> {
    let needle = format!("widens={field} ");
    lines.iter().find(|l| l.contains(&needle))
}

// ── Task 3.2 — the widening lines (R7.1, R7.6, R8.3) ─────────────────

#[test]
fn widening_lines_name_profile_field_and_values_without_verbose() {
    let tree = Tree::new("lines", WIDE);
    let out = tree.dry_run(&["--profile", "wide"]);
    assert_ok(&out);
    let lines = widening_lines(&out, "wide");
    let hosts = line_for(&lines, "allow_hosts").expect("allow_hosts line");
    assert!(
        hosts.contains("registry.npmjs.org")
            && hosts.contains("api.example.com"),
        "{hosts}"
    );
    assert!(
        line_for(&lines, "pictures").is_some(),
        "capability line: {lines:?}"
    );
    // A tightening is not a widening.
    assert!(line_for(&lines, "no_gpu").is_none(), "{lines:?}");
}

#[test]
fn widening_lines_never_carry_a_secret_value() {
    let tree = Tree::new("secret", WIDE);
    let out = tree.dry_run(&["--profile", "wide"]);
    assert_ok(&out);
    let err = stderr(&out);
    assert!(
        !err.contains("topsecret-value"),
        "secret value on stderr: {err}"
    );
    let lines = widening_lines(&out, "wide");
    let env =
        line_for(&lines, "env_pass").expect("env_pass line names the key");
    assert!(env.contains("AJ047_SECRET"), "{env}");
}

#[test]
fn dry_run_prints_the_same_widening_lines_as_a_real_launch() {
    require_bwrap_net!();
    let tree = Tree::new("same-lines", WIDE);
    let dry = tree.dry_run(&["--profile", "wide"]);
    assert_ok(&dry);
    let real = tree.launch(&["--profile", "wide"], "true");
    assert_ok(&real);
    let dry_lines = widening_lines(&dry, "wide");
    assert!(!dry_lines.is_empty());
    assert_eq!(dry_lines, widening_lines(&real, "wide"));
}

// ── Selection and refusals at launch (R6.1, R6.3, R6.5, R6.9, R7.3) ──

#[test]
fn profile_given_twice_is_refused() {
    let tree = Tree::new("twice", WIDE);
    // One --profile is a valid launch; the refusal is about the repetition.
    assert_ok(&tree.dry_run(&["--profile", "wide"]));
    let err = assert_refused(&tree.dry_run(&[
        "--profile",
        "wide",
        "--profile",
        "wide",
    ]));
    assert!(err.contains("--profile"), "{err}");
}

#[test]
fn profile_unknown_key_fails_the_launch_before_anything_runs() {
    let tree = Tree::new(
        "unknown-key",
        "[profiles.typo]\nprofile_version = 1\nallow_host = [\"x.example\"]\n",
    );
    let out = tree.dry_run(&["--profile", "typo"]);
    let err = assert_refused(&out);
    assert!(err.contains("typo") && err.contains("allow_host"), "{err}");
    assert!(
        stdout(&out).is_empty(),
        "nothing may be printed as a launch"
    );
}

#[test]
fn missing_profile_lists_the_defined_names() {
    let tree = Tree::new("missing", WIDE);
    let err = assert_refused(&tree.dry_run(&["--profile", "nope"]));
    assert!(err.contains("nope") && err.contains("wide"), "{err}");
}

#[test]
fn malformed_unselected_profile_is_harmless_and_a_sibling_still_selects() {
    let global = format!(
        "{WIDE}\n[profiles.bad]\nprofile_version = \"x\"\nallow_hosts = 3\n"
    );
    let tree = Tree::new("malformed-sibling", &global);
    assert_ok(&tree.dry_run(&[]));
    let out = tree.dry_run(&["--profile", "wide"]);
    assert_ok(&out);
    assert!(!widening_lines(&out, "wide").is_empty());
    let err = assert_refused(&tree.dry_run(&["--profile", "bad"]));
    assert!(err.contains("bad"), "{err}");
}

// ── Task 3.3 — the project file and saving (R6.6, R7.7) ──────────────

#[test]
fn project_file_cannot_select_a_profile_and_is_warned() {
    let tree = Tree::new("project-select", WIDE);
    std::fs::write(
        tree.project.join(".ai-jail"),
        "profile = \"wide\"\n[profiles.evil]\nprofile_version = 1\nnetwork = true\n",
    )
    .unwrap();
    let out = tree.dry_run(&[]);
    assert_ok(&out);
    let err = stderr(&out);
    assert!(
        err.lines().any(|l| {
            let l = l.to_lowercase();
            l.contains("profile") && l.contains("cli")
        }),
        "missing the 'only the CLI selects a profile' warning: {err}"
    );
    assert!(widening_lines(&out, "wide").is_empty(), "{err}");
    assert!(widening_lines(&out, "evil").is_empty(), "{err}");
}

#[test]
fn init_never_writes_a_profile_key_into_the_project_file() {
    let tree = Tree::new("init", WIDE);
    let out = tree.run(&["--profile", "wide", "--init", "bash"]);
    assert_ok(&out);
    let body = tree.saved_project_policy();
    assert!(!body.is_empty(), "--init writes the project policy");
    for leaked in ["registry.npmjs.org", "pictures", "profile", "AJ047_SECRET"]
    {
        assert!(
            !body.contains(leaked),
            "{leaked} leaked into the project policy:\n{body}"
        );
    }
}

#[test]
fn auto_save_never_writes_a_profile_key_into_the_project_file() {
    require_bwrap_net!();
    let tree = Tree::new("auto-save", WIDE);
    let _lock = common::SANDBOX_RUN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Without --no-save-config: a normal launch auto-saves the project
    // policy.
    let out = tree.run(&[
        "--no-status-bar",
        "--profile",
        "wide",
        "bash",
        "-c",
        "true",
    ]);
    assert_ok(&out);
    let body = tree.saved_project_policy();
    for leaked in ["registry.npmjs.org", "pictures", "profile", "AJ047_SECRET"]
    {
        assert!(
            !body.contains(leaked),
            "{leaked} leaked into the project policy:\n{body}"
        );
    }
}

// ── Task 3.4 — the audit launch record (R8.1, R8.3) ──────────────────

#[test]
fn audit_record_carries_the_profile_and_its_widenings() {
    require_bwrap_net!();
    let tree = Tree::new("audit", WIDE);
    let out = tree.launch(&["--audit-log", "--profile", "wide"], "exit 4");
    assert_eq!(out.status.code(), Some(4), "stderr={}", stderr(&out));
    let log = tree.home.join(".local/share/ai-jail/history.jsonl");
    let content = std::fs::read_to_string(&log).unwrap();
    assert!(
        !content.contains("topsecret-value"),
        "secret value recorded"
    );
    let record: serde_json::Value =
        serde_json::from_str(content.lines().last().unwrap()).unwrap();
    assert_eq!(record["type"], "launch");
    assert_eq!(record["exit_code"], 4);
    assert_eq!(record["profile"]["name"], "wide");
    let widenings = record["profile"]["widenings"]
        .as_array()
        .expect("widenings");
    let hosts = widenings
        .iter()
        .find(|w| w["field"] == "allow_hosts")
        .expect("allow_hosts widening");
    let granted: Vec<&str> = hosts["granted"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(granted.contains(&"registry.npmjs.org"), "{granted:?}");
    assert!(granted.contains(&"api.example.com"), "{granted:?}");
    let env = widenings
        .iter()
        .find(|w| w["field"] == "env_pass")
        .expect("env_pass widening");
    assert_eq!(env["granted"], serde_json::json!(["AJ047_SECRET"]));
}
