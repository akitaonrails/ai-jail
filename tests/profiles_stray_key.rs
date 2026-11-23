// Through the built binary: a global config carrying an unknown
// top-level `profiles = 5`, which releases before profiles ignore, still
// launches when no profile is named, and `status` / `status --json` with
// `--profile w` name the selected profile —
// in a field of its own, not the onboarding `project.profile_present`.
// Each test gets a temporary HOME, XDG_CONFIG_HOME and project under the
// cargo target tmp dir; the global config is
// `$XDG_CONFIG_HOME/ai-jail/config.toml`, dir 0700, file 0600. Dry runs
// and `status` need no sandbox.
#![cfg(target_os = "linux")]

mod common;

use common::ai_jail;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

const W: &str = "\
[profiles.w]
profile_version = 1
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
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "aj-prof-stray-key-{name}-{}-{id}",
            std::process::id()
        ));
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
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
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

/// Every JSON path (dotted keys, `[i]` for arrays) whose string value is
/// exactly `value`.
fn paths_with_string(
    v: &serde_json::Value,
    value: &str,
    at: String,
    out: &mut Vec<String>,
) {
    match v {
        serde_json::Value::String(s) if s == value => out.push(at),
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                let next = if at.is_empty() {
                    k.clone()
                } else {
                    format!("{at}.{k}")
                };
                paths_with_string(child, value, next, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (i, child) in items.iter().enumerate() {
                paths_with_string(child, value, format!("{at}[{i}]"), out);
            }
        }
        _ => {}
    }
}

/// Whether `line` carries `word` as a whole token.
fn has_token(line: &str, word: &str) -> bool {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'))
        .any(|t| t == word)
}

// ── An unknown top-level `profiles` key is inert ─────────────────────

#[test]
fn plain_launch_with_a_non_table_profiles_key_exits_zero() {
    // The shapes an existing v3.3.0 config could already carry, none of
    // which v3.3.0 refuses.
    for (tag, global) in [
        ("int", "profiles = 5\n"),
        ("str", "profiles = \"x\"\n"),
        (
            "aot",
            "[[profiles]]\nprofile_version = 1\npictures = true\n",
        ),
    ] {
        let tree = Tree::new(tag, &format!("no_gpu = true\n{global}"));
        let out = tree.run(&[
            "--no-status-bar",
            "--no-save-config",
            "--dry-run",
            "bash",
        ]);
        assert_ok(&out);
        assert!(
            !stderr(&out).contains("widens="),
            "{tag}: no profile selected, yet a widening: {}",
            stderr(&out)
        );
    }
}

#[test]
fn profile_with_a_non_table_profiles_key_is_refused_as_a_table() {
    // The converse: the same file, once a profile is named, is refused,
    // saying `profiles` must be a table.
    let tree = Tree::new("int-sel", "profiles = 5\n");
    let out = tree.run(&[
        "--no-status-bar",
        "--no-save-config",
        "--profile",
        "x",
        "--dry-run",
        "bash",
    ]);
    assert!(!out.status.success(), "must refuse: {}", stderr(&out));
    let err = stderr(&out);
    assert!(err.contains("profiles") && err.contains("table"), "{err}");
}

// ── Status names the selected profile ────────────────────────────────

#[test]
fn status_json_names_the_selected_profile() {
    let tree = Tree::new("status-json", W);
    let out = tree.run(&["--profile", "w", "status", "--json"]);
    assert_ok(&out);
    // Premise: the profile was applied (its widening line printed).
    assert!(
        stderr(&out).contains("profile=w widens=pictures"),
        "{}",
        stderr(&out)
    );
    let json: serde_json::Value = serde_json::from_str(&stdout(&out))
        .unwrap_or_else(|e| panic!("status --json: {e}\n{}", stdout(&out)));
    let mut hits = Vec::new();
    paths_with_string(&json, "w", String::new(), &mut hits);
    let named: Vec<&String> = hits
        .iter()
        .filter(|p| p.to_lowercase().contains("profile"))
        .filter(|p| !p.starts_with("project.profile_present"))
        .collect();
    assert!(
        !named.is_empty(),
        "no profile field carries \"w\" (string hits: {hits:?}):\n{json:#}"
    );
}

#[test]
fn status_json_names_no_profile_when_none_is_selected() {
    // The converse: the same global, no --profile — nothing in the
    // report may claim that `w` is in force.
    let tree = Tree::new("status-json-none", W);
    let out = tree.run(&["status", "--json"]);
    assert_ok(&out);
    let json: serde_json::Value = serde_json::from_str(&stdout(&out))
        .unwrap_or_else(|e| panic!("status --json: {e}\n{}", stdout(&out)));
    let mut hits = Vec::new();
    paths_with_string(&json, "w", String::new(), &mut hits);
    assert!(hits.is_empty(), "{hits:?}:\n{json:#}");
}

#[test]
fn status_text_names_the_selected_profile() {
    let tree = Tree::new("status-text", W);
    let out = tree.run(&["--profile", "w", "status"]);
    assert_ok(&out);
    let all = format!("{}{}", stdout(&out), stderr(&out));
    // Premise: the profile was applied.
    assert!(all.contains("profile=w widens=pictures"), "{all}");
    // The widening line itself does not count: status must name it.
    let named: Vec<&str> = all
        .lines()
        .filter(|l| !l.contains("widens="))
        .filter(|l| l.to_lowercase().contains("profile") && has_token(l, "w"))
        .collect();
    assert!(!named.is_empty(), "status does not name profile w:\n{all}");
}
