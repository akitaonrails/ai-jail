// The project's own limit survives save and migration, through the built
// binary.
//
// Both cases use a trusted `nproc = 8192` above the built-in default
// (4096) and a project `nproc = 6000` between the two.
//
// - External project document: a real launch auto-saves the policy; the
//   next `--dry-run` must still report the project's 6000.
// - Legacy repository `.ai-jail`: the launch that migrates it must run at
//   the 6000 `--dry-run` reported, and the written project document must
//   hold `nproc = 6000` before the legacy file is gone.
//
// Each test runs with a temporary HOME, XDG_CONFIG_HOME and project
// directory, so the developer's own config cannot leak in. Tests skip
// with a message when bwrap cannot create user namespaces.
#![cfg(target_os = "linux")]

mod common;

use common::ai_jail;
use sha2::{Digest, Sha256};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

const GLOBAL_NPROC_8192: &str = "[rlimit]\nnproc = 8192\n";

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
            "rlimit-project-save-{name}-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        let home = root.join("home");
        let xdg = root.join("xdg");
        for dir in [&project, &home, &xdg] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let project = project.canonicalize().unwrap();
        Self {
            root,
            project,
            home,
            xdg,
        }
    }

    fn store(&self) -> PathBuf {
        self.xdg.join("ai-jail")
    }

    fn prepare_store(&self) {
        let projects = self.store().join("projects");
        std::fs::create_dir_all(&projects).unwrap();
        for dir in [self.store(), projects] {
            std::fs::set_permissions(
                dir,
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
    }

    fn write_private(&self, path: &Path, text: &str) {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    fn write_global(&self, text: &str) {
        self.prepare_store();
        self.write_private(&self.store().join("config.toml"), text);
    }

    fn project_doc_path(&self) -> PathBuf {
        self.store()
            .join("projects")
            .join(format!("{}.toml", project_key(&self.project)))
    }

    /// The external project document, as onboarding saves it, carrying
    /// `constraints` (a TOML body for `[constraints.rlimit]`).
    fn write_project_doc(&self, rlimit_constraints: &str) {
        self.prepare_store();
        let key = project_key(&self.project);
        let doc = format!(
            "schema_version = 1\nonboarding_complete = true\n\n[project]\n\
             canonical_path = {:?}\nkey = {key:?}\n\n[constraints.rlimit]\n\
             {rlimit_constraints}",
            self.project.to_str().unwrap()
        );
        self.write_private(&self.project_doc_path(), &doc);
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

    /// A real launch of `sh -c script` that auto-saves, as an ordinary
    /// run does.
    fn launch(&self, script: &str) -> Output {
        self.run(&["--no-status-bar", "sh", "-c", script])
    }

    /// `--dry-run sh` from the project; never auto-saves.
    fn dry_run(&self) -> Output {
        self.run(&["--no-status-bar", "--dry-run", "sh"])
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Same formula as `project_identity` in src/config_store.rs.
fn project_key(canonical: &Path) -> String {
    let digest =
        format!("{:x}", Sha256::digest(canonical.as_os_str().as_bytes()));
    let base = canonical
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("{base}-{}", &digest[..20])
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn assert_ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "ai-jail failed: status={:?}\nstdout={}\nstderr={}",
        o.status,
        stdout(o),
        stderr(o)
    );
    stdout(o) + &stderr(o)
}

/// The `rlimit name=nproc ...` line of a `--dry-run`.
fn nproc_line(dry_run: &Output) -> String {
    let text = assert_ok(dry_run);
    text.lines()
        .map(str::trim)
        .find(|l| l.starts_with("rlimit name=nproc "))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("no nproc line in the dry run: {text}"))
}

/// `soft=` of a `--dry-run` rlimit line.
fn soft_of(line: &str) -> String {
    line.split_whitespace()
        .find_map(|w| w.strip_prefix("soft="))
        .unwrap_or_else(|| panic!("no soft= in {line}"))
        .to_string()
}

/// The last non-empty stdout line of a launch (the script's output).
fn last_line(o: &Output) -> String {
    assert_ok(o);
    stdout(o)
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .unwrap_or_else(|| panic!("no output: {}", stderr(o)))
        .to_string()
}

/// `constraints.rlimit.nproc` of a written project document, as text
/// (the store may write it as an integer or as a string).
fn doc_nproc(path: &Path) -> Option<String> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: toml::Value = toml::from_str(&text).unwrap();
    let value = doc.get("constraints")?.get("rlimit")?.get("nproc")?;
    Some(match value {
        toml::Value::String(s) => s.clone(),
        other => other.to_string(),
    })
}

#[test]
fn external_project_nproc_survives_a_launch_under_a_raised_global() {
    require_bwrap!();
    let tree = Tree::new("external");
    tree.write_global(GLOBAL_NPROC_8192);
    tree.write_project_doc("nproc = 6000\n");

    let before = nproc_line(&tree.dry_run());
    assert!(
        before.contains("soft=6000") && before.contains("source=project"),
        "precondition, the project's 6000 applies: {before}"
    );

    // A real launch runs at 6000 and auto-saves the project policy.
    let out = tree.launch("ulimit -u");
    assert_eq!(last_line(&out), "6000", "stderr={}", stderr(&out));

    let after = nproc_line(&tree.dry_run());
    assert!(
        after.contains("soft=6000") && after.contains("source=project"),
        "the saved policy lost the project's 6000: {after}\ndocument={}",
        std::fs::read_to_string(tree.project_doc_path()).unwrap_or_default()
    );
    assert_eq!(
        doc_nproc(&tree.project_doc_path()).as_deref(),
        Some("6000"),
        "the document keeps nproc = 6000"
    );
}

#[test]
fn legacy_project_nproc_is_applied_and_kept_by_the_migrating_launch() {
    require_bwrap!();
    let tree = Tree::new("legacy");
    tree.write_global(GLOBAL_NPROC_8192);
    let legacy = tree.project.join(".ai-jail");
    std::fs::write(&legacy, "[rlimit]\nnproc = 6000\n").unwrap();

    // What `--dry-run` reports for this launch (it does not migrate).
    let reported = nproc_line(&tree.dry_run());
    assert!(
        reported.contains("source=project"),
        "precondition: {reported}"
    );
    let reported = soft_of(&reported);
    assert_eq!(reported, "6000", "precondition, the dry run's value");

    // The launch that migrates the legacy file applies that same value.
    let out = tree.launch("ulimit -u");
    assert_eq!(
        last_line(&out),
        reported,
        "the migrating launch ran at a different nproc than --dry-run \
         reported; stderr={}",
        stderr(&out)
    );

    // The project document now carries the entry; the legacy file may
    // only be gone once it does.
    let doc = tree.project_doc_path();
    assert!(
        doc.exists(),
        "no project document written: stderr={}",
        stderr(&out)
    );
    assert_eq!(
        doc_nproc(&doc).as_deref(),
        Some("6000"),
        "the migrated document dropped nproc = 6000 (legacy file still \
         there: {}); document={}",
        legacy.exists(),
        std::fs::read_to_string(&doc).unwrap_or_default()
    );

    let next = nproc_line(&tree.dry_run());
    assert!(
        next.contains("soft=6000") && next.contains("source=project"),
        "the next launch keeps the migrated 6000: {next}"
    );
}
