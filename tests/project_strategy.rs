//! `project_strategy = "repo-root"` through the real CLI: a linked git
//! worktree uses its main checkout's trusted project policy document.
//!
//! The main checkout and the linked worktree are built by hand with the
//! same file layout git writes, so no `git` binary is needed.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

use sha2::{Digest, Sha256};

mod common;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Tree {
    root: PathBuf,
    home: PathBuf,
    main: PathBuf,
    worktree: PathBuf,
    xdg: PathBuf,
}

impl Tree {
    /// `<root>/repo` is the main checkout with a real `.git/` directory;
    /// `<root>/repo__worktrees/feat-x` is a linked worktree of it.
    fn new(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "project-strategy-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        let home = root.join("home");
        let xdg = root.join("xdg");
        let main = root.join("repo");
        let worktree = root.join("repo__worktrees/feat-x");
        let git_dir = main.join(".git/worktrees/feat-x");
        for dir in [&home, &xdg, &worktree, &git_dir] {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(
            worktree.join(".git"),
            format!("gitdir: {}\n", git_dir.display()),
        )
        .unwrap();
        std::fs::write(
            git_dir.join("gitdir"),
            format!("{}\n", worktree.join(".git").display()),
        )
        .unwrap();
        std::fs::write(git_dir.join("commondir"), "../..\n").unwrap();
        Self {
            root,
            home,
            main,
            worktree,
            xdg,
        }
    }

    fn command(&self, cwd: &Path) -> Command {
        let mut cmd = Command::new(common::ai_jail());
        cmd.current_dir(cwd)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env_remove("AI_JAIL_QUIET")
            .stdin(Stdio::null());
        cmd
    }

    fn status(&self, cwd: &Path) -> (Output, serde_json::Value) {
        let output = self
            .command(cwd)
            .args(["--harness", "claude", "status", "--json"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|e| panic!("{e}: {output:?}"));
        (output, value)
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

    /// Write the project document keyed by `project`, as onboarding saves it.
    fn write_project_doc(&self, project: &Path, onboarding_complete: bool) {
        self.prepare_store();
        let key = project_key(project);
        let doc = format!(
            "schema_version = 1\nonboarding_complete = {onboarding_complete}\n\n[project]\ncanonical_path = {:?}\nkey = {key:?}\n",
            project.to_str().unwrap()
        );
        self.write_private(
            &self.store().join("projects").join(format!("{key}.toml")),
            &doc,
        );
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

fn path_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn worktree_status_reports_onboarded_with_repo_root() {
    let tree = Tree::new("repo-root-status");
    tree.write_global("project_strategy = \"repo-root\"\n");
    tree.write_project_doc(&tree.main, true);

    let (_, value) = tree.status(&tree.worktree);
    assert_eq!(
        value["harnesses"][0]["onboarding_complete"], true,
        "{value}"
    );
    assert_eq!(value["blockers"], serde_json::json!([]), "{value}");
    assert_eq!(value["project"]["canonical_path"], path_str(&tree.worktree));
    assert_eq!(value["project"]["policy_path"], path_str(&tree.main));
}

#[test]
fn worktree_status_requires_onboarding_with_basename() {
    let tree = Tree::new("basename-status");
    tree.write_global("");
    tree.write_project_doc(&tree.main, true);

    let (_, value) = tree.status(&tree.worktree);
    assert_eq!(
        value["harnesses"][0]["onboarding_complete"], false,
        "{value}"
    );
    let blockers = value["blockers"].as_array().unwrap();
    assert!(
        blockers
            .iter()
            .any(|blocker| blocker["code"] == "onboarding_required"),
        "{value}"
    );
    assert_eq!(value["project"]["canonical_path"], path_str(&tree.worktree));
    assert_eq!(
        value["project"]["policy_path"],
        value["project"]["canonical_path"]
    );
}

#[test]
fn noninteractive_worktree_launch_skips_first_run_with_repo_root() {
    require_any_sandbox!();
    let tree = Tree::new("repo-root-launch");
    tree.write_global("project_strategy = \"repo-root\"\n");
    tree.write_project_doc(&tree.main, true);

    let output = {
        let _guard = common::SANDBOX_RUN_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        tree.command(&tree.worktree)
            .args(["--harness", "claude", "--", "/usr/bin/true"])
            .output()
            .unwrap()
    };
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("Interactive setup skipped"), "{stderr}");
    // No per-directory document exists, so nothing is being overridden.
    assert!(!stderr.contains(IGNORED_NOTICE), "{stderr}");
    assert!(output.status.success(), "{output:?}");
}

/// The launch notice when repo-root overrides a saved per-directory policy.
const IGNORED_NOTICE: &str = "the saved policy for";

#[test]
fn stale_per_worktree_document_is_ignored_with_repo_root() {
    let tree = Tree::new("repo-root-stale");
    tree.write_global("project_strategy = \"repo-root\"\n");
    tree.write_project_doc(&tree.main, true);
    tree.write_project_doc(&tree.worktree, false);

    let (output, value) = tree.status(&tree.worktree);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let notice = format!(
        "project_strategy = repo-root: using the policy of {}; the saved policy for {} is ignored",
        path_str(&tree.main),
        path_str(&tree.worktree)
    );
    assert_eq!(stderr.matches(&notice).count(), 1, "{stderr}");
    assert_eq!(
        value["harnesses"][0]["onboarding_complete"], true,
        "{value}"
    );
    assert_eq!(value["blockers"], serde_json::json!([]), "{value}");
    assert_eq!(value["project"]["policy_path"], path_str(&tree.main));
}

impl Tree {
    /// Like `write_project_doc`, plus a `[constraints]` table.
    fn write_project_doc_with_constraints(
        &self,
        project: &Path,
        constraints: &str,
    ) {
        self.write_project_doc(project, true);
        let path = self.project_doc_path(project);
        let mut doc = std::fs::read_to_string(&path).unwrap();
        doc.push_str("\n[constraints]\n");
        doc.push_str(constraints);
        self.write_private(&path, &doc);
    }

    fn project_doc_path(&self, project: &Path) -> PathBuf {
        self.store()
            .join("projects")
            .join(format!("{}.toml", project_key(project)))
    }

    fn read_project_doc(&self, project: &Path) -> String {
        std::fs::read_to_string(self.project_doc_path(project)).unwrap()
    }

    /// A writable launch, so auto-save rewrites the shared document.
    fn launch(&self, cwd: &Path) -> Output {
        let _guard = common::SANDBOX_RUN_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let output = self
            .command(cwd)
            .args(["--harness", "claude", "--", "/usr/bin/true"])
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        output
    }
}

#[test]
fn worktree_launch_keeps_main_checkout_constraints_with_repo_root() {
    require_any_sandbox!();
    let tree = Tree::new("repo-root-keep-main");
    let vendor = tree.main.join("vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    tree.write_global("project_strategy = \"repo-root\"\n");
    tree.write_project_doc_with_constraints(
        &tree.main,
        &format!(
            "ro_maps = [{:?}]\nmask = [\"secret.txt\"]\n",
            path_str(&vendor)
        ),
    );

    tree.launch(&tree.worktree);

    let doc = tree.read_project_doc(&tree.main);
    assert!(doc.contains(path_str(&vendor)), "{doc}");
    assert!(doc.contains("secret.txt"), "{doc}");
}

#[test]
fn main_launch_keeps_worktree_constraints_with_repo_root() {
    require_any_sandbox!();
    let tree = Tree::new("repo-root-keep-worktree");
    let vendor = tree.worktree.join("vendor");
    std::fs::create_dir_all(&vendor).unwrap();
    tree.write_global("project_strategy = \"repo-root\"\n");
    tree.write_project_doc(&tree.main, true);

    // Save an absolute map constraint from the worktree.
    let output = tree
        .command(&tree.worktree)
        .args(["--harness", "claude", "--init", "--map", path_str(&vendor)])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let doc = tree.read_project_doc(&tree.main);
    assert!(doc.contains(path_str(&vendor)), "{doc}\n{output:?}");

    let output = tree.launch(&tree.main);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains(IGNORED_NOTICE), "{stderr}");

    let doc = tree.read_project_doc(&tree.main);
    assert!(doc.contains(path_str(&vendor)), "{doc}");
}
