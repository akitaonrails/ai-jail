use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_TEST_ID: AtomicUsize = AtomicUsize::new(0);

struct TestTree {
    root: PathBuf,
    project: PathBuf,
    home: PathBuf,
}

impl TestTree {
    fn new(name: &str) -> Self {
        let id = NEXT_TEST_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("config-errors-{name}-{}-{id}", std::process::id()));
        let project = root.join("project");
        let home = root.join("home");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir(&home).unwrap();
        Self {
            root,
            project,
            home,
        }
    }

    fn project_config(&self) -> PathBuf {
        self.project.join(".ai-jail")
    }

    fn global_config(&self) -> PathBuf {
        self.home.join(".ai-jail")
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ai-jail"))
            .args(args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env_remove("AI_JAIL_QUIET")
            .output()
            .expect("failed to run ai-jail")
    }
}

impl Drop for TestTree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn assert_parse_failure(output: &Output, path: &Path) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected exit 1, stdout={stdout:?}, stderr={stderr:?}"
    );
    assert!(stdout.is_empty(), "unexpected stdout: {stdout:?}");
    assert!(
        stderr.contains(&format!("Failed to parse {}", path.display())),
        "missing config path in stderr: {stderr:?}"
    );
    assert!(
        stderr.contains("TOML parse error"),
        "missing parser detail in stderr: {stderr:?}"
    );
}

#[test]
fn malformed_project_config_blocks_dry_run() {
    let tree = TestTree::new("project-dry-run");
    let path = tree.project_config();
    std::fs::write(&path, "command = [\"bash\"\n").unwrap();

    let output = tree.run(&["--dry-run", "--no-save-config", "/bin/true"]);

    assert_parse_failure(&output, Path::new(".ai-jail"));
}

#[test]
fn malformed_project_config_blocks_init_without_rewriting() {
    let tree = TestTree::new("project-init");
    let path = tree.project_config();
    let original = "command = [\"bash\"\n";
    std::fs::write(&path, original).unwrap();

    let output = tree.run(&["--init", "/bin/true"]);

    assert_parse_failure(&output, Path::new(".ai-jail"));
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
}

#[test]
fn malformed_global_config_is_fatal_even_with_clean() {
    let tree = TestTree::new("global-clean");
    let path = tree.global_config();
    let original = "no_gpu = tru\n";
    std::fs::write(&path, original).unwrap();

    let output = tree.run(&["--clean", "status"]);

    assert_parse_failure(&output, &path);
    assert_eq!(std::fs::read_to_string(path).unwrap(), original);
}

#[test]
fn exec_mode_does_not_suppress_config_errors() {
    let tree = TestTree::new("exec");
    std::fs::write(tree.project_config(), "command = [\"bash\"\n").unwrap();

    let output = tree.run(&["--exec", "status"]);

    assert_parse_failure(&output, Path::new(".ai-jail"));
}

#[test]
fn clean_init_replaces_a_malformed_project_config() {
    let tree = TestTree::new("clean-init");
    let path = tree.project_config();
    std::fs::write(&path, "command = [\"bash\"\n").unwrap();

    let output = tree.run(&["--clean", "--init", "/bin/true"]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "clean init failed: {stderr:?}");
    let saved = std::fs::read_to_string(path).unwrap();
    assert!(
        saved.contains("command = ["),
        "unexpected config: {saved:?}"
    );
    assert!(saved.contains("\"/bin/true\""));
}

#[test]
fn project_tilde_outside_map_is_denied_before_status() {
    let tree = TestTree::new("tilde-map");
    std::fs::write(tree.project_config(), "rw_maps = [\"~/.ssh\"]\n").unwrap();

    let output = tree.run(&["status"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "status failed: {stderr:?}");
    assert!(stderr.contains("outside project ignored"));
    assert!(!stderr.contains("RW maps: "), "map leaked: {stderr:?}");
}

#[cfg(unix)]
#[test]
fn project_symlink_map_escape_is_denied_before_status() {
    let tree = TestTree::new("symlink-map");
    let outside = tree.root.join("outside");
    std::fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, tree.project.join("escape")).unwrap();
    std::fs::write(tree.project_config(), "rw_maps = [\"escape\"]\n").unwrap();

    let output = tree.run(&["status"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "status failed: {stderr:?}");
    assert!(stderr.contains("outside project ignored"));
    assert!(!stderr.contains("RW maps: "), "map leaked: {stderr:?}");
}

#[cfg(unix)]
#[test]
fn project_symlink_map_to_nonexistent_outside_path_is_denied() {
    // A dangling in-project symlink resolves to a nonexistent path
    // outside the project — canonicalize fails, so the destination
    // cannot be proven inside the project and the map must be
    // rejected, not mounted.
    let tree = TestTree::new("symlink-map-dangling");
    let outside = tree.root.join("outside-missing");
    std::os::unix::fs::symlink(&outside, tree.project.join("escape")).unwrap();
    std::fs::write(tree.project_config(), "rw_maps = [\"escape\"]\n").unwrap();

    let output = tree.run(&["status"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "status failed: {stderr:?}");
    assert!(
        stderr.contains("outside project ignored"),
        "dangling symlink map not denied: {stderr:?}"
    );
    assert!(!stderr.contains("RW maps: "), "map leaked: {stderr:?}");
}

#[test]
fn sandbox_flag_after_command_hard_errors() {
    // Sandbox flags placed after the command would be passed to the
    // child instead of ai-jail — both the space-separated and the
    // `--flag=value` forms must hard-error, never silently forward.
    let tree = TestTree::new("flag-after-command");
    for args in [
        vec!["claude", "--browser", "soft"],
        vec!["claude", "--browser=soft"],
        vec!["claude", "--allow-tcp-port=443"],
    ] {
        let output = tree.run(&args);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(1),
            "args {args:?}: stdout={stdout:?}, stderr={stderr:?}"
        );
        assert!(stdout.is_empty(), "unexpected stdout: {stdout:?}");
        assert!(
            stderr.contains("after command"),
            "args {args:?} not rejected: {stderr:?}"
        );
    }
}

#[test]
fn exec_mode_keeps_project_security_denial_visible() {
    let tree = TestTree::new("exec-security-warning");
    std::fs::write(tree.project_config(), "ssh = true\n").unwrap();

    let output = tree.run(&["--exec", "status"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "status failed: {stderr:?}");
    assert!(
        stderr.contains("weakens the baseline sandbox"),
        "security denial suppressed in --exec: {stderr:?}"
    );
}

#[cfg(unix)]
#[test]
fn dangling_project_config_symlink_is_fatal() {
    let tree = TestTree::new("dangling-project-link");
    std::os::unix::fs::symlink(
        tree.root.join("missing"),
        tree.project_config(),
    )
    .unwrap();
    let output = tree.run(&["status"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("symlink"));
}

#[cfg(unix)]
#[test]
fn dangling_global_config_symlink_is_fatal() {
    let tree = TestTree::new("dangling-global-link");
    std::os::unix::fs::symlink(tree.root.join("missing"), tree.global_config())
        .unwrap();
    let output = tree.run(&["--clean", "status"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("symlink"));
}
