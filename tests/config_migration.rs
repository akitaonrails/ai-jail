//! External config-store migration through the real CLI.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

mod common;

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Tree {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    xdg: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "config-migration-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let home = root.join("home");
        let project = root.join("project");
        let xdg = root.join("xdg");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&xdg).unwrap();
        Self {
            root,
            home,
            project,
            xdg,
        }
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(common::ai_jail());
        cmd.current_dir(&self.project)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env_remove("AI_JAIL_QUIET");
        cmd
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }

    fn legacy_project(&self) -> PathBuf {
        self.project.join(".ai-jail")
    }

    fn legacy_global(&self) -> PathBuf {
        self.home.join(".ai-jail")
    }

    fn store(&self) -> PathBuf {
        self.xdg.join("ai-jail")
    }

    fn project_doc(&self) -> PathBuf {
        std::fs::read_dir(self.store().join("projects"))
            .unwrap()
            .filter_map(Result::ok)
            .find(|entry| entry.path().extension().is_some_and(|e| e == "toml"))
            .unwrap()
            .path()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn assert_ok(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "command failed: {stderr}");
    stderr
}

#[test]
fn repository_policy_migrates_only_monotonic_restrictions() {
    let tree = Tree::new("projection");
    std::fs::write(
        tree.legacy_project(),
        "command=['evil']\ngithub=true\nno_gpu=true\nno_network=true\n",
    )
    .unwrap();

    let stderr = assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
    // --clean intentionally ignores the repository file.
    assert!(tree.legacy_project().exists());
    assert!(!stderr.contains("AJ-MIG-002"));

    let stderr = assert_ok(&tree.run(&["--init", "/bin/true"]));
    assert!(!tree.legacy_project().exists());
    assert!(stderr.contains("AJ-MIG-002"));
    assert!(stderr.contains("IMPORTED RESTRICTIONS"));
    assert!(stderr.contains("REAPPROVAL REQUIRED"));
    assert!(stderr.contains("NOT IMPORTED"));
    let stored = std::fs::read_to_string(tree.project_doc()).unwrap();
    assert!(stored.contains("schema_version = 1"));
    assert!(stored.contains("no_gpu = true"));
    assert!(!stored.contains("evil"));
    assert!(!stored.contains("github = true"));
}

#[test]
fn warning_survives_quiet_mode_and_a_later_launch_error() {
    let tree = Tree::new("warning-later-error");
    std::fs::write(tree.legacy_project(), "github=true\nno_gpu=true\n")
        .unwrap();
    let mut command = tree.command();
    let output = command
        .env("AI_JAIL_QUIET", "1")
        .args(["--network", "--allow-host", "example.com", "/bin/true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("✓ AJ-MIG-002"));
    assert!(stderr.contains("⚠ AJ-MIG-003"));
    assert!(!stderr.contains("✓ AJ-MIG-003"));
    assert!(stderr.contains("✗"));
}

#[test]
fn migration_warning_inventory_includes_authority_categories() {
    let tree = Tree::new("authority-inventory");
    std::fs::write(
        tree.legacy_project(),
        "network=true\nprivate_home=false\ninherit_env=true\nssh=true\ngithub=true\naudio=true\nno_gpu=false\ncommand=['claude']\nrw_maps=['/tmp']\n",
    )
    .unwrap();
    let stderr = assert_ok(&tree.run(&["--init", "/bin/true"]));
    for field in [
        "unrestricted-network",
        "host-home",
        "inherit-host-environment",
        "ssh",
        "github-credentials",
        "audio",
        "gpu",
        "command claude",
        "rw-map /tmp",
    ] {
        assert!(stderr.contains(field), "missing {field}: {stderr}");
    }
}

#[test]
fn migration_inventory_uses_legacy_command_global_baseline() {
    let tree = Tree::new("command-baseline");
    std::fs::write(
        tree.legacy_global(),
        "[commands.claude]\nbrowser_profile='hard'\n",
    )
    .unwrap();
    std::fs::write(
        tree.legacy_project(),
        "command=['claude']\nbrowser_profile='soft'\n",
    )
    .unwrap();
    let stderr = assert_ok(&tree.run(&["--init", "/bin/true"]));
    assert!(stderr.contains("browser-profile soft"), "{stderr}");
}

#[test]
fn status_is_read_only_and_legacy_compatible() {
    let tree = Tree::new("status");
    std::fs::write(tree.legacy_project(), "no_gpu=true\n").unwrap();
    assert_ok(&tree.run(&["status"]));
    assert!(tree.legacy_project().exists());
    assert!(!tree.store().exists());
}

#[test]
fn status_provenance_uses_contributing_legacy_source_and_clean_ignores_it() {
    let tree = Tree::new("legacy-provenance-output");
    std::fs::write(tree.legacy_project(), "no_gpu=true\n").unwrap();
    let untrusted = assert_ok(&tree.run(&["status"]));
    assert!(untrusted.contains("Project policy source: legacy_untrusted"));
    assert!(untrusted.contains("Project grants: no"));
    assert!(untrusted.contains("Project constraints: yes"));
    let clean = assert_ok(&tree.run(&["--clean", "status"]));
    assert!(clean.contains("Project policy source: none"));
    assert!(clean.contains("Project grants: no"));
    assert!(clean.contains("Project constraints: no"));
    assert!(
        !clean.contains("▸ Config:"),
        "ignored legacy path leaked: {clean}"
    );

    std::fs::write(
        tree.legacy_global(),
        format!("trust_project_config=['{}']\n", tree.project.display()),
    )
    .unwrap();
    let trusted = assert_ok(&tree.run(&["status"]));
    assert!(trusted.contains("Project policy source: legacy_trusted"));
    assert!(trusted.contains("Project grants: yes"));
    assert!(trusted.contains("Project constraints: no"));
}

#[test]
fn clean_status_never_prints_ignored_external_config_path() {
    let tree = Tree::new("clean-external-status");
    assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
    let status = assert_ok(&tree.run(&["--clean", "status"]));
    assert!(status.contains("Project policy source: none"));
    assert!(status.contains("No contributing project policy."));
    assert!(
        !status.contains("▸ Config:"),
        "ignored external path leaked: {status}"
    );
    assert!(!status.contains(&tree.project_doc().display().to_string()));
}

#[test]
fn audit_provenance_uses_contributing_legacy_source_and_clean_ignores_it() {
    let tree = Tree::new("legacy-provenance-audit");
    std::fs::write(tree.legacy_project(), "no_gpu=true\n").unwrap();
    assert_ok(&tree.run(&[
        "--no-save-config",
        "--audit-log",
        "--clean",
        "/bin/true",
    ]));
    assert_ok(&tree.run(&["--no-save-config", "--audit-log", "/bin/true"]));
    std::fs::write(
        tree.legacy_global(),
        format!("trust_project_config=['{}']\n", tree.project.display()),
    )
    .unwrap();
    assert_ok(&tree.run(&["--no-save-config", "--audit-log", "/bin/true"]));
    let log = std::fs::read_to_string(
        tree.home.join(".local/share/ai-jail/history.jsonl"),
    )
    .unwrap();
    let records = log
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|record| record["type"] == "launch")
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 3, "unexpected launch record count");
    let expected = [
        ("none", false, false, false, false),
        ("legacy_untrusted", true, false, false, true),
        ("legacy_trusted", true, true, true, false),
    ];
    for (record, (source, project, trusted, grants, constraints)) in
        records.iter().zip(expected)
    {
        assert_eq!(record["config"]["project_source"], source);
        assert_eq!(record["config"]["project"], project);
        assert_eq!(record["config"]["project_trusted"], trusted);
        assert_eq!(record["config"]["project_grants"], grants);
        assert_eq!(record["config"]["project_constraints"], constraints);
    }
}

#[test]
fn audit_output_matrix_covers_external_constraints_grants_both_and_clean() {
    let tree = Tree::new("external-provenance-audit");
    std::fs::write(tree.legacy_project(), "no_gpu=true\n").unwrap();
    assert_ok(&tree.run(&["--init", "/bin/true"]));
    let record = |tree: &Tree| {
        assert_ok(&tree.run(&["--no-save-config", "--audit-log", "/bin/true"]));
        let log = std::fs::read_to_string(
            tree.home.join(".local/share/ai-jail/history.jsonl"),
        )
        .unwrap();
        serde_json::from_str::<serde_json::Value>(log.lines().last().unwrap())
            .unwrap()
    };
    let constraints = record(&tree);
    assert_eq!(constraints["config"]["project"], true);
    assert_eq!(constraints["config"]["project_trusted"], false);
    assert_eq!(constraints["config"]["project_source"], "external_store");
    assert_eq!(constraints["config"]["project_grants"], false);
    assert_eq!(constraints["config"]["project_constraints"], true);

    let path = tree.project_doc();
    let mut document = std::fs::read_to_string(&path).unwrap();
    document = document.replacen("[grants]", "[grants]\ngithub = true", 1);
    std::fs::write(&path, &document).unwrap();
    let both = record(&tree);
    assert_eq!(both["config"]["project"], true);
    assert_eq!(both["config"]["project_trusted"], true);
    assert_eq!(both["config"]["project_source"], "external_store");
    assert_eq!(both["config"]["project_grants"], true);
    assert_eq!(both["config"]["project_constraints"], true);

    document = document.replace("no_gpu = true\n", "");
    std::fs::write(&path, &document).unwrap();
    let grants = record(&tree);
    assert_eq!(grants["config"]["project"], true);
    assert_eq!(grants["config"]["project_trusted"], true);
    assert_eq!(grants["config"]["project_source"], "external_store");
    assert_eq!(grants["config"]["project_grants"], true);
    assert_eq!(grants["config"]["project_constraints"], false);

    assert_ok(&tree.run(&[
        "--no-save-config",
        "--audit-log",
        "--clean",
        "/bin/true",
    ]));
    let log = std::fs::read_to_string(
        tree.home.join(".local/share/ai-jail/history.jsonl"),
    )
    .unwrap();
    let clean: serde_json::Value =
        serde_json::from_str(log.lines().last().unwrap()).unwrap();
    assert_eq!(log.lines().count(), 4, "unexpected launch record count");
    assert_eq!(clean["config"]["project"], false);
    assert_eq!(clean["config"]["project_trusted"], false);
    assert_eq!(clean["config"]["project_source"], "none");
    assert_eq!(clean["config"]["project_grants"], false);
    assert_eq!(clean["config"]["project_constraints"], false);
}

#[test]
fn malformed_and_symlinked_project_sources_are_never_deleted() {
    let malformed = Tree::new("malformed");
    std::fs::write(malformed.legacy_project(), "no_gpu = tru\n").unwrap();
    let output = malformed.run(&["--init", "/bin/true"]);
    assert!(!output.status.success());
    assert!(malformed.legacy_project().exists());

    let linked = Tree::new("symlink");
    let target = linked.root.join("target");
    std::fs::write(&target, "no_gpu=true\n").unwrap();
    symlink(&target, linked.legacy_project()).unwrap();
    let output = linked.run(&["--init", "/bin/true"]);
    assert!(!output.status.success());
    assert!(linked.legacy_project().symlink_metadata().is_ok());
    assert!(target.exists());
}

#[test]
fn global_plain_and_safe_symlink_migrate_without_deleting_target() {
    let plain = Tree::new("global-plain");
    std::fs::write(plain.legacy_global(), "no_gpu=true\n").unwrap();
    let stderr = assert_ok(&plain.run(&["--clean", "--init", "/bin/true"]));
    assert!(stderr.contains("AJ-MIG-001"));
    assert!(!plain.legacy_global().exists());
    assert!(plain.store().join("config.toml").is_file());

    let linked = Tree::new("global-link");
    let target = linked.root.join("managed-config");
    std::fs::write(&target, "no_gpu=true\n").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
        .unwrap();
    symlink(&target, linked.legacy_global()).unwrap();
    assert_ok(&linked.run(&["--clean", "--init", "/bin/true"]));
    assert!(!linked.legacy_global().symlink_metadata().is_ok());
    assert_eq!(std::fs::read_to_string(target).unwrap(), "no_gpu=true\n");
}

#[test]
fn restored_global_source_preserves_edited_destination() {
    let tree = Tree::new("global-edited-idempotency");
    let original = "no_gpu=true\n";
    std::fs::write(tree.legacy_global(), original).unwrap();
    assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
    let edited = "no_gpu = true\nno_network = true\n";
    std::fs::write(tree.store().join("config.toml"), edited).unwrap();
    std::fs::write(tree.legacy_global(), original).unwrap();
    assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
    assert!(!tree.legacy_global().exists());
    assert_eq!(
        std::fs::read_to_string(tree.store().join("config.toml")).unwrap(),
        edited
    );
}

#[test]
fn conflicting_global_is_retained_and_fails_closed() {
    let tree = Tree::new("global-conflict");
    std::fs::write(tree.legacy_global(), "no_gpu=true\n").unwrap();
    let root = tree.store();
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .unwrap();
    std::fs::write(root.join("config.toml"), "no_gpu=false\n").unwrap();
    std::fs::set_permissions(
        root.join("config.toml"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let output = tree.run(&["--clean", "--init", "/bin/true"]);
    assert!(!output.status.success());
    assert!(tree.legacy_global().exists());
    assert_eq!(
        std::fs::read_to_string(root.join("config.toml")).unwrap(),
        "no_gpu=false\n"
    );
}

#[test]
fn relative_xdg_is_rejected_without_touching_legacy() {
    let tree = Tree::new("relative-xdg");
    std::fs::write(tree.legacy_project(), "no_gpu=true\n").unwrap();
    let output = tree
        .command()
        .env("XDG_CONFIG_HOME", Path::new("relative"))
        .args(["--init", "/bin/true"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(tree.legacy_project().exists());
}

#[test]
fn absent_home_and_xdg_use_no_relative_trusted_paths() {
    let tree = Tree::new("absent-home-xdg");
    let output = tree
        .command()
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .arg("status")
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(!stderr.contains("./config.toml"));
    assert!(!stderr.contains("./projects"));
    assert!(stderr.contains("Project policy source: none"));
}

#[test]
fn absent_home_and_xdg_never_read_project_config_toml() {
    let tree = Tree::new("relative-config-exploit");
    std::fs::write(
        tree.project.join("config.toml"),
        "this is malicious and invalid = [",
    )
    .unwrap();
    let output = tree
        .command()
        .env_remove("HOME")
        .env_remove("XDG_CONFIG_HOME")
        .arg("status")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn symlinked_xdg_store_inside_project_is_rejected_without_migration() {
    let tree = Tree::new("xdg-symlink-project");
    std::fs::write(tree.legacy_project(), "no_gpu=true\n").unwrap();
    let inside = tree.project.join("store");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::remove_dir(&tree.xdg).unwrap();
    symlink(&inside, &tree.xdg).unwrap();
    let output = tree.run(&["--init", "/bin/true"]);
    assert!(!output.status.success());
    assert!(tree.legacy_project().exists());
}

#[test]
fn public_trusted_store_directory_is_rejected_on_read() {
    let tree = Tree::new("public-store");
    assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
    std::fs::set_permissions(
        tree.store(),
        std::fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let output = tree.run(&["status"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("0700"));
}

#[test]
fn read_only_load_rejects_home_or_xdg_store_aliases_inside_project() {
    for via_xdg in [false, true] {
        let tree = Tree::new(if via_xdg {
            "readonly-xdg-alias"
        } else {
            "readonly-home-alias"
        });
        let base = tree.project.join("controlled");
        let store = base.join("ai-jail");
        std::fs::create_dir_all(store.join("projects")).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
            .unwrap();
        std::fs::set_permissions(
            &store,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(
            store.join("projects"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let mut command = tree.command();
        if via_xdg {
            let alias = tree.root.join("xdg-alias");
            symlink(&base, &alias).unwrap();
            command.env("XDG_CONFIG_HOME", alias);
        } else {
            command
                .env_remove("XDG_CONFIG_HOME")
                .env("HOME", &tree.project);
            std::fs::rename(&base, tree.project.join(".config")).unwrap();
        }
        let output = command.arg("status").output().unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("inside project")
                || stderr.contains("symlink component"),
            "{stderr}"
        );
    }
}

#[test]
fn trusted_store_rejects_all_non_exact_private_modes() {
    for mode in [0o711, 0o750, 0o755, 0o777] {
        let tree = Tree::new("unsafe-dir-mode");
        assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
        std::fs::set_permissions(
            tree.store(),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert!(
            !tree.run(&["status"]).status.success(),
            "accepted dir mode {mode:o}"
        );
    }
    for mode in [0o640, 0o644, 0o660, 0o666] {
        let tree = Tree::new("unsafe-file-mode");
        assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
        std::fs::set_permissions(
            tree.project_doc(),
            std::fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert!(
            !tree.run(&["status"]).status.success(),
            "accepted file mode {mode:o}"
        );
    }
    {
        let relative = "projects";
        let tree = Tree::new("unsafe-projects-mode");
        assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
        std::fs::set_permissions(
            tree.store().join(relative),
            std::fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        assert!(!tree.run(&["status"]).status.success());
    }
    for relative in ["config.toml", "global-migration.toml", ".lock"] {
        let tree = Tree::new("unsafe-global-file-mode");
        std::fs::write(tree.legacy_global(), "no_gpu=true\n").unwrap();
        assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
        let path = tree.store().join(relative);
        assert!(path.exists(), "missing test fixture {}", path.display());
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let output = if relative == "global-migration.toml" {
            std::fs::write(tree.legacy_global(), "no_gpu=true\n").unwrap();
            tree.run(&["--init", "/bin/true"])
        } else if relative == ".lock" {
            tree.run(&["--init", "/bin/true"])
        } else {
            tree.run(&["status"])
        };
        assert!(!output.status.success(), "accepted unsafe {relative}");
    }
}

#[test]
fn restored_legacy_files_are_idempotent_and_never_add_grants() {
    let tree = Tree::new("restored");
    let original = "no_gpu=true\ngithub=true\n";
    std::fs::write(tree.legacy_project(), original).unwrap();
    assert_ok(&tree.run(&["--init", "/bin/true"]));
    let destination = tree.project_doc();
    let first = std::fs::read_to_string(&destination).unwrap();
    assert!(!first.contains("github = true"));

    std::fs::write(tree.legacy_project(), original).unwrap();
    assert_ok(&tree.run(&["--init", "/bin/true"]));
    assert!(!tree.legacy_project().exists());
    let identical = std::fs::read_to_string(&destination).unwrap();
    assert_eq!(first, identical);

    std::fs::write(
        tree.legacy_project(),
        "no_gpu=true\nnetwork=false\ngithub=true\n",
    )
    .unwrap();
    assert_ok(&tree.run(&["--init", "/bin/true"]));
    let changed = std::fs::read_to_string(destination).unwrap();
    assert!(changed.contains("no_gpu = true"));
    assert!(changed.contains("network = false"));
    assert!(!changed.contains("github = true"));
}

#[test]
fn corrupt_durable_destination_never_quarantines_restored_source() {
    let tree = Tree::new("corrupt-destination");
    std::fs::write(tree.legacy_project(), "no_gpu=true\n").unwrap();
    assert_ok(&tree.run(&["--init", "/bin/true"]));
    std::fs::write(tree.project_doc(), "not valid toml = [").unwrap();
    std::fs::write(tree.legacy_project(), "no_gpu=true\n").unwrap();
    let output = tree.run(&["--init", "/bin/true"]);
    assert!(!output.status.success());
    assert!(tree.legacy_project().exists());
}

#[test]
fn concurrent_migration_produces_one_valid_document() {
    let tree = Tree::new("concurrent");
    std::fs::write(tree.legacy_project(), "no_gpu=true\n").unwrap();
    let mut first = tree
        .command()
        .args(["--init", "/bin/true"])
        .spawn()
        .unwrap();
    let mut second = tree
        .command()
        .args(["--init", "/bin/true"])
        .spawn()
        .unwrap();
    assert!(first.wait().unwrap().success());
    assert!(second.wait().unwrap().success());
    assert!(!tree.legacy_project().exists());
    let docs: Vec<_> = std::fs::read_dir(tree.store().join("projects"))
        .unwrap()
        .filter_map(Result::ok)
        .collect();
    assert_eq!(docs.len(), 1);
    let stored = std::fs::read_to_string(docs[0].path()).unwrap();
    assert!(stored.contains("schema_version = 1"));
    assert!(stored.contains("no_gpu = true"));
}

#[test]
fn trusted_store_and_migrated_legacy_name_stay_masked() {
    let tree = Tree::new("masking");
    assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
    let output =
        tree.run(&["--clean", "--no-hide-config", "--dry-run", "/bin/true"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "dry run failed: {stderr}");
    let rendered = String::from_utf8_lossy(&output.stdout);
    assert!(
        rendered.contains(&tree.store().display().to_string()),
        "trusted store missing from sandbox policy: {rendered}"
    );
    assert!(
        rendered.contains(&tree.legacy_project().display().to_string()),
        "legacy filename missing from sandbox policy: {rendered}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn final_exposure_validator_allows_masked_same_destination_ancestor() {
    let tree = Tree::new("same-dest-ancestor");
    assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
    let home = tree.home.display().to_string();
    let output = tree.run(&[
        "--clean",
        "--no-private-home",
        "--map",
        &home,
        "--dry-run",
        "/bin/true",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn final_exposure_validator_rejects_store_and_symlink_alias_at_alternate_destination()
 {
    let tree = Tree::new("alternate-store-exposure");
    assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
    let alias = tree.root.join("store-alias");
    symlink(tree.store(), &alias).unwrap();
    for source in [tree.store(), alias] {
        let spec = format!("{}:/tmp/exposed-policy", source.display());
        let output = tree.run(&["--map", &spec, "--dry-run", "/bin/true"]);
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("trusted config store")
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn absent_legacy_name_cannot_be_created_and_leaves_no_host_artifact() {
    let tree = Tree::new("absent-mask-enforcement");
    assert_ok(&tree.run(&["--clean", "--init", "/bin/true"]));
    assert!(!tree.legacy_project().exists());

    let output = tree.run(&[
        "--clean",
        "--no-hide-config",
        "/bin/sh",
        "-c",
        "printf attack > .ai-jail",
    ]);
    assert!(
        !output.status.success(),
        "sandbox unexpectedly created the mandatory masked file"
    );
    assert!(
        !tree.legacy_project().exists(),
        "temporary mask placeholder leaked onto the host"
    );
}
