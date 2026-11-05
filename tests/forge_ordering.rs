//! Forge credential preparation belongs only to a real, non-lockdown launch.

#![cfg(feature = "test-hooks")]

mod common;

use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

struct Tree {
    root: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
    project: PathBuf,
    marker: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("forge-ordering-{name}-{}-{id}", std::process::id()));
        let home = root.join("home");
        let xdg = root.join("xdg");
        let project = root.join("project");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&xdg).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        let marker = root.join("forge-prepare-called");
        Self {
            root,
            home,
            xdg,
            project,
            marker,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_ai-jail"))
            .args(args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env("NO_COLOR", "1")
            .env("AI_JAIL_TEST_FORGE_PREPARE_MARKER", &self.marker)
            .env_remove("AI_JAIL_QUIET")
            .output()
            .unwrap()
    }

    fn assert_not_prepared(&self, args: &[&str]) {
        let output = self.run(args);
        assert!(
            !self.marker.exists(),
            "forge prepare ran for {args:?}: {output:?}"
        );
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn nonlaunch_modes_never_prepare_forge_credentials() {
    Tree::new("status").assert_not_prepared(&["status"]);
    Tree::new("init").assert_not_prepared(&["--init", "/usr/bin/true"]);
    Tree::new("bootstrap")
        .assert_not_prepared(&["--bootstrap", "/usr/bin/true"]);
    Tree::new("dry-run").assert_not_prepared(&["--dry-run", "/usr/bin/true"]);
    Tree::new("audit-show").assert_not_prepared(&["--audit-show"]);
}

#[test]
fn every_lockdown_source_skips_forge_preparation() {
    Tree::new("cli-lockdown")
        .assert_not_prepared(&["--lockdown", "/usr/bin/true"]);

    let project = Tree::new("project-lockdown");
    std::fs::write(project.project.join(".ai-jail"), "lockdown = true\n")
        .unwrap();
    project.assert_not_prepared(&["/usr/bin/true"]);

    let global = Tree::new("global-lockdown");
    std::fs::write(global.home.join(".ai-jail"), "lockdown = true\n").unwrap();
    global.assert_not_prepared(&["/usr/bin/true"]);
}

#[test]
fn actual_launch_prepares_forge_at_child_handoff_without_printing_token() {
    if !common::bwrap_available() {
        return;
    }
    let _serial = common::SANDBOX_RUN_LOCK.lock().unwrap();
    let tree = Tree::new("actual-launch");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 8192];
        let count = stream.read(&mut request).unwrap();
        let request = String::from_utf8_lossy(&request[..count]);
        assert!(request.starts_with("GET /api/v4/projects/owner%2Frepo "));
        assert!(request.contains("Authorization: Bearer sentinel-forge-token"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\n{\"id\":42}")
            .unwrap();
    });

    let canonical = std::fs::canonicalize(&tree.project).unwrap();
    let digest = format!(
        "{:x}",
        Sha256::digest(canonical.as_os_str().as_encoded_bytes())
    );
    let project_key = format!("project-{}", &digest[..20]);
    let prefix = &digest[..24];
    let credential_id = format!("{prefix}-0123456789abcdef01234567");
    let store = tree.xdg.join("ai-jail");
    let forges = store.join("forges");
    let credentials = store.join("credentials");
    std::fs::create_dir_all(&forges).unwrap();
    std::fs::create_dir_all(&credentials).unwrap();
    for directory in [&store, &forges, &credentials] {
        std::fs::set_permissions(
            directory,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let binding = format!(
        "schema_version = 1\nprovider = \"gitlab_project\"\nrepository_id = 42\nrepository = \"owner/repo\"\ncredential_id = \"{credential_id}\"\nallow_private = true\nscope_verified = false\nscopes = [\"read_repository\"]\nexpires_at = \"2099-01-01\"\nopen_approved = true\n\n[origin]\nhost = \"127.0.0.1\"\nport = {port}\ntest_http = true\n"
    );
    let credential = "schema_version = 1\nprovider = \"gitlab_project\"\n\n[secret]\nkind = \"persistent_token\"\ntoken = \"sentinel-forge-token\"\n";
    let binding_path = forges.join(format!("{project_key}.toml"));
    let credential_path = credentials.join(format!("{credential_id}.toml"));
    std::fs::write(&binding_path, binding).unwrap();
    std::fs::write(&credential_path, credential).unwrap();
    for file in [&binding_path, &credential_path] {
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o600))
            .unwrap();
    }

    let check = tree.project.join("check-forge.sh");
    let expected_key = format!("credential.https://127.0.0.1:{port}.helper");
    std::fs::write(
        &check,
        format!(
            "#!/bin/sh\ntest \"$GITLAB_TOKEN\" = sentinel-forge-token || exit 41\ntest \"$AI_JAIL_FORGE_AUTHORITY\" = OPEN || exit 42\ntest \"$GIT_CONFIG_COUNT\" = 3 || exit 43\ntest \"$GIT_CONFIG_KEY_0\" = credential.helper || exit 44\ntest -z \"$GIT_CONFIG_VALUE_0\" || exit 45\ntest \"$GIT_CONFIG_KEY_1\" = credential.useHttpPath || exit 46\ntest \"$GIT_CONFIG_VALUE_1\" = true || exit 47\ntest \"$GIT_CONFIG_KEY_2\" = '{expected_key}' || exit 48\nprintf 'forge-handoff-ok\\n'\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&check, std::fs::Permissions::from_mode(0o700))
        .unwrap();

    let output = tree.run(&[
        "--no-network",
        "--no-mise",
        "--no-toolchains",
        "--no-agent-state",
        "./check-forge.sh",
    ]);
    server.join().unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(tree.marker.is_file());
    let combined = [output.stdout, output.stderr].concat();
    let rendered = String::from_utf8_lossy(&combined);
    assert!(rendered.contains("forge-handoff-ok"));
    assert!(rendered.contains("[ERROR] OPEN"));
    assert!(!combined.windows(2).any(|bytes| bytes == b"\x1b["));
    assert!(!rendered.contains("sentinel-forge-token"));
    let project_policy =
        store.join("projects").join(format!("{project_key}.toml"));
    if project_policy.is_file() {
        assert!(
            !std::fs::read_to_string(project_policy)
                .unwrap()
                .contains("sentinel-forge-token")
        );
    }
}
