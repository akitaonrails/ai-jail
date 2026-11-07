//! Stable wrapper-integration contract (W1-W8).

#![cfg(any(target_os = "linux", target_os = "macos"))]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Tree {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    xdg: PathBuf,
    request: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "wrapper-contract-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let home = root.join("home");
        let project = root.join("project");
        let xdg = root.join("xdg");
        let request = root.join("ai-memory-requests.json");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&xdg).unwrap();
        std::fs::write(
            &request,
            r#"{"version":1,"requester":"ai-memory","requests":[
              {"kind":"private_host","value":"192.168.0.90:49374","reason":"memory server for capture and recall"},
              {"kind":"env","value":"AI_MEMORY_SERVER_URL","reason":"where hooks send observations"},
              {"kind":"agent_state","value":true,"reason":"harness login survives the jail"}
            ]}"#,
        )
        .unwrap();
        std::fs::set_permissions(
            &request,
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        Self {
            root,
            home,
            project,
            xdg,
            request,
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(common::ai_jail());
        command
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env_remove("AI_JAIL_QUIET");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

#[test]
fn capabilities_are_machine_readable_and_versioned() {
    let tree = Tree::new("capabilities");
    let output = tree.run(&["capabilities", "--json"]);
    assert!(output.status.success(), "{output:?}");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["features"]["harness_flag"], true);
    assert_eq!(value["features"]["request_file"], true);
    assert_eq!(value["features"]["status_json"], true);
    assert_eq!(value["features"]["secret_private_http"], true);
    assert_eq!(value["features"]["inside_marker"], false);
    assert_eq!(value["exit_codes"]["required_grant"], 3);
}

#[test]
fn status_reports_pending_requests_without_prompting() {
    let tree = Tree::new("status");
    let output = tree.run(&[
        "--harness",
        "claude",
        "--request-file",
        tree.request.to_str().unwrap(),
        "status",
        "--json",
    ]);
    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["harnesses"][0]["name"], "claude");
    assert_eq!(value["requests"]["pending"].as_array().unwrap().len(), 3);
    assert_eq!(value["requests"]["pending"][0]["value"], "192.168.0.90");
    assert_eq!(value["requests"]["pending"][0]["port"], 49374);
    assert!(
        !value["grants"]["open"]
            .as_array()
            .unwrap()
            .iter()
            .any(|grant| grant == "private_hosts"),
        "a pending request must not appear as an effective grant"
    );
    assert!(
        value["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| blocker["code"] == "required_grant_not_approved")
    );
}

#[test]
fn noninteractive_unapproved_request_fails_with_distinct_code() {
    let tree = Tree::new("required-grant");
    let output = tree.run(&[
        "--harness",
        "claude",
        "--request-file",
        tree.request.to_str().unwrap(),
        "--",
        "ai-memory",
        "run",
        "--some-future-flag",
        "x",
        "claude",
    ]);
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Wrapper request from"), "{stderr}");
    assert!(!stderr.contains("AJ-"), "{stderr}");
}

#[test]
fn pending_request_blocks_launch_without_a_known_harness() {
    let tree = Tree::new("unknown-harness");
    let args = ["--request", "env=WRAPPER_FIXTURE", "--no-save-config"];
    let status = tree.run(
        &[
            args.as_slice(),
            &["status", "--json", "--", "/bin/echo", "child-ran"],
        ]
        .concat(),
    );
    assert!(status.status.success(), "{status:?}");
    let report: serde_json::Value =
        serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(report["harnesses"], serde_json::json!([]));
    assert!(
        report["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|blocker| {
                blocker["code"] == "required_grant_not_approved"
            })
    );

    let output = tree.run(
        &[
            args.as_slice(),
            &["--exec", "--no-network", "--", "/bin/echo", "child-ran"],
        ]
        .concat(),
    );
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("env WRAPPER_FIXTURE")
    );
}

#[test]
fn request_file_inside_checkout_is_refused() {
    let tree = Tree::new("inside-checkout");
    let inside = tree.project.join("requests.json");
    std::fs::copy(&tree.request, &inside).unwrap();
    let output = tree.run(&[
        "--harness",
        "claude",
        "--request-file",
        inside.to_str().unwrap(),
        "status",
        "--json",
    ]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("outside the project checkout")
    );
}

#[test]
fn request_file_symlink_and_public_writes_are_refused() {
    let tree = Tree::new("unsafe-request-file");
    let link = tree.root.join("request-link.json");
    std::os::unix::fs::symlink(&tree.request, &link).unwrap();
    let linked = tree.run(&[
        "--harness",
        "claude",
        "--request-file",
        link.to_str().unwrap(),
        "status",
        "--json",
    ]);
    assert!(!linked.status.success());
    assert!(String::from_utf8_lossy(&linked.stderr).contains("symlink"));

    let hard_link = tree.root.join("request-hard-link.json");
    std::fs::hard_link(&tree.request, &hard_link).unwrap();
    let linked = tree.run(&[
        "--harness",
        "claude",
        "--request-file",
        hard_link.to_str().unwrap(),
        "status",
        "--json",
    ]);
    assert!(!linked.status.success());
    assert!(
        String::from_utf8_lossy(&linked.stderr).contains("non-hard-linked")
    );
    std::fs::remove_file(hard_link).unwrap();

    std::fs::set_permissions(
        &tree.request,
        std::fs::Permissions::from_mode(0o620),
    )
    .unwrap();
    let writable = tree.run(&[
        "--harness",
        "claude",
        "--request-file",
        tree.request.to_str().unwrap(),
        "status",
        "--json",
    ]);
    assert!(!writable.status.success());
    assert!(
        String::from_utf8_lossy(&writable.stderr)
            .contains("not group/world writable")
    );
}

#[test]
fn secret_values_never_appear_in_machine_output_or_errors() {
    let tree = Tree::new("secret-redaction");
    let secret_request = tree.root.join("secret-requests.json");
    std::fs::write(
        &secret_request,
        r#"{"version":1,"requester":"test-wrapper","requests":[
          {"kind":"secret","value":"WRAPPER_TEST_TOKEN","host":"memory.example","reason":"authenticate to memory"}
        ]}"#,
    )
    .unwrap();
    std::fs::set_permissions(
        &secret_request,
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let sentinel = "must-not-appear-7f4b";
    let output = tree
        .command()
        .env("WRAPPER_TEST_TOKEN", sentinel)
        .args([
            "--harness",
            "claude",
            "--request-file",
            secret_request.to_str().unwrap(),
            "status",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(
        !output
            .stdout
            .windows(sentinel.len())
            .any(|w| w == sentinel.as_bytes())
    );
    assert!(
        !output
            .stderr
            .windows(sentinel.len())
            .any(|w| w == sentinel.as_bytes())
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["requests"]["pending"][0]["value"],
        "WRAPPER_TEST_TOKEN"
    );
    assert_eq!(value["requests"]["pending"][0]["host"], "memory.example");
}

#[test]
fn explicit_harness_contradiction_is_refused() {
    let tree = Tree::new("contradiction");
    let output = tree.run(&["--harness", "claude", "--dry-run", "--", "codex"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("contradicts"));
}
