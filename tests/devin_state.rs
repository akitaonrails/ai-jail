// End-to-end coverage for Devin state passthrough. Uses only synthetic state
// and a fake executable; the installed version, credentials, and project are
// all isolated under CARGO_TARGET_TMPDIR.
#![cfg(target_os = "linux")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

fn bwrap_available() -> bool {
    static RESULT: OnceLock<bool> = OnceLock::new();
    *RESULT.get_or_init(|| {
        Command::new("bwrap")
            .args([
                "--ro-bind",
                "/",
                "/",
                "--proc",
                "/proc",
                "--unshare-pid",
                "--unshare-uts",
                "--unshare-ipc",
                "--",
                "true",
            ])
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    })
}

struct DevinFixture {
    root: PathBuf,
    home: PathBuf,
    project: PathBuf,
    data_home: PathBuf,
    config_home: PathBuf,
    script: PathBuf,
}

impl DevinFixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("devin-state-{}-{nonce}", std::process::id()));
        let home = root.join("home");
        let project = root.join("project");
        let data_home = root.join("xdg-data");
        let config_home = root.join("xdg-config");
        let bin = project.join("bin");
        let script = bin.join("devin");

        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::create_dir_all(config_home.join("devin")).unwrap();

        // Keep the executable independent of the XDG installation tree so
        // --no-agent-state can test hidden state without hiding its launcher.
        std::fs::write(
            &script,
            r##"#!/bin/sh
set -eu
state="$XDG_DATA_HOME/devin"
config="$XDG_CONFIG_HOME/devin"
credential="$state/credentials.toml"
versions="$state/cli/_versions"

case "$1" in
  write-state)
    temporary="$state/credentials.toml.tmp"
    printf 'rotated synthetic credential\n' > "$temporary"
    mv "$temporary" "$credential"
    mkdir -p "$state/history"
    printf 'synthetic session\n' >> "$state/history/session.log"
    printf 'synthetic config\n' > "$config/config.json"
    echo STATE_WRITTEN
    ;;
  probe-install)
    payload="$versions/3000.11.3/bin/payload"
    if printf 'tampered\n' > "$payload" 2>/dev/null; then
      echo VERSION_WRITABLE
    else
      echo VERSION_READ_ONLY
    fi
    if mv "$versions/current" "$versions/current.moved" 2>/dev/null; then
      echo CURRENT_RENAME_ALLOWED
    else
      echo CURRENT_RENAME_BLOCKED
    fi
    ;;
  probe-ancestor)
    if mv "$state/cli" "$state/cli.moved" 2>/dev/null; then
      echo CLI_RENAME_ALLOWED
    else
      echo CLI_RENAME_BLOCKED
    fi
    if printf 'metadata\n' > "$state/cli/installation_id" 2>/dev/null; then
      echo CLI_METADATA_WRITABLE
    fi
    ;;
  probe-create)
    if mkdir -p "$versions/injected/bin" 2>/dev/null; then
      echo INSTALL_CREATED
    else
      echo INSTALL_CREATION_BLOCKED
    fi
    ;;
  probe-hidden)
    if [ -r "$credential" ]; then
      echo CREDENTIAL_VISIBLE
    else
      echo CREDENTIAL_HIDDEN
    fi
    if [ -r "$versions/3000.11.3/bin/payload" ]; then
      echo INSTALL_VISIBLE
    else
      echo INSTALL_HIDDEN
    fi
    ;;
  *)
    echo "unexpected fake Devin mode" >&2
    exit 2
    ;;
esac
"##,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&script, permissions).unwrap();

        let state = data_home.join("devin");
        let versions = state.join("cli/_versions");
        std::fs::create_dir_all(versions.join("3000.11.3/bin")).unwrap();
        std::fs::write(
            state.join("credentials.toml"),
            "original synthetic credential\n",
        )
        .unwrap();
        std::fs::write(
            versions.join("3000.11.3/bin/payload"),
            "host version payload\n",
        )
        .unwrap();
        std::os::unix::fs::symlink("3000.11.3", versions.join("current"))
            .unwrap();

        Self {
            root,
            home,
            project,
            data_home,
            config_home,
            script,
        }
    }

    fn run(&self, mode: &str, no_agent_state: bool) -> Output {
        self.run_extra(mode, no_agent_state, &[], &self.data_home)
    }

    fn run_extra(
        &self,
        mode: &str,
        no_agent_state: bool,
        flags: &[&str],
        data_home: &Path,
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ai-jail"));
        command
            .args([
                "--clean",
                "--no-save-config",
                "--no-network",
                "--no-toolchains",
                "--no-mise",
                "--no-ssh",
                "--no-gpu",
                "--no-docker",
                "--no-display",
                "--no-status-bar",
            ])
            .env("HOME", &self.home)
            .env("XDG_DATA_HOME", data_home)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .current_dir(&self.project);
        if !flags.contains(&"--dry-run") {
            command.arg("--exec");
        }
        if no_agent_state {
            command.arg("--no-agent-state");
        }
        command.args(flags);
        command
            .arg(&self.script)
            .arg(mode)
            .output()
            .expect("failed to run ai-jail with fake Devin")
    }
}

impl Drop for DevinFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn assert_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context}: status={:?}, stdout={}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn devin_state_is_writable_but_install_read_only_and_opt_out_hides_it() {
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }

    let fixture = DevinFixture::new();
    assert!(!fixture.data_home.starts_with(&fixture.home));
    let credential = fixture.data_home.join("devin/credentials.toml");
    let payload = fixture
        .data_home
        .join("devin/cli/_versions/3000.11.3/bin/payload");
    let current = fixture.data_home.join("devin/cli/_versions/current");

    let state = fixture.run("write-state", false);
    assert_success(&state, "default Devin state write");
    assert!(String::from_utf8_lossy(&state.stdout).contains("STATE_WRITTEN"));
    assert_eq!(
        std::fs::read_to_string(&credential).unwrap(),
        "rotated synthetic credential\n"
    );
    assert!(
        !fixture
            .data_home
            .join("devin/credentials.toml.tmp")
            .exists()
    );
    assert_eq!(
        std::fs::read_to_string(
            fixture.data_home.join("devin/history/session.log")
        )
        .unwrap(),
        "synthetic session\n"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.config_home.join("devin/config.json"))
            .unwrap(),
        "synthetic config\n"
    );

    let install = fixture.run("probe-install", false);
    assert_success(&install, "Devin installation protection probe");
    let install_stdout = String::from_utf8_lossy(&install.stdout);
    assert!(
        install_stdout.contains("VERSION_READ_ONLY"),
        "{install_stdout}"
    );
    assert!(
        install_stdout.contains("CURRENT_RENAME_BLOCKED"),
        "{install_stdout}"
    );
    assert_eq!(
        std::fs::read_to_string(&payload).unwrap(),
        "host version payload\n"
    );
    assert_eq!(
        std::fs::read_link(&current).unwrap(),
        Path::new("3000.11.3")
    );

    let ancestor = fixture.run("probe-ancestor", false);
    assert_success(&ancestor, "launcher ancestor protection");
    let stdout = String::from_utf8_lossy(&ancestor.stdout);
    assert!(stdout.contains("CLI_RENAME_BLOCKED"), "{stdout}");
    assert!(stdout.contains("CLI_METADATA_WRITABLE"), "{stdout}");
    assert!(!fixture.data_home.join("devin/cli.moved").exists());

    let opt_out = fixture.run("probe-hidden", true);
    assert_success(&opt_out, "--no-agent-state visibility probe");
    assert!(
        String::from_utf8_lossy(&opt_out.stdout).contains("CREDENTIAL_HIDDEN"),
        "stdout={}, stderr={}",
        String::from_utf8_lossy(&opt_out.stdout),
        String::from_utf8_lossy(&opt_out.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&credential).unwrap(),
        "rotated synthetic credential\n"
    );
}

#[test]
fn devin_incomplete_or_symlink_installations_fail_conservatively() {
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }
    for layout in ["missing-versions", "symlink-cli", "symlink-versions"] {
        let fixture = DevinFixture::new();
        let cli = fixture.data_home.join("devin/cli");
        let versions = cli.join("_versions");
        let external = fixture.root.join("external");
        match layout {
            "missing-versions" => std::fs::remove_dir_all(&versions).unwrap(),
            "symlink-cli" => {
                std::fs::rename(&cli, &external).unwrap();
                std::os::unix::fs::symlink(&external, &cli).unwrap();
            }
            _ => {
                std::fs::rename(&versions, &external).unwrap();
                std::os::unix::fs::symlink(&external, &versions).unwrap();
            }
        }
        let output = fixture.run("probe-create", false);
        assert_success(&output, layout);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("INSTALL_CREATION_BLOCKED"),
            "{layout}: {stdout}"
        );
        // --exec suppresses ordinary warnings; discovery still reports the
        // conservative fallback in the interactive/dry-run path.
        let discovery = fixture.run_extra(
            "probe-create",
            false,
            &["--dry-run"],
            &fixture.data_home,
        );
        assert_success(&discovery, layout);
        assert!(
            String::from_utf8_lossy(&discovery.stderr)
                .contains("sharing data read-only")
        );
        assert!(!versions.join("injected").exists());
        assert!(!external.join("injected").exists());
        if layout == "missing-versions" {
            assert!(!versions.exists());
        }
    }
}

#[test]
fn devin_external_installation_keeps_credentials_and_history_writable() {
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }
    let fixture = DevinFixture::new();
    let cli = fixture.data_home.join("devin/cli");
    std::fs::remove_dir_all(&cli).unwrap();
    let discovery = fixture.run_extra(
        "write-state",
        false,
        &["--dry-run"],
        &fixture.data_home,
    );
    assert_success(&discovery, "external installation discovery");
    let stderr = String::from_utf8_lossy(&discovery.stderr);
    assert!(!stderr.contains("Devin:"), "{stderr}");
    assert!(!cli.exists(), "discovery must not create a CLI tree");

    let output = fixture.run("write-state", false);
    assert_success(&output, "externally installed Devin state writes");
    assert!(String::from_utf8_lossy(&output.stdout).contains("STATE_WRITTEN"));
    let state = fixture.data_home.join("devin");
    assert_eq!(
        std::fs::read_to_string(state.join("credentials.toml")).unwrap(),
        "rotated synthetic credential\n"
    );
    assert_eq!(
        std::fs::read_to_string(state.join("history/session.log")).unwrap(),
        "synthetic session\n"
    );
    assert_eq!(
        std::fs::read_to_string(fixture.config_home.join("devin/config.json"))
            .unwrap(),
        "synthetic config\n"
    );
    assert!(!cli.exists());
}

#[test]
fn devin_missing_xdg_bases_warn_once_each_and_opt_out_does_not_warn() {
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }
    let mut fixture = DevinFixture::new();
    fixture.config_home = fixture.root.join("missing-config");
    let data = fixture.root.join("missing-data");
    let output =
        fixture.run_extra("probe-hidden", false, &["--dry-run"], &data);
    assert_success(&output, "missing XDG bases discovery");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        stderr.matches("cannot resolve XDG_DATA_HOME base").count(),
        1,
        "{stderr}"
    );
    assert_eq!(
        stderr
            .matches("cannot resolve XDG_CONFIG_HOME base")
            .count(),
        1,
        "{stderr}"
    );
    let output = fixture.run_extra("probe-hidden", true, &["--dry-run"], &data);
    assert_success(&output, "missing XDG bases with agent state disabled");
    assert!(
        !String::from_utf8_lossy(&output.stderr)
            .contains("cannot resolve XDG_")
    );
    assert!(!data.exists());
    assert!(!fixture.config_home.exists());
}

#[test]
fn devin_opt_out_only_protects_installations_already_visible_in_home() {
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }
    let mut fixture = DevinFixture::new();
    let output = fixture.run_extra(
        "probe-hidden",
        true,
        &["--no-private-home"],
        &fixture.data_home,
    );
    assert_success(&output, "external XDG opt-out");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("CREDENTIAL_HIDDEN"), "{stdout}");
    assert!(stdout.contains("INSTALL_HIDDEN"), "{stdout}");

    let data = fixture.home.join(".local/share");
    std::fs::create_dir_all(data.parent().unwrap()).unwrap();
    std::fs::rename(&fixture.data_home, &data).unwrap();
    fixture.data_home = data;
    let output = fixture.run_extra(
        "probe-install",
        true,
        &["--no-private-home"],
        &fixture.data_home,
    );
    assert_success(&output, "already-visible home installation");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("VERSION_READ_ONLY"), "{stdout}");
    assert!(stdout.contains("CURRENT_RENAME_BLOCKED"), "{stdout}");
    let output = fixture.run_extra(
        "probe-ancestor",
        true,
        &["--no-private-home"],
        &fixture.data_home,
    );
    assert_success(&output, "already-visible launcher ancestor");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("CLI_RENAME_BLOCKED")
    );
}

#[test]
fn devin_xdg_symlink_parent_and_relative_fallback_match_child_paths() {
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }
    let mut fixture = DevinFixture::new();
    let physical = fixture.root.join("physical");
    std::fs::create_dir_all(physical.join("nested")).unwrap();
    let data = physical.join("data");
    std::fs::rename(&fixture.data_home, &data).unwrap();
    fixture.data_home = data;
    std::os::unix::fs::symlink(
        physical.join("nested"),
        fixture.root.join("alias"),
    )
    .unwrap();
    let alias = fixture.root.join("alias/../data");
    let output = fixture.run_extra("write-state", false, &[], &alias);
    assert_success(&output, "physical XDG root");
    assert!(String::from_utf8_lossy(&output.stdout).contains("STATE_WRITTEN"));
    let output = fixture.run_extra("probe-ancestor", false, &[], &alias);
    assert_success(&output, "physical installation protection");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("CLI_RENAME_BLOCKED")
    );

    let fallback = fixture.home.join(".local/share");
    std::fs::create_dir_all(fallback.parent().unwrap()).unwrap();
    std::fs::rename(&fixture.data_home, &fallback).unwrap();
    fixture.data_home = fallback;
    let output = fixture.run_extra(
        "write-state",
        false,
        &[],
        Path::new("relative-data"),
    );
    assert_success(&output, "relative XDG fallback");
    assert!(String::from_utf8_lossy(&output.stdout).contains("STATE_WRITTEN"));
    assert!(!fixture.project.join("relative-data").exists());
}

#[test]
fn devin_explicit_writable_map_can_override_automatic_installation_protection()
{
    if !bwrap_available() {
        eprintln!("SKIPPED: bwrap cannot create user namespaces");
        return;
    }
    let fixture = DevinFixture::new();
    let data = fixture.data_home.join("devin");
    let path = data.to_str().unwrap();
    let output = fixture.run_extra(
        "probe-install",
        false,
        &["--rw-map", path],
        &fixture.data_home,
    );
    assert_success(&output, "explicit writable map");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("VERSION_WRITABLE")
    );
    assert_eq!(
        std::fs::read_to_string(
            data.join("cli/_versions/3000.11.3/bin/payload")
        )
        .unwrap(),
        "tampered\n"
    );
}
