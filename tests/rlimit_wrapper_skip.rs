// Explicit limits through the built binary: applied with every other
// control off, each clamp warned about once, and a one-off `--cpus` or
// `--rlimit` never carried into the next launch.
//
// Each test runs with a temporary HOME, XDG_CONFIG_HOME and project
// directory, so the developer's own config cannot leak in, and without
// `--exec`, which silences warnings. Tests that start a sandbox skip with
// a message when bwrap cannot create user and network namespaces.
#![cfg(target_os = "linux")]

mod common;

use common::ai_jail;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

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
            "rlimit-explicit-{name}-{}-{id}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        let home = root.join("home");
        let xdg = root.join("xdg");
        for dir in [&project, &home, &xdg] {
            std::fs::create_dir_all(dir).unwrap();
        }
        Self {
            root,
            project,
            home,
            xdg,
        }
    }

    /// Run ai-jail from the project. `nofile_hard`, when given, lowers the
    /// launching shell's NOFILE limit first, as a host limit would.
    fn run(&self, nofile_hard: Option<u64>, args: &[&str]) -> Output {
        let _lock = common::SANDBOX_RUN_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let ulimit = nofile_hard
            .map(|n| format!("ulimit -n {n} && "))
            .unwrap_or_default();
        Command::new("sh")
            .arg("-c")
            .arg(format!("{ulimit}exec \"$0\" \"$@\""))
            .arg(ai_jail())
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

    /// A real launch of `bash -c script`, network off, no auto-save.
    fn jail(
        &self,
        nofile_hard: Option<u64>,
        flags: &[&str],
        script: &str,
    ) -> Output {
        let mut args =
            vec!["--no-status-bar", "--no-save-config", "--no-network"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["bash", "-c", script]);
        self.run(nofile_hard, &args)
    }

    /// `--dry-run bash` from the project; never auto-saves.
    fn dry_run(&self, flags: &[&str]) -> Output {
        let mut args = vec!["--no-status-bar", "--no-network"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["--dry-run", "bash"]);
        self.run(None, &args)
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

fn assert_ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "ai-jail failed: status={:?}\nstdout={}\nstderr={}",
        o.status,
        stdout(o),
        stderr(o)
    );
    stdout(o)
}

/// `Max open files` soft and hard from a `/proc/self/limits` dump.
fn open_files(limits: &str) -> (String, String) {
    let line = limits
        .lines()
        .find(|l| l.starts_with("Max open files"))
        .unwrap_or_else(|| panic!("no Max open files line in {limits}"));
    let mut cols = line["Max open files".len()..].split_whitespace();
    (
        cols.next().unwrap().to_string(),
        cols.next().unwrap().to_string(),
    )
}

/// Warning lines (`⚠ ...` on a non-terminal stderr) naming every needle.
fn warnings_naming(o: &Output, needles: &[&str]) -> Vec<String> {
    stderr(o)
        .lines()
        .filter(|l| l.contains('⚠') && needles.iter().all(|n| l.contains(n)))
        .map(str::to_string)
        .collect()
}

fn allowed_cpus() -> Vec<usize> {
    let list = std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .map(|v| v.trim().to_string())
        .unwrap();
    let mut cpus = Vec::new();
    for part in list.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                cpus.extend(a.parse::<usize>().unwrap()..=b.parse().unwrap())
            }
            None => cpus.push(part.parse().unwrap()),
        }
    }
    cpus
}

#[test]
fn explicit_limit_applies_with_every_other_control_off() {
    require_bwrap_net!();
    let tree = Tree::new("all-off");
    let out = tree.jail(
        None,
        &[
            "--no-landlock",
            "--no-seccomp",
            "--no-rlimits",
            "--rlimit",
            "nofile=64",
        ],
        "cat /proc/self/limits",
    );
    let limits = assert_ok(&out);
    assert_eq!(
        open_files(&limits),
        ("64".to_string(), "64".to_string()),
        "{limits}"
    );
}

#[test]
fn default_limit_clamped_by_the_host_is_warned_about_once() {
    require_bwrap_net!();
    let tree = Tree::new("default-clamp");
    // The host hard NOFILE (4000) is below the default (65536).
    let out = tree.jail(Some(4000), &[], "cat /proc/self/limits");
    let limits = assert_ok(&out);
    assert_eq!(open_files(&limits).0, "4000", "{limits}");
    let hits = warnings_naming(&out, &["NOFILE", "65536", "4000"]);
    assert_eq!(hits.len(), 1, "stderr={}", stderr(&out));
}

#[test]
fn explicit_limit_clamped_by_the_host_is_warned_about_once() {
    require_bwrap_net!();
    let tree = Tree::new("explicit-clamp");
    let out = tree.jail(
        Some(4000),
        &["--rlimit", "nofile=8000"],
        "cat /proc/self/limits",
    );
    let limits = assert_ok(&out);
    assert_eq!(open_files(&limits).0, "4000", "{limits}");
    let hits = warnings_naming(&out, &["NOFILE", "8000", "4000"]);
    assert_eq!(hits.len(), 1, "stderr={}", stderr(&out));
}

#[test]
fn lockdown_clamps_an_explicit_value_and_warns_once() {
    require_bwrap_net!();
    let tree = Tree::new("lockdown-clamp");
    let out = tree.jail(
        None,
        &["--lockdown", "--rlimit", "nofile=8192"],
        "cat /proc/self/limits",
    );
    let limits = assert_ok(&out);
    assert_eq!(
        open_files(&limits),
        ("4096".to_string(), "4096".to_string()),
        "{limits}"
    );
    let hits = warnings_naming(&out, &["8192", "4096"]);
    assert_eq!(hits.len(), 1, "stderr={}", stderr(&out));
    assert!(
        hits[0].to_ascii_lowercase().contains("nofile"),
        "{}",
        hits[0]
    );
}

#[test]
fn cli_cpus_once_does_not_pin_the_next_launch() {
    require_bwrap_net!();
    let cpus = allowed_cpus();
    let first = cpus[0].to_string();
    let tree = Tree::new("cpus-sticky");
    // A real launch, saving the project policy as an ordinary run does.
    assert_ok(&tree.run(
        None,
        &[
            "--no-status-bar",
            "--no-network",
            "--cpus",
            &first,
            "bash",
            "-c",
            "true",
        ],
    ));
    let plain = tree.dry_run(&[]);
    let text = assert_ok(&plain) + &stderr(&plain);
    assert!(
        !text.lines().any(|l| l.trim().starts_with("cpus=")),
        "a plain launch must not inherit --cpus {first}: {text}"
    );
    // A different set on the next launch is this launch's choice, not a
    // conflict with the one before.
    if let Some(other) = cpus.get(1) {
        let other = other.to_string();
        let next = tree.dry_run(&["--cpus", &other]);
        let text = assert_ok(&next) + &stderr(&next);
        assert!(
            text.lines().any(|l| l.trim() == format!("cpus={other}")),
            "{text}"
        );
    }
}

#[test]
fn cli_rlimit_once_does_not_tighten_the_next_launch() {
    require_bwrap_net!();
    let tree = Tree::new("rlimit-sticky");
    assert_ok(&tree.run(
        None,
        &[
            "--no-status-bar",
            "--no-network",
            "--rlimit",
            "nofile=1024",
            "bash",
            "-c",
            "true",
        ],
    ));
    let next = tree.dry_run(&["--rlimit", "nofile=4096"]);
    let text = assert_ok(&next) + &stderr(&next);
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with("rlimit name=nofile "))
        .unwrap_or_else(|| panic!("no nofile line: {text}"));
    assert!(
        line.contains("soft=4096") && line.contains("source=cli"),
        "the second launch's own value applies: {line}"
    );
}

#[test]
fn project_policy_rlimit_survives_launch_after_launch() {
    require_bwrap_net!();
    let tree = Tree::new("project-rlimit");
    // A limit the project policy carries itself, written by hand.
    std::fs::write(tree.project.join(".ai-jail"), "[rlimit]\nnofile = 512\n")
        .unwrap();
    for launch in 1..=2 {
        let out = tree.run(
            None,
            &[
                "--no-status-bar",
                "--no-network",
                "bash",
                "-c",
                "cat /proc/self/limits",
            ],
        );
        let limits = assert_ok(&out);
        assert_eq!(
            open_files(&limits).0,
            "512",
            "launch {launch} keeps the project's own limit: {limits}"
        );
    }
}
