// `--dry-run` and the audit record report the soft and hard values the
// sandbox actually receives when the host's own hard limit is the one that
// binds, marked `ceiling=host`.
//
// The host limit is lowered for one launch only, by a `sh -c 'ulimit …;
// exec ai-jail …'` wrapper: lowering a hard limit needs no privilege, and
// ai-jail inherits it like any process started from a restricted shell.
// For `cpu` the sandbox gets `min(soft, host)` as soft and `min(soft + 5,
// host)` as hard, so a host limit below the request leaves no grace.
//
// Launches run without `--exec`, because `--exec` silences warnings, from a
// temporary HOME, XDG_CONFIG_HOME and project directory, so the developer's
// own config and history cannot leak in; they skip with a message when
// bwrap cannot create namespaces or the host is already below the limit a
// test lowers it to.
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
    fn new() -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("rlimit-host-ceiling-{}-{id}", std::process::id()));
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

    /// Run `ai-jail --no-status-bar --no-save-config <flags> sh -c
    /// <script>` from a shell that first runs `ulimit <host>`.
    fn under_host(&self, host: &str, flags: &[&str], script: &str) -> Output {
        let _lock = common::SANDBOX_RUN_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Command::new("sh")
            .arg("-c")
            .arg(format!("ulimit {host} && exec \"$0\" \"$@\""))
            .arg(ai_jail())
            .args(["--no-status-bar", "--no-save-config"])
            .args(flags)
            .args(["sh", "-c", script])
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env_remove("AI_JAIL_QUIET")
            .env_remove("NO_COLOR")
            .stdin(Stdio::null())
            .output()
            .expect("failed to spawn ai-jail")
    }

    /// The last record of this tree's audit log.
    fn last_record(&self) -> serde_json::Value {
        let log = self.home.join(".local/share/ai-jail/history.jsonl");
        let content = std::fs::read_to_string(&log)
            .unwrap_or_else(|e| panic!("no audit log at {log:?}: {e}"));
        let last = content.lines().last().expect("an empty audit log");
        serde_json::from_str(last).unwrap()
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn assert_ok(out: &Output) -> String {
    let stdout = text(&out.stdout);
    assert!(
        out.status.success(),
        "ai-jail failed ({:?}): stdout={stdout}\nstderr={}",
        out.status,
        text(&out.stderr)
    );
    stdout
}

/// The dry run's `rlimit name=<name> ...` line under a lowered host.
fn dry_run(host: &str, flags: &[&str], name: &str) -> String {
    let tree = Tree::new();
    let mut all = vec!["--dry-run"];
    all.extend_from_slice(flags);
    let stdout = assert_ok(&tree.under_host(host, &all, "true"));
    let prefix = format!("rlimit name={name} ");
    stdout
        .lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no {prefix:?} line in:\n{stdout}"))
        .to_string()
}

/// The value of `key=` on a dry-run line.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    line.split_whitespace()
        .find_map(|w| w.strip_prefix(prefix.as_str()))
}

/// The soft and hard columns of a `/proc/<pid>/limits` row.
fn limits_row(limits: &str, label: &str) -> (String, String) {
    let row = limits
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label} row in:\n{limits}"));
    let mut cols = row[label.len()..].split_whitespace();
    let soft = cols.next().unwrap().to_string();
    let hard = cols.next().unwrap().to_string();
    (soft, hard)
}

/// `/proc/self/limits` measured inside a real launch under the host.
fn measured(host: &str, flags: &[&str], label: &str) -> (String, String) {
    let tree = Tree::new();
    let script = format!("grep '^{label}' /proc/self/limits");
    let stdout = assert_ok(&tree.under_host(host, flags, &script));
    limits_row(&stdout, label)
}

/// Whether the test process's own hard limit for `label` is at least
/// `floor`, so `ulimit` can lower it there.
fn host_allows(label: &str, floor: u64) -> bool {
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap();
    let (_, hard) = limits_row(&limits, label);
    let roomy =
        hard == "unlimited" || hard.parse::<u64>().is_ok_and(|n| n >= floor);
    if !roomy {
        eprintln!("SKIPPED: host hard {label:?} {hard} is below {floor}");
    }
    roomy
}

const CPU: &str = "Max cpu time";
const NOFILE: &str = "Max open files";

#[test]
fn dry_run_leaves_cpu_unmarked_when_the_host_limit_is_roomy() {
    // The marker must not fire when the host changed nothing: a host
    // limit above the request and its grace, and one exactly at the grace.
    require_bwrap!();
    if !host_allows(CPU, 100) {
        return;
    }
    for host in ["-t 100", "-t 65"] {
        let line = dry_run(host, &["--rlimit", "cpu=60"], "cpu");
        assert_eq!(field(&line, "soft"), Some("60"), "{host}: {line}");
        assert_eq!(field(&line, "hard"), Some("65"), "{host}: {line}");
        assert_eq!(field(&line, "ceiling"), None, "{host}: {line}");
        assert_eq!(field(&line, "source"), Some("cli"), "{host}: {line}");
    }
}

#[test]
fn dry_run_reports_the_host_cpu_limit_the_sandbox_gets() {
    require_bwrap!();
    if !host_allows(CPU, 30) {
        return;
    }
    let flags = ["--rlimit", "cpu=60"];
    let line = dry_run("-t 30", &flags, "cpu");
    assert_eq!(field(&line, "soft"), Some("30"), "{line}");
    assert_eq!(field(&line, "hard"), Some("30"), "{line}");
    assert_eq!(field(&line, "ceiling"), Some("host"), "{line}");
    // The layer that asked is still named.
    assert_eq!(field(&line, "source"), Some("cli"), "{line}");

    // The same flags on a real launch under the same host measure it.
    let (soft, hard) = measured("-t 30", &flags, CPU);
    assert_eq!(field(&line, "soft"), Some(soft.as_str()), "{line}");
    assert_eq!(field(&line, "hard"), Some(hard.as_str()), "{line}");
}

#[test]
fn dry_run_shortens_the_cpu_grace_to_the_host_limit() {
    // The request fits under the host limit, its grace does not.
    require_bwrap!();
    if !host_allows(CPU, 62) {
        return;
    }
    let flags = ["--rlimit", "cpu=60"];
    let line = dry_run("-t 62", &flags, "cpu");
    assert_eq!(field(&line, "soft"), Some("60"), "{line}");
    assert_eq!(field(&line, "hard"), Some("62"), "{line}");
    let (soft, hard) = measured("-t 62", &flags, CPU);
    assert_eq!((soft.as_str(), hard.as_str()), ("60", "62"));
}

#[test]
fn dry_run_reports_the_host_nofile_below_the_supervisor_default() {
    // The supervisor would hold `nofile` at 65536; a host limit of 2048 is
    // lower still, so it is the value and the ceiling shown.
    require_bwrap!();
    if !host_allows(NOFILE, 2048) {
        return;
    }
    let flags = ["--rlimit", "nofile=100000"];
    let line = dry_run("-n 2048", &flags, "nofile");
    assert_eq!(field(&line, "soft"), Some("2048"), "{line}");
    assert_eq!(field(&line, "hard"), Some("2048"), "{line}");
    assert_eq!(field(&line, "ceiling"), Some("host"), "{line}");
    let (soft, hard) = measured("-n 2048", &flags, NOFILE);
    assert_eq!((soft.as_str(), hard.as_str()), ("2048", "2048"));
}

#[test]
fn audit_record_holds_the_host_cpu_limit_the_sandbox_gets() {
    require_bwrap!();
    if !host_allows(CPU, 30) {
        return;
    }
    let tree = Tree::new();
    let out = tree.under_host(
        "-t 30",
        &["--audit-log", "--rlimit", "cpu=60"],
        &format!("grep '^{CPU}' /proc/self/limits"),
    );
    let stdout = assert_ok(&out);
    let (in_soft, in_hard) = limits_row(&stdout, CPU);
    assert_eq!((in_soft.as_str(), in_hard.as_str()), ("30", "30"));

    let record = tree.last_record();
    assert_eq!(record["type"], "launch");
    let rlimits = record["rlimits"].as_array().expect("rlimits array");
    let cpu = rlimits
        .iter()
        .find(|r| r["name"] == "cpu")
        .unwrap_or_else(|| panic!("no cpu entry in {record}"));
    assert_eq!(cpu["soft"], 30, "{cpu}");
    assert_eq!(cpu["hard"], 30, "{cpu}");
    assert_eq!(cpu["source"], "cli", "{cpu}");
    // The record and the sandbox agree, number for number.
    assert_eq!(cpu["soft"].to_string(), in_soft, "{cpu}");
    assert_eq!(cpu["hard"].to_string(), in_hard, "{cpu}");

    // Reporting the host value must not silence the launch: the operator
    // asked for a value they are not getting, and hears it once.
    let stderr = text(&out.stderr);
    let warned: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("RLIMIT_CPU"))
        .collect();
    assert_eq!(warned.len(), 1, "one RLIMIT_CPU warning:\n{stderr}");
    assert!(warned[0].contains("requested 60"), "{}", warned[0]);
    assert!(warned[0].contains("30"), "{}", warned[0]);
}
