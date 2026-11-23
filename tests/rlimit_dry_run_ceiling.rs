// `--dry-run` reports the `core` and `nofile` values the sandbox actually
// receives, and every printed limit spells RLIM_INFINITY as `unlimited`.
//
// The supervisor applies its own `core` 0 and `nofile` 65536 with hard
// pinned to soft before it starts the sandbox, so an explicit value above
// them is unreachable inside. The dry run must print what a real launch
// with the same flags measures with `ulimit`, marked `ceiling=supervisor`
// where the ceiling changed the value, while the launch keeps warning about
// the clamp in the operator's own words.
//
// Launches run without `--exec`, because `--exec` silences warnings, from a
// temporary HOME, XDG_CONFIG_HOME and project directory, so the developer's
// own config cannot leak in; they skip with a message when bwrap cannot
// create namespaces.
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
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "rlimit-dry-run-ceiling-{}-{id}",
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
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Run `ai-jail --no-status-bar --no-save-config <flags> sh -c <script>`.
fn jail(flags: &[&str], script: &str) -> Output {
    let _lock = common::SANDBOX_RUN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tree = Tree::new();
    Command::new(ai_jail())
        .args(["--no-status-bar", "--no-save-config"])
        .args(flags)
        .args(["sh", "-c", script])
        .current_dir(&tree.project)
        .env("HOME", &tree.home)
        .env("XDG_CONFIG_HOME", &tree.xdg)
        .env_remove("AI_JAIL_QUIET")
        .env_remove("NO_COLOR")
        .stdin(Stdio::null())
        .output()
        .expect("failed to spawn ai-jail")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// The dry run's `rlimit name=<name> ...` line.
fn dry_run(flags: &[&str]) -> String {
    let mut all = vec!["--dry-run"];
    all.extend_from_slice(flags);
    let out = jail(&all, "true");
    let stdout = text(&out.stdout);
    assert!(
        out.status.success(),
        "dry run failed: stdout={stdout}\nstderr={}",
        text(&out.stderr)
    );
    stdout
}

fn line<'a>(stdout: &'a str, name: &str) -> &'a str {
    let prefix = format!("rlimit name={name} ");
    stdout
        .lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no {prefix:?} line in:\n{stdout}"))
}

/// The value of `key=` on a dry-run line.
fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    line.split_whitespace()
        .find_map(|w| w.strip_prefix(prefix.as_str()))
}

/// `ulimit -n` and `ulimit -c` measured inside a real launch.
fn measured(flags: &[&str]) -> (String, String, String) {
    let out = jail(flags, "echo nofile=$(ulimit -n) core=$(ulimit -c)");
    let stdout = text(&out.stdout);
    let stderr = text(&out.stderr);
    assert!(
        out.status.success(),
        "launch failed: stdout={stdout}\nstderr={stderr}"
    );
    let row = stdout
        .lines()
        .find(|l| l.starts_with("nofile="))
        .unwrap_or_else(|| panic!("no ulimit row in:\n{stdout}"));
    let mut cols = row.split_whitespace();
    let nofile = cols.next().unwrap().trim_start_matches("nofile=");
    let core = cols.next().unwrap().trim_start_matches("core=");
    (nofile.to_string(), core.to_string(), stderr)
}

/// The test process's own hard limit for a `/proc/self/limits` label.
fn host_hard(label: &str) -> String {
    let limits = std::fs::read_to_string("/proc/self/limits").unwrap();
    let row = limits
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label} in {limits}"));
    row[label.len()..]
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string()
}

/// Whether the host lets the supervisor reach its own defaults and the
/// sandbox reach the values asked for here; on a host with lower hard
/// limits the measured values are the host's, not ai-jail's.
fn host_is_roomy() -> bool {
    let nofile = host_hard("Max open files");
    let roomy = nofile == "unlimited"
        || nofile.parse::<u64>().is_ok_and(|n| n >= 100000);
    if !roomy {
        eprintln!("SKIPPED: host hard nofile {nofile} is below 100000");
    }
    roomy
}

#[test]
fn dry_run_leaves_values_within_the_ceiling_unmarked() {
    // The marker must not fire when the ceiling changed nothing.
    require_bwrap!();
    if !host_is_roomy() {
        return;
    }
    let flags = ["--rlimit", "nofile=1024", "--rlimit", "core=0"];
    let stdout = dry_run(&flags);
    let nofile = line(&stdout, "nofile");
    let core = line(&stdout, "core");
    assert_eq!(field(nofile, "soft"), Some("1024"), "{nofile}");
    assert_eq!(field(core, "soft"), Some("0"), "{core}");
    assert_eq!(field(nofile, "ceiling"), None, "{nofile}");
    assert_eq!(field(core, "ceiling"), None, "{core}");
    let (in_nofile, in_core, _) = measured(&flags);
    assert_eq!(field(nofile, "soft"), Some(in_nofile.as_str()));
    assert_eq!(field(core, "soft"), Some(in_core.as_str()));

    // Asking for exactly the supervisor default is not a clamp either.
    let stdout = dry_run(&["--rlimit", "nofile=65536"]);
    let nofile = line(&stdout, "nofile");
    assert_eq!(field(nofile, "soft"), Some("65536"), "{nofile}");
    assert_eq!(field(nofile, "ceiling"), None, "{nofile}");
}

#[test]
fn dry_run_reports_the_supervisor_ceiling_the_sandbox_gets() {
    require_bwrap!();
    if !host_is_roomy() {
        return;
    }
    let flags = ["--rlimit", "nofile=100000", "--rlimit", "core=unlimited"];
    let stdout = dry_run(&flags);
    let nofile = line(&stdout, "nofile");
    let core = line(&stdout, "core");
    assert_eq!(field(nofile, "soft"), Some("65536"), "{nofile}");
    assert_eq!(field(nofile, "hard"), Some("65536"), "{nofile}");
    assert_eq!(field(core, "soft"), Some("0"), "{core}");
    assert_eq!(field(core, "hard"), Some("0"), "{core}");
    assert_eq!(field(nofile, "ceiling"), Some("supervisor"), "{nofile}");
    assert_eq!(field(core, "ceiling"), Some("supervisor"), "{core}");
    // The layer that asked is still named.
    assert_eq!(field(nofile, "source"), Some("cli"), "{nofile}");
    assert_eq!(field(core, "source"), Some("cli"), "{core}");

    // The same flags on a real launch measure the same values.
    let (in_nofile, in_core, _) = measured(&flags);
    assert_eq!(field(nofile, "soft"), Some(in_nofile.as_str()), "{nofile}");
    assert_eq!(field(core, "soft"), Some(in_core.as_str()), "{core}");
}

#[test]
fn dry_run_without_the_default_set_prints_unlimited_unmarked() {
    // With `--no-rlimits` the supervisor holds no ceiling, so the request
    // is what is reported, and RLIM_INFINITY reads as typed.
    require_bwrap!();
    let stdout = dry_run(&[
        "--no-rlimits",
        "--rlimit",
        "nofile=100000",
        "--rlimit",
        "core=unlimited",
    ]);
    let nofile = line(&stdout, "nofile");
    let core = line(&stdout, "core");
    assert_eq!(field(nofile, "soft"), Some("100000"), "{nofile}");
    assert_eq!(field(core, "soft"), Some("unlimited"), "{core}");
    assert_eq!(field(core, "hard"), Some("unlimited"), "{core}");
    assert_eq!(field(nofile, "ceiling"), None, "{nofile}");
    assert_eq!(field(core, "ceiling"), None, "{core}");
    assert!(!stdout.contains("18446744073709551615"), "{stdout}");
}

#[test]
fn launch_warns_about_the_clamp_in_the_operators_words() {
    require_bwrap!();
    if !host_is_roomy() {
        return;
    }
    let (_, _, stderr) =
        measured(&["--rlimit", "nofile=100000", "--rlimit", "core=unlimited"]);
    // Reporting the ceiling in the dry run must not silence the launch:
    // the operator asked for a value they are not getting.
    let core: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("RLIMIT_CORE"))
        .collect();
    assert_eq!(core.len(), 1, "one RLIMIT_CORE warning:\n{stderr}");
    assert!(core[0].contains("requested unlimited"), "{}", core[0]);
    assert!(core[0].contains("applied 0"), "{}", core[0]);
    assert!(!stderr.contains("18446744073709551615"), "{stderr}");
    let nofile: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("RLIMIT_NOFILE"))
        .collect();
    assert_eq!(nofile.len(), 1, "one RLIMIT_NOFILE warning:\n{stderr}");
    assert!(nofile[0].contains("requested 100000"), "{}", nofile[0]);
    assert!(nofile[0].contains("applied 65536"), "{}", nofile[0]);
}
