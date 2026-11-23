// An explicit `core` or `nofile` never loosens ai-jail's own supervisor,
// measured on the running processes: the supervisor's
// `/proc/<pid>/limits` while the sandbox sleeps, and the sandbox's own
// `/proc/self/limits`.
//
// The supervisor is the spawned ai-jail process itself (it applies its
// limits, then forks bwrap). The launching shell first makes itself
// dumpable (core soft = hard) and lowers its `nofile` soft limit, so a
// supervisor that inherits instead of
// applying its defaults then shows `unlimited` / the low value.
//
// Each test runs with a temporary HOME, XDG_CONFIG_HOME and project
// directory, so the developer's own config cannot leak in, and skips with a
// message when bwrap cannot create namespaces.
#![cfg(target_os = "linux")]

mod common;

use common::ai_jail;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

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
            "rlimit-supervisor-{name}-{}-{id}",
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

    /// Spawn `ai-jail --no-status-bar --no-save-config <flags> sh -c
    /// '<script>'` from a shell that is dumpable and has `nofile` soft 2048.
    /// The shell `exec`s, so the child's pid is the supervisor's.
    fn spawn(&self, flags: &[&str], script: &str) -> Child {
        let mut args = vec!["--no-status-bar", "--no-save-config"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["sh", "-c", script]);
        Command::new("sh")
            .arg("-c")
            .arg(
                "ulimit -S -c \"$(ulimit -H -c)\" && ulimit -S -n 2048 \
                 && exec \"$0\" \"$@\"",
            )
            .arg(ai_jail())
            .args(&args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env_remove("AI_JAIL_QUIET")
            .env_remove("NO_COLOR")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn ai-jail")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// Soft and hard columns of the `label` line of a limits dump.
fn limit(limits: &str, label: &str) -> (String, String) {
    let line = limits
        .lines()
        .find(|l| l.starts_with(label))
        .unwrap_or_else(|| panic!("no {label} line in {limits}"));
    let mut cols = line[label.len()..].split_whitespace();
    (
        cols.next().unwrap().to_string(),
        cols.next().unwrap().to_string(),
    )
}

fn pair(soft: &str, hard: &str) -> (String, String) {
    (soft.to_string(), hard.to_string())
}

/// The last line of a `/proc/<pid>/limits` dump.
const LAST_LIMIT_LINE: &str = "Max realtime timeout";

/// Read the sandbox's stdout until its `/proc/self/limits` dump is complete.
/// The sandbox prints it before sleeping, so the supervisor has applied its
/// own limits by then (it forks other helpers earlier, so "has a child" is
/// not enough).
fn read_sandbox_dump(child: &mut Child) -> String {
    let stdout = child.stdout.as_mut().expect("piped stdout");
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut seen = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let text = String::from_utf8_lossy(&seen).into_owned();
        if let Some(i) = text.find(LAST_LIMIT_LINE)
            && text[i..].contains('\n')
        {
            return text;
        }
        assert!(Instant::now() < deadline, "no limits dump: {text}");
        match stdout.read(&mut buf) {
            Ok(0) => {
                let mut err = String::new();
                if let Some(e) = child.stderr.as_mut() {
                    let _ = e.read_to_string(&mut err);
                }
                panic!("ai-jail closed stdout early: {text}\nstderr={err}");
            }
            Ok(n) => seen.extend_from_slice(&buf[..n]),
            Err(e) => panic!("read ai-jail stdout: {e}"),
        }
    }
}

/// Run one launch: the supervisor's `/proc/<pid>/limits` during the
/// sandbox's sleep, and what the sandbox printed for `/proc/self/limits`.
fn launch(flags: &[&str]) -> (String, String) {
    let _lock = common::SANDBOX_RUN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let tree = Tree::new("launch");
    let mut child = tree.spawn(flags, "cat /proc/self/limits; sleep 3");
    let sandbox = read_sandbox_dump(&mut child);
    let pid = child.id();
    let supervisor =
        std::fs::read_to_string(Path::new(&format!("/proc/{pid}/limits")))
            .expect("read the supervisor's limits during the sleep");
    let out = child.wait_with_output().expect("wait for ai-jail");
    assert!(
        out.status.success(),
        "ai-jail failed: status={:?}\nstdout={sandbox}{}\nstderr={}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (supervisor, sandbox)
}

#[test]
fn supervisor_without_explicit_limits_runs_at_the_defaults() {
    // Baseline the explicit cases must match: no flag, defaults applied.
    require_bwrap!();
    let (supervisor, sandbox) = launch(&[]);
    assert_eq!(
        limit(&supervisor, "Max core file size"),
        pair("0", "0"),
        "supervisor:\n{supervisor}"
    );
    assert_eq!(
        limit(&supervisor, "Max open files"),
        pair("65536", "65536"),
        "supervisor:\n{supervisor}"
    );
    assert_eq!(
        limit(&sandbox, "Max core file size"),
        pair("0", "0"),
        "sandbox:\n{sandbox}"
    );
}

#[test]
fn supervisor_keeps_core_zero_when_core_zero_is_explicit() {
    // An explicit `core=0` must not remove the supervisor's core limit:
    // the supervisor holds the egress proxy and its secret substitution.
    require_bwrap!();
    let (supervisor, sandbox) = launch(&["--rlimit", "core=0"]);
    assert_eq!(
        limit(&supervisor, "Max core file size"),
        pair("0", "0"),
        "supervisor:\n{supervisor}"
    );
    assert_eq!(
        limit(&sandbox, "Max core file size"),
        pair("0", "0"),
        "sandbox:\n{sandbox}"
    );
}

#[test]
fn supervisor_keeps_its_nofile_default_whatever_nofile_is_explicit() {
    require_bwrap!();
    // Asking for the default value must not hand the supervisor the
    // launching shell's 2048.
    let (supervisor, sandbox) =
        launch(&["--rlimit", "core=0", "--rlimit", "nofile=65536"]);
    assert_eq!(
        limit(&supervisor, "Max open files"),
        pair("65536", "65536"),
        "supervisor:\n{supervisor}"
    );
    assert_eq!(
        limit(&supervisor, "Max core file size"),
        pair("0", "0"),
        "supervisor:\n{supervisor}"
    );
    assert_eq!(
        limit(&sandbox, "Max open files"),
        pair("65536", "65536"),
        "sandbox:\n{sandbox}"
    );
    // The converse: a tighter explicit value is the sandbox's alone and
    // does not reach the supervisor.
    let (supervisor, sandbox) = launch(&["--rlimit", "nofile=1024"]);
    assert_eq!(
        limit(&supervisor, "Max open files"),
        pair("65536", "65536"),
        "supervisor:\n{supervisor}"
    );
    assert_eq!(
        limit(&sandbox, "Max open files"),
        pair("1024", "1024"),
        "sandbox:\n{sandbox}"
    );
}
