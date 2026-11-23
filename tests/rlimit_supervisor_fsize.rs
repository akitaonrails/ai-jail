// Under `--lockdown` an explicit `fsize` never loosens ai-jail's own
// supervisor, measured on the running processes: the supervisor's
// `/proc/<pid>/limits` while the sandbox sleeps, and the sandbox's own
// `/proc/self/limits`.
//
// The supervisor is the spawned ai-jail process itself (it applies its
// limits, then forks bwrap). Lockdown's 1 GiB `fsize` default stays on it
// whether the explicit `fsize` comes from the CLI or from a legacy project
// `.ai-jail` (untrusted input); the explicit value is the sandbox's. The
// file-size clamp is reported at most once per launch.
//
// Each test runs with a temporary HOME, XDG_CONFIG_HOME and project
// directory, so the developer's own config cannot leak in, and skips with a
// message when bwrap cannot create network namespaces (lockdown needs one).
#![cfg(target_os = "linux")]

mod common;

use common::ai_jail;
use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

const ONE_GIB: &str = "1073741824";
const HALF_GIB: &str = "536870912";
const QUARTER_GIB: &str = "268435456";

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
            "rlimit-supervisor-fsize-{name}-{}-{id}",
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

    /// Spawn `ai-jail --no-status-bar <flags> sh -c '<script>'`. With
    /// `host_fsize`, util-linux `prlimit` sets that soft and hard `fsize`
    /// first and execs ai-jail, so in both cases the child's pid is the
    /// supervisor's.
    fn spawn(
        &self,
        flags: &[&str],
        script: &str,
        host_fsize: Option<&str>,
    ) -> Child {
        let mut command = match host_fsize {
            Some(bytes) => {
                let mut c = Command::new("prlimit");
                c.arg(format!("--fsize={bytes}:{bytes}"))
                    .arg("--")
                    .arg(ai_jail());
                c
            }
            None => Command::new(ai_jail()),
        };
        command
            .arg("--no-status-bar")
            .args(flags)
            .args(["sh", "-c", script])
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env_remove("AI_JAIL_QUIET")
            .env_remove("NO_COLOR")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command.spawn().expect("failed to spawn ai-jail")
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn prlimit_available() -> bool {
    Command::new("prlimit")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
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

const FSIZE: &str = "Max file size";

/// The last line of a `/proc/<pid>/limits` dump.
const LAST_LIMIT_LINE: &str = "Max realtime timeout";

/// Read the sandbox's stdout until its `/proc/self/limits` dump is complete.
/// The sandbox prints it before sleeping, so the supervisor has applied its
/// own limits by then.
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

struct Launch {
    supervisor: String,
    sandbox: String,
    stderr: String,
}

impl Launch {
    /// The stderr lines that report the file-size limit.
    fn fsize_lines(&self) -> Vec<&str> {
        self.stderr
            .lines()
            .filter(|l| l.contains("RLIMIT_FSIZE"))
            .collect()
    }
}

/// Run one launch in `tree`: the supervisor's `/proc/<pid>/limits` during
/// the sandbox's sleep, the sandbox's own dump, and ai-jail's stderr.
fn launch_in(tree: &Tree, flags: &[&str], host_fsize: Option<&str>) -> Launch {
    let _lock = common::SANDBOX_RUN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut child =
        tree.spawn(flags, "cat /proc/self/limits; sleep 3", host_fsize);
    let sandbox = read_sandbox_dump(&mut child);
    let pid = child.id();
    let supervisor =
        std::fs::read_to_string(Path::new(&format!("/proc/{pid}/limits")))
            .expect("read the supervisor's limits during the sleep");
    let out = child.wait_with_output().expect("wait for ai-jail");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "ai-jail failed: status={:?}\nstdout={sandbox}{}\nstderr={stderr}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
    );
    Launch {
        supervisor,
        sandbox,
        stderr,
    }
}

fn launch(flags: &[&str], host_fsize: Option<&str>) -> Launch {
    launch_in(&Tree::new("cli"), flags, host_fsize)
}

/// The supervisor holds lockdown's 1 GiB, the sandbox the explicit 512 MiB,
/// and the file-size limit is reported at most once.
fn assert_supervisor_keeps_one_gib(run: &Launch) {
    assert_eq!(
        limit(&run.supervisor, FSIZE),
        pair(ONE_GIB, ONE_GIB),
        "supervisor:\n{}",
        run.supervisor
    );
    assert_eq!(
        limit(&run.sandbox, FSIZE),
        pair(HALF_GIB, HALF_GIB),
        "sandbox:\n{}",
        run.sandbox
    );
    assert!(
        run.fsize_lines().len() <= 1,
        "the file-size limit reported more than once: {:?}",
        run.fsize_lines()
    );
}

#[test]
fn supervisor_fsize_lockdown_without_explicit_fsize_runs_at_one_gib() {
    // Baseline the explicit cases must match, green by design: lockdown's
    // default on both processes.
    require_bwrap_net!();
    require_lockdown_tools!("cat", "sleep");
    let run = launch(&["--lockdown"], None);
    assert_eq!(
        limit(&run.supervisor, FSIZE),
        pair(ONE_GIB, ONE_GIB),
        "supervisor:\n{}",
        run.supervisor
    );
    assert_eq!(
        limit(&run.sandbox, FSIZE),
        pair(ONE_GIB, ONE_GIB),
        "sandbox:\n{}",
        run.sandbox
    );
}

#[test]
fn supervisor_fsize_keeps_one_gib_under_cli_fsize() {
    // An explicit `fsize` must not drop lockdown's limit from the
    // supervisor: the sandbox runs at 512 MiB, the supervisor at 1 GiB.
    require_bwrap_net!();
    require_lockdown_tools!("cat", "sleep");
    let run = launch(&["--lockdown", "--rlimit", "fsize=512M"], None);
    assert_supervisor_keeps_one_gib(&run);
}

#[test]
fn supervisor_fsize_keeps_one_gib_under_legacy_project_fsize() {
    // The repository's own `.ai-jail` is untrusted: its `fsize` must not
    // loosen the process that holds the proxy's secrets. The launch is an
    // ordinary one, so it also migrates the legacy file.
    require_bwrap_net!();
    require_lockdown_tools!("cat", "sleep");
    let tree = Tree::new("legacy");
    std::fs::write(
        tree.project.join(".ai-jail"),
        "lockdown = true\n\n[rlimit]\nfsize = \"512M\"\n",
    )
    .unwrap();
    let run = launch_in(&tree, &[], None);
    assert_supervisor_keeps_one_gib(&run);
}

#[test]
fn supervisor_fsize_reports_a_lower_host_hard_limit_once() {
    // Guard, green by design: with the host hard limit below both lockdown's
    // default and the explicit value, the supervisor's default is clamped
    // silently and the sandbox's clamp is the one line reported.
    require_bwrap_net!();
    require_lockdown_tools!("cat", "sleep");
    if !prlimit_available() {
        eprintln!("SKIPPED: util-linux prlimit not found in PATH");
        return;
    }
    let run =
        launch(&["--lockdown", "--rlimit", "fsize=512M"], Some(QUARTER_GIB));
    assert_eq!(
        limit(&run.supervisor, FSIZE),
        pair(QUARTER_GIB, QUARTER_GIB),
        "supervisor:\n{}",
        run.supervisor
    );
    assert_eq!(
        limit(&run.sandbox, FSIZE),
        pair(QUARTER_GIB, QUARTER_GIB),
        "sandbox:\n{}",
        run.sandbox
    );
    assert_eq!(
        run.fsize_lines().len(),
        1,
        "the clamp is reported exactly once: stderr={}",
        run.stderr
    );
}
