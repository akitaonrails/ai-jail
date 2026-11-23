// Adjustable per-process limits and CPU affinity, observed through the
// built binary.
//
// Launch-refusal and --dry-run tests need no sandbox. Tests that look
// inside the jail need bwrap with user + network namespaces and skip with
// a message when it is unavailable, through the shared harness in
// `tests/common/mod.rs` (`require_bwrap_net!`, `ai_jail()`, `run_in()`).
// Every launch runs with a temporary HOME, XDG_CONFIG_HOME and project
// directory, so the developer's own global config cannot leak in. The
// trusted global config is `$XDG_CONFIG_HOME/ai-jail/config.toml`
// (upstream v3.3.0); `~/.ai-jail` is only the legacy file it migrates.
#![cfg(target_os = "linux")]

mod common;

use common::ai_jail;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_ID: AtomicUsize = AtomicUsize::new(0);

fn tool_available(bin: &str) -> bool {
    Command::new(bin)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

macro_rules! require_tool {
    ($bin:expr) => {
        if !tool_available($bin) {
            eprintln!("SKIPPED: {} not found in PATH", $bin);
            return;
        }
    };
}

struct Tree {
    root: PathBuf,
    project: PathBuf,
    home: PathBuf,
    xdg: PathBuf,
}

impl Tree {
    fn new(name: &str) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("rlimit-values-{name}-{}-{id}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let project = root.join("project");
        let home = root.join("home");
        let xdg = root.join("xdg");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&xdg).unwrap();
        Self {
            root,
            project,
            home,
            xdg,
        }
    }

    /// Write the trusted global config: `<xdg>/ai-jail/config.toml`,
    /// directory 0700 and file 0600 as the store requires.
    fn global(&self, body: &str) -> &Self {
        let store = self.xdg.join("ai-jail");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::set_permissions(
            &store,
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        let path = store.join("config.toml");
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .unwrap();
        self
    }

    /// Write the legacy project policy (`.ai-jail` in the project), which
    /// v3.3.0 still reads, untrusted, when no stored project policy exists.
    fn project_file(&self, body: &str) -> &Self {
        std::fs::write(self.project.join(".ai-jail"), body).unwrap();
        self
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(ai_jail())
            .args(args)
            .current_dir(&self.project)
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.xdg)
            .env_remove("AI_JAIL_QUIET")
            .stdin(Stdio::null())
            .output()
            .expect("failed to run ai-jail")
    }

    /// `--dry-run bash` with extra flags; no sandbox is started.
    fn dry_run(&self, flags: &[&str]) -> Output {
        let mut args = vec!["--no-status-bar", "--no-save-config"];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["--dry-run", "bash"]);
        self.run(&args)
    }

    /// Run `bash -c script` inside a real sandbox from the project, network
    /// off, through the shared `run_in` (private HOME and config home).
    fn jail(&self, flags: &[&str], script: &str) -> Output {
        let mut all = vec!["--no-network"];
        all.extend_from_slice(flags);
        common::run_in(Some(&self.project), &all, script)
    }

    /// Like `jail`, but with this tree's HOME, so the audit log lands in
    /// `<home>/.local/share/ai-jail/history.jsonl`.
    fn jail_with_home(&self, flags: &[&str], script: &str) -> Output {
        let _lock = common::SANDBOX_RUN_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut args = vec![
            "--no-status-bar",
            "--exec",
            "--no-save-config",
            "--no-network",
        ];
        args.extend_from_slice(flags);
        args.extend_from_slice(&["bash", "-c", script]);
        self.run(&args)
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

fn assert_refused(o: &Output) -> String {
    assert!(
        !o.status.success(),
        "launch must be refused\nstdout={}\nstderr={}",
        stdout(o),
        stderr(o)
    );
    stderr(o)
}

/// The `rlimit name=<n> ...` line of a --dry-run, from stdout or stderr.
fn dry_run_limit_line(o: &Output, name: &str) -> Option<String> {
    let prefix = format!("rlimit name={name} ");
    stdout(o)
        .lines()
        .chain(stderr(o).lines().collect::<Vec<_>>())
        .map(str::trim)
        .find(|l| l.starts_with(&prefix))
        .map(str::to_string)
}

fn field(line: &str, key: &str) -> Option<String> {
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix(&format!("{key}=")))
        .map(str::to_string)
}

/// The CPUs this test process may use, from the kernel.
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

fn allowed_list_text() -> String {
    std::fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .map(|v| v.trim().to_string())
        .unwrap()
}

// ── --dry-run lines and --help ──────────────

#[test]
fn dry_run_prints_each_effective_limit_with_soft_hard_and_source() {
    let tree = Tree::new("dry-run-cli");
    let out = tree.dry_run(&["--rlimit", "nofile=1024", "--rlimit", "cpu=60"]);
    assert_ok(&out);
    let nofile = dry_run_limit_line(&out, "nofile").expect("nofile line");
    assert_eq!(field(&nofile, "soft").as_deref(), Some("1024"), "{nofile}");
    assert_eq!(field(&nofile, "hard").as_deref(), Some("1024"), "{nofile}");
    assert_eq!(field(&nofile, "source").as_deref(), Some("cli"), "{nofile}");
    let cpu = dry_run_limit_line(&out, "cpu").expect("cpu line");
    assert_eq!(field(&cpu, "soft").as_deref(), Some("60"), "{cpu}");
    assert_eq!(field(&cpu, "hard").as_deref(), Some("65"), "{cpu}");
    // A default the CLI did not touch is still listed, as a default.
    let core = dry_run_limit_line(&out, "core").expect("core line");
    assert_eq!(field(&core, "soft").as_deref(), Some("0"), "{core}");
    assert_eq!(field(&core, "source").as_deref(), Some("default"), "{core}");
}

#[test]
fn dry_run_labels_global_and_project_sources() {
    let tree = Tree::new("dry-run-sources");
    tree.global("[rlimit]\nnofile = 2048\n")
        .project_file("[rlimit]\ndata = \"4G\"\n");
    let out = tree.dry_run(&["--rlimit", "data=8G"]);
    assert_ok(&out);
    let nofile = dry_run_limit_line(&out, "nofile").expect("nofile line");
    assert_eq!(field(&nofile, "soft").as_deref(), Some("2048"), "{nofile}");
    assert_eq!(
        field(&nofile, "source").as_deref(),
        Some("global"),
        "{nofile}"
    );
    // The project's 4G tightens the CLI's 8G, so the project wins.
    let data = dry_run_limit_line(&out, "data").expect("data line");
    assert_eq!(
        field(&data, "soft").as_deref(),
        Some((4_u64 << 30).to_string().as_str()),
        "{data}"
    );
    assert_eq!(field(&data, "source").as_deref(), Some("project"), "{data}");
}

#[test]
fn help_says_limits_are_per_process_and_cpu_is_not_a_throttle() {
    let tree = Tree::new("help");
    let out = tree.run(&["--help"]);
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(text.contains("--rlimit"), "--help lacks --rlimit");
    assert!(text.contains("--cpus"), "--help lacks --cpus");
    let lower = text.to_lowercase();
    assert!(
        lower.contains("each process") || lower.contains("per process"),
        "--help must say every --rlimit applies to each process on its own"
    );
    assert!(
        lower.contains("throttle"),
        "--help must say cpu is CPU time that ends a process, not a throttle"
    );
}

// ── Launch refusals for --rlimit ────────────────────────

#[test]
fn byte_suffix_on_a_count_limit_is_refused_but_accepted_on_a_byte_limit() {
    let tree = Tree::new("suffix");
    // Hostile half first: the suffix must not be accepted on nofile.
    let err = assert_refused(&tree.dry_run(&["--rlimit", "nofile=4K"]));
    assert!(err.contains("--rlimit"), "must name the flag: {err}");
    assert!(err.contains("4K"), "must name the value: {err}");
    let out = tree.dry_run(&["--rlimit", "fsize=4K"]);
    assert_ok(&out);
    let fsize = dry_run_limit_line(&out, "fsize").expect("fsize line");
    assert_eq!(field(&fsize, "soft").as_deref(), Some("4096"), "{fsize}");
}

#[test]
fn malformed_rlimit_values_refuse_the_launch_naming_flag_value_and_forms() {
    let tree = Tree::new("malformed");
    for spec in ["rss=1", "nofile=12X", "fsize=16777216T", "nofile", "=5"] {
        let err = assert_refused(&tree.dry_run(&["--rlimit", spec]));
        assert!(
            err.contains("--rlimit"),
            "{spec}: must name the flag: {err}"
        );
        assert!(err.contains(spec), "{spec}: must name the value: {err}");
        assert!(
            err.contains("unlimited") || err.contains("nofile"),
            "{spec}: must list the accepted forms or names: {err}"
        );
    }
}

#[test]
fn lockdown_clamps_a_limit_above_its_default_and_keeps_one_below() {
    let tree = Tree::new("lockdown");
    let below =
        assert_ok(&tree.dry_run(&["--lockdown", "--rlimit", "nofile=1024"]));
    assert!(below.contains("rlimit name=nofile soft=1024 "), "{below}");
    // Lockdown only tightens: a value above its ceiling runs at it.
    let above =
        assert_ok(&tree.dry_run(&["--lockdown", "--rlimit", "nofile=8192"]));
    assert!(above.contains("rlimit name=nofile soft=4096 "), "{above}");
    // The dry run says the limit was clamped, since the wrapper arguments
    // it prints still carry the value asked for.
    assert!(
        above.contains(
            "rlimit name=nofile requested=8192 lockdown_ceiling=4096"
        ),
        "{above}"
    );
}

#[test]
fn lockdown_clamp_under_a_lower_host_limit_warns_once() {
    require_bwrap_net!();
    let tree = Tree::new("lockdown-host");
    let _lock = common::SANDBOX_RUN_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // The host hard NOFILE (3000) is below the lockdown ceiling (4096).
    let out = Command::new("sh")
        .arg("-c")
        .arg("ulimit -n 3000 && exec \"$0\" \"$@\"")
        .arg(ai_jail())
        .args([
            "--no-status-bar",
            "--no-save-config",
            "--no-network",
            "--lockdown",
            "--rlimit",
            "nofile=8192",
            "bash",
            "-c",
            "grep 'open files' /proc/self/limits",
        ])
        .current_dir(&tree.project)
        .env("HOME", &tree.home)
        .env("XDG_CONFIG_HOME", &tree.xdg)
        .env_remove("AI_JAIL_QUIET")
        .env_remove("NO_COLOR")
        .stdin(Stdio::null())
        .output()
        .expect("failed to run ai-jail");
    let limits = assert_ok(&out);
    assert!(limits.contains(" 3000 "), "{limits}");
    let err = stderr(&out);
    let nofile: Vec<&str> = err
        .lines()
        .filter(|l| l.contains('⚠') && l.contains("NOFILE"))
        .collect();
    assert_eq!(nofile.len(), 1, "one warning per limit: {err}");
    assert!(
        nofile[0].contains("8192") && nofile[0].contains("applied 3000"),
        "{}",
        nofile[0]
    );
}

#[test]
fn unknown_rlimit_name_in_a_config_file_is_fatal() {
    let tree = Tree::new("config-unknown-name");
    tree.global("[rlimit]\nrss = 1\n");
    let err = assert_refused(&tree.dry_run(&[]));
    assert!(err.contains("rss"), "{err}");
}

// ── --cpus refusals at launch ──────────

#[test]
fn cpus_outside_the_allowed_set_refuse_the_launch_naming_entry_and_set() {
    let tree = Tree::new("cpus-outside");
    let allowed = allowed_cpus();
    let outside = (0..1024).rev().find(|c| !allowed.contains(c)).unwrap();
    let err = assert_refused(&tree.dry_run(&["--cpus", &outside.to_string()]));
    assert!(err.contains(&outside.to_string()), "{err}");
    assert!(err.contains(&allowed_list_text()), "names the set: {err}");
    let err = assert_refused(&tree.dry_run(&["--cpus", "0-x"]));
    assert!(err.contains("0-x"), "{err}");
}

#[test]
fn cpus_without_seccomp_is_refused_as_advisory() {
    let tree = Tree::new("cpus-no-seccomp");
    let cpu = allowed_cpus()[0].to_string();
    let err = assert_refused(&tree.dry_run(&["--no-seccomp", "--cpus", &cpu]));
    assert!(err.to_lowercase().contains("seccomp"), "{err}");
}

#[test]
fn project_cpus_disjoint_from_the_trusted_set_refuse_the_launch() {
    let tree = Tree::new("cpus-disjoint");
    let cpus = allowed_cpus();
    let trusted = cpus[0];
    let other = cpus.get(1).copied().unwrap_or(trusted + 1);
    // A project set that overlaps the trusted one narrows it: accepted.
    tree.project_file(&format!("cpus = \"{trusted}\"\n"));
    assert_ok(&tree.dry_run(&["--cpus", &format!("{trusted},{other}")]));
    // One that shares no CPU with it leaves nothing to run on: refused.
    tree.project_file(&format!("cpus = \"{other}\"\n"));
    assert_refused(&tree.dry_run(&["--cpus", &trusted.to_string()]));
}

#[test]
fn dry_run_prints_the_effective_cpu_set() {
    let tree = Tree::new("cpus-dry-run");
    let cpu = allowed_cpus()[0].to_string();
    let out = tree.dry_run(&["--cpus", &cpu]);
    assert_ok(&out);
    let text = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        text.lines()
            .map(str::trim)
            .any(|l| l.starts_with("cpus") && l.contains(&cpu)),
        "no `cpus ...` line naming {cpu}: {text}"
    );
}

// ── limits and affinity observed inside the jail ──────────

#[test]
fn rlimit_nofile_is_the_soft_and_hard_limit_inside() {
    require_bwrap_net!();
    let tree = Tree::new("nofile");
    let out = tree.jail(&["--rlimit", "nofile=64"], "ulimit -Sn; ulimit -Hn");
    assert_eq!(
        assert_ok(&out).split_whitespace().collect::<Vec<_>>(),
        ["64", "64"]
    );
}

#[test]
fn rlimit_cpu_ends_a_busy_loop_with_sigxcpu_not_sigkill() {
    require_bwrap_net!();
    require_tool!("timeout");
    let tree = Tree::new("cpu");
    // 152 = 128 + SIGXCPU(24); 137 would mean SIGKILL (the soft == hard
    // trap) and 124/137 from `timeout` would mean no limit at all.
    let out = tree.jail(
        &["--rlimit", "cpu=1"],
        "timeout -s KILL 20 bash -c 'while :; do :; done'; echo status=$?",
    );
    assert_eq!(assert_ok(&out).trim(), "status=152");
}

#[test]
fn rlimit_fsize_stops_a_large_write_with_sigxfsz() {
    require_bwrap_net!();
    let tree = Tree::new("fsize");
    // 153 = 128 + SIGXFSZ(25).
    let out = tree.jail(
        &["--rlimit", "fsize=1M"],
        "head -c 2097152 /dev/zero > /tmp/aj-fsize.big; echo status=$?",
    );
    assert_eq!(assert_ok(&out).trim(), "status=153");
}

/// `nproc` must be applied after bwrap's clone: the host
/// user runs far more than 64 processes, so applying it outside would make
/// the namespace clone itself fail with EAGAIN. The forks the jail manages
/// under the limit are printed, because the README records what `nproc`
/// counts on this kernel only as this test measures it.
#[test]
fn rlimit_nproc_is_applied_inside_and_its_count_is_measured() {
    require_bwrap_net!();
    require_tool!("python3");
    let tree = Tree::new("nproc");
    let script = "python3 -c '\nimport os, resource, signal\n\
        print(\"limit\", *resource.getrlimit(resource.RLIMIT_NPROC))\n\
        kids = []\n\
        for _ in range(200):\n\
        \x20   try:\n\
        \x20       pid = os.fork()\n\
        \x20   except OSError:\n\
        \x20       break\n\
        \x20   if pid == 0:\n\
        \x20       signal.pause()\n\
        \x20       os._exit(0)\n\
        \x20   kids.append(pid)\n\
        print(\"spawned\", len(kids))\n\
        for k in kids:\n\
        \x20   os.kill(k, signal.SIGKILL)\n\
        for k in kids:\n\
        \x20   os.waitpid(k, 0)\n'";
    let out = tree.jail(&["--rlimit", "nproc=64"], script);
    let text = assert_ok(&out);
    assert!(
        text.contains("limit 64 64"),
        "nproc soft/hard inside: {text}"
    );
    let spawned: usize = text
        .lines()
        .find_map(|l| l.strip_prefix("spawned "))
        .and_then(|n| n.trim().parse().ok())
        .expect("spawned count");
    let host_procs = std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().parse::<u32>().is_ok())
        .count();
    eprintln!(
        "nproc_measurement limit=64 spawned_inside={spawned} \
         host_processes_visible={host_procs} kernel={}",
        std::fs::read_to_string("/proc/sys/kernel/osrelease")
            .unwrap_or_default()
            .trim()
    );
    assert!(spawned < 64, "nproc=64 was not enforced: {spawned} forks");
}

#[test]
fn cpus_restricts_every_sandboxed_process_to_the_list() {
    require_bwrap_net!();
    let tree = Tree::new("cpus-inside");
    let cpu = allowed_cpus()[0].to_string();
    let out = tree.jail(
        &["--cpus", &cpu],
        "grep Cpus_allowed_list /proc/self/status; \
         bash -c 'grep Cpus_allowed_list /proc/self/status'",
    );
    let text = assert_ok(&out);
    let lists: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .map(str::trim)
        .collect();
    assert_eq!(lists, [cpu.as_str(), cpu.as_str()], "{text}");
}

#[test]
fn affinity_lock_fires_only_when_cpus_is_set() {
    require_bwrap_net!();
    require_tool!("python3");
    let tree = Tree::new("cpus-lock");
    let probe = "python3 -c 'import os\n\
        try:\n\
        \x20   os.sched_setaffinity(0, os.sched_getaffinity(0))\n\
        \x20   print(\"SET_OK\")\n\
        except PermissionError as e:\n\
        \x20   print(\"EPERM\" if e.errno == 1 else \"OTHER\")\n\
        print(\"GET\", sorted(os.sched_getaffinity(0)))\n'";
    // Hostile half first: without --cpus nothing may be locked.
    let plain = assert_ok(&tree.jail(&[], probe));
    assert!(plain.contains("SET_OK"), "locked without --cpus: {plain}");
    let cpu = allowed_cpus()[0];
    let pinned = assert_ok(&tree.jail(&["--cpus", &cpu.to_string()], probe));
    assert!(pinned.contains("EPERM"), "not locked with --cpus: {pinned}");
    assert!(pinned.contains(&format!("GET [{cpu}]")), "{pinned}");
}

#[test]
fn taskset_cannot_widen_the_cpu_set_inside() {
    require_bwrap_net!();
    require_tool!("taskset");
    let tree = Tree::new("taskset");
    let cpu = allowed_cpus()[0].to_string();
    let script = format!(
        "taskset -p -c {} $$ >/dev/null 2>&1 && echo WIDENED || echo REFUSED",
        allowed_list_text()
    );
    let out = tree.jail(&["--cpus", &cpu], &script);
    assert_eq!(assert_ok(&out).trim(), "REFUSED");
}

// ── the audit launch record ────────────────────────

#[test]
fn audit_record_carries_effective_rlimits_and_cpus() {
    require_bwrap_net!();
    let tree = Tree::new("audit");
    let cpu = allowed_cpus()[0].to_string();
    let out = tree.jail_with_home(
        &["--audit-log", "--rlimit", "nofile=1024", "--cpus", &cpu],
        "exit 3",
    );
    assert_eq!(out.status.code(), Some(3), "stderr={}", stderr(&out));
    let log = tree.home.join(".local/share/ai-jail/history.jsonl");
    let content = std::fs::read_to_string(&log).unwrap();
    let record: serde_json::Value =
        serde_json::from_str(content.lines().last().unwrap()).unwrap();
    // Existing fields are unchanged.
    assert_eq!(record["type"], "launch");
    assert_eq!(record["exit_code"], 3);
    assert_eq!(record["network"], "off");
    let rlimits = record["rlimits"].as_array().expect("rlimits array");
    let nofile = rlimits
        .iter()
        .find(|r| r["name"] == "nofile")
        .expect("nofile entry");
    assert_eq!(nofile["soft"], 1024);
    assert_eq!(nofile["hard"], 1024);
    assert_eq!(nofile["source"], "cli");
    let core = rlimits.iter().find(|r| r["name"] == "core").expect("core");
    assert_eq!(core["source"], "default");
    assert_eq!(record["cpus"], cpu.as_str());
}

// ── supervisor and wrapper agree (round trip) ─────────────

/// What the supervisor reports (--dry-run) is what the wrapper applies
/// (/proc/self/limits inside), for every name and through every value
/// form: the `--rlimit` pairs forwarded to `--landlock-exec` must
/// re-parse to the same numbers.
#[test]
fn roundtrip_dry_run_limits_match_the_limits_inside_the_sandbox() {
    require_bwrap_net!();
    let tree = Tree::new("roundtrip");
    let flags = [
        "--rlimit",
        "nproc=300",
        "--rlimit",
        "nofile=512",
        "--rlimit",
        "core=0",
        "--rlimit",
        "cpu=120",
        "--rlimit",
        "fsize=64M",
        "--rlimit",
        "data=8G",
        "--rlimit",
        "as=unlimited",
    ];
    let dry = tree.dry_run(&flags);
    assert_ok(&dry);
    let inside = assert_ok(&tree.jail(&flags, "cat /proc/self/limits"));
    let kernel_row = |label: &str| -> (String, String) {
        let row = inside
            .lines()
            .find(|l| l.starts_with(label))
            .unwrap_or_else(|| panic!("no {label} row: {inside}"));
        let cols: Vec<&str> = row[label.len()..].split_whitespace().collect();
        let norm = |v: &str| {
            if v == "unlimited" {
                u64::MAX.to_string()
            } else {
                v.to_string()
            }
        };
        (norm(cols[0]), norm(cols[1]))
    };
    for (name, label) in [
        ("nproc", "Max processes"),
        ("nofile", "Max open files"),
        ("core", "Max core file size"),
        ("cpu", "Max cpu time"),
        ("fsize", "Max file size"),
        ("data", "Max data size"),
        ("as", "Max address space"),
    ] {
        let line = dry_run_limit_line(&dry, name)
            .unwrap_or_else(|| panic!("no dry-run line for {name}"));
        let norm = |v: Option<String>| {
            let v = v.unwrap_or_default();
            if v == "unlimited" {
                u64::MAX.to_string()
            } else {
                v
            }
        };
        let reported = (norm(field(&line, "soft")), norm(field(&line, "hard")));
        assert_eq!(reported, kernel_row(label), "{name}: {line}");
    }
}
