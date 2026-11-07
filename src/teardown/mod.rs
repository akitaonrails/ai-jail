//! Process-tree teardown: the wrapper inside the sandbox
//! waits for the command, lists the processes that outlived it, stops
//! them gracefully and reports them to the supervisor on a pipe.
//!
//! Linux-only: the module is compiled out on macOS, where the flag is
//! accepted and changes nothing.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, Instant};

mod reaper;
pub use reaper::{claim_report_fd, run_command_as_reaper};
mod supervisor;
pub use supervisor::TeardownRun;
// The unit tests below reach these through
// `use super::*`; production code goes through `TeardownRun`.
#[cfg(test)]
use supervisor::{read_report, stderr_line};

/// Fixed grace between SIGTERM and SIGKILL.
pub const GRACE: Duration = Duration::from_millis(2000);

/// The only report version this build reads and writes.
pub const REPORT_VERSION: u32 = 1;

/// Survivor-list poll interval while the grace runs.
const POLL: Duration = Duration::from_millis(50);

/// The fields of `/proc/<pid>/stat` the teardown needs. Read from `stat`
/// only, never `cmdline` or `environ`.
#[derive(Debug, Clone)]
pub struct ProcStat {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub state: char,
    /// Field 22, `starttime`: clock ticks since boot.
    pub start_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Survivor {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub age_s: u64,
    pub ended_by: EndedBy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EndedBy {
    Sigterm,
    Sigkill,
    AlreadyGone,
}

/// The command's own end, as the wrapper saw it. On the wire it is
/// `{"exited":N}` or `{"signaled":N,"core":B}`: a
/// plain derive would produce `{"Signaled":{…}}`, so it goes through
/// `WireChild`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WireChild", into = "WireChild")]
pub enum ChildStatusWire {
    Exited(i32),
    Signaled { signal: i32, core: bool },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireChild {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exited: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    signaled: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    core: Option<bool>,
}

impl From<ChildStatusWire> for WireChild {
    fn from(child: ChildStatusWire) -> Self {
        match child {
            ChildStatusWire::Exited(code) => WireChild {
                exited: Some(code),
                signaled: None,
                core: None,
            },
            ChildStatusWire::Signaled { signal, core } => WireChild {
                exited: None,
                signaled: Some(signal),
                core: Some(core),
            },
        }
    }
}

impl TryFrom<WireChild> for ChildStatusWire {
    type Error = String;

    /// Exactly one of `exited`/`signaled`, and `core` only (and always)
    /// with `signaled`: the wrapper writes no other shape, so any other
    /// combination is a forged or damaged report.
    fn try_from(wire: WireChild) -> Result<Self, String> {
        match (wire.exited, wire.signaled, wire.core) {
            (Some(code), None, None) => Ok(ChildStatusWire::Exited(code)),
            (None, Some(signal), Some(core)) => {
                Ok(ChildStatusWire::Signaled { signal, core })
            }
            _ => Err("child must be {\"exited\":N} or \
                 {\"signaled\":N,\"core\":B}"
                .to_string()),
        }
    }
}

/// The one JSON line the wrapper writes on the report fd.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeardownReport {
    pub v: u32,
    pub child: ChildStatusWire,
    pub survivors: Vec<Survivor>,
    pub grace_ms: u64,
    /// The command tree's resource use (`getrusage(RUSAGE_CHILDREN)`
    /// after the last reap), or null when it could not be read. Always
    /// present on the wire: a report without it is damaged, not "unknown".
    #[serde(deserialize_with = "Option::deserialize")]
    pub usage: Option<WireUsage>,
    pub complete: bool,
    pub incomplete_reason: Option<String>,
}

/// Resource use of everything the wrapper waited for: the command, every
/// survivor it reaped, and any port bridge that died while the command
/// ran (the wrapper reaps those too).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireUsage {
    pub cpu_user_ms: u64,
    pub cpu_system_ms: u64,
    pub peak_rss_kib: u64,
}

/// How the teardown of one run ended, as the supervisor learned it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TeardownSection {
    Inactive,
    Reported(TeardownReport),
    Missing { reason: String },
}

/// Parses one `/proc/<pid>/stat` line. `comm` sits in parentheses and is
/// chosen by the process itself (`PR_SET_NAME`), so it may hold `)` and
/// spaces: split at the LAST `)`, never on whitespace.
pub fn parse_proc_stat(text: &str) -> Option<ProcStat> {
    let open = text.find('(')?;
    let close = text.rfind(')')?;
    if close < open {
        return None;
    }
    let pid = text[..open].trim().parse().ok()?;
    let comm = text[open + 1..close].to_string();
    let mut rest = text[close + 1..].split_whitespace();
    let state_field = rest.next()?;
    let mut state_chars = state_field.chars();
    let state = state_chars.next()?;
    if state_chars.next().is_some() {
        return None;
    }
    let ppid = rest.next()?.parse().ok()?;
    // Fields 5..21 sit between ppid (4) and starttime (22).
    let start_ticks = rest.nth(17)?.parse().ok()?;
    Some(ProcStat {
        pid,
        ppid,
        comm,
        state,
        start_ticks,
    })
}

/// Lists the live processes under `proc_root`, except pid 1 (bwrap's
/// init), this process and `exclude` (the bridges). Zombies are already
/// dead and skipped. An entry that vanishes mid-read is skipped; a root
/// that cannot be read is an `Err`, so the caller can mark the report
/// incomplete instead of claiming a clean teardown.
pub fn list_survivors(
    proc_root: &Path,
    exclude: &[i32],
) -> Result<Vec<ProcStat>, String> {
    let me = std::process::id() as i32;
    let entries = std::fs::read_dir(proc_root)
        .map_err(|e| format!("{}: {e}", proc_root.display()))?;
    let mut out = Vec::new();
    for entry in entries {
        let entry =
            entry.map_err(|e| format!("{}: {e}", proc_root.display()))?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<i32>().ok())
        else {
            continue;
        };
        if pid == 1 || pid == me || exclude.contains(&pid) {
            continue;
        }
        let path = entry.path().join("stat");
        // `comm` is raw bytes cut at 15, so it may end inside a UTF-8
        // character: read bytes and decode lossily, or one such name would
        // turn the whole listing into an error (every delimiter the parser
        // uses is ASCII).
        let text = match std::fs::read(&path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) if vanished(&e) => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        match parse_proc_stat(&text) {
            Some(stat) if !is_dead_state(stat.state) => out.push(stat),
            _ => {}
        }
    }
    Ok(out)
}

/// ENOENT, or ESRCH from a `/proc/<pid>` whose process exited between the
/// directory listing and the read.
fn vanished(e: &std::io::Error) -> bool {
    e.kind() == std::io::ErrorKind::NotFound
        || e.raw_os_error() == Some(nix::libc::ESRCH)
}

/// `Z` (zombie) and `X` (dead) are processes that already ended.
fn is_dead_state(state: char) -> bool {
    matches!(state, 'Z' | 'X')
}

/// Stops `list` (see `stop_survivors_noting_errors`) and drops the note
/// about unexpected `kill` errors. Test-only: the wrapper needs the note
/// for `incomplete_reason`, so it calls `stop_survivors_noting_errors`.
#[cfg(test)]
pub fn stop_survivors(list: Vec<ProcStat>, grace: Duration) -> Vec<Survivor> {
    stop_survivors_noting_errors(list, grace).0
}

/// SIGTERM each process, poll every 50 ms up to `grace` while reaping
/// with `waitpid(-1, WNOHANG)`, then SIGKILL the rest. Returns
/// the survivors in input order, and a note naming any `kill` error other
/// than ESRCH, for the report's `incomplete_reason`: such a process is
/// recorded as `already-gone`, because nothing more can be done to it.
pub fn stop_survivors_noting_errors(
    list: Vec<ProcStat>,
    grace: Duration,
) -> (Vec<Survivor>, Option<String>) {
    use nix::sys::signal::Signal;

    let now = AgeClock::read();
    let mut errors: Vec<String> = Vec::new();
    let mut tracked: Vec<Tracked> = list
        .into_iter()
        .map(|stat| {
            let ended_by = match send(stat.pid, Signal::SIGTERM) {
                Ok(()) => {
                    // A stopped process keeps the SIGTERM pending until it
                    // is continued, and would otherwise cost the whole
                    // grace and a SIGKILL. For a running one SIGCONT changes
                    // nothing unless it handles the signal, as after any
                    // job-control resume.
                    let _ = send(stat.pid, Signal::SIGCONT);
                    None
                }
                Err(nix::errno::Errno::ESRCH) => Some(EndedBy::AlreadyGone),
                Err(e) => {
                    errors.push(format!("kill({}, SIGTERM): {e}", stat.pid));
                    Some(EndedBy::AlreadyGone)
                }
            };
            Tracked {
                age_s: now.age_of(stat.start_ticks),
                stat,
                ended_by,
            }
        })
        .collect();

    let deadline = Instant::now() + grace;
    loop {
        reap_all();
        for t in tracked.iter_mut().filter(|t| t.ended_by.is_none()) {
            if !is_alive(&t.stat) {
                t.ended_by = Some(EndedBy::Sigterm);
            }
        }
        if tracked.iter().all(|t| t.ended_by.is_some()) {
            break;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        std::thread::sleep(left.min(POLL));
    }

    for t in tracked.iter_mut().filter(|t| t.ended_by.is_none()) {
        t.ended_by = Some(match send(t.stat.pid, Signal::SIGKILL) {
            Ok(()) => EndedBy::Sigkill,
            // It died between the last poll and the SIGKILL: the TERM
            // ended it.
            Err(nix::errno::Errno::ESRCH) => EndedBy::Sigterm,
            Err(e) => {
                errors.push(format!("kill({}, SIGKILL): {e}", t.stat.pid));
                EndedBy::AlreadyGone
            }
        });
    }
    // A SIGKILLed process is not a zombie yet when kill() returns: wait
    // for it, briefly, so the wrapper's getrusage counts it.
    let killed: Vec<&ProcStat> = tracked
        .iter()
        .filter(|t| t.ended_by == Some(EndedBy::Sigkill))
        .map(|t| &t.stat)
        .collect();
    let reaped_by = Instant::now() + KILL_REAP_WAIT;
    loop {
        reap_all();
        if !killed.iter().any(|s| is_alive(s)) {
            break;
        }
        if Instant::now() >= reaped_by {
            errors.push("usage-partial".into());
            break;
        }
        std::thread::sleep(KILL_REAP_POLL);
    }

    let survivors = tracked
        .into_iter()
        .map(|t| Survivor {
            pid: t.stat.pid,
            ppid: t.stat.ppid,
            comm: t.stat.comm,
            age_s: t.age_s,
            ended_by: t.ended_by.unwrap_or(EndedBy::AlreadyGone),
        })
        .collect();
    let note = (!errors.is_empty()).then(|| errors.join("; "));
    (survivors, note)
}

/// How many later rounds stop what a re-listing found: a supervisor that
/// respawns its worker on SIGTERM is followed this far, and no further,
/// so a teardown always ends. One more listing then only checks.
const RESPAWN_ROUNDS: usize = 3;

/// The grace a later round gets at least, once the first round has used
/// most of `grace`: all rounds share one deadline. With the listing
/// settle (50 ms) and the SIGKILL reap wait ([`KILL_REAP_WAIT`]) the
/// worst case is about 50 + 2000 + 500 + 3 × (50 + 250 + 500) + 50 ms,
/// near 5 s.
const RESPAWN_GRACE_FLOOR: Duration = Duration::from_millis(250);

/// How long a SIGKILLed survivor is waited for before its usage is
/// given up on (`usage-partial`).
const KILL_REAP_WAIT: Duration = Duration::from_millis(500);
const KILL_REAP_POLL: Duration = Duration::from_millis(10);

/// Stops `list`, then lists again with `relist` and stops what appeared
/// meanwhile, up to [`RESPAWN_ROUNDS`] times. Processes still appearing
/// after the last round are not stopped here (the pid namespace ends
/// them with the sandbox) and mark the report `survivors-respawned`.
pub fn stop_survivors_in_rounds<F>(
    list: Vec<ProcStat>,
    grace: Duration,
    relist: &mut F,
) -> (Vec<Survivor>, Option<String>)
where
    F: FnMut() -> Result<Vec<ProcStat>, String>,
{
    stop_survivors_in_rounds_with(
        list,
        grace,
        relist,
        &mut stop_survivors_noting_errors,
    )
}

/// The rounds of [`stop_survivors_in_rounds`], with the per-round stop
/// passed in, so the rounds can be tested without signalling anything.
fn stop_survivors_in_rounds_with<F, S>(
    list: Vec<ProcStat>,
    grace: Duration,
    relist: &mut F,
    stop: &mut S,
) -> (Vec<Survivor>, Option<String>)
where
    F: FnMut() -> Result<Vec<ProcStat>, String>,
    S: FnMut(Vec<ProcStat>, Duration) -> (Vec<Survivor>, Option<String>),
{
    let mut survivors = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    // A process already handled may still be listed (a SIGKILLed one not
    // yet reaped by its parent): pid and start time identify it.
    let mut seen: Vec<(i32, u64)> = Vec::new();
    let mut next = list;
    let mut round = 0;
    let deadline = Instant::now() + grace;
    while !next.is_empty() {
        if round > RESPAWN_ROUNDS {
            // First, so cutting the joined reason cannot drop it.
            notes.insert(0, "survivors-respawned".into());
            break;
        }
        seen.extend(next.iter().map(|s| (s.pid, s.start_ticks)));
        let left = deadline.saturating_duration_since(Instant::now());
        let round_grace = if round == 0 {
            grace
        } else {
            left.max(RESPAWN_GRACE_FLOOR.min(grace))
        };
        let (stopped, note) = stop(next, round_grace);
        survivors.extend(stopped);
        if let Some(note) = note {
            note_once(&mut notes, &note);
        }
        round += 1;
        next = match relist() {
            Ok(found) => found
                .into_iter()
                .filter(|s| !seen.contains(&(s.pid, s.start_ticks)))
                .collect(),
            Err(e) => {
                note_once(&mut notes, &e);
                Vec::new()
            }
        };
    }
    let note = (!notes.is_empty()).then(|| notes.join("; "));
    (survivors, note)
}

/// Adds each `; `-separated token of `note` that `notes` does not hold
/// yet: every round may give up on the same thing (`usage-partial`), and
/// a reason says it once.
fn note_once(notes: &mut Vec<String>, note: &str) {
    for token in note.split("; ") {
        if !notes.iter().any(|n| n == token) {
            notes.push(token.to_string());
        }
    }
}

struct Tracked {
    stat: ProcStat,
    age_s: u64,
    ended_by: Option<EndedBy>,
}

fn send(pid: i32, sig: nix::sys::signal::Signal) -> nix::Result<()> {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), sig)
}

/// Reaps every child that has ended, without blocking. As sub-reaper the
/// wrapper inherits the command's orphans, and an unreaped zombie would
/// otherwise still answer `kill(pid, 0)`.
fn reap_all() {
    use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
    let any = nix::unistd::Pid::from_raw(-1);
    while let Ok(status) = waitpid(any, Some(WaitPidFlag::WNOHANG)) {
        if status == WaitStatus::StillAlive {
            break;
        }
    }
}

/// Alive means: the pid still exists, is not a zombie, and is the same
/// process (same start time) rather than a reused pid. A zombie whose own
/// parent has not reaped it yet is dead for teardown purposes.
fn is_alive(stat: &ProcStat) -> bool {
    if let Err(nix::errno::Errno::ESRCH) =
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(stat.pid), None)
    {
        return false;
    }
    match std::fs::read(format!("/proc/{}/stat", stat.pid)) {
        Ok(bytes) => match parse_proc_stat(&String::from_utf8_lossy(&bytes)) {
            Some(now) => {
                !is_dead_state(now.state) && now.start_ticks == stat.start_ticks
            }
            None => true,
        },
        Err(e) => !vanished(&e),
    }
}

/// The two inputs of `age_seconds`, read once per teardown. Either read
/// failing yields age 0 rather than an error.
struct AgeClock {
    uptime_s: f64,
    clk_tck: u64,
}

impl AgeClock {
    fn read() -> Self {
        use nix::unistd::{SysconfVar, sysconf};
        let clk_tck = match sysconf(SysconfVar::CLK_TCK) {
            Ok(Some(n)) => u64::try_from(n).unwrap_or(0),
            _ => 0,
        };
        let uptime_s = std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|t| t.split_whitespace().next()?.parse().ok())
            .unwrap_or(0.0);
        AgeClock { uptime_s, clk_tck }
    }

    fn age_of(&self, start_ticks: u64) -> u64 {
        age_seconds(start_ticks, self.uptime_s, self.clk_tck)
    }
}

/// Whole seconds a process has lived: `uptime - starttime / CLK_TCK`.
/// Saturating: a zero tick rate, a non-finite uptime or a start after
/// "now" (a racing read) is age 0, never a panic or an underflow.
pub fn age_seconds(start_ticks: u64, uptime_now_s: f64, clk_tck: u64) -> u64 {
    if clk_tck == 0 || !uptime_now_s.is_finite() {
        return 0;
    }
    let age = uptime_now_s - start_ticks as f64 / clk_tck as f64;
    if age.is_finite() && age > 0.0 {
        // `as` saturates on overflow; the value is finite and positive.
        age.floor() as u64
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    // Listing survivors, the stderr line, the report's wire format and stopping
    // survivors. Assumes TeardownReport derives Serialize (the wrapper writes
    // it) and Deserialize with deny_unknown_fields (the supervisor reads it).

    use super::supervisor::parse_report_line;
    use super::*;
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};

    /// A /proc/<pid>/stat line with `comm` and `state`/`ppid` placed where
    /// the kernel puts them; starttime is field 22.
    fn stat_line(pid: i32, comm: &str, state: char, ppid: i32) -> String {
        format!(
            "{pid} ({comm}) {state} {ppid} {pid} {pid} 0 -1 4194560 100 0 0 0 \
         1 2 0 0 20 0 1 0 12345 1000000 200 18446744073709551615 1 1 0 0 \
         0 0 0 0 0 0 0 0 17 3 0 0 0 0 0\n"
        )
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ai-jail-teardown-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn add_proc(root: &Path, pid: i32, comm: &str, state: char, ppid: i32) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("stat"), stat_line(pid, comm, state, ppid))
            .unwrap();
    }

    fn survivor(comm: &str) -> Survivor {
        Survivor {
            pid: 7,
            ppid: 2,
            comm: comm.to_string(),
            age_s: 0,
            ended_by: EndedBy::Sigterm,
        }
    }

    fn pipe_with(bytes: Vec<u8>) -> OwnedFd {
        let (reader, mut writer) = std::io::pipe().unwrap();
        std::thread::spawn(move || {
            let _ = writer.write_all(&bytes);
        });
        reader.into()
    }

    // ── parse_proc_stat ────────────────────────────────────────────

    #[test]
    fn parse_proc_stat_splits_at_the_last_paren() {
        // A comm that imitates the fields after it.
        let p = parse_proc_stat(&stat_line(42, "x) R 99 (", 'S', 7)).unwrap();
        assert_eq!(p.pid, 42);
        assert_eq!(p.comm, "x) R 99 (");
        assert_eq!(p.state, 'S', "state comes after the LAST ')'");
        assert_eq!(p.ppid, 7);
        assert_eq!(p.start_ticks, 12345);

        let p = parse_proc_stat(&stat_line(9, "my server", 'R', 1)).unwrap();
        assert_eq!(p.comm, "my server");
        assert_eq!(p.state, 'R');

        let z = parse_proc_stat(&stat_line(8, "sleep", 'Z', 2)).unwrap();
        assert_eq!(z.state, 'Z');
    }

    #[test]
    fn parse_proc_stat_rejects_malformed_text() {
        for bad in [
            "",
            "42 sleep S 1",
            "42 (sleep",
            "x (sleep) S 1",
            "42 (sleep) S",
        ] {
            assert!(parse_proc_stat(bad).is_none(), "{bad:?}");
        }
    }

    // ── list_survivors ─────────────────────────────────────────────

    #[test]
    fn list_survivors_skips_init_self_excluded_and_zombies() {
        let root = temp_dir("proc");
        let me = std::process::id() as i32;
        add_proc(&root, 1, "bwrap", 'S', 0);
        add_proc(&root, me, "ai-jail", 'S', 1);
        add_proc(&root, 3, "ai-jail", 'S', me); // the proxy bridge
        add_proc(&root, 7, "sleep", 'S', me);
        add_proc(&root, 8, "defunct", 'Z', me);
        add_proc(&root, 11, "node server", 'R', 7);
        std::fs::create_dir_all(root.join("12")).unwrap(); // vanished: no stat
        std::fs::create_dir_all(root.join("sys")).unwrap();
        std::fs::write(root.join("uptime"), "1.0 1.0\n").unwrap();
        std::os::unix::fs::symlink(me.to_string(), root.join("self")).unwrap();

        let mut got: Vec<(i32, String)> = list_survivors(&root, &[me, 3])
            .expect("a readable fixture /proc")
            .into_iter()
            .map(|p| (p.pid, p.comm))
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec![(7, "sleep".to_string()), (11, "node server".to_string())]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_survivors_never_opens_cmdline_or_environ() {
        // FIFOs block any open-for-read, so touching them hangs.
        let root = temp_dir("fifo");
        add_proc(&root, 7, "sleep", 'S', 2);
        for name in ["cmdline", "environ"] {
            let p = root.join("7").join(name);
            let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
            assert_eq!(unsafe { nix::libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let r = root.clone();
        std::thread::spawn(move || {
            let _ = tx.send(list_survivors(&r, &[]).map(|v| v.len()));
        });
        let n = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("list_survivors opened cmdline or environ");
        assert_eq!(n, Ok(1));
        // Unblock any reader before cleanup, best effort.
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn list_survivors_reports_an_unreadable_proc_root() {
        // An unreadable /proc is not "no survivors": the caller must be able
        // to mark the report incomplete instead of claiming a clean teardown.
        let root = temp_dir("noproc");
        let missing = root.join("no-such-proc");
        let err = match list_survivors(&missing, &[]) {
            Ok(v) => panic!("a missing /proc listed {} survivors", v.len()),
            Err(e) => e,
        };
        assert!(!err.is_empty());
        // An empty but readable root is a clean, empty list.
        match list_survivors(&root, &[]) {
            Ok(v) => assert!(v.is_empty()),
            Err(e) => panic!("an empty readable /proc is not an error: {e}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // ── age_seconds ────────────────────────────────────────────────

    #[test]
    fn age_is_derived_from_start_ticks_and_uptime() {
        // Started 250 ticks (2.5 s at 100 Hz) after boot, now 10.9 s uptime.
        assert_eq!(age_seconds(250, 10.9, 100), 8);
        // The tick rate matters: the same ticks at 250 Hz started at 1 s.
        assert_eq!(age_seconds(250, 10.9, 250), 9);
        assert_eq!(age_seconds(1000, 10.0, 100), 0, "started just now");
        // Saturating: a start after "now" (clock skew, a racing read) and a
        // zero tick rate never underflow or panic.
        assert_eq!(age_seconds(5000, 10.0, 100), 0);
        assert_eq!(age_seconds(250, 10.0, 0), 0);
        assert_eq!(age_seconds(0, f64::NAN, 100), 0);
    }

    // ── stderr_line ───────────────────────────────────

    #[test]
    fn stderr_line_is_none_without_survivors() {
        assert!(stderr_line(&[]).is_none());
    }

    #[test]
    fn stderr_line_names_count_and_caps_at_ten() {
        const NAMES: [&str; 12] = [
            "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf",
            "hotel", "india", "juliett", "kilo", "lima",
        ];
        let three: Vec<Survivor> =
            NAMES[..3].iter().map(|n| survivor(n)).collect();
        let line = stderr_line(&three).unwrap();
        assert!(line.contains('3'), "{line}");
        for n in &NAMES[..3] {
            assert!(line.contains(n), "{line}");
        }
        assert!(!line.contains("more"), "{line}");

        let ten: Vec<Survivor> =
            NAMES[..10].iter().map(|n| survivor(n)).collect();
        let line = stderr_line(&ten).unwrap();
        assert!(!line.contains("more"), "exactly 10 needs no suffix: {line}");

        let twelve: Vec<Survivor> = NAMES.iter().map(|n| survivor(n)).collect();
        let line = stderr_line(&twelve).unwrap();
        assert!(line.contains("12"), "{line}");
        assert!(line.contains("+2 more"), "{line}");
        let named = NAMES.iter().filter(|n| line.contains(*n)).count();
        assert_eq!(named, 10, "at most 10 names: {line}");
        assert!(!line.contains('\n'), "one line: {line:?}");
    }

    // ── report wire format and read_report ────────────

    const VALID: &str = "{\"v\":1,\"child\":{\"exited\":0},\"survivors\":[{\"pid\":7,\"ppid\":2,\"comm\":\"sleep\",\"age_s\":0,\"ended_by\":\"sigterm\"}],\"grace_ms\":2000,\"usage\":null,\"complete\":true,\"incomplete_reason\":null}\n";

    #[test]
    fn read_report_accepts_the_documented_line() {
        let r = read_report(pipe_with(VALID.as_bytes().to_vec())).unwrap();
        assert_eq!(r.v, 1);
        assert!(matches!(r.child, ChildStatusWire::Exited(0)));
        assert_eq!(r.survivors.len(), 1);
        assert_eq!(r.survivors[0].comm, "sleep");
        assert_eq!(r.survivors[0].pid, 7);
        assert!(matches!(r.survivors[0].ended_by, EndedBy::Sigterm));
        assert_eq!(r.grace_ms, 2000);
        assert!(r.complete);
        assert!(r.incomplete_reason.is_none());

        let sig = "{\"v\":1,\"child\":{\"signaled\":9,\"core\":false},\"survivors\":[],\"grace_ms\":2000,\"usage\":null,\"complete\":true,\"incomplete_reason\":null}\n";
        let r = read_report(pipe_with(sig.as_bytes().to_vec())).unwrap();
        assert!(matches!(
            r.child,
            ChildStatusWire::Signaled {
                signal: 9,
                core: false
            }
        ));
    }

    #[test]
    fn report_round_trips_through_its_wire_form() {
        let report = TeardownReport {
            v: 1,
            child: ChildStatusWire::Signaled {
                signal: 15,
                core: false,
            },
            survivors: vec![Survivor {
                pid: 9,
                ppid: 2,
                comm: "stuck".into(),
                age_s: 3,
                ended_by: EndedBy::Sigkill,
            }],
            grace_ms: GRACE.as_millis() as u64,
            usage: None,
            complete: false,
            incomplete_reason: Some("subreaper-unavailable".into()),
        };
        let wire = serde_json::to_value(&report).unwrap();
        assert_eq!(wire["child"]["signaled"], 15);
        assert_eq!(wire["child"]["core"], false);
        assert_eq!(wire["survivors"][0]["ended_by"], "sigkill");
        assert_eq!(wire["grace_ms"], 2000);
        let mut line = serde_json::to_string(&report).unwrap();
        line.push('\n');
        let back = read_report(pipe_with(line.into_bytes())).unwrap();
        assert!(!back.complete);
        assert_eq!(
            back.incomplete_reason.as_deref(),
            Some("subreaper-unavailable")
        );
        assert!(matches!(back.survivors[0].ended_by, EndedBy::Sigkill));
        assert_eq!(GRACE, Duration::from_millis(2000), "a fixed grace");
    }

    #[test]
    fn read_report_refuses_unknown_fields_malformed_missing_and_oversized() {
        let extra = VALID.replace("\"v\":1,", "\"v\":1,\"forged\":true,");
        let e_unknown = refused(read_report(pipe_with(extra.into_bytes())));
        let extra_inner =
            VALID.replace("\"age_s\":0,", "\"age_s\":0,\"cmdline\":\"x\",");
        assert!(read_report(pipe_with(extra_inner.into_bytes())).is_err());
        let e_malformed =
            refused(read_report(pipe_with(b"{\"v\":1,\n".to_vec())));
        let e_missing = refused(read_report(pipe_with(Vec::new())));

        // A valid report padded past 64 KiB: must be refused, and the read
        // must stop at the bound instead of draining everything.
        let mut huge = VALID.trim_end().replace(
            "\"comm\":\"sleep\"",
            &format!("\"comm\":\"{}\"", "s".repeat(70 * 1024)),
        );
        huge.push('\n');
        huge.push_str(&"x".repeat(4 << 20));
        let started = Instant::now();
        let e_large = refused(read_report(pipe_with(huge.into_bytes())));
        assert!(started.elapsed() < Duration::from_secs(5));

        // Each cause is named distinctly: a refusal says why.
        let causes = [&e_malformed, &e_missing, &e_large];
        for (i, a) in causes.iter().enumerate() {
            for b in &causes[i + 1..] {
                assert_ne!(a, b, "causes must be distinguishable");
            }
        }
        assert!(!e_unknown.is_empty());
    }

    #[test]
    fn read_report_refuses_an_unknown_version() {
        // A future (or forged) version is refused even
        // when every other field is valid.
        for v in ["0", "2", "99"] {
            let line = VALID.replacen("\"v\":1", &format!("\"v\":{v}"), 1);
            let err = refused(read_report(pipe_with(line.into_bytes())));
            assert!(err.contains("unsupported-version"), "v={v}: {err}");
        }
        assert!(read_report(pipe_with(VALID.as_bytes().to_vec())).is_ok());
    }

    /// The error of a refused report (TeardownReport need not be Debug).
    fn refused(r: Result<TeardownReport, String>) -> String {
        match r {
            Ok(_) => panic!("the report was accepted"),
            Err(e) => e,
        }
    }

    // ── stop_survivors — in a child test process, because it reaps ──

    #[test]
    fn stop_survivors_terms_then_kills() {
        // Other tests swap PATH (and TMPDIR) under ENV_LOCK, and
        // the child inherits the environment at spawn, so spawn under it too.
        let _env = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let output =
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("teardown::tests::stop_survivors_child")
                .arg("--ignored")
                .env("AI_JAIL_TEARDOWN_CHILD", "1")
                .output()
                .expect("spawn child test");
        assert!(
            output.status.success(),
            "child failed\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore]
    fn stop_survivors_child() {
        if std::env::var_os("AI_JAIL_TEARDOWN_CHILD").is_none() {
            return;
        }
        use std::process::Command;
        let polite = Command::new("sleep").arg("30").spawn().unwrap();
        let stubborn = Command::new("sh")
            .args(["-c", "trap '' TERM; exec sleep 30"])
            .spawn()
            .unwrap();
        let mut gone = Command::new("true").spawn().unwrap();
        gone.wait().unwrap();
        // Wait until sh has exec'd sleep (its trap is
        // then in place) instead of a fixed 200 ms.
        stat_when(stubborn.id(), "sleep", None);
        let stat = |pid: u32| {
            let text = std::fs::read_to_string(format!("/proc/{pid}/stat"));
            text.ok().and_then(|t| parse_proc_stat(&t))
        };
        let mut list =
            vec![stat(polite.id()).unwrap(), stat(stubborn.id()).unwrap()];
        let mut ghost = list[0].clone();
        ghost.pid = gone.id() as i32;
        list.push(ghost);
        let started = Instant::now();
        let out = stop_survivors(list, Duration::from_millis(400));
        let took = started.elapsed();
        let by_pid = |pid: u32| {
            out.iter()
                .find(|s| s.pid == pid as i32)
                .unwrap_or_else(|| panic!("pid {pid} missing from the result"))
        };
        assert!(matches!(by_pid(polite.id()).ended_by, EndedBy::Sigterm));
        assert!(matches!(by_pid(stubborn.id()).ended_by, EndedBy::Sigkill));
        assert!(matches!(by_pid(gone.id()).ended_by, EndedBy::AlreadyGone));
        assert!(
            took >= Duration::from_millis(400),
            "grace honoured: {took:?}"
        );
        assert!(took < Duration::from_secs(3), "no extra wait: {took:?}");
        assert_eq!(by_pid(polite.id()).comm, "sleep");
        std::mem::forget((polite, stubborn));
    }

    // ── read_report stops at the first line ────────────
    //
    // Another supervisor child can inherit the report fd, so EOF may come
    // only after the join: the reader must return at the first `\n`.

    /// Runs `read_report` on its own thread and reports back on a channel,
    /// so a reader that waits for EOF shows up as a timeout, not a hang.
    fn read_report_on_a_thread(
        fd: OwnedFd,
    ) -> std::sync::mpsc::Receiver<Result<TeardownReport, String>> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(read_report(fd));
        });
        rx
    }

    #[test]
    fn read_report_returns_at_the_first_line_without_waiting_for_eof() {
        // One complete line, then a write end that stays open
        // (as an inheriting helper would hold it), so no EOF ever comes.
        let (reader, mut writer) = std::io::pipe().unwrap();
        writer.write_all(VALID.as_bytes()).unwrap();
        let rx = read_report_on_a_thread(reader.into());
        let started = Instant::now();
        let report = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("read_report waited for EOF past the first line")
            .expect("the documented line is a valid report");
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(report.v, 1);
        assert!(matches!(report.child, ChildStatusWire::Exited(0)));
        assert_eq!(report.survivors.len(), 1);
        assert_eq!(report.survivors[0].comm, "sleep");

        // Bytes after the newline belong to nobody: the first line alone is
        // the report, so trailing data neither joins it nor spoils it.
        let (reader, mut trailing) = std::io::pipe().unwrap();
        let mut bytes = VALID.as_bytes().to_vec();
        bytes.extend_from_slice(b"{\"v\":2,\"forged\":");
        trailing.write_all(&bytes).unwrap();
        let rx = read_report_on_a_thread(reader.into());
        let report = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("read_report waited past the first line")
            .expect("trailing bytes after the newline spoiled the report");
        assert_eq!(report.v, 1);

        // One line arriving in two writes is one report; the reader neither
        // returns at the chunk boundary nor needs EOF once the newline lands.
        let (reader, mut split) = std::io::pipe().unwrap();
        let (head, tail) = VALID.split_at(VALID.len() / 2);
        split.write_all(head.as_bytes()).unwrap();
        let rx = read_report_on_a_thread(reader.into());
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            rx.try_recv().is_err(),
            "read_report returned before the line was complete"
        );
        split.write_all(tail.as_bytes()).unwrap();
        let report = rx
            .recv_timeout(Duration::from_secs(1))
            .expect("read_report waited for EOF after the newline")
            .expect("a line split across writes is still one report");
        assert_eq!(report.grace_ms, 2000);
        assert!(report.complete);

        // The write ends stay open until here, on purpose.
        drop((writer, trailing, split));
    }

    // ── stopped and respawning survivors ──
    //
    // Each case runs in a child test process, like
    // stop_survivors_terms_then_kills: stopping survivors reaps with
    // waitpid(-1), which must not reap the other tests' children.

    /// Runs the `#[ignore]`d child test `name` of this module in a fresh test
    /// process and fails with its output when it fails. A filter that matched
    /// nothing would also exit 0, so exactly one test must have run.
    fn run_child_test(name: &str) {
        let _env = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let output =
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(format!("teardown::tests::{name}"))
                .arg("--ignored")
                .env("AI_JAIL_TEARDOWN_CHILD", "1")
                .output()
                .expect("spawn child test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "child {name} failed\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn in_child_test() -> bool {
        std::env::var_os("AI_JAIL_TEARDOWN_CHILD").is_some()
    }

    /// The `/proc` entry of `pid` once it runs `comm` (a fresh fork shows its
    /// parent's name until it execs) and, when `state` is given, once it is in
    /// that state.
    fn stat_when(pid: u32, comm: &str, state: Option<char>) -> ProcStat {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|t| parse_proc_stat(&t));
            if let Some(s) = stat
                && s.comm == comm
                && state.is_none_or(|want| s.state == want)
            {
                return s;
            }
            assert!(Instant::now() < deadline, "pid {pid} never became {comm}");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A child of this test process, killed and reaped when dropped, so a
    /// failing case leaves nothing behind. Its stdio is null: an inherited
    /// pipe would keep the parent test's `output()` waiting for it.
    struct Fixture(std::process::Child);

    impl Fixture {
        fn spawn(program: &str, args: &[&str]) -> Fixture {
            use std::process::Stdio;
            Fixture(
                std::process::Command::new(program)
                    .args(args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            )
        }

        fn id(&self) -> u32 {
            self.0.id()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn spawn_sleep() -> (Fixture, ProcStat) {
        let child = Fixture::spawn("sleep", &["30"]);
        let stat = stat_when(child.id(), "sleep", None);
        (child, stat)
    }

    fn ended_by_term(out: &[Survivor], pid: u32) -> bool {
        out.iter().any(|s| {
            s.pid == pid as i32 && matches!(s.ended_by, EndedBy::Sigterm)
        })
    }

    #[test]
    fn stopped_survivor_is_continued_and_ends_by_sigterm() {
        run_child_test("stopped_survivor_child");
    }

    #[test]
    #[ignore]
    fn stopped_survivor_child() {
        if !in_child_test() {
            return;
        }
        // A survivor with a TERM handler, stopped (SIGSTOP, or a job stopped by
        // the terminal): its SIGTERM stays pending until something continues
        // it. Without SIGCONT it would cost the whole grace and a SIGKILL.
        let dir = temp_dir("stopped");
        let ready = dir.join("ready");
        let script = format!(
            "trap 'exit 0' TERM; : > '{}'; while :; do sleep 0.05; done",
            ready.display()
        );
        let child = Fixture::spawn("sh", &["-c", &script]);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() {
            assert!(Instant::now() < deadline, "the trap was never installed");
            std::thread::sleep(Duration::from_millis(10));
        }
        let pid = nix::unistd::Pid::from_raw(child.id() as i32);
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGSTOP).unwrap();
        let stopped = stat_when(child.id(), "sh", Some('T'));

        let grace = Duration::from_millis(1500);
        let started = Instant::now();
        let out = stop_survivors(vec![stopped], grace);
        let took = started.elapsed();
        assert_eq!(out.len(), 1);
        assert!(
            ended_by_term(&out, child.id()),
            "a stopped survivor must be continued and end by its SIGTERM"
        );
        assert!(took < grace, "it did not cost the grace: {took:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn respawned_survivor_is_stopped_in_a_later_round() {
        run_child_test("respawned_survivor_child");
    }

    #[test]
    #[ignore]
    fn respawned_survivor_child() {
        if !in_child_test() {
            return;
        }
        // The opposite of the persistent case below: a process that appears
        // once after the SIGKILL sweep (a supervisor restarting its worker) is
        // found by the next listing, stopped the same way and recorded, and the
        // report stays complete.
        let (first, first_stat) = spawn_sleep();
        let mut later: Vec<Fixture> = Vec::new();
        let mut calls = 0_usize;
        let mut relist = || -> Result<Vec<ProcStat>, String> {
            calls += 1;
            assert!(calls <= 10, "the re-list is not bounded");
            if calls == 1 {
                let (child, stat) = spawn_sleep();
                later.push(child);
                Ok(vec![stat])
            } else {
                Ok(Vec::new())
            }
        };
        let (out, note) = stop_survivors_in_rounds(
            vec![first_stat],
            Duration::from_millis(400),
            &mut relist,
        );
        assert!(ended_by_term(&out, first.id()), "the first survivor");
        let respawned = later[0].id();
        let found = out
            .iter()
            .find(|s| s.pid == respawned as i32)
            .expect("the process the re-list found is recorded");
        assert!(matches!(found.ended_by, EndedBy::Sigterm));
        assert_eq!(found.comm, "sleep");
        assert!(
            note.is_none(),
            "one respawn that the next round stops is not incomplete: {note:?}"
        );
        assert!(
            (2..=4).contains(&calls),
            "listed again until a round found nothing, at most 3 rounds: {calls}"
        );
        assert_eq!(
            nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(respawned as i32),
                None
            ),
            Err(nix::errno::Errno::ESRCH),
            "the respawned process really ended"
        );
    }

    #[test]
    fn persistent_respawn_marks_survivors_respawned() {
        run_child_test("persistent_respawn_child");
    }

    #[test]
    #[ignore]
    fn persistent_respawn_child() {
        if !in_child_test() {
            return;
        }
        // Every listing finds a new process: the rounds stop at 3 and the
        // report says why it cannot claim a clean teardown.
        let (first, first_stat) = spawn_sleep();
        let mut spawned: Vec<Fixture> = Vec::new();
        let mut calls = 0_usize;
        let mut relist = || -> Result<Vec<ProcStat>, String> {
            calls += 1;
            assert!(calls <= 10, "the re-list is not bounded");
            let (child, stat) = spawn_sleep();
            spawned.push(child);
            Ok(vec![stat])
        };
        let started = Instant::now();
        let (out, note) = stop_survivors_in_rounds(
            vec![first_stat],
            Duration::from_millis(400),
            &mut relist,
        );
        let took = started.elapsed();
        assert!(
            (3..=4).contains(&calls),
            "at most 3 rounds: {calls} listings"
        );
        let note = note.expect("leftovers after the last round are incomplete");
        assert!(note.contains("survivors-respawned"), "{note}");
        assert!(ended_by_term(&out, first.id()), "the first survivor");
        for child in spawned.iter().take(3) {
            assert!(
                ended_by_term(&out, child.id()),
                "each process a round found is stopped the same way: {}",
                child.id()
            );
        }
        assert!(took < Duration::from_secs(5), "bounded: {took:?}");
        // A leftover from a last listing is the pid namespace's to end; here
        // the fixtures end it when they drop.
    }

    // ── the wrapper's usage in the report ───────

    const VALID_WITH_USAGE: &str = "{\"v\":1,\"child\":{\"exited\":0},\"survivors\":[],\"grace_ms\":2000,\"usage\":{\"cpu_user_ms\":412,\"cpu_system_ms\":96,\"peak_rss_kib\":183204},\"complete\":true,\"incomplete_reason\":null}\n";

    const USAGE_OBJECT: &str =
        "{\"cpu_user_ms\":412,\"cpu_system_ms\":96,\"peak_rss_kib\":183204}";

    fn report_with(usage: Option<WireUsage>) -> TeardownReport {
        TeardownReport {
            v: 1,
            child: ChildStatusWire::Exited(0),
            survivors: Vec::new(),
            grace_ms: 2000,
            usage,
            complete: true,
            incomplete_reason: None,
        }
    }

    fn through_the_pipe(report: &TeardownReport) -> TeardownReport {
        let mut line = serde_json::to_string(report).unwrap();
        line.push('\n');
        read_report(pipe_with(line.into_bytes())).expect("own line reads back")
    }

    #[test]
    fn report_round_trips_usage() {
        let report = report_with(Some(WireUsage {
            cpu_user_ms: 412,
            cpu_system_ms: 96,
            peak_rss_kib: 183_204,
        }));
        let wire = serde_json::to_value(&report).unwrap();
        assert_eq!(
            wire["usage"],
            serde_json::from_str::<serde_json::Value>(USAGE_OBJECT).unwrap(),
            "exactly the three figures, under their documented names"
        );
        let back = through_the_pipe(&report).usage.expect("usage survives");
        assert_eq!(
            (back.cpu_user_ms, back.cpu_system_ms, back.peak_rss_kib),
            (412, 96, 183_204)
        );
        let documented = read_report(pipe_with(VALID_WITH_USAGE.into()))
            .expect("the documented line is a valid report")
            .usage
            .expect("the documented line carries usage");
        assert_eq!(documented.peak_rss_kib, 183_204);

        // A failed getrusage is written as an explicit null, so
        // the field is never simply left out.
        let failed = report_with(None);
        let wire = serde_json::to_value(&failed).unwrap();
        assert!(
            wire.as_object().unwrap().contains_key("usage"),
            "usage is written even when unknown: {wire}"
        );
        assert!(wire["usage"].is_null(), "{wire}");
        assert!(through_the_pipe(&failed).usage.is_none());

        // Zero is a figure, not a missing one.
        let zero = report_with(Some(WireUsage {
            cpu_user_ms: 0,
            cpu_system_ms: 0,
            peak_rss_kib: 0,
        }));
        let back = through_the_pipe(&zero).usage.expect("zero is not null");
        assert_eq!(back.peak_rss_kib, 0);
    }

    #[test]
    fn report_without_usage_is_malformed() {
        let usage_member = format!(",\"usage\":{USAGE_OBJECT}");
        assert!(VALID_WITH_USAGE.contains(&usage_member));

        // An absent `usage` is not a null one. The wire is internal and
        // versioned, so a report without the field is damaged or forged,
        // never "usage unknown".
        let absent = VALID_WITH_USAGE.replace(&usage_member, "");
        let err = refused(read_report(pipe_with(absent.into_bytes())));
        assert!(err.starts_with("malformed"), "{err}");

        // An explicit null (getrusage failed), by contrast, is a valid
        // report.
        let null = VALID_WITH_USAGE.replace(&usage_member, ",\"usage\":null");
        let r = read_report(pipe_with(null.into_bytes()))
            .expect("a null usage is a valid report");
        assert!(r.usage.is_none());

        // The figures are exact too: one missing, one extra, or a negative
        // value is malformed.
        for bad in [
            "{\"cpu_user_ms\":412,\"cpu_system_ms\":96}",
            "{\"cpu_user_ms\":412,\"cpu_system_ms\":96,\"peak_rss_kib\":1,\"ru_maxrss\":1}",
            "{\"cpu_user_ms\":-1,\"cpu_system_ms\":96,\"peak_rss_kib\":1}",
        ] {
            let line = VALID_WITH_USAGE
                .replace(&usage_member, &format!(",\"usage\":{bad}"));
            let err = refused(read_report(pipe_with(line.into_bytes())));
            assert!(err.starts_with("malformed"), "{bad}: {err}");
        }
        assert!(read_report(pipe_with(VALID_WITH_USAGE.into())).is_ok());
    }

    // ── incomplete reasons and escaping ───────────────

    /// A process nobody can signal: its pid is above the kernel's limit
    /// (pid_max is at most 2^22), so even a stray kill reaches nothing.
    fn unreachable_stat(n: i32) -> ProcStat {
        ProcStat {
            pid: 4_194_304 + 1000 + n,
            ppid: 1,
            comm: "worker".into(),
            state: 'S',
            start_ticks: 1,
        }
    }

    /// Stops nothing: records each process as SIGKILLed and returns, one
    /// round at a time, the note `notes` scripts for that round.
    fn scripted_stop(
        notes: Vec<Option<&'static str>>,
    ) -> impl FnMut(Vec<ProcStat>, Duration) -> (Vec<Survivor>, Option<String>)
    {
        let mut notes = notes.into_iter();
        move |list, _grace| {
            let out = list
                .into_iter()
                .map(|s| Survivor {
                    pid: s.pid,
                    ppid: s.ppid,
                    comm: s.comm,
                    age_s: 0,
                    ended_by: EndedBy::Sigkill,
                })
                .collect();
            (out, notes.next().flatten().map(str::to_string))
        }
    }

    /// Three rounds: the first list, then two re-listings that each find
    /// one new process, then one that finds nothing.
    fn three_rounds(
        notes: Vec<Option<&'static str>>,
    ) -> (Vec<Survivor>, Option<String>) {
        let mut calls = 0;
        let mut relist = || -> Result<Vec<ProcStat>, String> {
            calls += 1;
            assert!(calls <= 10, "the re-list is not bounded");
            Ok(if calls <= 2 {
                vec![unreachable_stat(calls)]
            } else {
                Vec::new()
            })
        };
        let mut stop = scripted_stop(notes);
        stop_survivors_in_rounds_with(
            vec![unreachable_stat(0)],
            Duration::from_millis(400),
            &mut relist,
            &mut stop,
        )
    }

    #[test]
    fn incomplete_reason_lists_each_token_once() {
        const SIGTERM_NOTE: &str =
            "kill(4195305, SIGTERM): EPERM: Operation not permitted";
        const SIGKILL_NOTE: &str =
            "kill(4195305, SIGKILL): EPERM: Operation not permitted";
        const OTHER_PID_NOTE: &str =
            "kill(4195306, SIGKILL): EPERM: Operation not permitted";

        // Every round gives up on the usage of a SIGKILLed process, once
        // alone and twice inside a round's joined note: one token.
        let (out, note) = three_rounds(vec![
            Some("usage-partial"),
            Some(
                "kill(4195305, SIGTERM): EPERM: Operation not permitted; \
                 usage-partial",
            ),
            Some(
                "usage-partial; \
                 kill(4195305, SIGKILL): EPERM: Operation not permitted; \
                 kill(4195306, SIGKILL): EPERM: Operation not permitted",
            ),
        ]);
        assert_eq!(out.len(), 3, "each round's processes are recorded");
        let note = note.expect("a round that gave up is incomplete");
        let tokens: Vec<&str> = note.split("; ").collect();
        assert_eq!(
            tokens.iter().filter(|t| **t == "usage-partial").count(),
            1,
            "usage-partial is listed once: {note}"
        );
        // Notes that differ only in the signal or in one pid digit name
        // different failures, and each one stays.
        for kept in [SIGTERM_NOTE, SIGKILL_NOTE, OTHER_PID_NOTE] {
            assert_eq!(
                tokens.iter().filter(|t| **t == kept).count(),
                1,
                "{kept:?} is listed once: {note}"
            );
        }
        assert_eq!(tokens.len(), 4, "no other token: {note}");

        // One round's single token is the whole reason.
        let (_, note) = three_rounds(vec![Some("usage-partial"), None, None]);
        assert_eq!(note.as_deref(), Some("usage-partial"));

        // Rounds without a note leave the teardown complete.
        let (_, note) = three_rounds(vec![None, None, None]);
        assert_eq!(note, None);
    }

    #[test]
    fn survivor_names_are_escaped_like_every_warning() {
        let name = "a\u{200b}b\u{202e}c\u{1b}d";
        let line = stderr_line(&[survivor(name)]).unwrap();
        assert!(
            line.contains(&crate::output::escape_control_bytes(name)),
            "the name goes through the warning escape: {line:?}"
        );
        assert!(line.contains("a?b?c?d"), "{line:?}");
    }

    // ── names, keys and late reaps ──────────────
    // A `comm` cut inside a UTF-8 character, a report line with a
    // duplicated key, and the usage of a survivor that had to be SIGKILLed.

    fn stat_bytes(pid: i32, comm: &[u8]) -> Vec<u8> {
        let mut line = format!("{pid} (").into_bytes();
        line.extend_from_slice(comm);
        line.extend_from_slice(
            b") S 1 1 1 0 -1 4194560 100 0 0 0 1 2 0 0 20 0 1 0 12345 \
          1000000 200 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 \
          3 0 0 0 0 0\n",
        );
        line
    }

    #[test]
    fn a_comm_cut_inside_a_utf8_character_does_not_hide_other_survivors() {
        let root = std::env::temp_dir()
            .join(format!("ai-jail-teardown-utf8-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        for (pid, comm) in [
            (4001, b"sleep".as_slice()),
            // "ж" x 8 cut by the kernel at 15 bytes: ends in a lone 0xd0.
            (
                4002,
                b"\xd0\xb6\xd0\xb6\xd0\xb6\xd0\xb6\xd0\xb6\xd0\xb6\xd0\xb6\xd0",
            ),
        ] {
            let dir = root.join(pid.to_string());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("stat"), stat_bytes(pid, comm)).unwrap();
        }
        let mut found =
            list_survivors(&root, &[]).expect("listing must succeed");
        found.sort_by_key(|s| s.pid);
        let pids: Vec<i32> = found.iter().map(|s| s.pid).collect();
        assert_eq!(pids, vec![4001, 4002]);
        assert_eq!(found[0].comm, "sleep");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_duplicated_version_key_is_refused() {
        let line = b"{\"v\":2,\"child\":{\"exited\":0},\"survivors\":[],\
        \"grace_ms\":2000,\"usage\":null,\"complete\":true,\"incomplete_reason\":null,\
        \"v\":1}\n";
        assert!(parse_report_line(line).is_err());
        // The same report with one `v` is accepted.
        let ok = b"{\"v\":1,\"child\":{\"exited\":0},\"survivors\":[],\
        \"grace_ms\":2000,\"usage\":null,\"complete\":true,\"incomplete_reason\":null}\n";
        assert!(parse_report_line(ok).is_ok());
    }

    #[test]
    fn a_sigkilled_survivor_is_reaped_before_its_usage_is_read() {
        // Reaps with waitpid(-1): runs in a child test process, like the
        // other stop tests, and under ENV_LOCK, because other tests swap
        // PATH and the child spawns `sh`.
        let _env = crate::test_utils::ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let output =
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("teardown::tests::sigkilled_usage_child")
                .arg("--ignored")
                .env("AI_JAIL_TEARDOWN_CHILD", "1")
                .output()
                .expect("spawn child test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "child failed\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    #[ignore]
    fn sigkilled_usage_child() {
        use nix::sys::resource::{UsageWho, getrusage};
        if std::env::var_os("AI_JAIL_TEARDOWN_CHILD").is_none() {
            return;
        }
        // A survivor that ignores SIGTERM and burns CPU until the SIGKILL.
        // It touches `ready` once the trap is installed: a SIGTERM sent
        // before that would end it, not exercise the SIGKILL path.
        let ready = std::env::temp_dir()
            .join(format!("ai-jail-sigkilled-usage-{}", std::process::id()));
        let _ = std::fs::remove_file(&ready);
        let script = format!(
            "trap '' TERM; : > '{}'; while :; do :; done",
            ready.display()
        );
        let burner = std::process::Command::new("sh")
            .args(["-c", &script])
            .spawn()
            .unwrap();
        let pid = burner.id();
        std::mem::forget(burner);
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !ready.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "the trap was never installed"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let _ = std::fs::remove_file(&ready);
        // Some CPU time to count before the stop.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|t| parse_proc_stat(&t))
            .expect("the burner is listed");
        let (out, note) = stop_survivors_noting_errors(
            vec![stat],
            std::time::Duration::from_millis(200),
        );
        assert!(matches!(out[0].ended_by, EndedBy::Sigkill), "{out:?}");
        assert_eq!(note, None, "reaped within the wait");
        let usage = getrusage(UsageWho::RUSAGE_CHILDREN).unwrap();
        assert!(
            usage.user_time().tv_sec() > 0 || usage.user_time().tv_usec() > 0,
            "the killed survivor's CPU time is counted"
        );
    }
}
