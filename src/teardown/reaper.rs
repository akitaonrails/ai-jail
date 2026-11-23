//! The landlock wrapper as sub-reaper: with
//! `--teardown-report-fd N` it spawns the command instead of becoming it,
//! stops what outlived the command, reports on N, and ends the way the
//! command ended.
//!
//! It runs AFTER Landlock and seccomp are applied, so every syscall here
//! must stay allowed by them; among them `wait4`, `kill`, `prctl`,
//! `getdents64` and `openat` on `/proc`, `rt_sigaction`, `rt_sigprocmask`,
//! `prlimit64`, `getrusage`, `clock_nanosleep` and `write`. The deny lists
//! (sandbox/seccomp.rs) name none of them; `clone3` returns ENOSYS there
//! and std falls back to `clone`.

use super::{
    ChildStatusWire, GRACE, ProcStat, REPORT_VERSION, Survivor, TeardownReport,
    WireUsage, child_pidfd, list_survivors, signal_pidfd,
    stop_survivors_then_relist,
};
use nix::errno::Errno;
use nix::sys::signal::{
    SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal,
    pthread_sigmask, sigaction,
};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::sync::atomic::{AtomicI32, Ordering};

/// Survivors the report lists before it is cut:
/// 256 worst-case entries stay under the supervisor's 64 KiB read bound.
const SURVIVOR_CAP: usize = 256;

/// Bound on `incomplete_reason`: one `kill` errno note per survivor could
/// otherwise push a 256-entry report past the 64 KiB read bound.
const REASON_CAP: usize = 4096;

/// The command's pidfd, retained until the forwarder is disarmed.
static REAPER_CHILD_FD: AtomicI32 = AtomicI32::new(-1);

/// SIGTERM/SIGHUP handler: forward to the command. Async-signal-
/// safe only: an atomic load, a raw syscall, and errno saved and restored so
/// the interrupted `waitpid` reads its own errno, not this one's.
extern "C" fn forward_to_reaper_child(sig: nix::libc::c_int) {
    let saved = Errno::last_raw();
    let fd = REAPER_CHILD_FD.load(Ordering::SeqCst);
    if fd >= 0 {
        // SAFETY: this single-threaded wrapper retains the kernel handle
        // until the handler is disarmed. Ignore errors if the child exited.
        unsafe {
            nix::libc::syscall(
                nix::libc::SYS_pidfd_send_signal,
                fd,
                sig,
                std::ptr::null::<nix::libc::siginfo_t>(),
                0,
            )
        };
    }
    Errno::set_raw(saved);
}

/// Takes ownership of the report descriptor and marks it close-on-exec,
/// so neither the bridges nor the command inherit it. Called
/// before the bridges are spawned.
pub fn claim_report_fd(fd: RawFd) -> Result<OwnedFd, String> {
    // 0-2 are the command's stdio: marking one CLOEXEC would take it away.
    if fd <= 2 {
        return Err(format!("--teardown-report-fd {fd}: not a report fd"));
    }
    use nix::sys::stat::fstat;
    if !fstat(fd).is_ok_and(|stat| {
        stat.st_mode & nix::libc::S_IFMT == nix::libc::S_IFIFO
    }) {
        return Err("Teardown report descriptor must be a pipe".into());
    }
    // SAFETY: F_GETFD/F_SETFD only read and set the descriptor's flags;
    // an invalid `fd` makes them fail with EBADF, which is returned.
    let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
    if flags < 0
        // SAFETY: as above; it only adds FD_CLOEXEC to the flags just read.
        || unsafe {
            nix::libc::fcntl(
                fd,
                nix::libc::F_SETFD,
                flags | nix::libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err(format!(
            "--teardown-report-fd {fd}: cannot set close-on-exec: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `fd` is open (F_GETFD succeeded) and nothing else in this
    // process owns it: it was inherited by number from the supervisor and
    // is named only by the internal flag, so this is its single owner.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// The dispositions and mask in force before the wrapper changed them,
/// restored in the command before its exec, so the command starts exactly
/// as it would have on the exec path (SIGINT stays the command's).
#[derive(Clone, Copy)]
struct Inherited {
    actions: [(Signal, SigAction); 5],
    mask: SigSet,
}

fn set_action(
    signal: Signal,
    handler: SigHandler,
) -> Result<SigAction, String> {
    let action = SigAction::new(handler, SaFlags::SA_RESTART, SigSet::empty());
    // SAFETY: the handler is either SIG_IGN/SIG_DFL or
    // `forward_to_reaper_child`, which is async-signal-safe (see there).
    unsafe { sigaction(signal, &action) }
        .map_err(|e| format!("Cannot set the {signal} disposition: {e}"))
}

/// SIGINT and SIGQUIT ignored, SIGTERM and SIGHUP forwarded,
/// SIGCHLD default (an inherited SIG_IGN would auto-reap the
/// command and lose its status). TERM and HUP are left blocked: they are
/// delivered once the command's pid is known.
fn install_signals() -> Result<Inherited, String> {
    let mut forwarded = SigSet::empty();
    forwarded.add(Signal::SIGTERM);
    forwarded.add(Signal::SIGHUP);
    let mut mask = SigSet::empty();
    pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&forwarded), Some(&mut mask))
        .map_err(|e| format!("Cannot block SIGTERM/SIGHUP: {e}"))?;
    let forward = SigHandler::Handler(forward_to_reaper_child);
    let actions = [
        (
            Signal::SIGINT,
            set_action(Signal::SIGINT, SigHandler::SigIgn)?,
        ),
        (
            Signal::SIGQUIT,
            set_action(Signal::SIGQUIT, SigHandler::SigIgn)?,
        ),
        (Signal::SIGTERM, set_action(Signal::SIGTERM, forward)?),
        (Signal::SIGHUP, set_action(Signal::SIGHUP, forward)?),
        (
            Signal::SIGCHLD,
            set_action(Signal::SIGCHLD, SigHandler::SigDfl)?,
        ),
    ];
    Ok(Inherited { actions, mask })
}

fn spawn_command(cmd: &[String], inherited: Inherited) -> Result<Pid, String> {
    let mut command = std::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    // SAFETY: runs in the forked child before its exec, where only
    // async-signal-safe calls are allowed: sigaction(2) and
    // pthread_sigmask(2) with values copied in, no allocation, no lock.
    unsafe {
        command.pre_exec(move || {
            for (signal, action) in inherited.actions {
                sigaction(signal, &action)?;
            }
            pthread_sigmask(
                SigmaskHow::SIG_SETMASK,
                Some(&inherited.mask),
                None,
            )?;
            Ok(())
        });
    }
    // Same message as the exec path's, so a missing command reads alike.
    let child = command
        .spawn()
        .map_err(|e| format!("Failed to exec {}: {e}", cmd[0]))?;
    let pid = i32::try_from(child.id())
        .map_err(|_| format!("Failed to exec {}: pid out of range", cmd[0]))?;
    // Dropping `child` neither kills nor reaps it; `waitpid` below does.
    Ok(Pid::from_raw(pid))
}

/// Waits for the command, reaping everything else that ends meanwhile:
/// as sub-reaper the wrapper inherits every orphan, and a zombie left
/// until the command exits would still count against RLIMIT_NPROC. A
/// bridge reaped here is dropped from `bridges`, so its pid, if reused,
/// is not excluded from the survivors.
fn wait_for_command(
    child: Pid,
    bridges: &mut Vec<i32>,
) -> Result<ChildStatusWire, String> {
    loop {
        match waitpid(Pid::from_raw(-1), None) {
            Ok(WaitStatus::Exited(pid, code)) if pid == child => {
                return Ok(ChildStatusWire::Exited(code));
            }
            Ok(WaitStatus::Signaled(pid, signal, core)) if pid == child => {
                return Ok(ChildStatusWire::Signaled {
                    signal: signal as i32,
                    core,
                });
            }
            Ok(status) => {
                if let Some(pid) = status.pid() {
                    bridges.retain(|&b| b != pid.as_raw());
                }
            }
            Err(Errno::EINTR) => {}
            Err(e) => {
                return Err(format!("Cannot wait for {child}: {e}"));
            }
        }
    }
}

/// Spawns `cmd` as this process's child and ends the way it ends.
/// `bridge_pids` are the wrapper's own bridges: never survivors, killed
/// silently after the report.
pub fn run_command_as_reaper(
    cmd: &[String],
    report: OwnedFd,
    bridge_pids: &[i32],
) -> Result<i32, String> {
    if cmd.is_empty() {
        return Err("--landlock-exec requires a command".into());
    }
    let mut reasons: Vec<String> = Vec::new();
    // Not dumpable: /proc/<this pid>/fd is then closed to the command (same
    // uid, same Landlock domain), so it cannot reopen the report pipe there
    // and write a forged first line. It also keeps
    // the host's core handler away from the re-raise below: a piped
    // core_pattern ignores RLIMIT_CORE. exec resets the flag, so the
    // command itself is unaffected.
    // A pidfd for this wrapper is valid, but waitid must reject it as a
    // non-child. Older kernels that cannot verify PIDFd return another error.
    if !matches!(
        child_pidfd(nix::unistd::getpid().as_raw()),
        Err(Errno::ECHILD)
    ) || nix::sys::prctl::set_child_subreaper(true).is_err()
        || nix::sys::prctl::set_dumpable(false).is_err()
    {
        drop(report);
        let error = std::process::Command::new(&cmd[0]).args(&cmd[1..]).exec();
        return Err(format!("Failed to exec {}: {error}", cmd[0]));
    }
    let inherited = install_signals()?;
    let child = spawn_command(cmd, inherited)?;
    let child_handle = child_pidfd(child.as_raw()).ok();
    if let Some(handle) = &child_handle {
        REAPER_CHILD_FD.store(handle.as_raw_fd(), Ordering::SeqCst);
    } else {
        reasons.push("child-pidfd-unavailable".into());
    }
    // A TERM/HUP that arrived during the spawn is delivered here, now
    // that the forwarder knows where to send it.
    pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&inherited.mask), None)
        .map_err(|e| format!("Cannot unblock SIGTERM/SIGHUP: {e}"))?;

    let mut live_bridges = bridge_pids.to_vec();
    let status = wait_for_command(child, &mut live_bridges)?;
    // The command is reaped: nothing is left to forward to, and its pid
    // may be reused.
    REAPER_CHILD_FD.store(-1, Ordering::SeqCst);

    let survivors = stop_the_survivors(&live_bridges, &mut reasons);
    // After the last reap, so the figures cover the command and every
    // survivor stopped above.
    let usage = children_usage();
    write_report(report, status, survivors, usage, &reasons);
    kill_bridges(bridge_pids);
    Ok(end_like(status))
}

/// One poll interval, given to survivors before they are named: a
/// command that ends right after `cmd &` leaves a forked child that may
/// not have reached its `execve` yet, and would be named after the shell
/// (measured: 12 of 30 runs of `sh -c 'sleep 300 & exit 0'` listed `sh`).
const SETTLE: std::time::Duration = std::time::Duration::from_millis(50);

/// Lists the survivors; when there are any, waits `SETTLE` and lists
/// again, so in-flight execs carry their real name. No survivors, no
/// delay.
fn list_settled(exclude: &[i32]) -> Result<Vec<ProcStat>, String> {
    let proc_root = std::path::Path::new("/proc");
    let me = nix::unistd::getpid().as_raw();
    let owned = || {
        list_survivors(proc_root, exclude).map(|list| {
            list.into_iter()
                .filter(|stat| stat.ppid == me)
                .collect::<Vec<_>>()
        })
    };
    let first = owned()?;
    if first.is_empty() {
        return Ok(first);
    }
    std::thread::sleep(SETTLE);
    owned()
}

fn stop_the_survivors(
    bridges: &[i32],
    reasons: &mut Vec<String>,
) -> Vec<Survivor> {
    match list_settled(bridges) {
        Ok(list) => {
            // The signal layer independently verifies child ownership.
            let mut relist = || list_settled(bridges);
            let (survivors, note) =
                stop_survivors_then_relist(list, GRACE, &mut relist);
            cap_survivor_list(survivors, note, reasons)
        }
        Err(e) => {
            reasons.push(e);
            Vec::new()
        }
    }
}

/// Cuts the report's list at [`SURVIVOR_CAP`]. The truncation token goes
/// in before the per-pid notes, so cutting the joined reason at
/// `REASON_CAP` cannot drop it.
fn cap_survivor_list(
    mut survivors: Vec<Survivor>,
    note: Option<String>,
    reasons: &mut Vec<String>,
) -> Vec<Survivor> {
    if survivors.len() > SURVIVOR_CAP {
        survivors.truncate(SURVIVOR_CAP);
        reasons.push("survivor-list-truncated".into());
    }
    reasons.extend(note);
    survivors
}

/// One JSON line on the report fd, then close. A write error is ignored:
/// the supervisor then sees a missing report.
fn write_report(
    report: OwnedFd,
    child: ChildStatusWire,
    survivors: Vec<Survivor>,
    usage: Option<WireUsage>,
    reasons: &[String],
) {
    let report_line = TeardownReport {
        v: REPORT_VERSION,
        child,
        survivors,
        grace_ms: u64::try_from(GRACE.as_millis()).unwrap_or(u64::MAX),
        usage,
        complete: reasons.is_empty(),
        incomplete_reason: bounded_reason(reasons),
    };
    let mut file = std::fs::File::from(report);
    if let Ok(mut line) = serde_json::to_string(&report_line) {
        line.push('\n');
        let _ = file.write_all(line.as_bytes());
    }
}

/// `RUSAGE_CHILDREN` of the wrapper: CPU time summed over, and the
/// largest resident set of, every process it reaped. `None` when the
/// call fails; the report then says the figures are unknown.
fn children_usage() -> Option<WireUsage> {
    use nix::sys::resource::{UsageWho, getrusage};
    let usage = getrusage(UsageWho::RUSAGE_CHILDREN).ok()?;
    let ms = |t: nix::sys::time::TimeVal| {
        let ms = t.tv_sec().saturating_mul(1000) + t.tv_usec() / 1000;
        u64::try_from(ms).unwrap_or(0)
    };
    Some(WireUsage {
        cpu_user_ms: ms(usage.user_time()),
        cpu_system_ms: ms(usage.system_time()),
        // Linux reports ru_maxrss in KiB.
        peak_rss_kib: u64::try_from(usage.max_rss()).unwrap_or(0),
    })
}

fn bounded_reason(reasons: &[String]) -> Option<String> {
    if reasons.is_empty() {
        return None;
    }
    let mut text = reasons.join("; ");
    if text.len() > REASON_CAP {
        let mut cut = REASON_CAP;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        text.truncate(cut);
        text.push_str(" …");
    }
    Some(text)
}

/// SIGKILL each bridge still alive as this process's child. One may have
/// died and been reaped already (by the wait or the survivor stop), and
/// its pid reused: the parent check keeps a stranger out, and ESRCH is
/// fine.
fn kill_bridges(bridge_pids: &[i32]) {
    for &pid in bridge_pids {
        if let Ok(handle) = child_pidfd(pid) {
            let _ = signal_pidfd(&handle, Signal::SIGKILL);
        }
    }
}

/// The wrapper's own end, so the exit code callers see is unchanged:
/// the command's code, or the command's signal re-raised on the
/// wrapper with no core dump of its own, `128 + sig` if that returns.
fn end_like(status: ChildStatusWire) -> i32 {
    match status {
        ChildStatusWire::Exited(code) => code,
        ChildStatusWire::Signaled { signal, .. } => reraise(signal),
    }
}

fn reraise(sig: i32) -> i32 {
    let fallback = 128 + sig;
    let Ok(signal) = Signal::try_from(sig) else {
        return fallback;
    };
    // Second layer behind the wrapper being non-dumpable (see
    // run_command_as_reaper): no core file even if that call failed.
    let _ = nix::sys::resource::setrlimit(
        nix::sys::resource::Resource::RLIMIT_CORE,
        0,
        0,
    );
    if !matches!(signal, Signal::SIGKILL | Signal::SIGSTOP) {
        let _ = set_action(signal, SigHandler::SigDfl);
    }
    let mut set = SigSet::empty();
    set.add(signal);
    let _ = pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&set), None);
    let _ = nix::sys::signal::kill(nix::unistd::getpid(), signal);
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reason_is_none_without_reasons_and_joins_them() {
        assert_eq!(bounded_reason(&[]), None);
        let r = ["subreaper-unavailable".to_string(), "x".to_string()];
        assert_eq!(
            bounded_reason(&r).as_deref(),
            Some("subreaper-unavailable; x")
        );
    }

    #[test]
    fn bounded_reason_cuts_at_a_char_boundary() {
        let long = vec!["ж".repeat(REASON_CAP)];
        let text = bounded_reason(&long).unwrap();
        assert!(text.len() <= REASON_CAP + " …".len());
        assert!(text.ends_with(" …"));
    }

    #[test]
    fn claim_report_fd_refuses_stdio_and_a_closed_fd() {
        for fd in [-1, 0, 1, 2] {
            assert!(claim_report_fd(fd).is_err(), "fd {fd}");
        }
        // A number far above any open descriptor of the test binary.
        assert!(claim_report_fd(1_000_000).is_err());
    }

    #[test]
    fn claim_report_fd_refuses_a_non_pipe() {
        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(claim_report_fd(file.as_raw_fd()).is_err());
    }

    #[test]
    fn claim_report_fd_sets_close_on_exec() {
        use std::os::fd::{AsRawFd, IntoRawFd};
        let (read, write) = nix::unistd::pipe().unwrap();
        drop(read);
        // Clear CLOEXEC, as the supervisor's dup2 leaves it.
        let raw = write.into_raw_fd();
        // SAFETY: `raw` is the open pipe end just released above.
        unsafe { nix::libc::fcntl(raw, nix::libc::F_SETFD, 0) };
        let owned = claim_report_fd(raw).unwrap();
        // SAFETY: F_GETFD on a descriptor `owned` keeps open.
        let flags =
            unsafe { nix::libc::fcntl(owned.as_raw_fd(), nix::libc::F_GETFD) };
        assert!(flags & nix::libc::FD_CLOEXEC != 0);
    }

    /// A survivor the teardown had to SIGKILL.
    fn killed(pid: i32) -> Survivor {
        Survivor {
            pid,
            ppid: 2,
            comm: "worker".into(),
            age_s: 0,
            ended_by: super::super::EndedBy::Sigkill,
        }
    }

    /// One distinct `kill` errno note per survivor, joined as the stop
    /// joins them: far past `REASON_CAP` for a list near `SURVIVOR_CAP`.
    fn kill_notes(n: usize) -> String {
        (0..n)
            .map(|pid| {
                format!("kill({pid}, SIGKILL): EPERM: Operation not permitted")
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    #[test]
    fn truncated_survivor_list_keeps_its_token_under_the_cap() {
        const TOKEN: &str = "survivor-list-truncated";
        assert!(kill_notes(SURVIVOR_CAP).len() > REASON_CAP);

        // One survivor over the cap: the list is cut, and the reason, cut
        // at its own cap by the per-pid notes, still says so.
        let mut reasons = vec!["dumpable-unavailable".to_string()];
        let all: Vec<Survivor> =
            (0..=SURVIVOR_CAP as i32).map(killed).collect();
        let kept = cap_survivor_list(
            all,
            Some(kill_notes(SURVIVOR_CAP + 1)),
            &mut reasons,
        );
        assert_eq!(kept.len(), SURVIVOR_CAP);
        assert!(
            kept.iter().enumerate().all(|(i, s)| s.pid == i as i32),
            "the first survivors are the ones kept"
        );
        let text = bounded_reason(&reasons).unwrap();
        assert!(text.len() <= REASON_CAP + " …".len(), "{}", text.len());
        assert!(text.ends_with(" …"), "the notes still reach the cap");
        assert_eq!(text.matches(TOKEN).count(), 1, "{text}");
        assert!(text.contains("dumpable-unavailable"), "{text}");

        // Exactly the cap: nothing is cut from the list, so the reason,
        // cut by the same notes, carries no such token.
        let mut reasons = vec!["dumpable-unavailable".to_string()];
        let all: Vec<Survivor> = (0..SURVIVOR_CAP as i32).map(killed).collect();
        let kept = cap_survivor_list(
            all,
            Some(kill_notes(SURVIVOR_CAP)),
            &mut reasons,
        );
        assert_eq!(kept.len(), SURVIVOR_CAP);
        let text = bounded_reason(&reasons).unwrap();
        assert!(text.ends_with(" …"), "{}", text.len());
        assert!(!text.contains(TOKEN), "nothing was cut: {text}");

        // A cut list with no note: the token is the whole reason.
        let mut reasons = Vec::new();
        let all: Vec<Survivor> =
            (0..SURVIVOR_CAP as i32 + 44).map(killed).collect();
        let kept = cap_survivor_list(all, None, &mut reasons);
        assert_eq!(kept.len(), SURVIVOR_CAP);
        assert_eq!(bounded_reason(&reasons).as_deref(), Some(TOKEN));
    }
}
