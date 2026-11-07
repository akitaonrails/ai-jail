//! The supervisor half of the teardown report: the pipe
//! whose write end the wrapper inherits at a fixed descriptor number, the
//! reader that runs while the supervisor waits, and the stderr lines.
//!
//! The descriptor is made inheritable in the supervisor right before the
//! spawn and closed right after it (`signals::SpawnBracket`), because the
//! supervised-exec wrapper replaces the `Command` and drops `pre_exec`
//! hooks. It survives the supervised exec and bwrap's exec
//! because it is not close-on-exec, and the in-sandbox wrapper marks it
//! close-on-exec before it spawns anything.

use super::{
    EndedBy, REPORT_VERSION, Survivor, TeardownReport, TeardownSection,
};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

/// `TeardownSection::Missing` reason when no report pipe could be set up;
/// the run goes on without teardown.
pub const PIPE_UNAVAILABLE: &str = "pipe-unavailable";

/// The supervisor stops reading the report at this bound. 256 survivors
/// with 15-byte comms fit well inside it.
const REPORT_CAP: usize = 64 * 1024;

/// Names in the stderr survivor line before `+N more`.
const STDERR_NAMES: usize = 10;

/// The report pipe before the spawn.
struct ReportPipe {
    read: OwnedFd,
    write: OwnedFd,
    /// Holds the number the wrapper is told (`--teardown-report-fd N`): a
    /// close-on-exec duplicate of `write`, so no descriptor opened before
    /// the spawn (the bwrap args memfd) can take the number, and no child
    /// spawned meanwhile inherits it.
    slot: OwnedFd,
}

/// Where one run's teardown report stands.
enum RunState {
    /// `--teardown-report` was not given, or the sandbox never started.
    Inactive,
    /// No pipe could be set up; the cause was reported at the start.
    Unavailable,
    /// The pipe is open and the sandbox is not spawned yet.
    Ready(ReportPipe),
    /// The sandbox runs; a thread reads the report and sends it here.
    Reading(Receiver<Result<TeardownReport, String>>),
    /// The sandbox runs, but no reader could be started.
    Unread(String),
}

/// The teardown report of one run, from the pipe to the section.
pub struct TeardownRun {
    state: RunState,
}

impl TeardownRun {
    /// Opens the report pipe when `requested`. A failure is reported on
    /// stderr and the run goes on without teardown.
    pub fn start(requested: bool) -> Self {
        let state = if !requested {
            RunState::Inactive
        } else {
            match open_report_pipe() {
                Ok(pipe) => RunState::Ready(pipe),
                Err(e) => {
                    crate::output::security_warn(&format!(
                        "Teardown report unavailable, running without it: {e}"
                    ));
                    RunState::Unavailable
                }
            }
        };
        Self { state }
    }

    /// The descriptor number the wrapper writes its report to, while the
    /// pipe waits for the spawn.
    pub fn report_fd(&self) -> Option<RawFd> {
        match &self.state {
            RunState::Ready(pipe) => Some(pipe.slot.as_raw_fd()),
            _ => None,
        }
    }

    /// Joins the reader (after the wait) and prints what the run left:
    /// the survivor line or why the report is missing.
    pub fn finish(self) -> TeardownSection {
        let section = match self.state {
            // Never spawned: the start failed before the sandbox existed.
            RunState::Inactive | RunState::Ready(_) => {
                return TeardownSection::Inactive;
            }
            // Its cause was printed when the pipe failed.
            RunState::Unavailable => {
                return TeardownSection::Missing {
                    reason: PIPE_UNAVAILABLE.to_string(),
                };
            }
            RunState::Unread(reason) => TeardownSection::Missing { reason },
            // Bounded: finish() runs after the wait, so a wrapper that wrote
            // its report has already done so; a child that inherited N in
            // the spawn window (the update check's curl) must not hold the
            // launch's exit open until it ends.
            RunState::Reading(reader) => {
                match reader.recv_timeout(READ_GRACE) {
                    Ok(Ok(report)) => TeardownSection::Reported(report),
                    Ok(Err(reason)) => TeardownSection::Missing { reason },
                    Err(RecvTimeoutError::Timeout) => {
                        TeardownSection::Missing {
                            reason: "missing: report reader timed out"
                                .to_string(),
                        }
                    }
                    Err(RecvTimeoutError::Disconnected) => {
                        TeardownSection::Missing {
                            reason: "missing: the report reader panicked"
                                .to_string(),
                        }
                    }
                }
            }
        };
        announce(&section);
        section
    }
}

impl crate::signals::SpawnBracket for TeardownRun {
    fn before_spawn(&mut self) -> Result<(), String> {
        if let RunState::Ready(pipe) = &self.state {
            let n = pipe.slot.as_raw_fd();
            // SAFETY: both are open descriptors owned by `pipe`. dup2 onto
            // the slot's own number replaces it, atomically, with a
            // duplicate that is NOT close-on-exec, so the sandbox
            // inherits N; `slot` still owns (and later closes) N.
            if unsafe { nix::libc::dup2(pipe.write.as_raw_fd(), n) } < 0 {
                return Err(format!(
                    "Cannot pass the teardown report descriptor {n} to the \
                     sandbox: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(())
    }

    fn after_spawn(&mut self, spawned: bool) {
        let state = std::mem::replace(&mut self.state, RunState::Inactive);
        self.state = match state {
            RunState::Ready(ReportPipe { read, write, slot }) => {
                // Only the sandbox holds the write end now, so EOF comes
                // when the wrapper is gone.
                drop(slot);
                drop(write);
                if spawned {
                    start_reader(read)
                } else {
                    RunState::Inactive
                }
            }
            other => other,
        };
    }
}

/// How long finish() waits for the reader once the sandbox has exited.
const READ_GRACE: Duration = Duration::from_secs(1);

/// Reads concurrently with the wait, so a report larger than the pipe
/// buffer never blocks the wrapper and, through it, bwrap.
fn start_reader(read: OwnedFd) -> RunState {
    let (tx, rx) = std::sync::mpsc::channel();
    match std::thread::Builder::new()
        .name("teardown-report".into())
        .spawn(move || {
            let _ = tx.send(read_report(read));
        }) {
        Ok(_) => RunState::Reading(rx),
        // The read end is dropped with the closure, so the wrapper's write
        // fails with EPIPE (ignored there) instead of blocking.
        Err(e) => {
            RunState::Unread(format!("missing: report reader not started: {e}"))
        }
    }
}

fn announce(section: &TeardownSection) {
    match section {
        TeardownSection::Reported(report) => {
            if let Some(line) = stderr_line(&report.survivors) {
                crate::output::security_warn(&line);
            }
            // An incomplete report may list nothing at all (a /proc read
            // error), which would otherwise read as "nothing survived".
            if !report.complete {
                let reason = report
                    .incomplete_reason
                    .as_deref()
                    .unwrap_or("no reason given");
                // security_warn escapes the whole message.
                crate::output::security_warn(&format!(
                    "Teardown report incomplete: {reason}"
                ));
            }
        }
        TeardownSection::Missing { reason } => {
            // A parse error can echo part of a damaged line back.
            crate::output::security_warn(&format!(
                "Teardown report incomplete: {reason}"
            ));
        }
        TeardownSection::Inactive => {}
    }
}

fn open_report_pipe() -> Result<ReportPipe, String> {
    let mut fds: [RawFd; 2] = [-1; 2];
    // SAFETY: pipe2 writes two fresh descriptors into `fds` or fails.
    if unsafe { nix::libc::pipe2(fds.as_mut_ptr(), nix::libc::O_CLOEXEC) } < 0 {
        return Err(format!("pipe2: {}", std::io::Error::last_os_error()));
    }
    // SAFETY: both descriptors are fresh and owned by nothing else.
    let (low_read, low_write) =
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    let above = highest_open_fd()?.saturating_add(1);
    // All three move above every descriptor open now, and the two low
    // originals close below: the descriptors the launch opens next (the
    // bwrap args memfd, the supervision gate) get the numbers they get
    // without the flag, so the command's descriptor table is unchanged
    // (`teardown_report_fd_is_not_visible_to_the_command`).
    // Each lands above the previous one, not merely above `above`: another
    // thread (the egress proxy's) may close a descriptor in between, and
    // "lowest free" would then put a pipe end below the slot.
    let slot = dup_above(&low_write, above)?;
    let read = dup_above(&low_read, slot.as_raw_fd() + 1)?;
    let write = dup_above(&low_write, read.as_raw_fd() + 1)?;
    Ok(ReportPipe { read, write, slot })
}

/// A close-on-exec duplicate of `fd` on the lowest free number >= `above`.
fn dup_above(fd: &OwnedFd, above: RawFd) -> Result<OwnedFd, String> {
    // SAFETY: F_DUPFD_CLOEXEC duplicates an open descriptor onto the
    // lowest free number >= `above`, or fails with errno set.
    let n = unsafe {
        nix::libc::fcntl(fd.as_raw_fd(), nix::libc::F_DUPFD_CLOEXEC, above)
    };
    if n < 0 {
        return Err(format!(
            "choosing a report descriptor above {above}: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `n` is the fresh duplicate just returned, owned by nothing.
    Ok(unsafe { OwnedFd::from_raw_fd(n) })
}

/// The highest descriptor number open in this process: N is chosen
/// above every open fd.
fn highest_open_fd() -> Result<RawFd, String> {
    let entries = std::fs::read_dir("/proc/self/fd")
        .map_err(|e| format!("reading /proc/self/fd: {e}"))?;
    let mut highest: RawFd = 2;
    for entry in entries {
        let entry = entry.map_err(|e| format!("reading /proc/self/fd: {e}"))?;
        if let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<RawFd>().ok())
        {
            highest = highest.max(fd);
        }
    }
    Ok(highest)
}

/// The one stderr line for survivors, or `None` when there are
/// none. Names are `comm` only. A process picks its own `comm`, so each
/// name goes through the escape every warning uses: the line stays one
/// line and cannot carry terminal escapes or hidden characters.
pub fn stderr_line(survivors: &[Survivor]) -> Option<String> {
    // A process that was already gone when the teardown reached it was
    // not stopped, so the line neither counts nor names it.
    let stopped: Vec<&Survivor> = survivors
        .iter()
        .filter(|s| s.ended_by != EndedBy::AlreadyGone)
        .collect();
    if stopped.is_empty() {
        return None;
    }
    let n = stopped.len();
    let names: Vec<String> = stopped
        .iter()
        .take(STDERR_NAMES)
        .map(|s| crate::output::escape_control_bytes(&s.comm))
        .collect();
    let mut line = format!(
        "{n} process{} outlived the command and {} stopped: {}",
        if n == 1 { "" } else { "es" },
        if n == 1 { "was" } else { "were" },
        names.join(", ")
    );
    if n > STDERR_NAMES {
        line.push_str(&format!(" +{} more", n - STDERR_NAMES));
    }
    Some(line)
}

/// Supervisor side: reads the wrapper's report from `fd`. Returns at the
/// FIRST `\n`, without waiting for EOF, because another supervisor child
/// may hold an inherited copy of the write end. Reads at most
/// 64 KiB. Every refusal names its cause first: `missing`, `malformed`,
/// `too-large` or `unsupported-version`.
pub fn read_report(fd: OwnedFd) -> Result<TeardownReport, String> {
    let line = read_first_line(std::fs::File::from(fd))?;
    parse_report_line(&line)
}

fn read_first_line(mut src: impl std::io::Read) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let room = REPORT_CAP - buf.len();
        if room == 0 {
            return Err(format!(
                "too-large: no report line within {REPORT_CAP} bytes"
            ));
        }
        let want = room.min(chunk.len());
        let n = match src.read(&mut chunk[..want]) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("missing: report read failed: {e}")),
        };
        if n == 0 {
            return Err(if buf.is_empty() {
                "missing: no report before EOF".to_string()
            } else {
                "malformed: report line not terminated before EOF".to_string()
            });
        }
        let start = buf.len();
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf[start..].iter().position(|&b| b == b'\n') {
            // Bytes after the newline are not part of the report.
            buf.truncate(start + i);
            return Ok(buf);
        }
    }
}

/// The version is checked before the shape, so a future report with new
/// fields reads as `unsupported-version`, not `malformed`.
pub(super) fn parse_report_line(line: &[u8]) -> Result<TeardownReport, String> {
    let value: serde_json::Value =
        serde_json::from_slice(line).map_err(|e| format!("malformed: {e}"))?;
    match value.get("v").and_then(serde_json::Value::as_u64) {
        Some(v) if v != u64::from(REPORT_VERSION) => {
            return Err(format!(
                "unsupported-version: report v{v}, this build reads \
                 v{REPORT_VERSION}"
            ));
        }
        _ => {}
    }
    // Decoded from the bytes, not the Value: a Value keeps the last of
    // duplicated keys, so `{"v":2,…,"v":1}` would pass the check above.
    serde_json::from_slice(line).map_err(|e| format!("malformed: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::SpawnBracket;

    const LINE: &[u8] = br#"{"v":1,"child":{"exited":0},"survivors":[{"pid":7,"ppid":2,"comm":"sleep","age_s":0,"ended_by":"sigterm"}],"grace_ms":2000,"usage":null,"complete":true,"incomplete_reason":null}
"#;

    fn close_on_exec(fd: RawFd) -> bool {
        // SAFETY: F_GETFD only reads the flags of a descriptor the test owns.
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
        assert!(flags >= 0, "fd {fd} is open");
        flags & nix::libc::FD_CLOEXEC != 0
    }

    #[test]
    fn without_the_flag_nothing_is_opened() {
        let run = TeardownRun::start(false);
        assert_eq!(run.report_fd(), None);
        assert_eq!(run.finish(), TeardownSection::Inactive);
    }

    #[test]
    fn the_slot_is_close_on_exec_until_armed_right_before_the_spawn() {
        let mut run = TeardownRun::start(true);
        let n = run.report_fd().expect("a pipe opens");
        assert!(n > 2, "never a stdio number: {n}");
        assert!(close_on_exec(n), "a child spawned earlier does not get N");
        run.before_spawn().unwrap();
        assert!(!close_on_exec(n), "the sandbox inherits N");
        run.after_spawn(false);
        assert_eq!(run.report_fd(), None);
        // A spawn that failed leaves no report to wait for.
        assert_eq!(run.finish(), TeardownSection::Inactive);
    }

    #[test]
    fn a_report_written_on_the_slot_is_read_back() {
        let mut run = TeardownRun::start(true);
        let n = run.report_fd().unwrap();
        run.before_spawn().unwrap();
        // Stand-in for the wrapper: its copy of N outlives the supervisor's.
        // SAFETY: `n` is open (owned by `run`) and LINE is a valid buffer.
        let wrote =
            unsafe { nix::libc::write(n, LINE.as_ptr().cast(), LINE.len()) };
        assert_eq!(wrote, LINE.len() as isize);
        run.after_spawn(true);
        match run.finish() {
            TeardownSection::Reported(report) => {
                assert_eq!(report.survivors.len(), 1);
                assert_eq!(report.survivors[0].comm, "sleep");
            }
            other => panic!("expected a report, got {other:?}"),
        }
    }

    #[test]
    fn every_supervisor_copy_of_the_write_end_closes_after_the_spawn() {
        // Nothing writes: EOF arrives only if both the pipe's write end and
        // the slot were closed by after_spawn, so finish cannot hang.
        let mut run = TeardownRun::start(true);
        run.before_spawn().unwrap();
        run.after_spawn(true);
        match run.finish() {
            TeardownSection::Missing { reason } => {
                assert!(reason.starts_with("missing:"), "{reason}");
            }
            other => panic!("expected a missing report, got {other:?}"),
        }
    }

    #[test]
    fn the_slot_sits_above_every_descriptor_open_before_it() {
        // A descriptor this test holds open across start(): other test threads
        // open and close descriptors meanwhile, so a number read from
        // /proc/self/fd beforehand may be freed again, but this one cannot.
        let held = std::fs::File::open("/dev/null").unwrap();
        let highest = held.as_raw_fd();
        let run = TeardownRun::start(true);
        let n = run.report_fd().unwrap();
        assert!(n > highest, "{n} <= {highest}");
        assert!(highest_open_fd().unwrap() >= n);
    }

    #[test]
    fn the_pipe_leaves_no_descriptor_below_the_slot() {
        // Every report descriptor sits at or above N, so the numbers the
        // launch opens next are the ones it gets without the flag.
        let run = TeardownRun::start(true);
        let n = run.report_fd().unwrap();
        let RunState::Ready(pipe) = &run.state else {
            panic!("the pipe opened");
        };
        assert!(pipe.read.as_raw_fd() > n, "read end above N");
        assert!(pipe.write.as_raw_fd() > n, "write end above N");
        assert!(close_on_exec(pipe.read.as_raw_fd()));
        assert!(close_on_exec(pipe.write.as_raw_fd()));
    }

    #[test]
    fn finish_is_bounded_when_a_stray_child_holds_the_write_end() {
        // A child spawned in the inheritable window (the update check's curl)
        // keeps N open; the wrapper dies without writing. finish() must not
        // wait for that child.
        let mut run = TeardownRun::start(true);
        let n = run.report_fd().expect("a pipe opens");
        run.before_spawn().unwrap();
        // SAFETY: dup of a descriptor the run owns; closed at the end.
        let stray = unsafe { nix::libc::dup(n) };
        assert!(stray >= 0);
        run.after_spawn(true);
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(run.finish());
        });
        let section = rx
            .recv_timeout(std::time::Duration::from_secs(3))
            .expect("finish() returns although a stray writer stays open");
        assert!(
            matches!(&section, TeardownSection::Missing { reason } if reason.contains("timed out")),
            "{section:?}"
        );
        // SAFETY: closing the dup made above.
        unsafe { nix::libc::close(stray) };
    }

    fn ended(comm: &str, ended_by: EndedBy) -> Survivor {
        Survivor {
            pid: 7,
            ppid: 2,
            comm: comm.into(),
            age_s: 0,
            ended_by,
        }
    }

    #[test]
    fn stderr_line_counts_only_the_survivors_it_stopped() {
        let mixed = [
            ended("sleep", EndedBy::Sigterm),
            ended("ghost", EndedBy::AlreadyGone),
            ended("stuck", EndedBy::Sigkill),
        ];
        let line = stderr_line(&mixed).expect("two were stopped");
        assert!(line.starts_with("2 processes"), "{line}");
        assert!(line.contains("sleep") && line.contains("stuck"), "{line}");
        assert!(!line.contains("ghost"), "not stopped, not named: {line}");

        let gone = [ended("ghost", EndedBy::AlreadyGone)];
        assert_eq!(stderr_line(&gone), None, "nothing was stopped");
    }
}
