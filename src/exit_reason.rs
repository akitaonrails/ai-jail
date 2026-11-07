// How a run ended, in structured form.
//
// A pure function of the wait status and the limits ai-jail put in
// force, so every rule is unit-testable without a sandbox. The stderr
// line is built from this structure rather than from the raw status.
//
// The exit code is never derived from the reason: `code` is the plain
// wait-status mapping (the exit code, or `128 + signal`), so scripts that
// branch on it see the same code whether or not a line is printed.

use nix::sys::resource::{Resource, getrlimit};
use nix::sys::signal::Signal;

// Signal numbers come from nix (libc), not literals, so the table holds
// on both Linux and macOS.
const SIGKILL: i32 = Signal::SIGKILL as i32;
const SIGXCPU: i32 = Signal::SIGXCPU as i32;
const SIGXFSZ: i32 = Signal::SIGXFSZ as i32;

/// Signals a user or a harness sends on purpose; a death by one of them
/// needs no explanation unless a limit explains it.
const DELIBERATE: [Signal; 4] = [
    Signal::SIGHUP,
    Signal::SIGINT,
    Signal::SIGPIPE,
    Signal::SIGTERM,
];

/// Where the "128 + N" window starts: bwrap folds a child's signal death
/// into an ordinary exit `128 + sig` (measured: `kill -9` exits 137).
const SIGNAL_EXIT_BASE: i32 = 128;
const SIGNAL_EXIT_LAST: i32 = SIGNAL_EXIT_BASE + 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    Exited(i32),
    Signaled { signal: i32, core: bool },
}

/// How the status was learned: an exit code taken as it is, a 128+N
/// decode of an exit code, or `waitpid` itself seeing a signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusSource {
    ExitCode,
    Inferred,
    Direct,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChildStatus {
    pub termination: Termination,
    pub source: StatusSource,
}

/// What the host does to a child's end. Only bwrap folds a child's
/// signal death into an exit code `128 + N`, and only Linux has the
/// kernel log `journalctl -k` reads; it is passed in, rather than read
/// from `cfg` here, so both kinds of host are testable on either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostTraits {
    pub folds_signals: bool,
    pub kernel_log_hint: bool,
}

impl HostTraits {
    pub const CURRENT: HostTraits = HostTraits {
        folds_signals: cfg!(target_os = "linux"),
        kernel_log_hint: cfg!(target_os = "linux"),
    };
}

impl ChildStatus {
    /// The code `main` returns for this end: the exit code, or `128 + sig`
    /// for a signal. An inferred signal maps back to the very `128 + sig`
    /// it was decoded from.
    pub fn exit_code(&self) -> i32 {
        match self.termination {
            Termination::Exited(c) => c,
            Termination::Signaled { signal, .. } => SIGNAL_EXIT_BASE + signal,
        }
    }
}

/// The limit values in force for this run, as read back from the
/// kernel. `None` means ai-jail set none (or failed to), so no value may
/// be claimed for it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LimitsInForce {
    pub file_size: Option<u64>,
}

impl LimitsInForce {
    /// Called after `sandbox::rlimits::apply`, with what it returned.
    /// The value is the soft RLIMIT_FSIZE this process now holds: apply
    /// clamps the lockdown value to the parent's hard limit, so the
    /// constant it asked for is not necessarily the one in force.
    pub fn read_back(file_size_set: bool) -> Self {
        let file_size = if file_size_set {
            getrlimit(Resource::RLIMIT_FSIZE)
                .ok()
                .map(|(soft, _)| soft)
                .filter(|&soft| soft != nix::sys::resource::RLIM_INFINITY)
        } else {
            None
        };
        LimitsInForce { file_size }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Limit {
    CpuTime,
    FileSize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonKind {
    Exited,
    Signaled,
    Limit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExitReason {
    pub code: i32,
    pub signal: Option<i32>,
    pub core_dumped: bool,
    pub kind: ReasonKind,
    pub limit: Option<Limit>,
    pub evidence: Option<String>,
    pub source: StatusSource,
}

/// Decode 129..=192 as `128 + signal`, marked inferred, where the host
/// folds signals: on Linux every status passes through bwrap, which
/// reports a child's signal death that way. Anything else, and every
/// code on a host that does not fold, is an ordinary exit code.
pub fn from_exit_code(code: i32, host: HostTraits) -> ChildStatus {
    let window = (SIGNAL_EXIT_BASE + 1)..=SIGNAL_EXIT_LAST;
    if host.folds_signals && window.contains(&code) {
        ChildStatus {
            termination: Termination::Signaled {
                signal: code - SIGNAL_EXIT_BASE,
                core: false,
            },
            source: StatusSource::Inferred,
        }
    } else {
        ChildStatus {
            termination: Termination::Exited(code),
            source: StatusSource::ExitCode,
        }
    }
}

/// Apply the rules in order: SIGXCPU, SIGXFSZ, SIGKILL, then every
/// other signal.
pub fn classify(status: &ChildStatus, limits: &LimitsInForce) -> ExitReason {
    let (signal, core) = match status.termination {
        Termination::Exited(_) => (None, false),
        Termination::Signaled { signal, core } => (Some(signal), core),
    };
    let (kind, limit, evidence) = signal_reason(signal, limits);
    ExitReason {
        code: status.exit_code(),
        signal,
        core_dumped: core,
        kind,
        limit,
        evidence,
        source: status.source,
    }
}

impl ExitReason {
    /// The one stderr line, or `None` when there is nothing to say: a
    /// normal exit, or a deliberate signal no limit explains.
    pub fn explanation(&self, host: HostTraits) -> Option<String> {
        if self.kind == ReasonKind::Exited || self.is_deliberate_signal() {
            return None;
        }
        let killed_by =
            self.signal.map(|s| format!("killed by {}", signal_name(s)));
        let mut detail = match (killed_by, self.evidence.as_deref()) {
            (Some(k), Some(e)) => format!("{k}: {e}"),
            (Some(k), None) => k,
            (None, Some(e)) => e.to_string(),
            (None, None) => return None,
        };
        // Where to look for the OOM killer is host-specific, so it is
        // added here and kept out of the evidence text.
        if host.kernel_log_hint && self.is_unattributed_sigkill() {
            detail.push_str(" (`journalctl -k | grep -i oom`)");
        }
        let core = if self.core_dumped {
            " (core dumped)"
        } else {
            ""
        };
        // A decoded exit code may also be a command that simply exited
        // with 128+N, so the line says which code it was read from.
        let inferred = if self.source == StatusSource::Inferred {
            format!(" (inferred from exit code {})", self.code)
        } else {
            String::new()
        };
        Some(format!(
            "sandbox exited with {}: {detail}{core}{inferred}",
            self.code
        ))
    }

    fn is_unattributed_sigkill(&self) -> bool {
        self.limit.is_none() && self.signal == Some(SIGKILL)
    }

    /// A signal a limit explains is never silenced, whatever it is.
    fn is_deliberate_signal(&self) -> bool {
        self.limit.is_none()
            && self
                .signal
                .is_some_and(|n| DELIBERATE.iter().any(|s| *s as i32 == n))
    }
}

fn signal_reason(
    signal: Option<i32>,
    limits: &LimitsInForce,
) -> (ReasonKind, Option<Limit>, Option<String>) {
    let Some(sig) = signal else {
        return (ReasonKind::Exited, None, None);
    };
    match sig {
        SIGXCPU => {
            // ai-jail sets no CPU-time rlimit, so the limit came from
            // outside; say so rather than imply it was ai-jail's.
            let evidence = "a CPU-time rlimit was reached; ai-jail set none, \
                            so it came from the parent environment or the \
                            command itself";
            (
                ReasonKind::Limit,
                Some(Limit::CpuTime),
                Some(evidence.into()),
            )
        }
        SIGXFSZ => {
            // Never claim a value that is not in force.
            let evidence = match limits.file_size {
                Some(b) => format!(
                    "the file-size rlimit was reached ({})",
                    human_bytes(b)
                ),
                None => "a file-size rlimit was reached; ai-jail set none, \
                         so it came from the parent environment or the \
                         command itself"
                    .into(),
            };
            (ReasonKind::Limit, Some(Limit::FileSize), Some(evidence))
        }
        SIGKILL => {
            let evidence = "ai-jail cannot attribute it to one of its \
                            limits; the usual cause is the host OOM killer";
            (ReasonKind::Signaled, None, Some(evidence.into()))
        }
        _ => (ReasonKind::Signaled, None, None),
    }
}

/// An unknown number becomes `signal N`, never a panic.
fn signal_name(sig: i32) -> String {
    Signal::try_from(sig)
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|_| format!("signal {sig}"))
}

/// Binary units with one decimal, the way the verbose rlimit lines
/// would read them.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    // The rules table is exercised in one order: for each rule, the case
    // where it would fire WRONGLY comes before the case where it holds.

    use super::*;

    const GIB: u64 = 1 << 30;

    /// The host every case outside the host-traits section describes: bwrap
    /// folds signals and the kernel log exists. Spelled out, not taken from
    /// `CURRENT`, so the cases hold on a macOS test run too.
    const LINUX: HostTraits = HostTraits {
        folds_signals: true,
        kernel_log_hint: true,
    };

    fn no_limits() -> LimitsInForce {
        LimitsInForce::default()
    }

    fn signaled(signal: i32, source: StatusSource) -> ChildStatus {
        ChildStatus {
            termination: Termination::Signaled {
                signal,
                core: false,
            },
            source,
        }
    }

    fn exited(code: i32) -> ChildStatus {
        ChildStatus {
            termination: Termination::Exited(code),
            source: StatusSource::ExitCode,
        }
    }

    fn mentions_one_gib(s: &str) -> bool {
        s.contains("1 GiB") || s.contains("1.0 GiB") || s.contains("1073741824")
    }

    // ── from_exit_code ──────────────────────────────────────

    #[test]
    fn from_exit_code_decodes_only_129_to_192() {
        // The codes right outside the window must NOT be decoded as signals.
        for code in [0, 1, 127, 128, 193, 255] {
            let status = from_exit_code(code, LINUX);
            assert!(
                matches!(status.termination, Termination::Exited(c) if c == code),
                "code {code} must stay an exit code"
            );
        }
        // Then the window itself, both ends included.
        for (code, sig) in [(129, 1), (137, 9), (152, 24), (153, 25), (192, 64)]
        {
            let status = from_exit_code(code, LINUX);
            assert!(
                matches!(
                    status.termination,
                    Termination::Signaled { signal, core: false } if signal == sig
                ),
                "code {code} must decode to signal {sig}"
            );
            assert!(
                matches!(status.source, StatusSource::Inferred),
                "a 128+N decode is inferred, never reported (code {code})"
            );
        }
    }

    #[test]
    fn plain_exit_code_is_marked_exit_code() {
        // The variant is read through its Debug name so this case compiles
        // on every branch, before and after the rename; the summary's
        // `exit-code` string is pinned where it is written (run_summary).
        fn source_name(status: &ChildStatus) -> String {
            format!("{:?}", status.source)
        }
        const NO_FOLDING: HostTraits = HostTraits {
            folds_signals: false,
            kernel_log_hint: false,
        };
        // Where the mark would fire wrongly: a code a folding host decodes
        // is a 128+N inference, never a code taken as it is.
        for code in [129, 137, 192] {
            let status = from_exit_code(code, LINUX);
            assert!(
                matches!(status.source, StatusSource::Inferred),
                "code {code} on a folding host is decoded, not taken as it is"
            );
        }
        // The converse: on a host that does not fold, the same window is a
        // plain exit code, and so is every code around it.
        for code in [0, 1, 128, 129, 137, 192, 193, 255] {
            let status = from_exit_code(code, NO_FOLDING);
            assert_eq!(
                status.termination,
                Termination::Exited(code),
                "code {code} stays an exit code without folding"
            );
            assert_eq!(
                source_name(&status),
                "ExitCode",
                "code {code} without folding is taken as it is"
            );
        }
        // Then the codes outside the window on a folding host.
        for code in [0, 1, 127, 128, 193, 255] {
            let status = from_exit_code(code, LINUX);
            assert_eq!(
                status.termination,
                Termination::Exited(code),
                "code {code} stays an exit code"
            );
            assert_eq!(
                source_name(&status),
                "ExitCode",
                "code {code} outside the window is taken as it is"
            );
        }
    }

    // ── silence: the case that must stay silent first ─────────────

    #[test]
    fn deliberate_signals_and_normal_exits_are_silent() {
        for sig in [1, 2, 13, 15] {
            let r =
                classify(&signaled(sig, StatusSource::Direct), &no_limits());
            assert!(
                r.explanation(LINUX).is_none(),
                "deliberate signal {sig} must print nothing: {:?}",
                r.explanation(LINUX)
            );
            assert!(r.limit.is_none(), "signal {sig} names no limit");
            assert!(matches!(r.kind, ReasonKind::Signaled));
            assert_eq!(r.code, 128 + sig, "code unchanged");
        }
        for code in [0, 1, 3] {
            let r = classify(&exited(code), &no_limits());
            assert!(
                r.explanation(LINUX).is_none(),
                "exit {code} prints nothing"
            );
            assert!(matches!(r.kind, ReasonKind::Exited));
            assert_eq!(r.code, code);
        }
    }

    #[test]
    fn an_unexplained_signal_is_named() {
        // any other signal end prints one line naming the signal.
        let r = classify(&signaled(11, StatusSource::Direct), &no_limits());
        let line = r.explanation(LINUX).expect("SIGSEGV must be explained");
        assert!(line.contains("SIGSEGV"), "{line}");
        assert!(!line.contains('\n'), "one line: {line:?}");
        assert!(r.limit.is_none());
        assert_eq!(r.code, 139);
    }

    #[test]
    fn an_unknown_signal_number_does_not_panic() {
        let r = classify(&signaled(99, StatusSource::Direct), &no_limits());
        let line = r
            .explanation(LINUX)
            .expect("an unknown signal is still a signal");
        assert!(line.contains("99"), "{line}");
    }

    // ── unattributed SIGKILL ────────────────────────────────

    #[test]
    fn unattributed_sigkill_points_at_the_host_oom_killer() {
        let bare = classify(&signaled(9, StatusSource::Inferred), &no_limits());
        assert!(bare.limit.is_none());
        assert!(matches!(bare.kind, ReasonKind::Signaled));
        let line = bare.explanation(LINUX).expect("explained");
        assert!(line.contains("SIGKILL"), "{line}");
        assert!(line.to_lowercase().contains("oom"), "host OOM hint: {line}");
        assert!(!line.contains('\n'), "one line: {line:?}");
    }

    // ── what the host folds and logs ────────────────────────
    //
    // The platform enters as a value, so both kinds of host are tested
    // here on Linux. Only bwrap folds a child's signal death into an exit
    // code `128 + N`, and only Linux has the kernel log `journalctl -k`
    // reads. Each trait is varied alone, the other taken from CURRENT.

    #[test]
    fn exit_code_in_the_signal_window_stays_an_exit_code_without_folded_signals()
     {
        // Where nothing folds signals, 137 is a command that exited 137:
        // decoding it would invent a SIGKILL, and an OOM hint, for a plain
        // exit.
        const NO_FOLDING: HostTraits = HostTraits {
            folds_signals: false,
            ..HostTraits::CURRENT
        };
        for code in [129, 137, 143, 153, 161, 192] {
            let status = from_exit_code(code, NO_FOLDING);
            assert_eq!(
                status.termination,
                Termination::Exited(code),
                "code {code} must stay an exit code"
            );
            assert_eq!(
                status.source,
                StatusSource::ExitCode,
                "code {code} is taken as it is, never inferred"
            );
            assert_eq!(status.exit_code(), code, "code unchanged");
            let r = classify(&status, &no_limits());
            assert!(matches!(r.kind, ReasonKind::Exited), "code {code}: {r:?}");
            assert_eq!(r.signal, None, "code {code} names no signal");
            assert_eq!(
                r.explanation(NO_FOLDING),
                None,
                "an exit code prints nothing (code {code})"
            );
        }
    }

    #[test]
    fn exit_code_137_still_decodes_to_sigkill_where_signals_fold() {
        // Switching the decode off elsewhere must not switch it off where
        // bwrap folds the signal into the code.
        const FOLDING: HostTraits = HostTraits {
            folds_signals: true,
            ..HostTraits::CURRENT
        };
        for (code, signal) in [(137, SIGKILL), (161, 33)] {
            let status = from_exit_code(code, FOLDING);
            assert_eq!(
                status.termination,
                Termination::Signaled {
                    signal,
                    core: false,
                },
                "code {code} is 128 + {signal}"
            );
            assert_eq!(
                status.source,
                StatusSource::Inferred,
                "a decode is inferred (code {code})"
            );
            assert_eq!(status.exit_code(), code, "code unchanged");
        }
        let r = classify(&from_exit_code(137, FOLDING), &no_limits());
        assert!(matches!(r.kind, ReasonKind::Signaled), "{r:?}");
        assert_eq!(r.signal, Some(SIGKILL));
        let line = r
            .explanation(FOLDING)
            .expect("a decoded SIGKILL is explained");
        assert!(line.contains("SIGKILL"), "{line}");
        assert!(line.contains("(inferred from exit code 137)"), "{line}");
        // And the host these tests run on is one that folds.
        assert_eq!(
            HostTraits::CURRENT.folds_signals,
            cfg!(target_os = "linux"),
            "signals fold on Linux, and only there"
        );
    }

    #[test]
    fn sigkill_explanation_omits_the_kernel_log_hint_when_the_host_has_none() {
        // Without a kernel log the hint names a command that is not there.
        // The pointer at the host OOM killer stays: it holds on every host.
        const NO_KERNEL_LOG: HostTraits = HostTraits {
            kernel_log_hint: false,
            ..HostTraits::CURRENT
        };
        const KERNEL_LOG: HostTraits = HostTraits {
            kernel_log_hint: true,
            ..HostTraits::CURRENT
        };
        let r =
            classify(&signaled(SIGKILL, StatusSource::Direct), &no_limits());
        let line = r
            .explanation(NO_KERNEL_LOG)
            .expect("an unattributed SIGKILL is still explained");
        assert!(!line.contains("journalctl"), "no kernel-log hint: {line}");
        assert!(line.contains("SIGKILL"), "{line}");
        assert!(
            line.to_lowercase().contains("oom"),
            "host OOM pointer kept: {line}"
        );
        assert!(!line.contains('\n'), "one line: {line:?}");
        // Where the host has the log, the hint stays.
        let line = r.explanation(KERNEL_LOG).expect("explained");
        assert!(line.contains("journalctl"), "kernel-log hint: {line}");
        assert_eq!(
            HostTraits::CURRENT.kernel_log_hint,
            cfg!(target_os = "linux"),
            "the kernel-log hint is Linux's, and only Linux's"
        );
    }

    // ── claim only what is known ──────────────────────────────────
    //
    // The cases below are written against the interface where the reason
    // is a function of the status and the limits read back from the kernel.
    // `reason_of` is the one place that spells the `classify` call.

    const MIB_512: u64 = 512 << 20;

    fn reason_of(status: &ChildStatus, limits: &LimitsInForce) -> ExitReason {
        classify(status, limits)
    }

    fn mentions_512_mib(s: &str) -> bool {
        s.contains("512 MiB")
            || s.contains("512.0 MiB")
            || s.contains("536870912")
    }

    /// A byte value of any size, as the explanation would print one.
    fn mentions_a_byte_value(s: &str) -> bool {
        [
            " B)",
            " B,",
            "KiB",
            "MiB",
            "GiB",
            "TiB",
            "18446744073709551615",
        ]
        .iter()
        .any(|unit| s.contains(unit))
    }

    /// Re-run one `#[ignore]`d case of this module in a child test process,
    /// so the rlimits it sets (a lowered hard limit cannot be raised again)
    /// never reach the rest of the suite.
    fn run_rlimit_child(case: &str) {
        let output = std::process::Command::new(
            std::env::current_exe().expect("current test binary"),
        )
        .arg("--exact")
        .arg(format!("exit_reason::tests::{case}"))
        .arg("--ignored")
        .env("AI_JAIL_FSIZE_CHILD", "1")
        .output()
        .expect("spawn child rlimit test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "child {case} failed\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("1 passed"),
            "child {case} did not run\nstdout:\n{stdout}"
        );
    }

    /// The kernel's own account of how `pid` ended, read without reaping it
    /// (`WNOWAIT`), so the code under test still reaps it afterwards.
    #[cfg(target_os = "linux")]
    fn peek_end(pid: i32) -> nix::sys::wait::WaitStatus {
        use nix::sys::wait::{Id, WaitPidFlag, waitid};
        let pid = nix::unistd::Pid::from_raw(pid);
        loop {
            match waitid(
                Id::Pid(pid),
                WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT,
            ) {
                Err(nix::errno::Errno::EINTR) => continue,
                other => return other.expect("waitid"),
            }
        }
    }

    /// Start `sh -c <script>` and return its pid. The case reaps it through
    /// the code under test (`wait_child_status`), never through `Child`.
    #[cfg(target_os = "linux")]
    fn spawn_sh(script: &str) -> i32 {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .current_dir(std::env::temp_dir())
            .spawn()
            .map(|child| child.id() as i32)
            .expect("spawn sh")
    }

    #[cfg(target_os = "linux")]
    fn signal_child(pid: i32, signal: Signal) {
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), signal)
            .expect("kill");
    }

    #[test]
    fn exit_code_round_trips_for_every_code() {
        // Every exit code a process can return comes back unchanged, the
        // 129..=192 window decoded as a signal included, and the reason never
        // rewrites it.
        for code in 0..=255 {
            let status = from_exit_code(code, LINUX);
            assert_eq!(
                status.exit_code(),
                code,
                "exit code {code} must come back unchanged"
            );
            let reason = reason_of(&status, &LimitsInForce::default());
            assert_eq!(reason.code, code, "the reason never changes the code");
        }
        // A signal waitpid saw itself maps to 128 + N, as before.
        for signal in 1..=64 {
            let status = signaled(signal, StatusSource::Direct);
            assert_eq!(status.exit_code(), 128 + signal, "signal {signal}");
            let reason = reason_of(&status, &LimitsInForce::default());
            assert_eq!(reason.code, 128 + signal, "signal {signal}");
        }
    }

    // `waitid` (for the WNOWAIT peek) is not in nix on macOS.
    #[cfg(target_os = "linux")]
    #[test]
    fn direct_status_reports_signal_and_core() {
        use crate::signals::wait_child_status;
        use nix::sys::wait::WaitStatus;

        // An ordinary `exit 143` has the code a SIGTERM death has, and must not
        // be reported as a signal waitpid saw.
        let pid = spawn_sh("exit 143");
        let status = wait_child_status(pid);
        assert_eq!(
            status.source,
            StatusSource::Inferred,
            "an exit code is decoded, never seen: {status:?}"
        );
        assert_eq!(status.exit_code(), 143);

        // A real SIGTERM death, by contrast, is `Direct`, with the same code.
        let pid = spawn_sh("exec sleep 30");
        signal_child(pid, Signal::SIGTERM);
        let status = wait_child_status(pid);
        assert_eq!(status.source, StatusSource::Direct, "{status:?}");
        assert_eq!(
            status.termination,
            Termination::Signaled {
                signal: Signal::SIGTERM as i32,
                core: false,
            }
        );
        assert_eq!(status.exit_code(), 143);

        // A core-capable signal: the core flag is the kernel's, whichever way
        // this host's core_pattern decides it.
        let pid = spawn_sh("ulimit -c 0; exec sleep 30");
        signal_child(pid, Signal::SIGSEGV);
        let kernel_core = match peek_end(pid) {
            WaitStatus::Signaled(_, Signal::SIGSEGV, core) => core,
            other => panic!("expected a SIGSEGV death, got {other:?}"),
        };
        let status = wait_child_status(pid);
        assert_eq!(status.source, StatusSource::Direct, "{status:?}");
        assert_eq!(
            status.termination,
            Termination::Signaled {
                signal: Signal::SIGSEGV as i32,
                core: kernel_core,
            }
        );
        let line = reason_of(&status, &LimitsInForce::default())
            .explanation(LINUX)
            .expect("a SIGSEGV death is explained");
        assert!(line.contains("SIGSEGV"), "{line}");
        assert_eq!(
            line.contains("core dumped"),
            kernel_core,
            "the line reports the core flag waitpid saw: {line}"
        );
        assert!(!line.contains("inferred"), "seen, not inferred: {line}");
    }

    #[test]
    fn inferred_reason_names_the_exit_code() {
        // A signal waitpid saw is a fact, and must not be qualified as
        // inferred.
        let direct = signaled(11, StatusSource::Direct);
        let r = reason_of(&direct, &LimitsInForce::default());
        let line = r.explanation(LINUX).expect("SIGSEGV is explained");
        assert!(!line.contains("inferred"), "{line}");
        // A deliberate signal stays silent when decoded too: the qualifier
        // never makes a silent end speak.
        for code in [129, 130, 141, 143] {
            let r = reason_of(
                &from_exit_code(code, LINUX),
                &LimitsInForce::default(),
            );
            assert_eq!(r.explanation(LINUX), None, "exit code {code}");
        }
        // Every decoded line says so, with the code it was decoded from (not
        // the signal number), whether or not it carries evidence.
        for (code, signal) in
            [(139, "SIGSEGV"), (137, "SIGKILL"), (153, "SIGXFSZ")]
        {
            let r = reason_of(
                &from_exit_code(code, LINUX),
                &LimitsInForce::default(),
            );
            let line =
                r.explanation(LINUX).expect("a decoded signal is explained");
            assert!(line.contains(signal), "{line}");
            let qualifier = format!("(inferred from exit code {code})");
            assert_eq!(
                line.matches(&qualifier).count(),
                1,
                "exactly one {qualifier}: {line}"
            );
            assert!(!line.contains('\n'), "one line: {line:?}");
        }
    }

    #[test]
    fn file_size_named_without_value_when_the_set_failed() {
        // Whatever FSIZE this process holds, a set that failed leaves no value
        // ai-jail may claim.
        let limits = LimitsInForce::read_back(false);
        assert_eq!(limits.file_size, None, "a failed set has no value");

        let r = reason_of(&signaled(25, StatusSource::Direct), &limits);
        assert!(matches!(r.limit, Some(Limit::FileSize)), "{r:?}");
        let line = r.explanation(LINUX).expect("SIGXFSZ is explained");
        assert!(line.contains("SIGXFSZ"), "{line}");
        assert!(line.contains("file-size"), "the limit is named: {line}");
        assert!(!mentions_a_byte_value(&line), "no value: {line}");
    }

    #[test]
    fn file_size_value_is_the_one_read_back() {
        // A parent hard limit below 1 GiB clamps the lockdown value, and the
        // line must report the clamped one.
        run_rlimit_child("file_size_read_back_child_clamped");
        // Then the plain lockdown run: the value is what the kernel holds.
        run_rlimit_child("file_size_read_back_child_unclamped");
    }

    #[test]
    #[ignore]
    fn file_size_read_back_child_clamped() {
        use nix::sys::resource::{Resource, getrlimit, setrlimit};
        if std::env::var_os("AI_JAIL_FSIZE_CHILD").is_none() {
            return;
        }
        let (_, hard_before) =
            getrlimit(Resource::RLIMIT_FSIZE).expect("getrlimit");
        let clamp = MIB_512.min(hard_before);
        setrlimit(Resource::RLIMIT_FSIZE, clamp, clamp).expect("lower FSIZE");

        let lockdown = crate::config::Config {
            lockdown: Some(true),
            ..crate::config::Config::default()
        };
        crate::sandbox::rlimits::apply(&lockdown, false);
        let limits = LimitsInForce::read_back(true);
        assert_eq!(
            limits.file_size,
            Some(clamp),
            "the value in force, not the lockdown default"
        );

        let line = reason_of(&signaled(25, StatusSource::Direct), &limits)
            .explanation(LINUX)
            .expect("SIGXFSZ is explained");
        assert!(!mentions_one_gib(&line), "clamped below 1 GiB: {line}");
        if clamp == MIB_512 {
            assert!(mentions_512_mib(&line), "the clamped value: {line}");
        }
    }

    #[test]
    #[ignore]
    fn file_size_read_back_child_unclamped() {
        use nix::sys::resource::{Resource, getrlimit};
        if std::env::var_os("AI_JAIL_FSIZE_CHILD").is_none() {
            return;
        }
        let (_, hard_before) =
            getrlimit(Resource::RLIMIT_FSIZE).expect("getrlimit");

        let lockdown = crate::config::Config {
            lockdown: Some(true),
            ..crate::config::Config::default()
        };
        crate::sandbox::rlimits::apply(&lockdown, false);
        let limits = LimitsInForce::read_back(true);
        let (soft_after, _) =
            getrlimit(Resource::RLIMIT_FSIZE).expect("getrlimit");
        assert_eq!(
            limits.file_size,
            Some(soft_after),
            "read back, not assumed"
        );
        assert_eq!(limits.file_size, Some(GIB.min(hard_before)));

        let line = reason_of(&signaled(25, StatusSource::Direct), &limits)
            .explanation(LINUX)
            .expect("SIGXFSZ is explained");
        if hard_before >= GIB {
            assert!(mentions_one_gib(&line), "the lockdown value: {line}");
        }
    }
}
