use nix::sys::signal::{
    self, SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal,
};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD_PID: AtomicI32 = AtomicI32::new(0);
static PENDING_SIGNAL: AtomicI32 = AtomicI32::new(0);
#[cfg(test)]
static INJECT_CANCEL_IN_SPAWN_WINDOW: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_child_pid(pid: i32) {
    CHILD_PID.store(pid, Ordering::SeqCst);
    let pending = PENDING_SIGNAL.load(Ordering::SeqCst);
    if pid > 0 && pending > 0 {
        unsafe {
            nix::libc::kill(pid, pending);
        }
    }
}

pub fn cancellation_signal() -> Option<i32> {
    let signal = PENDING_SIGNAL.load(Ordering::SeqCst);
    (signal > 0).then_some(signal)
}

pub fn abort_if_cancelled() -> Result<(), String> {
    cancellation_signal().map_or(Ok(()), |signal| {
        Err(format!(
            "Launch cancelled by signal {signal} before sandbox start"
        ))
    })
}

pub struct SupervisionGate {
    read: OwnedFd,
    write: OwnedFd,
}

struct HandledSignalMask {
    previous: SigSet,
    restored: bool,
}

impl HandledSignalMask {
    fn block() -> Result<Self, String> {
        let mut handled = SigSet::empty();
        handled.add(Signal::SIGINT);
        handled.add(Signal::SIGTERM);
        handled.add(Signal::SIGHUP);
        let mut previous = SigSet::empty();
        signal::pthread_sigmask(
            SigmaskHow::SIG_BLOCK,
            Some(&handled),
            Some(&mut previous),
        )
        .map_err(|e| format!("Cannot block launch signals: {e}"))?;
        Ok(Self {
            previous,
            restored: false,
        })
    }

    fn restore(&mut self) -> Result<(), String> {
        if !self.restored {
            signal::pthread_sigmask(
                SigmaskHow::SIG_SETMASK,
                Some(&self.previous),
                None,
            )
            .map_err(|e| format!("Cannot restore launch signal mask: {e}"))?;
            self.restored = true;
        }
        Ok(())
    }
}

impl Drop for HandledSignalMask {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub fn wrap_supervised_command(
    command: &mut Command,
) -> Result<SupervisionGate, String> {
    // The write end must not survive the exec into the supervisor, or the
    // sandboxed command inherits a stray writable descriptor. Only the read
    // end is handed to the supervisor, so only it has CLOEXEC cleared.
    let (read, write) = nix::unistd::pipe().map_err(|e| e.to_string())?;
    let write_flags =
        unsafe { nix::libc::fcntl(write.as_raw_fd(), nix::libc::F_GETFD) };
    if write_flags < 0
        || unsafe {
            nix::libc::fcntl(
                write.as_raw_fd(),
                nix::libc::F_SETFD,
                write_flags | nix::libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err("Cannot prepare supervised execution gate".into());
    }
    let flags =
        unsafe { nix::libc::fcntl(read.as_raw_fd(), nix::libc::F_GETFD) };
    if flags < 0
        || unsafe {
            nix::libc::fcntl(
                read.as_raw_fd(),
                nix::libc::F_SETFD,
                flags & !nix::libc::FD_CLOEXEC,
            )
        } < 0
    {
        return Err("Cannot prepare supervised execution gate".into());
    }

    let original =
        std::mem::replace(command, Command::new("/__ai_jail_invalid"));
    let executable = std::env::current_exe()
        .map_err(|e| format!("Cannot locate ai-jail supervisor: {e}"))?;
    let mut wrapper = Command::new(executable);
    wrapper
        .env_clear()
        .arg("--supervised-exec-fd")
        .arg(read.as_raw_fd().to_string())
        .arg("--")
        .arg(original.get_program())
        .args(original.get_args());
    for (name, value) in original.get_envs() {
        if let Some(value) = value {
            wrapper.env(name, value);
        }
    }
    if let Some(directory) = original.get_current_dir() {
        wrapper.current_dir(directory);
    }
    // Set this after copying the sandbox environment so an inherited or
    // explicitly supplied value cannot disable the internal gate.
    wrapper.env("AI_JAIL_SUPERVISED_EXEC", "1");
    *command = wrapper;
    Ok(SupervisionGate { read, write })
}

pub fn spawn_supervised(
    command: &mut Command,
    gate: SupervisionGate,
) -> Result<Child, String> {
    let mut mask = HandledSignalMask::block()?;
    abort_if_cancelled()?;
    let mut child = command
        .spawn()
        .map_err(|e| format!("Failed to start sandbox gate: {e}"))?;
    drop(gate.read);
    #[cfg(test)]
    if INJECT_CANCEL_IN_SPAWN_WINDOW.swap(false, Ordering::SeqCst) {
        // The signal is pending in the kernel until the mask is restored.
        // This exercises the real handler-delivery side of the registration
        // handoff, not merely the cancellation-state check below.
        unsafe {
            nix::libc::raise(nix::libc::SIGTERM);
        }
    }
    let pid = child.id() as i32;
    set_child_pid(pid);
    if let Err(error) = mask.restore() {
        drop(gate.write);
        let _ = child.kill();
        let _ = child.wait();
        clear_child_pid_if(pid);
        return Err(error);
    }
    if cancellation_signal().is_some() {
        drop(gate.write);
        let _ = child.wait();
        clear_child_pid_if(pid);
        return Err("Launch cancelled before sandbox command execution".into());
    }
    let byte = [1u8];
    let written = unsafe {
        nix::libc::write(
            gate.write.as_raw_fd(),
            byte.as_ptr().cast(),
            byte.len(),
        )
    };
    drop(gate.write);
    if written != 1 {
        let _ = child.kill();
        let _ = child.wait();
        clear_child_pid_if(pid);
        return Err("Cannot release supervised sandbox execution gate".into());
    }
    Ok(child)
}

pub fn run_supervised_exec(fd: i32, command: &[String]) -> Result<i32, String> {
    if std::env::var_os("AI_JAIL_SUPERVISED_EXEC").is_none() {
        return Err("--supervised-exec-fd is an internal mode".into());
    }
    if fd < 0 || command.is_empty() {
        return Err("Invalid supervised execution request".into());
    }
    let mut handled = SigSet::empty();
    handled.add(Signal::SIGINT);
    handled.add(Signal::SIGTERM);
    handled.add(Signal::SIGHUP);
    signal::pthread_sigmask(SigmaskHow::SIG_UNBLOCK, Some(&handled), None)
        .map_err(|e| format!("Cannot unblock supervised child signals: {e}"))?;
    let mut byte = [0u8; 1];
    let read = unsafe { nix::libc::read(fd, byte.as_mut_ptr().cast(), 1) };
    unsafe { nix::libc::close(fd) };
    if read != 1 || byte[0] != 1 {
        return Err("Supervised execution was cancelled".into());
    }
    let error = Command::new(&command[0])
        .args(&command[1..])
        .env_remove("AI_JAIL_SUPERVISED_EXEC")
        .exec();
    Err(format!("Cannot execute supervised sandbox: {error}"))
}

pub fn clear_child_pid_if(pid: i32) {
    let _ =
        CHILD_PID.compare_exchange(pid, 0, Ordering::SeqCst, Ordering::SeqCst);
}

extern "C" fn forward_signal(sig: nix::libc::c_int) {
    if sig == nix::libc::SIGWINCH {
        // PTY proxy: defer to IO loop which resizes vt100 first.
        // No PTY proxy: SIGWINCH reaches the child directly from
        // the kernel (we don't use --new-session for interactive
        // terminals, so the child shares the session).
        crate::pty::set_sigwinch_pending();
        return;
    }

    PENDING_SIGNAL.store(sig, Ordering::SeqCst);
    let pid = CHILD_PID.load(Ordering::SeqCst);
    if pid > 0 {
        unsafe {
            nix::libc::kill(pid, sig);
        }
    }
}

pub fn install_handlers() {
    let action = SigAction::new(
        SigHandler::Handler(forward_signal),
        SaFlags::SA_RESTART,
        SigSet::empty(),
    );

    // SIGWINCH must NOT use SA_RESTART so that poll() returns
    // EINTR immediately, allowing the IO loop to process the
    // resize without waiting for the poll timeout.
    let winch_action = SigAction::new(
        SigHandler::Handler(forward_signal),
        SaFlags::empty(),
        SigSet::empty(),
    );

    for sig in [Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
        unsafe {
            let _ = signal::sigaction(sig, &action);
        }
    }
    unsafe {
        let _ = signal::sigaction(Signal::SIGWINCH, &winch_action);
    }
}

pub fn wait_child(pid: i32) -> i32 {
    let pid = nix::unistd::Pid::from_raw(pid);
    loop {
        match waitpid(pid, Some(WaitPidFlag::empty())) {
            Ok(WaitStatus::Exited(_, code)) => return code,
            Ok(WaitStatus::Signaled(_, sig, _)) => return 128 + sig as i32,
            Ok(_) => continue,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(_) => return 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // CHILD_PID is process-global, so serialise the few tests that
    // mutate it. Otherwise parallel test execution can swap it under
    // each other and produce ghost failures.
    static PID_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn set_child_pid_round_trips() {
        let _guard = PID_LOCK.lock().unwrap();
        let saved = CHILD_PID.load(Ordering::SeqCst);
        set_child_pid(424242);
        assert_eq!(CHILD_PID.load(Ordering::SeqCst), 424242);
        set_child_pid(0);
        assert_eq!(CHILD_PID.load(Ordering::SeqCst), 0);
        CHILD_PID.store(saved, Ordering::SeqCst);
    }

    #[test]
    fn supervision_gate_write_end_does_not_survive_exec() {
        let mut command = Command::new("/usr/bin/true");
        let gate = wrap_supervised_command(&mut command).unwrap();
        let write_flags = unsafe {
            nix::libc::fcntl(gate.write.as_raw_fd(), nix::libc::F_GETFD)
        };
        assert!(write_flags >= 0);
        assert_ne!(
            write_flags & nix::libc::FD_CLOEXEC,
            0,
            "the gate write end would leak into the sandboxed command"
        );
        // The supervisor needs the read end after exec.
        let read_flags = unsafe {
            nix::libc::fcntl(gate.read.as_raw_fd(), nix::libc::F_GETFD)
        };
        assert!(read_flags >= 0);
        assert_eq!(read_flags & nix::libc::FD_CLOEXEC, 0);
    }

    #[test]
    fn clear_child_pid_only_clears_matching_supervised_process() {
        let _guard = PID_LOCK.lock().unwrap();
        let saved = CHILD_PID.load(Ordering::SeqCst);
        set_child_pid(424242);
        clear_child_pid_if(7);
        assert_eq!(CHILD_PID.load(Ordering::SeqCst), 424242);
        clear_child_pid_if(424242);
        assert_eq!(CHILD_PID.load(Ordering::SeqCst), 0);
        CHILD_PID.store(saved, Ordering::SeqCst);
    }

    #[test]
    fn install_handlers_does_not_panic() {
        // Best we can do from userland: the call has to succeed
        // without aborting the test binary. The actual handler-
        // installation is verified indirectly by every integration
        // test that runs through pty::run.
        install_handlers();
    }

    #[test]
    fn forward_signal_sigwinch_defers_to_pty() {
        // SIGWINCH must NOT call libc::kill — it should only set
        // the PTY's pending flag. We verify by clearing the flag,
        // calling the handler, then checking the flag flipped on.
        let _drain = crate::pty::take_sigwinch_pending_for_test();
        forward_signal(nix::libc::SIGWINCH);
        assert!(crate::pty::take_sigwinch_pending_for_test());
    }

    #[test]
    fn forward_signal_with_zero_child_pid_is_noop() {
        // CHILD_PID == 0 means there's nothing to forward to.
        // `libc::kill(0, sig)` would send to the entire process
        // group, which would terminate the test runner. Verify
        // the guard at line `if pid > 0` actually prevents the
        // kill by setting PID to zero and sending SIGTERM. If
        // the guard were missing the test process would die.
        let _guard = PID_LOCK.lock().unwrap();
        let saved = CHILD_PID.load(Ordering::SeqCst);
        let saved_pending = PENDING_SIGNAL.load(Ordering::SeqCst);
        PENDING_SIGNAL.store(0, Ordering::SeqCst);
        CHILD_PID.store(0, Ordering::SeqCst);
        forward_signal(nix::libc::SIGTERM);
        // If we got here, the guard works.
        CHILD_PID.store(saved, Ordering::SeqCst);
        PENDING_SIGNAL.store(saved_pending, Ordering::SeqCst);
    }

    #[test]
    fn sigterm_is_forwarded_to_the_supervised_startup_process() {
        use std::process::{Command, Stdio};

        let _guard = PID_LOCK.lock().unwrap();
        let saved = CHILD_PID.load(Ordering::SeqCst);
        let saved_pending = PENDING_SIGNAL.load(Ordering::SeqCst);
        PENDING_SIGNAL.store(0, Ordering::SeqCst);
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        set_child_pid(child.id() as i32);
        forward_signal(nix::libc::SIGTERM);
        let status = child.wait().unwrap();
        assert!(!status.success());
        clear_child_pid_if(child.id() as i32);
        CHILD_PID.store(saved, Ordering::SeqCst);
        PENDING_SIGNAL.store(saved_pending, Ordering::SeqCst);
    }

    #[test]
    fn pending_signal_is_forwarded_when_a_child_registers_late() {
        use std::process::{Command, Stdio};

        let _guard = PID_LOCK.lock().unwrap();
        let saved = CHILD_PID.load(Ordering::SeqCst);
        let saved_pending = PENDING_SIGNAL.load(Ordering::SeqCst);
        CHILD_PID.store(0, Ordering::SeqCst);
        PENDING_SIGNAL.store(nix::libc::SIGTERM, Ordering::SeqCst);
        let mut child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        set_child_pid(child.id() as i32);
        assert!(!child.wait().unwrap().success());
        clear_child_pid_if(child.id() as i32);
        CHILD_PID.store(saved, Ordering::SeqCst);
        PENDING_SIGNAL.store(saved_pending, Ordering::SeqCst);
    }

    #[test]
    fn pending_cancellation_prevents_the_sandbox_spawn_seam() {
        let _guard = PID_LOCK.lock().unwrap();
        let saved_pending = PENDING_SIGNAL.load(Ordering::SeqCst);
        PENDING_SIGNAL.store(nix::libc::SIGINT, Ordering::SeqCst);
        let mut executed = false;
        if abort_if_cancelled().is_ok() {
            executed = true;
        }
        assert!(!executed, "sandbox spawn seam must remain unreachable");
        PENDING_SIGNAL.store(saved_pending, Ordering::SeqCst);
    }

    #[test]
    fn signal_in_spawn_registration_window_never_executes_child() {
        let _guard = PID_LOCK.lock().unwrap();
        let saved = CHILD_PID.load(Ordering::SeqCst);
        let saved_pending = PENDING_SIGNAL.load(Ordering::SeqCst);
        CHILD_PID.store(0, Ordering::SeqCst);
        PENDING_SIGNAL.store(0, Ordering::SeqCst);
        install_handlers();
        let root = std::env::temp_dir()
            .join(format!("ai-jail-spawn-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir(&root).unwrap();
        let canary = root.join("executed");
        let (read, write) = nix::unistd::pipe().unwrap();
        let flags =
            unsafe { nix::libc::fcntl(read.as_raw_fd(), nix::libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe {
                nix::libc::fcntl(
                    read.as_raw_fd(),
                    nix::libc::F_SETFD,
                    flags & !nix::libc::FD_CLOEXEC,
                )
            },
            0
        );
        let supervisor = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("ai-jail");
        let mut command = Command::new(supervisor);
        command
            .env("AI_JAIL_SUPERVISED_EXEC", "1")
            .arg("--supervised-exec-fd")
            .arg(read.as_raw_fd().to_string())
            .arg("--")
            .arg("/bin/sh")
            .args(["-c", &format!("printf executed > '{}'", canary.display())]);
        let gate = SupervisionGate { read, write };
        INJECT_CANCEL_IN_SPAWN_WINDOW.store(true, Ordering::SeqCst);
        let error = spawn_supervised(&mut command, gate).unwrap_err();
        assert!(error.contains("cancelled"));
        assert!(!canary.exists(), "gated child command must not execute");
        assert_eq!(CHILD_PID.load(Ordering::SeqCst), 0);
        std::fs::remove_dir_all(root).unwrap();
        CHILD_PID.store(saved, Ordering::SeqCst);
        PENDING_SIGNAL.store(saved_pending, Ordering::SeqCst);
    }
}
