use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

pub fn set_child_pid(pid: i32) {
    CHILD_PID.store(pid, Ordering::SeqCst);
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
        CHILD_PID.store(0, Ordering::SeqCst);
        forward_signal(nix::libc::SIGTERM);
        // If we got here, the guard works.
        CHILD_PID.store(saved, Ordering::SeqCst);
    }
}
