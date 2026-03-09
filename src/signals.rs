use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use std::sync::atomic::{AtomicI32, Ordering};

static CHILD_PID: AtomicI32 = AtomicI32::new(0);

pub fn set_child_pid(pid: i32) {
    CHILD_PID.store(pid, Ordering::SeqCst);
}

extern "C" fn forward_signal(sig: nix::libc::c_int) {
    if sig == nix::libc::SIGWINCH {
        // Resize the PTY immediately (async-signal-safe ioctl).
        crate::pty::resize_pty();
        // Don't forward SIGWINCH to the child yet — the IO loop
        // will do it AFTER clearing the screen and re-establishing
        // the scroll region, so the child redraws onto a clean
        // canvas.
        crate::statusbar::request_redraw(true, true);
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

    for sig in [
        Signal::SIGINT,
        Signal::SIGTERM,
        Signal::SIGHUP,
        Signal::SIGWINCH,
    ] {
        unsafe {
            let _ = signal::sigaction(sig, &action);
        }
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
