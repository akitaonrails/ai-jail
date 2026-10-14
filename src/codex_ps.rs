//! Minimal `ps` compatibility for Codex's macOS app-server manager.
//!
//! `/bin/ps` is setuid on macOS, so Seatbelt refuses to execute it even when
//! the caller is allowed to inspect processes in the same sandbox. Codex uses
//! `ps -p PID -o stat= -o lstart=` to validate the PID it just started. This
//! helper implements only that query and reads no command lines or host
//! process data.

use std::ffi::{OsStr, c_char, c_int, c_void};
use std::path::Path;

const PROC_PIDTBSDINFO: c_int = 3;
const MAXCOMLEN: usize = 16;

#[repr(C)]
struct ProcBsdInfo {
    flags: u32,
    status: u32,
    xstatus: u32,
    pid: u32,
    ppid: u32,
    uid: u32,
    gid: u32,
    ruid: u32,
    rgid: u32,
    svuid: u32,
    svgid: u32,
    reserved: u32,
    comm: [c_char; MAXCOMLEN],
    name: [c_char; MAXCOMLEN * 2],
    nfiles: u32,
    pgid: u32,
    pjobc: u32,
    tdev: u32,
    tpgid: u32,
    nice: i32,
    start_tvsec: u64,
    start_tvusec: u64,
}

unsafe extern "C" {
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}

pub(super) fn is_compat_invocation() -> bool {
    std::env::args_os()
        .next()
        .as_deref()
        .and_then(OsStr::to_str)
        .and_then(|arg0| Path::new(arg0).file_name())
        == Some(OsStr::new("ps"))
}

pub(super) fn run() -> i32 {
    match codex_pid_arg(std::env::args_os().skip(1)) {
        Some(pid) => match process_info(pid) {
            Ok((state, start_time)) => {
                println!("{state} {start_time}");
                0
            }
            Err(error) => {
                eprintln!("ps: {error}");
                1
            }
        },
        None => {
            eprintln!("ps: unsupported query (Codex PID validation only)");
            1
        }
    }
}

fn codex_pid_arg(
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Option<c_int> {
    let args: Vec<_> = args.into_iter().collect();
    if args.len() != 6
        || args[0] != "-p"
        || args[2] != "-o"
        || args[3] != "stat="
        || args[4] != "-o"
        || args[5] != "lstart="
    {
        return None;
    }
    args[1].to_str()?.parse().ok()
}

fn process_info(pid: c_int) -> Result<(char, String), String> {
    if pid <= 0 {
        return Err("invalid process id".into());
    }

    let mut info = std::mem::MaybeUninit::<ProcBsdInfo>::uninit();
    // SAFETY: proc_pidinfo writes PROC_PIDTBSDINFO into the correctly sized,
    // aligned buffer. The value is read only when the full structure was
    // returned.
    let bytes = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            std::mem::size_of::<ProcBsdInfo>() as c_int,
        )
    };
    if bytes != std::mem::size_of::<ProcBsdInfo>() as c_int {
        return Err(format!("cannot inspect process {pid}"));
    }

    // SAFETY: the full structure was returned by proc_pidinfo above.
    let info = unsafe { info.assume_init() };
    let state = match info.status {
        2 => 'R', // SRUN
        4 => 'T', // SSTOP
        5 => 'Z', // SZOMB
        _ => 'S',
    };
    Ok((
        state,
        format!("{}.{:06}", info.start_tvsec, info.start_tvusec),
    ))
}

#[cfg(test)]
mod tests {
    use super::{codex_pid_arg, process_info};

    #[test]
    fn accepts_only_codex_pid_validation_query() {
        let args = ["-p", "123", "-o", "stat=", "-o", "lstart="];
        assert_eq!(codex_pid_arg(args.into_iter().map(Into::into)), Some(123));
        let args = ["-p", "123", "-o", "args="];
        assert_eq!(codex_pid_arg(args.into_iter().map(Into::into)), None);
    }

    #[test]
    fn reports_self_with_a_stable_start_time() {
        let (state, start_time) =
            process_info(std::process::id() as i32).unwrap();
        assert!(matches!(state, 'R' | 'S' | 'T'));
        assert!(start_time.contains('.'));
    }
}
