//! Host-written results for one launch. The output name is reserved by
//! linking a fully written file, so existing files and concurrent runs
//! cannot be overwritten.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use nix::fcntl::{AtFlags, OFlag, openat};
use nix::libc;
use nix::sys::stat::{Mode, fchmod, fstatat};
use nix::unistd::{UnlinkatFlags, geteuid, linkat, unlinkat};
use serde_json::{Value, json};

use crate::exit_reason::{ExitReason, Limit, ReasonKind, StatusSource};

pub(crate) struct RunSummary {
    directory: File,
    name: OsString,
    path: PathBuf,
    started_at: SystemTime,
    start: Instant,
}

impl RunSummary {
    pub(crate) fn open(path: &Path) -> Result<Self, String> {
        let open = || -> io::Result<Self> {
            let name = path.file_name().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected a file name",
                )
            })?;
            let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(parent.unwrap_or(Path::new(".")))?;
            let metadata = directory.metadata()?;
            if metadata.uid() != geteuid().as_raw()
                || metadata.mode() & 0o022 != 0
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "parent directory must be owned by you and writable only by you",
                ));
            }
            match fstatat(
                Some(directory.as_raw_fd()),
                name,
                AtFlags::AT_SYMLINK_NOFOLLOW,
            ) {
                Err(nix::errno::Errno::ENOENT) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(io::ErrorKind::AlreadyExists.into()),
            }
            Ok(Self {
                directory,
                name: name.to_owned(),
                path: path.to_owned(),
                started_at: SystemTime::now(),
                start: Instant::now(),
            })
        };
        open().map_err(|error| {
            format!("Cannot use run summary {}: {error}", path.display())
        })
    }

    pub(crate) fn finish(
        &self,
        run_id: &str,
        command: &[String],
        exit: Value,
        egress: Option<(crate::egress_log::EgressTotals, bool)>,
        teardown: Value,
        resources: Value,
    ) {
        let egress = egress.map(|(totals, complete)| {
            json!({
                "complete": complete,
                "allowed": totals.allowed,
                "denied": totals.denied,
                "errored": totals.errored,
                "bytes_up": totals.bytes_up,
                "bytes_down": totals.bytes_down,
            })
        });
        let document = json!({
            "schema_version": 1,
            "run_id": run_id,
            "started_at": crate::audit::rfc3339(self.started_at),
            "finished_at": crate::audit::rfc3339(SystemTime::now()),
            "duration_ms": self.start.elapsed().as_millis().min(u64::MAX as u128) as u64,
            "program": crate::command::basename(command),
            "exit": exit,
            "egress": egress,
            "teardown": teardown,
            "resources": resources,
        });
        if let Err(error) = self.publish(run_id, &document) {
            crate::output::security_warn(&format!(
                "Cannot write run summary {}: {error}",
                self.path.display(),
            ));
        }
    }

    fn publish(&self, run_id: &str, document: &Value) -> io::Result<()> {
        let dir = Some(self.directory.as_raw_fd());
        let temporary =
            OsString::from(format!(".ai-jail-summary-{run_id}.tmp"));
        let mode = Mode::S_IRUSR | Mode::S_IWUSR;
        let fd = openat(
            dir,
            temporary.as_os_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_CLOEXEC,
            mode,
        )?;
        // SAFETY: openat returned a new descriptor exclusively owned here.
        let mut file = unsafe { File::from_raw_fd(fd) };
        let written = (|| -> io::Result<()> {
            fchmod(fd, mode)?;
            serde_json::to_writer_pretty(&mut file, document)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            linkat(
                dir,
                temporary.as_os_str(),
                dir,
                self.name.as_os_str(),
                AtFlags::empty(),
            )?;
            Ok(())
        })();
        let cleaned =
            unlinkat(dir, temporary.as_os_str(), UnlinkatFlags::NoRemoveDir);
        written?;
        cleaned?;
        self.directory.sync_all()
    }
}

pub(crate) fn exit_value(reason: &ExitReason) -> Value {
    json!({
        "code": reason.code,
        "signal": reason.signal,
        "core_dumped": reason.core_dumped,
        "kind": match reason.kind {
            ReasonKind::Exited => "exited",
            ReasonKind::Signaled => "signaled",
            ReasonKind::Limit => "limit",
        },
        "source": match reason.source {
            StatusSource::ExitCode => "exit_code",
            StatusSource::Inferred => "inferred",
            StatusSource::Direct => "direct",
        },
        "limit": reason.limit.map(|limit| match limit { Limit::FileSize => "file_size" }),
    })
}

#[cfg(target_os = "linux")]
pub(crate) fn teardown_values(
    section: crate::teardown::TeardownSection,
) -> (Value, Value) {
    use crate::teardown::TeardownSection;
    match section {
        TeardownSection::Inactive => (Value::Null, Value::Null),
        TeardownSection::Missing { reason } => {
            (json!({"status": "missing", "reason": reason}), Value::Null)
        }
        TeardownSection::Reported(report) => (
            json!({
                "status": if report.complete { "complete" } else { "incomplete" },
                "reason": report.incomplete_reason,
                "grace_ms": report.grace_ms,
                "survivors": report.survivors,
            }),
            json!(report.usage),
        ),
    }
}
