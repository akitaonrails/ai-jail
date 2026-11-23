// Integrity of the teardown report channel: the command must not be able
// to reach the wrapper's report descriptor, not even by reopening it
// through /proc/<wrapper>/fd/N. The supervisor takes the first line, so a
// forged line written first would replace the real report.
//
// Linux-only; skips (does not fail) when bwrap cannot create namespaces,
// like tests/run_observability.rs.
#![cfg(target_os = "linux")]

mod common;

use common::{SANDBOX_RUN_LOCK, ai_jail};
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// A well-formed report naming a survivor that never existed: if the
/// supervisor prints its name, it read this line instead of the real one.
const FORGED: &str = r#"{"v":1,"child":{"exited":0},"survivors":[{"pid":99,"ppid":2,"comm":"forged-survivor","age_s":0,"ended_by":"sigterm"}],"grace_ms":2000,"usage":null,"complete":true,"incomplete_reason":null}"#;

/// Every pipe the wrapper holds above stdio gets the forged line; the
/// command then ends with its own code, 3.
fn forging_script() -> String {
    format!(
        "for f in /proc/$PPID/fd/*; do n=${{f##*/}}; \
         [ \"$n\" -gt 2 ] 2>/dev/null || continue; \
         case \"$(readlink \"$f\" 2>/dev/null)\" in pipe:*) \
         printf '%s\\n' '{FORGED}' 2>/dev/null >\"$f\" \
         && echo \"forged-into-$n\";; esac; done; exit 3"
    )
}

fn run(name: &str, extra: &[&str]) -> std::process::Output {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("teardown-integrity-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    let home = root.join("home");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::create_dir_all(&home).unwrap();
    // The mandatory `.ai-jail` mask warns when the file is absent.
    std::fs::write(project.join(".ai-jail"), "").unwrap();
    let mut c = Command::new(ai_jail());
    c.args(["--clean", "--no-save-config", "--no-status-bar"])
        .args(extra)
        .args(["--teardown-report", "--exec", "sh", "-c"])
        .arg(forging_script())
        .current_dir(&project)
        .env("HOME", &home)
        .stdin(Stdio::null());
    let _lock = SANDBOX_RUN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    c.output().unwrap()
}

#[test]
fn teardown_report_cannot_be_forged_through_proc() {
    require_bwrap_net!();
    for (name, extra) in [
        ("plain", &[][..]),
        // Every restriction the wrapper applies, at once.
        ("lockdown", &["--lockdown"][..]),
    ] {
        let out = run(name, extra);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(3), "{name}: {stderr}");
        assert!(
            !stderr.contains("forged-survivor"),
            "{name}: the supervisor read the forged line \
             (stdout: {stdout}) stderr: {stderr}"
        );
        assert!(
            !stdout.contains("forged-into-"),
            "{name}: the command reopened a wrapper pipe: {stdout}"
        );
        // The real report arrived intact: no survivors, nothing missing.
        assert_eq!(stderr, "", "{name}");
    }
}
