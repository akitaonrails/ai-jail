// Through the built binary: the final effective-access
// review names the selected named profile as `profile=<name>`, and
// says nothing of one when none is selected. The review is the one a
// noninteractive first run prints ("Complete effective access"); the
// widening lines printed before it, which also carry `profile=<name>`,
// do not count. Temporary HOME, XDG_CONFIG_HOME (global config 0600 in a
// 0700 dir), project, and an empty PATH so the harness is never found.
#![cfg(target_os = "linux")]

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const GLOBAL: &str = "\
[profiles.wide]
profile_version = 1
allow_hosts = [\"api.example.com\"]
";

/// Run a noninteractive first launch of `claude` and return the review:
/// the stderr text from "Complete effective access" on.
fn review(tag: &str, flags: &[&str]) -> String {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("aj-interface-profile-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let project = root.join("project");
    let home = root.join("home");
    let store = root.join("xdg").join("ai-jail");
    let empty_path = root.join("empty-path");
    for dir in [&project, &home, &store, &empty_path] {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o700))
        .unwrap();
    let config = store.join("config.toml");
    std::fs::write(&config, GLOBAL).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
        .unwrap();
    let output = Command::new(common::ai_jail())
        .args(flags)
        .arg("claude")
        .current_dir(&project)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", root.join("xdg"))
        .env("PATH", &empty_path)
        .env_remove("AI_JAIL_QUIET")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&root);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let at = stderr
        .find("Complete effective access")
        .unwrap_or_else(|| panic!("no final review: {stderr}"));
    stderr[at..].to_string()
}

/// Lines of the review that carry `profile=` as a token, widening lines
/// excluded. `browser_profile=` or the onboarding "harness profile" are
/// not it.
fn profile_lines(review: &str) -> Vec<&str> {
    review
        .lines()
        .filter(|l| !l.contains("widens="))
        .filter(|l| {
            l.match_indices("profile=").any(|(at, _)| {
                l[..at]
                    .chars()
                    .last()
                    .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
            })
        })
        .collect()
}

#[test]
fn interface_final_review_names_the_selected_profile() {
    let review = review("selected", &["--profile", "wide"]);
    let lines = profile_lines(&review);
    assert!(
        lines.iter().any(|l| l.contains("profile=wide")),
        "the final review does not name profile=wide:\n{review}"
    );
}

#[test]
fn interface_final_review_names_no_profile_when_none_is_selected() {
    let review = review("none", &[]);
    assert!(profile_lines(&review).is_empty(), "{review}");
}
