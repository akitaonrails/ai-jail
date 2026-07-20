//! Command inspection helpers.
//!
//! ai-jail normally treats the first argv element as the active tool. Some
//! launchers, however, select an AI harness later in their argv. Keep that
//! distinction explicit: the invoked command is still executed unchanged,
//! while policy and terminal behavior may use the effective harness.

use std::path::Path;

const AI_MEMORY_GLOBAL_VALUE_OPTIONS: &[&str] = &["--data-dir", "--config"];

const AI_MEMORY_RUN_VALUE_OPTIONS: &[&str] = &[
    "--workspace",
    "--project",
    "--workstream",
    "--new",
    "--executable",
];

/// A harness selected by `ai-memory run`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManagedHarness<'a> {
    /// Canonical ai-jail command/config name.
    pub name: &'static str,
    /// Explicit `--executable` value, when supplied to ai-memory.
    executable: Option<&'a str>,
}

impl<'a> ManagedHarness<'a> {
    /// Executable ai-memory will resolve for the selected harness.
    pub(crate) fn executable(self) -> &'a str {
        self.executable.unwrap_or(self.name)
    }
}

/// Basename of the process ai-jail was asked to invoke.
pub(crate) fn basename(command: &[String]) -> Option<&str> {
    command.first().and_then(|cmd| {
        Path::new(cmd).file_name().and_then(|name| name.to_str())
    })
}

/// Canonical harness selected by an `ai-memory run` command.
///
/// Wrapper options are deliberately parsed narrowly from ai-memory's
/// published interface. Unknown options fail closed to the outer command
/// instead of guessing that a later token is a harness.
pub(crate) fn managed_harness(
    command: &[String],
) -> Option<ManagedHarness<'_>> {
    if basename(command) != Some("ai-memory") {
        return None;
    }

    let mut index = 1;
    loop {
        let argument = command.get(index)?.as_str();
        if argument == "run" {
            index += 1;
            break;
        }
        index =
            skip_value_option(command, index, AI_MEMORY_GLOBAL_VALUE_OPTIONS)?;
    }

    let mut executable = None;
    let mut options_ended = false;
    while let Some(argument) = command.get(index).map(String::as_str) {
        if !options_ended && argument == "--" {
            options_ended = true;
            index += 1;
            continue;
        }

        if !options_ended
            && let Some((option, value)) = argument.split_once('=')
        {
            if !is_run_value_option(option) || value.is_empty() {
                return None;
            }
            if option == "--executable" {
                executable = Some(value);
            }
            index += 1;
            continue;
        }

        if !options_ended && is_run_value_option(argument) {
            let value = command.get(index + 1)?.as_str();
            if argument == "--executable" {
                executable = Some(value);
            }
            index += 2;
            continue;
        }

        if argument.starts_with('-') {
            return None;
        }

        let name = canonical_harness_name(argument)?;
        return Some(ManagedHarness { name, executable });
    }

    None
}

fn skip_value_option(
    command: &[String],
    index: usize,
    options: &[&str],
) -> Option<usize> {
    let argument = command.get(index)?.as_str();
    if let Some((option, value)) = argument.split_once('=') {
        return (options.contains(&option) && !value.is_empty())
            .then_some(index + 1);
    }
    if !options.contains(&argument) {
        return None;
    }
    command.get(index + 1)?;
    Some(index + 2)
}

fn is_run_value_option(argument: &str) -> bool {
    AI_MEMORY_GLOBAL_VALUE_OPTIONS.contains(&argument)
        || AI_MEMORY_RUN_VALUE_OPTIONS.contains(&argument)
}

/// Command name used for terminal and automatic-profile behavior.
pub(crate) fn effective_name(command: &[String]) -> Option<&str> {
    managed_harness(command)
        .map(|harness| harness.name)
        .or_else(|| basename(command))
}

/// Executables that private-home mode must keep visible.
///
/// A managed run needs both the outer ai-memory launcher and the selected
/// native harness. The argv itself remains untouched.
pub(crate) fn executable_candidates(command: &[String]) -> Vec<&str> {
    let mut candidates = Vec::new();
    if let Some(outer) = command.first() {
        candidates.push(outer.as_str());
    }
    if let Some(harness) = managed_harness(command) {
        let executable = harness.executable();
        if !candidates.contains(&executable) {
            candidates.push(executable);
        }
    }
    candidates
}

fn canonical_harness_name(value: &str) -> Option<&'static str> {
    match value {
        "claude" | "claude-code" => Some("claude"),
        "codex" => Some("codex"),
        "opencode" | "open-code" => Some("opencode"),
        "pi" => Some("pi"),
        "omp" | "oh-my-pi" => Some("omp"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn direct_command_uses_its_basename() {
        let command = args(&["/usr/bin/codex", "--yolo"]);
        assert_eq!(basename(&command), Some("codex"));
        assert_eq!(effective_name(&command), Some("codex"));
        assert_eq!(managed_harness(&command), None);
    }

    #[test]
    fn ai_memory_run_detects_supported_harnesses_and_aliases() {
        for (value, expected) in [
            ("claude", "claude"),
            ("claude-code", "claude"),
            ("codex", "codex"),
            ("opencode", "opencode"),
            ("open-code", "opencode"),
            ("pi", "pi"),
            ("omp", "omp"),
            ("oh-my-pi", "omp"),
        ] {
            let command = args(&["/home/u/bin/ai-memory", "run", value]);
            assert_eq!(effective_name(&command), Some(expected));
        }
    }

    #[test]
    fn ai_memory_run_skips_wrapper_options_but_not_native_args() {
        let command = args(&[
            "ai-memory",
            "--config=/etc/ai-memory.toml",
            "--data-dir",
            "/tmp/memory",
            "run",
            "--workspace",
            "team",
            "--project=demo",
            "--workstream",
            "codex",
            "--new=next",
            "claude",
            "--model",
            "opus",
            "codex",
        ]);
        let harness = managed_harness(&command).unwrap();
        assert_eq!(harness.name, "claude");
        assert_eq!(harness.executable(), "claude");
    }

    #[test]
    fn ai_memory_run_observes_explicit_executable() {
        let command = args(&[
            "ai-memory",
            "run",
            "--executable=/home/u/bin/custom-codex",
            "codex",
        ]);
        let harness = managed_harness(&command).unwrap();
        assert_eq!(harness.name, "codex");
        assert_eq!(harness.executable(), "/home/u/bin/custom-codex");
        assert_eq!(
            executable_candidates(&command),
            vec!["ai-memory", "/home/u/bin/custom-codex"]
        );
    }

    #[test]
    fn unknown_or_incomplete_wrapper_syntax_stays_outer_scoped() {
        for command in [
            args(&["ai-memory", "status"]),
            args(&["ai-memory", "--unknown", "run", "codex"]),
            args(&["ai-memory", "--config", "run", "codex"]),
            args(&["ai-memory", "run", "--unknown", "codex"]),
            args(&["ai-memory", "run", "--project"]),
            args(&["ai-memory", "run", "not-a-harness"]),
        ] {
            assert_eq!(effective_name(&command), Some("ai-memory"));
            assert_eq!(managed_harness(&command), None);
        }
    }
}
