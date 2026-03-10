# ai-jail — Copilot Instructions

## What This Project Is

A Rust CLI tool that wraps bubblewrap (`bwrap`) on Linux and `sandbox-exec` on macOS to sandbox AI coding agents (Claude Code, GPT Codex, OpenCode, Crush). Config is persisted in `.ai-jail` TOML files (project-level and global `$HOME/.ai-jail`).

## Build, Test, Lint

```bash
cargo build --release        # stripped ~881K binary
cargo test                   # all tests
cargo test --lib config::    # all tests in config module
cargo test --lib config::merge_cli_command_replaces_config  # single test
cargo fmt                    # required before committing (max_width = 80)
cargo clippy -- -D warnings  # CI enforces zero warnings
```

CI runs `cargo fmt --check`, `cargo clippy -- -D warnings`, and `cargo test` on every push/PR.

## Architecture

### Config Loading (three-level merge)

`$HOME/.ai-jail` (global) → `./.ai-jail` (project) → CLI flags (highest priority).

- Boolean flags use `Option<bool>` for three-state logic (`None` = use default/auto-detect).
- Maps (`rw_maps`, `ro_maps`) are extended and deduplicated, not replaced.
- Commands from CLI replace config entirely.
- Config is saved atomically (temp file + rename). Lockdown mode skips auto-save.

### Platform Backend Selection

Compile-time via `#[cfg(target_os)]`:

- **Linux:** `sandbox/bwrap.rs` (namespace/mount sandbox) + `sandbox/landlock.rs` (LSM VFS + network rules) + `sandbox/seccomp.rs` (syscall filter) + `sandbox/rlimits.rs` (resource limits)
- **macOS:** `sandbox/seatbelt.rs` (SBPL profile for `sandbox-exec`) + `sandbox/rlimits.rs` (resource limits)
- **Shared:** `sandbox/mod.rs` exposes `check()`, `prepare()`, `build()`, `dry_run()` as the platform-agnostic API.

### Mount Order (Linux/bwrap)

Mounts are order-dependent. `MountSet` in `bwrap.rs` enforces this sequence via `ordered_mounts()`:

1. Base → 2. /sys masks → 3. GPU → 4. SHM → 5. Docker → 6. Display → 7. Home dotfiles → 8. Config hide → 9. Cache hide → 10. Local overrides → 11. Extra user mounts → 12. Project dir

The tmpfs for `$HOME` **must** come before individual dotfile bind mounts. Reordering breaks the sandbox.

### Main Orchestration (`main.rs`)

Parse CLI → load/merge configs → handle subcommands (`--status`, `--init`, `--bootstrap`) → check sandbox tool → save config → apply rlimits → build sandbox `Command` → spawn (PTY proxy if status bar enabled, otherwise direct) → forward signals → exit with child status. Seccomp is applied inside the Landlock wrapper (after Landlock, before exec).

### PTY / Status Bar

When enabled (`-s`), `pty.rs` creates a PTY proxy between the terminal and the child process. `statusbar.rs` manages a persistent bottom-row status line using terminal scroll regions. The status bar survives screen resets by the child application.

## Critical Rule: Backward Compatibility

**Every version must parse previously generated `.ai-jail` files.** This is the project's most important invariant.

### Config rules

- Never remove or rename a config field. Obsolete fields: keep deserializing, ignore the value.
- Never change a field's type. Need richer types? Add a new field.
- New fields must use `#[serde(default)]`. Old configs without them must still parse.
- Never use `#[serde(deny_unknown_fields)]`.
- Only serialize fields that differ from defaults.

### CLI rules

- Never remove a CLI flag. Obsolete flags: accept silently, optionally warn to stderr.
- Never change the meaning of an existing flag.
- New flags must default to preserving prior behavior.

### Testing compatibility

`src/config.rs` has regression tests that parse old config formats. When changing config.rs, **add a new regression test with the old format before making changes**. Never delete existing regression tests.

## Coding Conventions

- **No async/tokio.** Synchronous CLI tool only.
- **Minimal deps.** Current: `lexopt`, `serde`, `toml`, `serde_json`, `nix`, `landlock`, `seccompiler` (Linux). Don't add crates without strong justification.
- **No clap.** Argument parsing uses `lexopt` to keep the binary small.
- **Raw ANSI for colors.** `output.rs` handles escape codes directly — no color crate.
- **Warn and skip, never crash.** Missing paths and non-critical errors produce a warning and continue. Only fatal errors (no bwrap, can't get cwd) cause an exit.
- **Signal safety.** `signals.rs` handler must only use async-signal-safe operations (currently just `libc::kill`).
- **RAII for cleanup.** Temp files use a `Drop` guard — no manual cleanup.
- Tests live in `#[cfg(test)] mod tests` at the bottom of each source file.
