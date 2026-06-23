# ai-jail — Development Guidelines

## What This Project Is

A Rust CLI tool that wraps bubblewrap (`bwrap`) to sandbox AI coding agents (Claude Code, GPT Codex, OpenCode, Crush). It replaces a bash script with config persistence (`.ai-jail` TOML), proper signal handling, and a developer-friendly CLI.

## Project Structure

```
src/
  main.rs         -- entry point, orchestration, TempFile RAII guard
  cli.rs          -- argument parsing with lexopt
  config.rs       -- .ai-jail TOML config load/save/merge (project + global)
  sandbox/
    mod.rs        -- shared sandbox logic, mount lists, launch wrapper
    bwrap.rs      -- bwrap command builder + mount discovery (Linux)
    landlock.rs   -- Landlock LSM path + network rules (Linux)
    seccomp.rs    -- seccomp-bpf syscall filter (Linux)
    rlimits.rs    -- resource limits (NPROC, NOFILE, CORE)
    seatbelt.rs   -- sandbox-exec SBPL profile generation (macOS)
  pty.rs          -- PTY proxy with vt100 virtual terminal (raw mode, IO loop, diff rendering)
  statusbar.rs    -- persistent terminal status bar overlay (redraw, update check)
  signals.rs      -- signal forwarding + child process reaping
  output.rs       -- colored terminal output helpers (raw ANSI, no deps)
  bootstrap.rs    -- AI tool config generation (Claude, Codex, OpenCode)
```

## Critical Rule: Backward Compatibility

**Every new version MUST work with previously generated `.ai-jail` config files.**

This is the single most important invariant of the project. Users generate `.ai-jail` files in their project directories and expect them to keep working after upgrading the binary.

### Config file rules

- **Never remove a config field.** If a field becomes obsolete, keep deserializing it but ignore its value. Use `#[serde(default)]` on all fields so missing fields get defaults.
- **Never rename a config field.** If a better name is needed, add the new name and keep the old one as an alias (`#[serde(alias = "old_name")]`).
- **Never change a field's type.** A `Vec<String>` must stay a `Vec<String>`. If richer types are needed, add a new field.
- **New fields must have defaults.** Always use `#[serde(default)]` so old config files without the field still parse.
- **Unknown fields must be silently ignored.** Never use `#[serde(deny_unknown_fields)]`. This allows old configs with removed fields to still load.
- When writing config files, only serialize fields that differ from defaults (keeps files clean for users who edit them by hand).

### CLI option rules

- **Never remove a CLI flag.** If a flag becomes obsolete, keep accepting it silently (with an optional deprecation warning to stderr).
- **Never change the meaning of an existing flag.** `--no-gpu` must always mean "disable GPU passthrough".
- **New flags must not break existing invocations.** Defaults for new flags must preserve the prior behavior.
- **Positional command behavior is sacred.** `ai-jail claude` must always mean "run claude inside the sandbox".

### Testing backward compatibility

There are regression tests in `src/config.rs` that parse old config file formats. **When changing config.rs, always add a new regression test with the old format before making changes.** Never delete existing regression tests.

## Coding Conventions

- **No async, no tokio.** This is a synchronous CLI tool.
- **Minimal dependencies.** Current deps: `lexopt`, `serde`, `toml`, `serde_json`, `vt100`, `nix`, `landlock`, `seccompiler` (Linux). Do not add new crates without a strong justification.
- **No clap.** We use `lexopt` for argument parsing to keep the binary small.
- **Raw ANSI for colors.** No color crate — `output.rs` handles this with raw escape codes.
- **Warn and skip, never crash.** Missing paths, unreadable dirs, and non-critical errors produce a warning and continue. Only truly fatal errors (no bwrap, can't get cwd) should cause an exit.
- **Signal safety.** The signal handler (`signals.rs`) must only use async-signal-safe operations. The current handler just calls `libc::kill` on the stored child PID.
- **RAII for cleanup.** Temp files use a `Drop` guard, not manual cleanup.

## Mount Order Matters

The bwrap command mounts are order-dependent. The sequence in `sandbox/bwrap.rs` must be:

1. Base mounts (`/usr`, `/etc`, `/opt`, `/sys`, `/dev`, `/proc`, `/tmp`, `/run`)
2. Sensitive /sys masks (tmpfs over `/sys/firmware`, `/sys/kernel/security`, etc.)
3. GPU devices
4. Docker socket
5. Tailscale socket
6. Shared memory (`/dev/shm`)
7. Display mounts (X11, Wayland, XDG_RUNTIME_DIR)
8. systemd user bus mounts (`--systemd-user`, narrow XDG runtime sockets)
9. Home directory (tmpfs `$HOME` first, then dotfiles on top)
10. Config hide (tmpfs over sensitive `~/.config/*` subdirs)
11. Cache hide (tmpfs over sensitive `~/.cache/*` subdirs)
12. Local overrides (`~/.local/state`, `~/.local/share/*` rw subdirs)
13. Linked Git worktree metadata
14. SSH agent socket and `~/.ssh` exemption mounts
15. Pictures mount
16. Browser profile state mount
17. Extra user mounts (`--map`, `--rw-map`)
18. Overlay maps (`--overlay-map` — copy-on-write `--overlay-src`/`--overlay`)
19. Project directory (pwd, rw or ro depending on mode)
20. Mask overlays (`--mask` and hidden project `.ai-jail`)
21. Deny overlays (`--deny-path`, mode-000 file/dir placeholders)
22. Overlay storage hide (tmpfs over `<project>/.ai-jail-overlays`, last so it sits on top of the project mount that contains the upper/work layers)

Changing this order can break the sandbox. The tmpfs for `$HOME` must come before the individual dotfile bind mounts. Overlay maps come after the home/dotfile mounts (so an overlay on a home path sits on top). Mask and deny overlays come after the project mount so they override project-visible files. Overlay storage hide comes last, after the project mount, so it masks the upper/work layers the project mount would otherwise expose.

## Before Committing

Always run `cargo fmt` before committing. CI enforces `cargo fmt --check` and will fail on unformatted code. The project uses `max_width = 80` via `rustfmt.toml`.

```
cargo fmt
cargo clippy -- -D warnings
cargo test
```

## Running Tests

```
cargo test
```

Tests are in `#[cfg(test)]` modules at the bottom of each source file. Config tests use `tempfile`-style patterns with `std::env::temp_dir()`.

## Building

```
cargo build --release    # 881K stripped binary
```

Install by copying `target/release/ai-jail` to `~/.local/bin/` or `/usr/local/bin/`.
