# 1.0 pre-release audit

State: ai-jail at v0.10.3 + `d8f40b6` (post-#43 docs commit). 12 603 LOC across 14 source files. 343 unit tests + 5 resize integration tests + 15 sandbox-escape integration tests on Linux.

Findings sorted by **impact**, not file. Each item is a one-line action you can lift directly into a TODO. Nothing here is a release blocker — it's "what to polish if we want 1.0 to feel like 1.0."

## Tier 1 — worth doing before 1.0

### Long functions that have outgrown their original shape

| Function | Lines | File | What to do |
|---|---|---|---|
| `pty::io_loop` | 277 | `src/pty.rs:178` | Split: SIGWINCH handling, master-read branch, stdin-read branch, status-bar redraw. The current single function juggles 5 mutable state machines. |
| `sandbox::bwrap::discover_mounts` | 178 | `src/sandbox/bwrap.rs:851` | Each `let foo_mount = if … { … }` block (ssh_agent, pictures, mask, browser_state, home_dotfiles + claude_dir, …) is a candidate for its own `fn discover_X`. |
| `sandbox::seatbelt::generate_sbpl_profile` | 174 | `src/sandbox/seatbelt.rs:158` | Six logically distinct sections (process, IPC, network, reads, writes, atomic). Extract per-section emit helpers; the function then reads as policy structure. |
| `config::display_status` | 130 | `src/config.rs` | Mostly `match` + `bool_opt` calls. Lift each block into a small printer helper to make the output schema obvious. |
| `config::merge` | 97 | `src/config.rs` | Most of the body is repetitive CLI→config boolean transfer. See dedup item below. |

### Repetition that compounds with every new flag

- **`config::merge_with_global` boilerplate** (16 `if local.X.is_some() { c.X = local.X }` blocks; ~50 LOC). With each new opt-in flag this grows by 3 lines. Add a `merge_field!($field)` macro local to the module. Same applies to `config::merge` (the CLI side).
- **CLI `--foo`/`--no-foo` pairs** (`src/cli.rs:137–180` and friends). ~15 of these. A `paired_flag!("ssh", args.ssh)` macro or a static `[(positive_name, negative_name, setter), ...]` array replaces the wall of `Long("ssh") => args.ssh = Some(true), Long("no-ssh") => args.ssh = Some(false),`.
- **SBPL escape helpers** (`src/sandbox/seatbelt.rs:115`–`152`). `sbpl_escape` and `sbpl_regex_escape` share the same `\\ " \n \r \t` table. Have `sbpl_regex_escape` call into `sbpl_escape` for the common characters and only override the regex-metacharacter table.
- **Linked-worktree test fixture** appears twice with identical body: `src/sandbox/mod.rs` tests and `src/sandbox/seatbelt.rs:596–626` tests. Lift into `src/sandbox/mod.rs` as `#[cfg(test)] pub(super) fn fixture()` or a test-support module.
- **Tilde expansion** — `expand_tilde` is correctly used for `rw_maps`, `ro_maps`, `mask` in `merge()`, but `claude_dir` runs a separate `expand_tilde` call right after. Consolidate so every PathBuf field gets the same treatment in one pass.

### Test coverage gaps that affect 1.0 promises

- **`src/signals.rs` (66 lines): zero tests.** The signal handler is the kind of code that goes silently wrong. Add at least: handler installation succeeds, `forward_signal(SIGWINCH)` sets the PTY pending flag without touching `CHILD_PID`, and `forward_signal(SIGINT)` calls `kill` on the stored PID.
- **`src/sandbox/rlimits.rs` (154 lines):** the `apply_nproc` re-entry path (the one that fixed the EAGAIN regression in v0.8.0) has no isolated test. A test that sets `RLIMIT_NPROC` to the current value and verifies the hard limit gets pinned would prevent regressions.
- **`hide_config` auto-mask** (#41 fix): there's a unit test for the bwrap dry-run including/excluding the `--ro-bind <empty> .ai-jail` triple, but no test that the dedup logic works when the user explicitly also lists `.ai-jail` in `mask`. Easy add.
- **`browser_profile` soft-mode state persistence:** unit tests verify the mount point is computed and added, but nothing checks that `~/.local/share/ai-jail/browsers/<name>` survives a sandbox round-trip. An integration test that runs `ai-jail --browser=soft bash -c 'touch /run/user/...'`-style would catch a future regression. Macos coverage is harder; flag as known gap.
- **Lockdown + `--allow-tcp-port` + Landlock V4 unavailable:** the hard-fail path is documented but not tested. Synthesise the failure (mock the V4 status) and assert the error message.
- **Cross-platform parity for `private_home`:** Linux has unit tests for the tmpfs-$HOME path. macOS seatbelt has 1 test (`private_home_writable_paths_skip_host_home_state`). A test that asserts the SBPL profile contains the correct deny-read rules on `private_home + browser_mode = false` is missing.

## Tier 2 — nice to have, not 1.0-critical

### Style / clippy-pedantic findings (cargo clippy -- -W clippy::pedantic counts)

| Category | Count | Notes |
|---|---|---|
| Docstrings missing backticks around identifiers | 25 | Cosmetic; cherry-pick the most-visible public APIs. |
| Module name repetition (e.g. `bwrap::BwrapMount`) | 10 | Worth doing if we ever re-export across modules. |
| `.map(...).unwrap_or(...)` on `Result` | 5 | Replace with `.unwrap_or_else` or `?` where appropriate. |
| `format!` appended to existing `String` | 4 | Use `write!`. |
| Identical match arms with `\|` patterns | 4 | Merge. |
| Variables can be inlined into `format!` strings | 4 | `format!("{x}")` instead of `format!("{}", x)`. |
| Lossy/sign-changing casts (`as`) | 6 total | Audit individually — some are intentional (e.g. `u8 → u16` for terminal sizing). |

### Specific micro-issues worth fixing

- **`config::expand_tilde` doesn't handle `~user/`** (other-user home). The function's docstring says "leaves `~user` alone" but the behaviour is fine — just confusing to read. Either remove the comment or add a test that pins the behaviour.
- **`statusbar.rs` redraw key parsing** (`pty::parse_resize_redraw_key`) accepts `ctrl-l`, `ctrl-shift-l`, `disabled`. The error message says "must be ctrl-X or ctrl-shift-X" but doesn't show what the user gave. Include the offending input in the error.
- **`unwrap` / `expect` count: 215 outside tests.** Most are in places where panicking is correct (e.g. string-only-ASCII assumptions in vt100 helpers). Two worth re-examining: `src/output.rs` writes to stderr with `let _ = writeln!(...)` (correct, can't do better), and the `pty::io_loop` uses `.as_raw_fd()` ifs that are infallible by construction. Not a blocker — flag for a one-evening grep pass.

### Dead code

- **The two existing `#[allow(dead_code)]` markers** in `src/sandbox/mod.rs:45` and `:81` are legitimate platform splits — keep.
- **No other dead code surfaced** in clippy/grep passes.

## Tier 3 — explicitly *not* worth doing right now

- Rewriting `io_loop` into an async state machine. Tempting, but the project's "no tokio" CLAUDE.md rule is load-bearing. Sync loop with manual state is the right shape; just split it into smaller fns.
- Switching `Result<_, String>` to a typed error enum. Useful for a future library extraction, irrelevant for a CLI that prints strings to a human.
- Pulling `LinkedWorktreeFixture` into a separate test crate. Inline duplication is fine for 2 sites — fix it when it's 4+.

## Suggested order if you tackle this in one sitting

1. **Macros for the two boilerplate hotspots** (`config::merge_with_global` and CLI flag pairing). ~30 min, removes ~80 LOC, makes every future flag a 1-liner.
2. **Split `io_loop`** into 4–5 smaller fns. ~1 h, this is the single piece of code most likely to grow a subtle bug in the next year.
3. **Lift SBPL escape commonality + lift the worktree test fixture.** ~30 min combined.
4. **Add the `signals.rs` and `rlimits.rs` unit tests.** ~45 min — they're the only "zero-test" surfaces left.
5. **Lift `discover_mounts` and `generate_sbpl_profile` into smaller helpers.** ~1 h. Less urgent than `io_loop` since they're pure value-builders without IO.

After that the codebase looks like a 1.0.
