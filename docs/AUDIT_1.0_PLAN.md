# 1.0 audit execution plan

Goal: ship every Tier 1 + Tier 2 item from `AUDIT_1.0.md` without breaking any of the 363 existing tests, and without altering any user-observable behavior. Tier 3 items stay un-done (they're the "explicitly skip" list — async rewrite, typed error enum, separate test crate).

## Operating rules

1. **Refactor only.** No new features, no CLI/config schema changes, no test removals. Tests are added; existing tests stay green.
2. **Atomic commits.** Each step is one commit on master with the full `cargo fmt --check && cargo clippy -- -D warnings && cargo test` suite green. If something goes wrong it's bisectable.
3. **Stop and report at the end of each phase**, not each commit, so you can sanity-check progress without micro-management.
4. **No version bump** until the audit is finished, then a single `1.0.0` tag at the end.
5. If a step turns out to be riskier than the audit predicted, bail and document why in the commit message — don't force a refactor that obscures the original logic.

## Phase 1 — boilerplate reduction (safest, biggest LOC win)

Six small commits. None of them change observable behavior; all of them are caught by the existing test suite.

| # | Commit | Touches | Net LOC |
|---|---|---|---|
| 1 | Add `merge_field!` macro + apply to `config::merge_with_global` | `src/config.rs` | −30 |
| 2 | Apply `merge_field!` to `config::merge` (CLI → config side) | `src/config.rs` | −20 |
| 3 | Add CLI `paired_bool_flag!` macro for `--foo / --no-foo` pairs | `src/cli.rs` | −20 |
| 4 | Have `sbpl_regex_escape` delegate to `sbpl_escape` for the shared char table | `src/sandbox/seatbelt.rs` | −10 |
| 5 | Lift `LinkedWorktreeFixture` into a shared `tests` submodule in `sandbox/mod.rs` | `src/sandbox/mod.rs`, `seatbelt.rs`, `landlock.rs`, `bwrap.rs` | −60 |
| 6 | Run all PathBuf fields through `expand_tilde` in one pass in `config::merge` | `src/config.rs` | −5 |

Expected: ~145 LOC removed, zero behavior change. Each commit ends with full suite green.

## Phase 2 — long-function splits (more delicate)

These are pure rearrangements of existing logic. Each split keeps the exact same control flow; only the function boundary moves. Reviewed visually after each split.

| # | Commit | Function | Approach |
|---|---|---|---|
| 7 | Split `config::display_status` | 130 LOC | Each `match config.X { … }` block becomes a `print_X(config)` helper. |
| 8 | Split `sandbox::seatbelt::generate_sbpl_profile` | 174 LOC | One helper per section (process, IPC, network, reads, writes, atomic, deny). Each helper takes `&mut String` and pushes its own block. |
| 9 | Split `sandbox::bwrap::discover_mounts` | 178 LOC | Each `let foo_mount = if … { build_foo() } else { vec![] }` block already exists implicitly. Lift each computation into a named `fn discover_foo(config, …) -> Vec<Mount>` helper. |
| 10 | Split `pty::io_loop` | 277 LOC | Higher risk. Approach: extract `handle_sigwinch`, `handle_master_read`, `handle_stdin_read`, `redraw_when_idle` into private helpers taking `&mut IoState` (a new struct holding the loop's mutable state). The for-loop body becomes ~25 lines calling them. Visually verify against current version. |

`pty::io_loop` is the riskiest item in this plan. If the split looks like it might subtly change ordering, I'll commit the IoState struct first, run the full suite, then move helpers out one at a time.

## Phase 3 — test gap fills

Pure additions; no existing code changes.

| # | Commit | What |
|---|---|---|
| 11 | `signals.rs` unit tests | Handler installation succeeds; `forward_signal(SIGWINCH)` flips the PTY pending flag without touching `CHILD_PID`; `forward_signal(SIGINT)` calls into the stored PID branch (mocked via a recordable hook). |
| 12 | `rlimits::apply_nproc` test | Pin a low NPROC, then call `apply_nproc` and assert via `getrlimit` that hard == soft. Linux-only test, gated `#[cfg(target_os = "linux")]`. |
| 13 | `hide_config` dedup test | When user already has `.ai-jail` in their `mask`, the auto-append step doesn't produce a duplicate `--ro-bind` triple. |
| 14 | Browser-profile soft-mode mount existence test | Unit test: given `browser_profile = "soft"`, `discover_mounts` returns a `browser_state` mount pointing at `~/.local/share/ai-jail/browsers/<name>`. |
| 15 | Lockdown + `allow_tcp_ports` + V4-unavailable failure-mode test | Use the existing apply_net_rules code path; assert the error message contains "Landlock V4" and "lockdown" when V4 is detected as unavailable. Hard to mock cleanly — may have to settle for documenting the path manually. |

## Phase 4 — Tier 2 cleanup

One commit, mechanical. Clippy `-W clippy::pedantic -W clippy::nursery` is the source of truth; I'll work through these:

- 25 missing-backtick doc warnings → fix all
- `.map(...).unwrap_or(...)` on `Result` (5) → use `?` or `unwrap_or_else`
- 4 inline-format opportunities → `format!("{x}")` style
- 4 identical match arms → merge with `|`
- 4 `format!` append to `String` → `write!`
- 6 lossy/sign-changing `as` casts → audit each; convert via `From`/`try_into` where safe, leave with a `// SAFETY:` comment where intentional

After this, run `cargo clippy -- -W clippy::pedantic` and see how close we get to zero pedantic warnings. Some (e.g. `module_name_repetitions`) are configured-off; that's fine.

## Phase 5 — final check before tag

- `cargo fmt --check`
- `cargo clippy -- -D warnings` (default lints)
- `cargo test` (all suites)
- `cargo build --release` succeeds, binary under 1 MB
- README and release notes still build (no broken links)
- Update `CLAUDE.md` if any conventions changed (likely just a note that `merge_field!` is the pattern for new flags)

If everything's green: bump `Cargo.toml` to `1.0.0`, commit, tag, push, manually flip the GitHub release out of draft.

## Time estimate

Conservatively, working sequentially with full test cycles between commits:

| Phase | Commits | Estimate |
|---|---|---|
| 1 — boilerplate | 6 | 1 h |
| 2 — function splits | 4 | 2 h (most of which is `io_loop`) |
| 3 — test gaps | 5 | 1 h |
| 4 — Tier 2 cleanup | 1 | 45 min |
| 5 — release | 1 | 15 min |
| **total** | **17 commits** | **~5 h** |

I'd suggest I run this end-to-end in the background, reporting at the end of each phase (4 reports + a final tag-ready summary). At any phase boundary you can review the master diff and ask me to stop or redo something.

## What I'm explicitly *not* doing

- Async rewrite of `io_loop` (Tier 3)
- Typed error enum replacing `Result<_, String>` (Tier 3)
- Separate test-support crate (Tier 3)
- Any new flag, env var, or `.ai-jail` field
- Any change that alters bwrap argument ordering, SBPL section ordering, Landlock rule ordering, or any user-observable runtime behavior
- Removing the two intentional `#[allow(dead_code)]` markers in `src/sandbox/mod.rs`
- Touching anything in `tests/` beyond the new tests in Phase 3
