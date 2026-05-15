# 1.0 pre-release security audit

**Scope**: 16 refactor commits between `91e3ce0` (planning-doc commit) and current `HEAD` (the post-Phase-4 state). All commits were intended to be behavior-preserving — same bwrap args, same SBPL profile, same Landlock ruleset, same signal handling, same seccomp filter. This audit verifies that.

**Result: Cleared for 1.0 tag.** No security regressions detected. Surfaces below were re-read against `git diff 91e3ce0..HEAD` and current HEAD.

## A. Confirmed clean

1. **bwrap argument ordering** (`src/sandbox/bwrap.rs`). The `discover_*` helper extractions preserve mount order and type. `discover_mask_mounts` dedup logic against the user list is unchanged. SSH agent socket forwarding stays gated by `lockdown || browser_mode || !config.ssh_enabled()`. `claude_dir` mount is only appended in `discover_home_dotfiles_full` when `!lockdown && path_exists()`. No user-controlled strings escape their argv slot.

2. **SBPL profile output** (`src/sandbox/seatbelt.rs`). Section order preserved: static → network → read → write → docker. `push_path_rule` consolidates four identical open-coded subpath/literal selectors into one helper without changing the logic. The double-escaping in `sbpl_regex_escape` is preserved: regex metacharacters get a single backslash, which then goes through `push_sbpl_escaped` which escapes the backslash again. The atomic-write regex `^...(\.tmp\.[0-9]+\.[0-9a-f]+|\.lock)$` is byte-identical to the pre-refactor version.

3. **Landlock ruleset** (`src/sandbox/landlock.rs`). Only change is a clippy cast-style fix; no guard logic, port handling, or ABI version touched.

4. **CLI translation** (`src/cli.rs`, `src/config.rs`). The `@`-binding pattern correctly assigns `true` for the positive name and `false` for the negative (verified for all 14 flag pairs). The `invert!`/`direct!`/`clone_into!`/`take!` macros each read each source field exactly once — no double-move risk. `claude_dir` tilde expansion still runs after merge so user-provided paths can't bypass it.

5. **PTY IoLoop** (`src/pty.rs`). SIGWINCH handler order is preserved: vt100 resize → real-terminal repaint → `resize_pty()` → `forward_sigwinch()`. POLLHUP drain happens before the loop breaks. The new `handle_master_read` writes only what was read from the master fd — no new output paths. No new `unsafe` blocks introduced.

6. **Signal handlers** (`src/signals.rs`). `forward_signal` remains `extern "C"` and async-signal-safe — only atomic loads/stores and one `libc::kill` call. All test additions are `#[cfg(test)]`-gated. The new `take_sigwinch_pending_for_test` is also `#[cfg(test)]`-only.

7. **Test additions**. No `#[ignore]` directives. The `test_support` module is `#[cfg(test)]`-gated at the parent `mod.rs`. The `apply_nproc_pins_hard_equal_to_soft` test does mutate the test binary's RLIMIT_NPROC permanently, but it's documented in-comment and 4096 is plenty of headroom for the rest of the suite.

8. **No secret leakage**. The new `test_support` module only uses `SystemTime`, `temp_dir`, and `process::id` to generate fixture paths — no env-var logging, no credential exposure, no SSH socket details beyond what was logged before. All fixtures live under `/tmp` and clean up on drop.

## B. Concerns

None.

The three highest-risk changes were audited specifically:

- **PTY IoLoop split**: the new `IoLoop` struct + methods preserve every state transition. Method boundaries are pure refactor; the surrounding poll/read/write order in the dispatcher matches the original 277-line function.
- **SBPL profile split**: `push_path_rule` is a single new helper that replaces four open-coded sites. Behaviour-equivalent.
- **CLI macro translation**: `invert!(gpu, no_gpu)` ⇔ old `if let Some(v) = cli.gpu { config.no_gpu = Some(!v); }` etc. Verified by inspection.

## C. Hardening opportunities

None worth taking before 1.0. Both candidates I noticed are nice-to-haves:

- `test_support::linked_worktree_fixture` could grow a `with_files()` builder if more git-layout variants get tested in future. For now, one fixture shape is enough.
- The `signals::forward_signal_with_zero_child_pid_is_noop` test pins the zero-PID guard but not the SIGTERM-forwarded-to-stored-PID case. The latter needs a recordable mock or a fork-based test harness; integration tests already cover it indirectly.

## Verdict

**Cleared for 1.0 tag.**

The 16 commits between `91e3ce0` and HEAD are behaviour-preserving refactors plus four test additions. The audited security surfaces (bwrap, SBPL, Landlock, CLI translation, PTY state machine, signal handler, RLIMIT pinning, test isolation) are functionally identical to their pre-refactor counterparts. Proceed to Phase 5.
