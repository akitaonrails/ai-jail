# Security advisories vs. the 2026-09-30 audits

Two GitHub security advisories are open in triage. This checks whether the
same-day audits (A = `SECURITY_AUDIT_2026-09-30.md`, B =
`SECURITY_AUDIT_2026-09-30_B.md`) caught what they report. Each advisory finding
was re-verified against the current tree, v2.3.0 `f62d576` — the advisories were
filed against older versions (v1.4.3 and v1.22.0).

## GHSA-w976-gw52-hvx2 — v1.22.0 source audit, five findings (High)

| #   | Advisory finding                                                   | Audit A    | Audit B    | Still present in v2.3.0             |
| --- | ------------------------------------------------------------------ | ---------- | ---------- | ----------------------------------- |
| 1   | `--worktree` circular validation → bind arbitrary host dir RW      | caught     | caught     | Yes (both audits reproduced it)     |
| 2   | TIOCSTI seccomp rule compares 64 bits; kernel reads 32             | caught     | caught\*   | Yes (confirmed empirically)         |
| 3   | Project `.ai-jail` clears trusted `lockdown` via browser `command` | **missed** | **missed** | **Yes — confirmed on current code** |
| 4   | macOS: every `/dev/ttysN` readable/writable                        | caught     | missed     | Not verified here (no Mac)          |
| 5   | macOS: masks are read-deny only in a renamable tree                | caught     | missed     | Not verified here (no Mac)          |

\* Audit B first rejected #2, then confirmed it after A's lead.

**Confirmation of #3 on v2.3.0** (neither audit found it): in a scratch dir with
`command = ["chromium"]` in `.ai-jail`, `ai-jail --lockdown --dry-run` produces
an inner argument list with **no `--lockdown`** and `--browser=hard` present —
the trusted lockdown was cleared by untrusted project input. Root cause:
`main.rs:507-508` adopts the project file's `command` when the CLI gives none,
and `apply_browser_profile` (`main.rs:72`) then sets `lockdown = Some(false)`,
_after_ the monotonic merge that is supposed to forbid a project from weakening
the sandbox. This contradicts `docs/SECURITY.md`'s monotonicity guarantee.

Both audits reviewed the config trust boundary and both found the _neighbouring_
"trusted project overrides CLI" issue, but neither traced the browser-profile
post-merge step that bypasses the monotonic guard for an untrusted project. This
is the more serious of the two, because it needs no `trust_project_config` — any
cloned repo qualifies.

## GHSA-frgp-q3qc-g78p — Landlock V6 scope absent, abstract-socket escape (Medium)

| Advisory finding                                                                                                                                                    | Audit A    | Audit B    |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------- | ---------- |
| Landlock applies V3 (fs) + V4 (net) but not V6 scope, so the documented "survives mount-namespace escapes" backstop does not cover abstract Unix sockets or signals | **missed** | **missed** |

**Confirmed on current code:** `src/sandbox/landlock.rs` has no `.scope()` call;
the threat-model comment still claims Landlock is a backstop that "survives
mount-namespace escapes" (`landlock.rs:10-14`).

**Severity is lower on v2.3.0 than when filed (v1.4.3).** The advisory's two
concrete vectors depended on the v1.4.3 default mounting `/tmp/.X11-unix` and
`/run/user/$UID/bus` with a shared network namespace. On v2.3.0 the default is
`--no-network` (netns unshared, verified: `--unshare-net` present) and both X11
and the systemd user bus are opt-in (verified: 0 binds by default). So the
default configuration is no longer exploitable by the advisory's PoC.

The **code gap is still real**, though, and both audits missed it: the moment a
user enables `--x11`/`--display` or `--systemd-user` (with `--network` for the
display to function), the abstract-socket and signal classes are reachable and
Landlock is not the backstop the docs claim. Neither audit examined the Landlock
ABI level against its own threat-model text — a blind spot in both.

## Scorecard

- **Caught by both audits:** advisory 1 findings #1, #2.
- **Caught by A only:** advisory 1 findings #4, #5 (macOS; B had no Mac).
- **Missed by both audits:** advisory 1 finding #3 (lockdown clear via browser
  command) and advisory 2 (Landlock V6 scope). Both confirmed present in v2.3.0.

Two genuine misses shared by both audits. #3 is a real untrusted-input
confinement downgrade that both audits walked past while looking at the adjacent
CLI-precedence issue; the Landlock-scope gap is a threat-model claim neither
audit tested. Both belong in the remediation plan alongside the audit findings.

## Provenance: were these caused by recent work?

No. Every advisory finding predates the recent proxy / phantom-secret / audit-log
work, established from `git log -S` on each vulnerable path:

| Advisory finding                          | Introduced            | Commit                                         |
| ----------------------------------------- | --------------------- | ---------------------------------------------- |
| worktree circular validation (adv1 #1)    | 2026-04-13            | `a1267f3` feat: support linked git worktrees   |
| browser command clears lockdown (adv1 #3) | 2026-04-29            | `512a3a0` Add browser profiles                 |
| TIOCSTI 64-bit compare (adv1 #2)          | 2026-08-15            | `b80e7fe` capabilities explicit opt-in         |
| macOS ttys / masks (adv1 #4, #5)          | early (macOS backend) | —                                              |
| Landlock has no V6 scope (adv2)           | 2026-03-02            | `56f70cd` v0.4.0 add Landlock — V6 never added |

The recent session commits (v2.0.0 → HEAD) touched the audit log, phantom
secrets, and the proxy. They did **not** touch `landlock.rs`, `seccomp.rs`, or
the worktree validator, and touched `main.rs` only for the audit path — not the
browser/lockdown step. So none of these advisories is a regression from recent
implementations.

Two nuances, stated for accuracy:

- The Alpine build fix this session (`3966f3d`, 2026-09-02) changed the TIOCSTI
  line from `libc::TIOCSTI` to `libc::TIOCSTI as _`. That edit touched the exact
  line advisory #2 is about, but only changed the cast; the compare width was
  already `Qword` since `b80e7fe`. The session brushed the line without
  introducing or worsening the bug.
- The recent-ish hardening release `b80e7fe` (explicit opt-in capabilities)
  _reduced_ advisory 2's severity: it made network off-by-default and X11/the
  user bus opt-in, so the advisory's default-configuration PoC no longer fires on
  v2.3.0. Recent work mitigated that advisory rather than causing it.

Where recent work _did_ add attack surface — the proxy, phantom secrets, the
audit log — the new weaknesses are exactly what the two same-day **audits**
found (duplicate-env phantom bypass, release-binary escape hatches, audit-disable,
audit-chain corruption). The two **advisories** are about the older core.
