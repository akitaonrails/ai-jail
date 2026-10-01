# Security audit comparison — 2026-09-30

Two independent audits of ai-jail v2.3.0 (`f62d576`) were produced the same day:

- **Audit A** — `docs/SECURITY_AUDIT_2026-09-30.md`
- **Audit B** — `docs/SECURITY_AUDIT_2026-09-30_B.md`

Audit B was produced without reading A until its own candidate list was fixed,
then reconciled against A with every shared lead re-derived from source. This
document reconciles the two. All severities are as each report stated them.

## Found by both (11)

| Finding                                          | A severity | B severity | How confirmed                       |
| ------------------------------------------------ | ---------- | ---------- | ----------------------------------- |
| Forged worktree metadata → arbitrary host dir RW | High       | High       | Empirically, independently, in both |
| Duplicate env entries bypass phantom secret      | High       | High       | Empirically, independently, in both |
| Overlay failure falls back to writable original  | High       | Medium     | Code                                |
| Global-config save drops credential policy       | Medium     | Medium     | Code                                |
| Trusted project config overrides explicit CLI    | Medium     | Medium     | Code                                |
| Update check runs bare `curl` from `PATH`        | High-cond. | Low-cond.  | Code (opt-in; needs PATH control)   |
| Deterministic placeholder leaks / guessable      | Medium/Low | Low        | Empirically in both                 |
| Untrusted project `allow_hosts` cannot shrink    | Medium     | doc-defect | Code                                |
| TIOCSTI seccomp compare uses wrong width         | Medium     | Medium\*   | Empirically                         |
| ESC-ESC primary-screen filter bypass             | Medium     | Medium\*   | Empirically                         |
| Untrusted project can disable audit logging      | Medium     | Medium\*   | Code                                |

\* B initially rejected the TIOCSTI width issue and filed the ESC-ESC bypass and
the audit-disable issue as "needs validation"; all three were confirmed only
after A's leads prompted a re-derivation. Recorded as false negatives in B.

The two High findings were reproduced independently by both audits, which is the
strongest available signal that they are real.

## Found only by audit A (11)

Plausible, and several judged genuine in B's reconciliation; B simply did not
reach them.

- **Redirected stdout leaves terminal stderr unfiltered** (Medium) — TTY-matrix
  gap B never examined.
- **Unbounded OSC accumulation in the vt100 parser** (Medium) — availability.
- **Proxy/bridge resource limits incomplete** (Medium) — threads spawned before
  admission, no absolute deadlines, half-close retention. B reviewed the
  256-connection cap and stopped.
- **HTTP-termination ambiguous framing** (Low) — B had _rejected_ smuggling
  outright; A's framing-hygiene framing is the better call.
- **Separate-process audit-chain corruption** (Medium) — B rejected only the
  same-handle case and missed the cross-process one.
- **Audit log has no growth/rate bound; lockdown `FSIZE` can `SIGXFSZ` the
  supervisor** (Medium) — B confirmed the 1 GiB `FSIZE_LOCKDOWN` limit exists but
  did not connect it to audit growth.
- **Only one secret binding selected per host** (Low functional).
- **Project config FIFO / oversized file blocks or exhausts supervisor before
  sandboxing** (Medium) — DoS B missed.
- **macOS: `/dev/ttys*` all readable/writable** (Medium, native validation).
- **macOS: masks do not consistently deny writes** (Medium, native validation).
- **macOS: agent-state passthrough overrides `hide_dotdirs`** (Medium).
- **macOS: predictable, reused session temp dir** (Medium, native validation).

(The four macOS items require a Mac, which B did not have.)

## Found only by audit B (3)

- **[Medium] Test-only escape hatches live in the release binary.**
  `AI_JAIL_TEST_PROXY_ALLOW_PRIVATE` (disables the SSRF address-range guard) and
  `AI_JAIL_TEST_PROXY_EXTRA_ROOTS` (injects a TLS trust root) are read from the
  process environment and are present in `strings` of the shipped release binary;
  neither is `cfg(test)`-gated. A did not report this. It is the most
  consequential item unique to either report: the environment is an unclosed
  control channel over the exact secret path phantom credentials are meant to
  protect.
- **[Low] `--env KEY=VALUE` visible in `/proc/<pid>/cmdline`** — confirmed
  empirically; other local users can read it.
- **[Doc] `RELEASE_SECURITY.md` omits the attestation / `id-token` step** the
  release workflow now runs.

## Which did better

**Audit A is the stronger report.** It surfaced roughly 11 substantiated issues
B missed — including the entire macOS surface and the proxy availability class —
and its severity calls were generally sharper (overlay fallback and update-check
as High). It also corrected two outright errors in B: B _rejected_ the TIOCSTI
width bug and filed the ESC-ESC bypass and audit-disable issue as unresolved
rather than confirming them.

**B was stronger in two narrow ways:** it found the release-binary escape hatches
A missed (one real Medium), and it was more empirical on the shared findings —
running the worktree, duplicate-env, TIOCSTI, and ESC-ESC exploits rather than
reasoning about them.

**Net:** the union of the two reports is the list to fix; neither alone is
complete. The release should block on the shared worktree and duplicate-env
Highs, the overlay-fallback High, and B's escape-hatch Medium. The value of
running two independent audits is exactly the two errors the cross-check caught.
