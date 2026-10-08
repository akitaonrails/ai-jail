# Windows port assessment

Research note (2026-10-08) on whether Microsoft's
[LiteBox](https://github.com/microsoft/litebox) is useful for a Windows build
of ai-jail, and what a Windows backend should use instead.

## TL;DR

**Do not integrate LiteBox.** It solves a different problem (a Linux library
OS, for running Linux programs on other platforms and for confidential
computing), not host-process accident-guarding on Windows. For Windows,
support **WSL2 + the existing Linux backend** first (zero new code); if a
native backend is later warranted, build it on Windows OS primitives
(AppContainer, Job Objects + a restricted token, Windows Sandbox), not a
LibOS.

## What ai-jail needs from a backend

ai-jail is a thin wrapper that execs an OS sandbox around a **native** command
(`claude`, `codex`, ...) and then gets out of the way (PTY proxy). A backend
must:

- confine a native host process (the harness is a native Node/CLI app);
- enforce a **host-filesystem access policy** — read-only binds, a read-write
  project directory as the blast radius, hidden credential/state paths;
- restrict network to off / filtered / full;
- be a thin confinement the real command runs under, not a runtime that
  re-implements the program's execution.

On Linux this is bubblewrap namespaces + Landlock + seccomp; on macOS it is
`sandbox-exec` (seatbelt).

## What LiteBox is

LiteBox is a **security-focused library OS** (gVisor/Gramine family), written
in Rust, **MIT-licensed**. It exposes a "North" interface — a Rust
`nix`/`rustix`-style **Linux syscall API** that guest programs target — over a
pluggable "South" `Platform`: Linux kernel, Linux userland, Windows userland,
LVBS (Linux VBS), OP-TEE, SEV-SNP. Its stated use cases are running
_unmodified Linux programs_ on those platforms (including "Linux programs on
Windows") plus confidential-computing targets.

Mechanically it **intercepts and emulates Linux syscalls**
(`litebox_syscall_rewriter`, `litebox_shim_linux`) and services them through
its own emulated filesystem and the chosen platform. It is explicitly early
and unstable ("some APIs and interfaces may change"), and Windows support is
x86-64 only.

## Why it does not fit a Windows ai-jail

1. **It sandboxes Linux programs, not native host processes.** LiteBox _is_ the
   runtime — it loads a Linux ELF and emulates its syscalls. A Windows ai-jail
   needs to confine a **native Windows** harness. LiteBox has no mechanism for
   that; it would be a different product (a Linux LibOS host), not a Windows
   backend behind ai-jail's existing `discover mounts -> build confinement ->
exec` shape.

2. **The Windows platform is explicitly not an isolation boundary.** The
   `litebox_platform_windows_userland` crate documents: _"The guest shares the
   host process's address space, so this platform does not isolate host memory
   from the guest: guest code or fixed-address mappings can read or overwrite
   it."_ Even for ai-jail's modest accident-guard bar, that is the wrong
   primitive.

3. **No host-filesystem access policy.** ai-jail's core is _host_-path
   allow/deny. LiteBox's read-only-filesystem semantics live in its **emulated
   guest filesystem**, not a policy over real Windows paths. There is nothing
   to map ai-jail's `--map`/`--rw-map`/mount-order model onto.

4. **Maturity and scope mismatch.** Early and explicitly unstable, x86-64 only
   on Windows, some runners need a nightly toolchain and custom targets. The
   project targets LibOS portability and confidential computing, not developer
   accident-guarding.

MIT + Rust means LiteBox is _technically_ linkable, but license and language
were never the obstacle — the architecture is.

## What a Windows backend should use instead

- **Fastest, highest-leverage: WSL2 + the existing Linux backend.** The
  bubblewrap + Landlock + seccomp path already works; a Windows user running
  the agent inside WSL2 gets the real sandbox today with no new ai-jail code.
  Worth documenting as the recommended Windows path.
- **Native Windows backend (only if warranted):** the OS primitives that match
  ai-jail's model are **AppContainer** (per-capability plus filesystem-ACL
  confinement), **Job Objects** with a **restricted / low-integrity token**,
  and for a stronger disposable blast radius **Windows Sandbox** (with mapped
  folders). That would be a new `src/sandbox/windows.rs` backend alongside
  `bwrap.rs` and `seatbelt.rs`, reusing the existing mount-discovery model to
  derive the confinement. A real project, but it fits the current
  architecture — unlike a LibOS.

## Conclusion

LiteBox is interesting for running Linux workloads on Windows or on TEEs, but
it is not a fit for sandboxing a native Windows AI harness. Recommend WSL2 as
the near-term Windows story and, if ever needed, a native AppContainer /
Job-Object backend rather than a library OS.
