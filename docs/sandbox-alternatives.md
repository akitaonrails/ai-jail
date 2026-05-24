# Why bwrap, and what else we looked at

**Date**: March 2026
**Decision**: Stick with bubblewrap. Maybe add Landlock later as a second layer.

## What we need from the sandbox

ai-jail wraps AI coding agents (Claude Code, Codex, OpenCode, Crush) so they can only touch what you allow. That means:

- Unprivileged operation (no root, no sudo)
- PID, UTS, IPC, and optionally network namespaces
- Bind-mounting host paths (ro or rw) into the sandbox
- Custom hostname and /etc/hosts
- Environment variable control
- Linux first, macOS second (via sandbox-exec)

## Why bwrap wins

bwrap runs unprivileged via `CLONE_NEWUSER`. No setuid, no root. Flatpak uses it for sandboxed desktop apps on Linux, so it is heavily exercised in the real world. It's a single static binary (~50KB, ~4K lines of C), maintained by the GNOME/Flatpak team. It handles PID/UTS/IPC/net namespaces, bind mounts, tmpfs, symlinks, env control, and `--die-with-parent`. Every major distro packages it.

For this use case, nothing else fits as well.

## What else we looked at

### Rust libraries

**Landlock** (`landlock` crate v0.4) -- Linux Security Module, kernel 5.13+. Restricts filesystem access per-path and (since kernel 6.2) network bind/connect per-port. Works unprivileged. But it can't create namespaces, can't do bind mounts, can't set a custom hostname. It restricts what syscalls can do, not the environment the process sees.

| Capability | Support |
|---|---|
| Filesystem restriction (per-path) | Yes (kernel 5.13+) |
| Network restriction (per-port) | Yes (kernel 6.2+) |
| Unprivileged | Yes |
| PID/UTS/IPC namespaces | No |
| Bind mounts | No |
| Custom hostname / /etc/hosts | No |
| macOS | No |

It cannot replace bwrap, but it makes a good second barrier. If bwrap's namespace setup ever has a bug, Landlock still gives kernel-level enforcement. About 50 lines of Rust to add, and it degrades cleanly on older kernels. Worth doing eventually.

**Birdcage** (`birdcage` crate, Phylum) -- wraps Landlock on Linux and sandbox-exec on macOS behind one API. The cross-platform part is appealing, but it's designed for restricting the calling process, not for launching a child in an isolated environment with custom mounts. Doesn't fit our execution model.

| Capability | Support |
|---|---|
| Filesystem restriction | Yes |
| Network restriction | Partial |
| Unprivileged | Yes |
| Namespaces | No |
| Bind mounts | No |
| Cross-platform | Yes (Linux + macOS) |

**Extrasafe** (`extrasafe` crate) -- friendly Rust API over seccomp-bpf. Filters which syscalls a process can make. Complementary to namespaces, not a replacement. bwrap already drops capabilities and sets `PR_SET_NO_NEW_PRIVS`, so the marginal benefit is small for the added complexity.

**Pure Rust reimplementation via `nix`** -- we already depend on `nix`, which exposes `clone()`, `mount()`, `pivot_root()`, `sethostname()`, `unshare()`. So we could, in theory, reimplement bwrap in Rust.

Pros: no external binary, single-binary distribution, full control.

Cons: bwrap handles a lot of edge cases -- UID/GID mapping via `/proc/PID/uid_map`, capability bounding sets, `PR_SET_NO_NEW_PRIVS`, mount propagation flags, cleanup on signal. That's 500+ lines of security-sensitive code we'd have to maintain, test across kernel versions and distros, and patch ourselves. bwrap gets upstream security fixes; ours would not. The bwrap binary is ~50KB, so the dependency cost is basically nothing.

Not worth it unless we specifically need to ship a single static binary with zero external deps.

### External tools

**Firejail** -- has all the capabilities we need, but it's a setuid root binary. Bigger attack surface by design. Multiple CVEs are tied to that approach (CVE-2022-31214, etc.). bwrap's unprivileged `CLONE_NEWUSER` model is safer for this project. Rejected.

**nsjail** (Google) -- capable, but config-file driven (protobuf), designed for server workloads and CTF infrastructure. Overkill for wrapping a CLI process. Less widely packaged.

**minijail** (Google/ChromeOS) -- ChromeOS-focused, not in standard repos, designed for system services rather than user-facing tools.

**systemd-run / systemd-nspawn** -- requires systemd. Doesn't work in containers or on non-systemd systems. `--user` mode has limited namespace support. Not portable enough.

None of these beat bwrap for our use case.

## Decision

We use bwrap on Linux and sandbox-exec on macOS.

sandbox-exec is deprecated Apple API, but nothing better exists on macOS without kernel extensions. It works.

If we add anything, it should be Landlock as a second layer: apply restrictions after fork, before exec, limiting the child to only the paths bwrap bind-mounts. That gives a kernel-enforced barrier in ~50 lines of Rust and degrades cleanly on kernels < 5.13.

## References

- bubblewrap: https://github.com/containers/bubblewrap
- Landlock: https://landlock.io / https://docs.rs/landlock
- Birdcage: https://github.com/phylum-dev/birdcage
- Extrasafe: https://docs.rs/extrasafe
- nsjail: https://github.com/google/nsjail
- Firejail CVE-2022-31214: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-31214
