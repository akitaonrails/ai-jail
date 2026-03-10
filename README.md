# ai-jail

A sandbox wrapper for AI coding agents (Linux: `bwrap`, macOS: `sandbox-exec`). Isolates tools like Claude Code, GPT Codex, OpenCode, and Crush so they can only access what you explicitly allow.

## Install

### Homebrew (macOS / Linux)

```bash
brew tap akitaonrails/tap && brew install ai-jail
```

### cargo install

```bash
cargo install ai-jail
```

### mise

```bash
mise use -g github:akitaonrails/ai-jail
```

### Nix (flake)

```bash
# Run directly without installing
nix run github:akitaonrails/ai-jail

# Install to your profile
nix profile install github:akitaonrails/ai-jail
```

### GitHub Releases

Download prebuilt binaries from the [Releases](https://github.com/akitaonrails/ai-jail/releases) page:

```bash
# Linux x86_64
curl -fsSL https://github.com/akitaonrails/ai-jail/releases/latest/download/ai-jail-linux-x86_64.tar.gz | tar xz
sudo mv ai-jail /usr/local/bin/

# macOS ARM (Apple Silicon)
curl -fsSL https://github.com/akitaonrails/ai-jail/releases/latest/download/ai-jail-macos-aarch64.tar.gz | tar xz
sudo mv ai-jail /usr/local/bin/
```

### From source

```bash
cargo build --release
cp target/release/ai-jail ~/.local/bin/
```

### Dependencies

- Linux: [bubblewrap](https://github.com/containers/bubblewrap) (`bwrap`) must be installed:
  - Arch: `pacman -S bubblewrap`
  - Debian/Ubuntu: `apt install bubblewrap`
  - Fedora: `dnf install bubblewrap`
  - If `bwrap` is in a non-standard location (e.g. Nix store), set `BWRAP_BIN=/absolute/path/to/bwrap`.
  - The Nix flake package already sets `BWRAP_BIN` automatically.
- macOS: `/usr/bin/sandbox-exec` is used (legacy/deprecated Apple interface).

## Quick Start

```bash
cd ~/Projects/my-app

# Run Claude Code in a sandbox
ai-jail claude

# Run bash inside the sandbox (for debugging)
ai-jail bash

# See what the sandbox would do without running it
ai-jail --dry-run claude
```

On first run, `ai-jail` creates a `.ai-jail` config file in the current directory. Subsequent runs reuse that config. Commit `.ai-jail` to your repo so the sandbox settings follow the project.

## Security notes

The default mode favors usability over maximum lockdown. These are intentionally open by default:

1. Docker socket passthrough auto-enables when `/var/run/docker.sock` exists (`--no-docker` disables it).
2. Display passthrough mounts `XDG_RUNTIME_DIR` on Linux, which can expose host IPC sockets.
3. Environment variables are inherited (tokens/secrets in your shell env are visible in-jail).

### Defense-in-depth layers (Linux)

ai-jail applies multiple overlapping security layers:

- **Namespace isolation** (bwrap): PID, UTS, IPC, mount namespaces. Network namespace in lockdown.
- **Landlock LSM** (V3 filesystem + V4 network): VFS-level access control independent of mount namespaces.
- **Seccomp-bpf** syscall filter: blocks ~30 dangerous syscalls (module loading, `ptrace`, `bpf`, namespace escape, etc.). Lockdown blocks additional NUMA/hostname syscalls.
- **Resource limits**: RLIMIT_NPROC (4096/1024 lockdown), RLIMIT_NOFILE (65536/4096 lockdown), RLIMIT_CORE=0. Prevents fork bombs and limits resource abuse.
- **Sensitive /sys masking**: tmpfs overlays hide `/sys/firmware`, `/sys/kernel/security`, `/sys/kernel/debug`, `/sys/fs/fuse`. Lockdown also masks `/sys/module`, `/sys/devices/virtual/dmi`, `/sys/class/net`.

Each layer can be individually disabled (`--no-seccomp`, `--no-rlimits`, `--no-landlock`) if it causes issues.

For hostile/untrusted workloads, use `--lockdown` (see below).

## What this is and isn't

ai-jail is a thin wrapper around OS-level sandboxing, so its security properties depend on the backend:

- `bwrap` (Linux): namespace + mount sandboxing in userspace, plus Landlock LSM for VFS-level access control (Linux 5.13+).
- `sandbox-exec` / seatbelt (macOS): legacy policy interface to Apple sandbox rules.

Some things to keep in mind:

- All backends depend on host kernel correctness. Kernel escapes are out of scope.
- These are process sandboxes, not hardware isolation. A VM runs a separate kernel and gives a stronger boundary.
- Timing/cache side channels and scheduler interference still exist in process sandboxes.
- Linux and macOS primitives are not equivalent; cross-platform policy parity is approximate.
- `sandbox-exec` on macOS is a deprecated interface. It works today but Apple could remove it.

If you need full isolation against unknown malware, use a disposable VM and treat ai-jail as one layer, not the whole story.

## Lockdown mode

`--lockdown` switches to strict read-only, ephemeral behavior for hostile workloads.

```bash
ai-jail --lockdown claude
```

This:

- Mounts the project read-only.
- Disables GPU, Docker, display passthrough, and mise.
- Ignores `--rw-map` and `--map` flags.
- Mounts `$HOME` as bare tmpfs (no host dotfiles).
- Linux: `--clearenv` with minimal allowlist, `--unshare-net`, `--new-session`.
- macOS: clears env to minimal allowlist, strips network and file-write rules from SBPL profile.

Persistence: `--lockdown` alone doesn't write `.ai-jail` (keeps runs ephemeral). Persist it with `ai-jail --init --lockdown`. Undo with `--no-lockdown`.

## What gets sandboxed

### Default behavior (no flags needed)

| Resource | Access | Notes |
|----------|--------|-------|
| `/usr`, `/etc`, `/opt`, `/sys` | read-only | System binaries and config |
| `/dev`, `/proc` | device/proc | Standard device and process access |
| `/tmp`, `/run` | tmpfs | Fresh temp dirs per session |
| `$HOME` | tmpfs | Empty home, then dotfiles layered on top |
| Project directory (pwd) | **read-write** | The whole point |
| GPU devices (`/dev/nvidia*`, `/dev/dri`) | device | For GPU-accelerated tools |
| Docker socket | read-write | If `/var/run/docker.sock` exists |
| X11/Wayland | passthrough | Display server access |
| `/dev/shm` | device | Shared memory (Chromium needs this) |

In `--lockdown`, project is mounted read-only and host write mounts are removed.

### Home directory handling

Your real `$HOME` is replaced with a tmpfs. Dotfiles and dotdirs are selectively layered on top:

**Never mounted (sensitive data):**
- `.gnupg`, `.aws`, `.ssh`, `.mozilla`, `.basilisk-dev`, `.sparrow`

**Mounted read-write (AI tools and build caches):**
- `.claude`, `.crush`, `.codex`, `.aider`, `.config`, `.cargo`, `.cache`, `.docker`

**Everything else:** mounted read-only.

**Hidden behind tmpfs:**
- `~/.config/BraveSoftware`, `~/.config/Bitwarden`
- `~/.cache/BraveSoftware`, `~/.cache/chromium`, `~/.cache/spotify`, `~/.cache/nvidia`, `~/.cache/mesa_shader_cache`, `~/.cache/basilisk-dev`

**Explicit file mounts:**
- `~/.gitconfig` (read-only)
- `~/.claude.json` (read-write)

**Local overrides (read-write):**
- `~/.local/state`
- `~/.local/share/{zoxide,crush,opencode,atuin,mise,yarn,flutter,kotlin,NuGet,pipx,ruby-advisory-db,uv}`

### Namespace isolation

PID, UTS, and IPC namespaces are isolated. Hostname inside is `ai-sandbox`. The process dies when the parent exits (`--die-with-parent`).
`--new-session` is on for non-interactive runs and always in `--lockdown`. In `--lockdown`, Linux also unshares network.

### Landlock LSM (Linux)

On Linux 5.13+, ai-jail applies [Landlock](https://landlock.io/) restrictions as defense-in-depth on top of bwrap. Landlock controls what the process can do at the VFS level, independent of mount namespaces. This closes attack vectors that bwrap alone doesn't cover: `/proc` escape routes, symlink tricks within allowed mounts, and acts as insurance against namespace bugs.

- Uses ABI V3 (Linux 6.2+) for filesystem rules with best-effort degradation to V1 on 5.13+ or no-op on older kernels.
- On Linux 6.5+, a second V4 ruleset adds network restrictions: lockdown mode denies all TCP bind/connect (defense-in-depth alongside `--unshare-net`).
- Applied in the parent process before spawning bwrap, so restrictions inherit through fork+exec.
- In `--lockdown`, Landlock rules are stricter: project is read-only, no home dotdirs, only `/tmp` is writable, no network.
- Disable with `--no-landlock` if it causes issues with specific tools.

### Status bar

Enable a persistent status line on the bottom row of your terminal:

```bash
ai-jail -s claude          # dark theme
ai-jail -s=light claude    # light theme
```

The bar shows the project path, running command, ai-jail version, and a green `↑` when an update is available. It uses a PTY proxy to keep the bar visible even when the child application resets the screen. The preference is stored in `$HOME/.ai-jail` and persists across sessions.

### mise integration

If [mise](https://mise.jdx.dev/) is found on `$PATH`, the sandbox automatically runs `mise trust && mise activate bash && mise env` before your command. This gives AI tools access to project-specific language versions. Disable with `--no-mise`.

## Usage

```
ai-jail [OPTIONS] [--] [COMMAND [ARGS...]]
```

### Commands

| Command | What it does |
|---------|-------------|
| `claude` | Run Claude Code |
| `codex` | Run GPT Codex |
| `opencode` | Run OpenCode |
| `crush` | Run Crush |
| `bash` | Drop into a bash shell |
| `status` | Show current `.ai-jail` config |
| Any other | Passed through as the command |

If no command is given and no `.ai-jail` config exists, defaults to `bash`.

### Options

| Flag | Description |
|------|-------------|
| `--rw-map <PATH>` | Mount PATH read-write (repeatable) |
| `--map <PATH>` | Mount PATH read-only (repeatable) |
| `--lockdown` / `--no-lockdown` | Enable/disable strict read-only lockdown mode |
| `--landlock` / `--no-landlock` | Enable/disable Landlock LSM (Linux 5.13+, default: on) |
| `--seccomp` / `--no-seccomp` | Enable/disable seccomp syscall filter (Linux, default: on) |
| `--rlimits` / `--no-rlimits` | Enable/disable resource limits (default: on) |
| `--gpu` / `--no-gpu` | Enable/disable GPU passthrough |
| `--docker` / `--no-docker` | Enable/disable Docker socket |
| `--display` / `--no-display` | Enable/disable X11/Wayland |
| `--mise` / `--no-mise` | Enable/disable mise integration |
| `-s`, `--status-bar[=light]` | Enable persistent status line (dark or light theme) |
| `--no-status-bar` | Disable persistent status line |
| `--clean` | Ignore existing config, start fresh |
| `--dry-run` | Print the bwrap command without executing |
| `--init` | Create/update config and exit (don't run) |
| `--bootstrap` | Generate smart permission configs for AI tools |
| `-v`, `--verbose` | Show detailed mount decisions |
| `-h`, `--help` | Show help |
| `-V`, `--version` | Show version |

### Examples

```bash
# Share an extra library directory read-write
ai-jail --rw-map ~/Projects/shared-lib claude

# Read-only access to reference data
ai-jail --map /opt/datasets claude

# No GPU, no Docker, just the basics
ai-jail --no-gpu --no-docker claude

# Suspicious/untrusted workload mode
ai-jail --lockdown bash

# See exactly what mounts are being set up
ai-jail --dry-run --verbose claude

# Create config without running
ai-jail --init --no-docker claude

# Regenerate config from scratch
ai-jail --clean --init claude

# Pass flags through to the sub-command (after --)
ai-jail -- claude --model opus
```

## Config file (`.ai-jail`)

Created in the project directory on first run. Example:

```toml
# ai-jail sandbox configuration
# Edit freely. Regenerate with: ai-jail --clean --init

command = ["claude"]
rw_maps = ["/home/user/Projects/shared-lib"]
ro_maps = []
no_gpu = true
lockdown = true
```

### Merge behavior

When CLI flags and an existing config are both present:

- `command`: CLI replaces config
- `rw_maps` / `ro_maps`: CLI values are appended (duplicates removed)
- Boolean flags: CLI overrides config (`--no-gpu` sets `no_gpu = true`)
- Config is updated after merge in normal mode; lockdown skips auto-save

### Available fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `command` | string array | `["bash"]` | Command to run inside sandbox |
| `rw_maps` | path array | `[]` | Extra read-write mounts |
| `ro_maps` | path array | `[]` | Extra read-only mounts |
| `no_gpu` | bool | not set (auto) | `true` disables GPU passthrough |
| `no_docker` | bool | not set (auto) | `true` disables Docker socket |
| `no_display` | bool | not set (auto) | `true` disables X11/Wayland |
| `no_mise` | bool | not set (auto) | `true` disables mise integration |
| `no_landlock` | bool | not set (auto) | `true` disables Landlock LSM (Linux only) |
| `no_seccomp` | bool | not set (auto) | `true` disables seccomp syscall filter (Linux only) |
| `no_rlimits` | bool | not set (auto) | `true` disables resource limits |
| `lockdown` | bool | not set (disabled) | `true` enables strict read-only lockdown mode |

Status bar preferences (`no_status_bar`, `status_bar_style`) are stored in `$HOME/.ai-jail` (global user config), not in per-project `.ai-jail` files.

When a boolean field is not set, the feature is enabled if the resource exists on the host.

## Windows

ai-jail doesn't support Windows natively and probably never will. The sandbox depends on Linux namespaces (via bwrap) and macOS seatbelt profiles (via sandbox-exec). Windows has nothing equivalent in userspace. AppContainers exist but they're a completely different API, need admin privileges for setup, and the security model doesn't map to what bwrap does. A Windows port would be a separate project, not a backend swap.

If you're on Windows, run ai-jail inside WSL 2. WSL 2 runs a real Linux kernel, so bwrap works normally.

### Setup

1. Install WSL 2 if you haven't:

```powershell
wsl --install
```

2. Open your WSL distro (Ubuntu by default) and install bubblewrap:

```bash
sudo apt update && sudo apt install bubblewrap
```

3. Build ai-jail from source inside WSL:

```bash
cd ~/Projects
git clone https://github.com/nicholasgasior/ai-jail.git
cd ai-jail
cargo build --release
cp target/release/ai-jail ~/.local/bin/
```

4. Run it from inside WSL against your project directory:

```bash
cd /mnt/c/Users/you/Projects/my-app
ai-jail claude
```

WSL 2 mounts your Windows drives under `/mnt/c/`, `/mnt/d/`, etc. The sandbox sees the Linux filesystem, so all the mount isolation works as expected. Your Windows files are accessible through those mount points.

One thing to watch: WSL 2 filesystem performance is slower on `/mnt/c/` (the Windows side) than on the native Linux filesystem (`~/`). For large projects, cloning into `~/Projects/` inside WSL instead of working from `/mnt/c/` makes a noticeable difference.

## License

GPL-3.0. See [LICENSE](LICENSE).
