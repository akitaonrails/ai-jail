# ai-jail

A sandbox wrapper for AI coding agents (Linux: `bwrap`, macOS: `sandbox-exec`). Run Claude Code, GPT Codex, OpenCode, Crush, and similar tools with access only to the paths you allow.

## Install

### Homebrew (macOS / Linux)

```bash
brew tap akitaonrails/tap && brew install ai-jail
```

### Arch Linux (AUR)

Two project-maintained AUR packages are available. Pick one:

```bash
yay -S ai-jail-bin    # prebuilt Linux x86_64 binary from GitHub Releases
yay -S ai-jail        # builds from source with your local Rust toolchain
```

The `-bin` variant is fastest and installs the same Linux x86_64 binary built by CI. The source variant compiles locally and is the right choice for Arch Linux ARM/aarch64. Both packages depend on `bubblewrap` and install the `ai-jail` binary to `/usr/bin/`. The project owns the AUR package bases, and packaging is tracked in `packaging/aur/`.

### cargo install

```bash
cargo install ai-jail
```

### mise

```bash
# Install the latest release globally
mise use -g github:akitaonrails/ai-jail

# Pin an exact release globally
mise use -g github:akitaonrails/ai-jail@1.4.0
```

Use the version as mise reports it (`1.4.0`), not the Git tag shorthand (`v1.4`). If a just-published release does not appear yet, clear mise's GitHub release cache first:

```bash
mise cache clear
mise ls-remote github:akitaonrails/ai-jail
mise use -g github:akitaonrails/ai-jail@1.4.0
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

#### Ubuntu 24.04+ / Debian 13+ users

These distros ship an AppArmor policy that denies unprivileged user namespace creation, which is how `bwrap` isolates the sandbox. If `ai-jail` fails with `bwrap: setting up uid map: Permission denied`, you need to either relax the system-wide restriction or install a local AppArmor profile for `bwrap`. This affects every tool that uses rootless user namespaces (Distrobox, rootless Podman, Flatpak from non-standard paths, etc.), not just ai-jail.

Option A — relax the restriction system-wide (simplest):

```bash
echo 'kernel.apparmor_restrict_unprivileged_userns=0' \
  | sudo tee /etc/sysctl.d/60-userns.conf
sudo sysctl --system
```

Option B — install an unconfined profile for `bwrap` only (keeps the rest of the policy intact):

```bash
sudo tee /etc/apparmor.d/bwrap >/dev/null <<'EOF'
abi <abi/4.0>,
include <tunables/global>
profile bwrap /usr/bin/bwrap flags=(unconfined) {
  userns,
  include if exists <local/bwrap>
}
EOF
sudo systemctl reload apparmor
```

Pick whichever matches your threat model. We don't ship a profile with ai-jail itself because the profile has to apply to `bwrap`, which is system-owned.

## Upgrade

```bash
# Homebrew
brew update && brew upgrade ai-jail

# cargo install
cargo install ai-jail --force

# mise
mise cache clear
mise upgrade github:akitaonrails/ai-jail
# or pin a specific release:
mise use -g github:akitaonrails/ai-jail@1.4.0

# Old releases used mise's ubi backend; remove that separate install if present:
mise unuse -g ubi:akitaonrails/ai-jail
mise uninstall ubi:akitaonrails/ai-jail --all

```

After a mise upgrade, open a new shell or refresh your command cache if the old binary still resolves (`rehash` in zsh, `hash -r` in bash).

For Nix profile installs, run `nix profile list` and upgrade the profile entry that contains `github:akitaonrails/ai-jail`.

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

On first run, `ai-jail` creates a `.ai-jail` config file in the current directory by default. Later runs reuse it. Commit `.ai-jail` to your repo if the sandbox policy belongs to the project. `--dry-run` is read-only and does not create or update config. Use `--no-save-config` for one-off real runs that should not persist config.

If you run `ai-jail` from a linked Git worktree, it auto-detects the worktree's external Git admin directories and exposes them safely inside the sandbox so `git status`, `git commit`, and similar commands keep working. Disable this with `--no-worktree` or `no_worktree = true`.

> ⚠️ **Only the current project directory is persistent by default.** Parent directories, sibling directories, `$HOME`, and `/tmp` live in tmpfs and are wiped when ai-jail exits. If the agent creates a sibling scaffold, clones into your home directory, or writes under `~/.cache`, that work disappears unless you push it, copy it back into the project, or expose the path with `--rw-map ~/path`. The agent cannot tell from inside the sandbox; the filesystem looks writable.

## Security notes

The default mode favors usability over maximum lockdown. These are intentionally open by default:

1. Docker socket passthrough auto-enables when `/var/run/docker.sock` exists (`--no-docker` disables it). On WSL 2 with Docker Desktop, ai-jail also exposes Docker Desktop's WSL CLI tools directory when present so the injected `docker` symlink keeps working.
2. Display passthrough mounts `XDG_RUNTIME_DIR` on Linux, which can expose host IPC sockets.
3. Environment variables are inherited (tokens/secrets in your shell env are visible in-jail).

**Hiding project-level secrets**: the project directory is mounted in its entirety, so files like `.env`, `credentials.json`, or `secrets.yml` are visible to whatever runs inside. Use `--mask PATH` to replace them with empty files inside the sandbox, or `--deny-path PATH` when you want reads/listing/writes to fail with permission denied. Both options accept glob patterns (`*`, `?`, `[a-z]`, and recursive `**`) that are expanded when the sandbox policy is built. Examples:

```bash
ai-jail --mask .env --mask .env.local claude
ai-jail --mask '**/*.env' claude
ai-jail --deny-path .env --deny-path 'secrets/*.json' claude
```

Or persist the list in `.ai-jail`:

```toml
mask = [".env", ".env.local", "credentials.json", "**/*.env"]
deny_paths = ["secrets/*.json"]
```

Glob masks/denies match existing files/directories only. Unmatched patterns are skipped with a warning, just like missing literal paths. Quote glob patterns in your shell so ai-jail receives the pattern instead of your shell expanding it first. Prefer `--deny-path` / `deny_paths` for project secrets when agents should see permission denied instead of an empty placeholder.

**Hiding the sandbox policy itself**: by default, ai-jail auto-masks the project's own `.ai-jail` config file inside the sandbox so the agent can't read its own policy and craft workarounds. Pass `--no-hide-config` (or set `no_hide_config = true`) if you need the file visible to the sandboxed process for some reason. The user's global `~/.ai-jail` is never mounted into the sandbox.

**Hiding machine identifiers**: `/etc/machine-id` and `/var/lib/dbus/machine-id` are stable, unique identifiers for the host. Agents that phone home for telemetry, error reports, or feature flags often read these to fingerprint the device. If you'd rather not let the sandboxed process see them, mask them per-run:

```bash
ai-jail --mask /etc/machine-id --mask /var/lib/dbus/machine-id grok
```

Or persist in `.ai-jail`:

```toml
mask = ["/etc/machine-id", "/var/lib/dbus/machine-id"]
```

This is opt-in because some software fails outright when the IDs are absent (notably some D-Bus services). Most CLI agents read them only for telemetry and degrade gracefully.

**Host `systemd --user` bus**: `--systemd-user` (or `systemd_user = true`) exposes the host user bus so tools like `systemd-run --user` can talk to the host user manager. This is dangerous: a sandboxed agent can ask the host user manager to start services outside the sandbox. It is off by default and only works in normal Linux mode. With `--no-display`, ai-jail bind-mounts only `$XDG_RUNTIME_DIR/bus` and `$XDG_RUNTIME_DIR/systemd/private`; with display enabled, `$XDG_RUNTIME_DIR` may already be exposed for Wayland/display IPC, so ai-jail only adds the bus environment. In browser profile mode, `--systemd-user` is skipped and ai-jail overlays permission-denied placeholders on the known user-bus sockets when display passthrough exposed `$XDG_RUNTIME_DIR`.

**Private home mode**: use `--private-home` when you want the project writable
but do not want normal host dotdirs like `~/.config`, `~/.cache`, `~/.local`,
or AI tool state mounted into the sandbox. Explicit mounts still apply.
On Linux, this uses a tmpfs `$HOME`; on macOS, seatbelt rules deny normal
host-home reads/writes instead.

```bash
ai-jail --private-home claude
ai-jail --private-home --rw-map ~/Downloads/test-data bash
```

### Defense-in-depth layers (Linux)

ai-jail uses several security layers:

- **Namespace isolation** (bwrap): PID, UTS, IPC, mount namespaces. Network namespace in lockdown.
- **Landlock LSM** (V3 filesystem + V4 network): VFS-level access control independent of mount namespaces.
- **Seccomp-bpf** syscall filter: blocks ~30 dangerous syscalls (module loading, `ptrace`, `bpf`, namespace escape, etc.). Lockdown blocks additional NUMA/hostname syscalls.
- **Resource limits**: RLIMIT_NPROC (4096/1024 lockdown), RLIMIT_NOFILE (65536/4096 lockdown), RLIMIT_CORE=0. Prevents fork bombs and limits resource abuse.
- **Sensitive /sys masking**: tmpfs overlays hide `/sys/firmware`, `/sys/kernel/security`, `/sys/kernel/debug`, `/sys/fs/fuse`. Lockdown also masks `/sys/module`, `/sys/devices/virtual/dmi`, `/sys/class/net`.

You can disable individual layers (`--no-seccomp`, `--no-rlimits`, `--no-landlock`) if a tool needs it.

For hostile/untrusted workloads, use `--lockdown` (see below).

## What this is and isn't

ai-jail is a thin wrapper around OS-level sandboxing, so its security properties depend on the backend:

- `bwrap` (Linux): namespace + mount sandboxing in userspace, plus Landlock LSM for VFS-level access control (Linux 5.13+).
- `sandbox-exec` / seatbelt (macOS): legacy policy interface to Apple sandbox rules.

Keep these limits in mind:

- All backends depend on host kernel correctness. Kernel escapes are out of scope.
- These are process sandboxes, not hardware isolation. A VM runs a separate kernel and gives a stronger boundary.
- Timing/cache side channels and scheduler interference still exist in process sandboxes.
- Linux and macOS primitives are not equivalent; cross-platform policy parity is approximate.
- `sandbox-exec` on macOS is a deprecated interface. It works today but Apple could remove it.

If you are dealing with unknown malware, use a disposable VM. Treat ai-jail as one layer, not the whole boundary.

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
- Still exposes validated linked Git worktree metadata read-only when needed, so read-only Git operations can work from linked worktrees.
- Linux: `--clearenv` with minimal allowlist, `--unshare-net`, `--new-session`.
- macOS: clears env to minimal allowlist, strips network and file-write rules from SBPL profile.

Persistence: `--lockdown` alone doesn't write `.ai-jail` (keeps runs ephemeral). Persist it with `ai-jail --init --lockdown`. Undo with `--no-lockdown`.

`--init` always writes config, so it cannot be combined with `--no-save-config`.

## Browser profiles

ai-jail can run browsers in an isolated browser profile. Browser commands are auto-detected for Chromium, Chrome, Brave, Firefox, and LibreWolf, or you can opt in explicitly:

```bash
ai-jail chromium              # auto: hard browser profile
ai-jail --browser chromium    # explicit hard profile
ai-jail --browser=soft firefox
ai-jail --no-browser chromium # disable browser auto-profile
```

Both browser profiles avoid your real host browser profiles. They use a private `$HOME`, mount the project read-only, and skip SSH keys, Docker, linked worktree metadata, extra maps, mise, config auto-save, and the terminal status bar. Display and network stay enabled so the browser can open and navigate sites.

- **Hard profile** (`--browser` / `--browser=hard`): all browser config, cache, history, cookies, extension state, and sessions live under sandbox tmpfs paths and disappear when the browser exits.
- **Soft profile** (`--browser=soft`): browser state survives only under `~/.local/share/ai-jail/browsers/<browser>`, so future ai-jail browser sessions can keep logins and history without touching `~/.config/chromium`, `~/.mozilla`, or other real browser profiles.

Chromium-family browsers run with Chromium's internal sandbox disabled inside ai-jail because the Chromium zygote/setuid sandbox does not work reliably through the bwrap/user namespace setup. The containment boundary is ai-jail's bwrap mount/process namespace plus Landlock/seccomp, not Chromium's own sandbox. Browser profiles also disable browser GPU acceleration by default to avoid probing unmapped DRM devices; pass `--gpu` if you want ai-jail to expose GPU devices and leave Chromium GPU acceleration enabled.

Expected Chromium terminal noise: D-Bus, systemd, UPower, Google Cloud Messaging, and EGL/WebGPU warnings can appear because browser profiles deliberately do not expose the host system bus or full desktop session. These messages are usually harmless if the browser window works. `--gpu` may add EGL/WebGPU capability warnings; omit `--gpu` for the quieter default software path.

This is meant for testing suspect extensions or websites without giving them read-write access to your normal home directory or browser profile. It is not anonymity: the browser still has network access, sites can fingerprint it, and anything you log into can identify you.

### Desktop launcher

Linux desktops can launch Chromium through ai-jail with a normal `.desktop` file. The repo includes a copyable example at `dist/desktop/ai-jail-chromium.desktop`:

```ini
[Desktop Entry]
Type=Application
Name=Chromium (ai-jail)
GenericName=Sandboxed Web Browser
Comment=Run Chromium inside ai-jail with an isolated persistent browser profile
Exec=ai-jail-chromium %U
Icon=chromium
Terminal=false
Categories=Network;WebBrowser;
MimeType=text/html;text/xml;application/xhtml+xml;x-scheme-handler/http;x-scheme-handler/https;
Keywords=ai-jail;sandbox;chromium;browser;private;
StartupNotify=true
StartupWMClass=chromium
```

Install it for your user:

```bash
mkdir -p ~/.local/bin
cp dist/desktop/ai-jail-chromium ~/.local/bin/
chmod +x ~/.local/bin/ai-jail-chromium

mkdir -p ~/.local/share/applications
cp dist/desktop/ai-jail-chromium.desktop ~/.local/share/applications/
chmod +x ~/.local/share/applications/ai-jail-chromium.desktop
desktop-file-edit --set-key=Exec \
  --set-value="$HOME/.local/bin/ai-jail-chromium %U" \
  ~/.local/share/applications/ai-jail-chromium.desktop
update-desktop-database ~/.local/share/applications
```

The wrapper adds `~/.local/share/mise/shims` to `PATH`, so mise-installed ai-jail works even when the launcher does not inherit your shell environment. It also launches from `~/.local/share/ai-jail/browser-launcher-cwd`; otherwise ai-jail may treat your whole home directory as the browser's project.

Change the wrapper command to `exec ai-jail --browser=hard chromium "$@"` if desktop-launched Chromium should always be throwaway. If your launcher caches applications, restart it after installing; on Omarchy/Walker, run `omarchy-restart-walker` or log out and back in.

## What gets sandboxed

### Default behavior (no flags needed)

| Resource | Access | Notes |
|----------|--------|-------|
| `/usr`, `/etc`, `/opt`, `/sys` | read-only | System binaries and config |
| `/dev`, `/proc` | device/proc | Standard device and process access |
| `/tmp`, `/run` | tmpfs | Fresh temp dirs per session |
| `$HOME` | tmpfs | Empty home, then dotfiles layered on top |
| Project directory (pwd) | **read-write** | The whole point |
| Linked Git worktree metadata | auto passthrough | Validated `.git` gitfile targets are mounted when the current directory is a linked worktree |
| GPU devices (`/dev/nvidia*`, `/dev/dri`) | device | For GPU-accelerated tools |
| Docker socket | read-write | If `/var/run/docker.sock` exists |
| X11/Wayland | passthrough | Display server access |
| `/dev/shm` | device | Shared memory (Chromium needs this) |

In `--lockdown`, project is mounted read-only and host write mounts are removed. For linked Git worktrees, validated external Git metadata is still exposed read-only unless disabled with `--no-worktree`.

In browser profile mode, the project is mounted read-only, `$HOME` is private tmpfs, normal host dotdirs are not mounted, and soft browser state is the only persistent browser-specific write mount.

In `--private-home` mode, normal host dotdirs are not exposed, but the project remains read-write and explicit `--map` / `--rw-map` mounts still work. On Linux this is a private tmpfs `$HOME`; on macOS it is enforced with seatbelt read/write allowlists because `sandbox-exec` cannot create a replacement home mount. This is useful for non-agent or experimental workloads where you want normal project access without exposing your real `~/.config`, `~/.cache`, or tool state.

### Home directory handling

Your real `$HOME` is replaced with a tmpfs. Dotfiles and dotdirs are selectively layered on top:

Pass `--private-home` or set `private_home = true` to skip this automatic dotdir layering entirely. `--ssh`, `--pictures`, `--map`, and `--rw-map` remain explicit opt-ins. On macOS, `sandbox-exec` does not provide tmpfs mounts, so ai-jail approximates this by denying normal host-home reads and writes.

**Never mounted (sensitive data):**
- `.gnupg`, `.aws`, `.ssh`, `.mozilla`, `.basilisk-dev`, `.sparrow`

**Mounted read-write (AI tools and build caches):**
- `.gemini`, `.claude`, `.crush`, `.codex`, `.aider`, `.soulforge`, `.grok`, `.agents`, `.omp`, `.pi`, `.pi-lens`, `.config`, `.cargo`, `.cache`, `.docker`

**Everything else:** mounted read-only.

**Hidden behind tmpfs:**
- `~/.config/BraveSoftware`, `~/.config/Bitwarden`
- `~/.cache/BraveSoftware`, `~/.cache/chromium`, `~/.cache/spotify`, `~/.cache/nvidia`, `~/.cache/mesa_shader_cache`, `~/.cache/basilisk-dev`

**Explicit file mounts:**
- `~/.gitconfig`, `~/.gitignore` (read-only) — git identity and global excludes
- `$XDG_CONFIG_HOME/git/` (read-only, falls back to `~/.config/git/`) — Git's XDG-style global config/ignore/attributes
- `~/.claude.json` (read-write)
- Validated linked Git worktree admin dirs outside the project tree (auto, same-path passthrough)

**Local overrides (read-write):**
- `~/.local/state`
- `~/.local/share/{zoxide,crush,opencode,atuin,mise,yarn,flutter,kotlin,NuGet,pipx,ruby-advisory-db,uv}`

### Namespace isolation

PID, UTS, and IPC namespaces are isolated. Hostname inside is `ai-sandbox`. The process dies when the parent exits (`--die-with-parent`).
`--new-session` is on for non-interactive runs and always in `--lockdown`. In `--lockdown`, Linux also unshares network.

### Landlock LSM (Linux)

On Linux 5.13+, ai-jail applies [Landlock](https://landlock.io/) restrictions on top of bwrap. Landlock controls filesystem access at the VFS level, independent of mount namespaces. It narrows damage from `/proc` escape routes, symlink tricks inside allowed mounts, and namespace bugs.

- Uses ABI V3 (Linux 6.2+) for filesystem rules with best-effort degradation to V1 on 5.13+ or no-op on older kernels.
- On Linux 6.5+, a second V4 ruleset adds network restrictions: lockdown mode denies all TCP bind/connect (defense-in-depth alongside `--unshare-net`).
- Applied after bwrap namespace setup via an internal wrapper, so Landlock sees the final sandbox mount layout.
- In `--lockdown`, Landlock rules are stricter: project is read-only, no home dotdirs, only `/tmp` is writable, no network.
- Disable with `--no-landlock` if it causes issues with specific tools.

### Status bar

Enable a persistent status line on the bottom row of your terminal:

```bash
ai-jail -s claude          # dark theme
ai-jail -s=light claude    # light theme
```

The bar shows the project path, running command, ai-jail version, and a green `↑` when an update is available. It uses a PTY proxy so it can stay visible even when the child application resets the screen. The preference is stored in `$HOME/.ai-jail` and persists across sessions.

**Why it exists**: when you run several AI CLI agents in parallel, one per terminal window or split, it's easy to lose track of which window belongs to which project. The status bar keeps the project path and command visible so you don't paste the wrong context into the wrong agent.

**Auto-disabled inside tmux and zellij.** Those tools already render a persistent status line and already own the terminal; ai-jail's PTY proxy is redundant and causes conflicts (nested PTYs, resize flicker, lost keyboard-protocol sequences, no Secure Input propagation). When ai-jail detects `$TMUX` or `$ZELLIJ` in the environment it silently skips the status bar and takes the direct-spawn path, letting the multiplexer drive the terminal. To force the ai-jail bar on anyway, pass `-s` explicitly or set `no_status_bar = false` in `~/.ai-jail`.

When running `codex` through the PTY proxy, ai-jail also injects a redraw key on terminal resize to force the app to repaint at the new width. The default is `ctrl-shift-l` for codex sessions. In practice, terminals collapse shifted control letters, so `ctrl-shift-l` and `ctrl-l` send the same control byte to the app.

Override or disable that global behavior in `$HOME/.ai-jail`:

```toml
status_bar_style = "pastel"
resize_redraw_key = "ctrl-l"
# or:
# resize_redraw_key = "disabled"
```

### mise integration

If [mise](https://mise.jdx.dev/) is found on `$PATH`, the sandbox automatically runs `mise trust && mise activate bash && mise env` before your command. This gives AI tools access to project-specific language versions. Disable with `--no-mise`.

## Usage

```
ai-jail [OPTIONS] [--] [COMMAND [ARGS...]]
```

### Commands

| Command | What it does |
|---------|-------------|
| `gemini` | Run Gemini CLI |
| `claude` | Run Claude Code |
| `codex` | Run GPT Codex |
| `opencode` | Run OpenCode |
| `crush` | Run Crush |
| `pi` | Run Pi CLI |
| `bash` | Drop into a bash shell |
| `status` | Show current `.ai-jail` config |
| Any other | Passed through as the command |

If no command is given and no `.ai-jail` config exists, defaults to `bash`.

### Options

| Flag | Description |
|------|-------------|
| `--rw-map <PATH>` | Mount PATH read-write (repeatable). Relative paths and `..` are resolved against the project directory, so `--rw-map ../sister-project` works from a project root. Mapping `/` is refused; map explicit subpaths instead. |
| `--map <PATH>` | Mount PATH read-only (repeatable). Same path resolution as `--rw-map`. Mapping `/` is refused; map explicit subpaths instead. |
| `--overlay-map <PATH>` | Mount PATH **copy-on-write** (repeatable). The agent sees PATH read-write, but writes land on a side layer under `<project>/.ai-jail-overlays/` while PATH itself is never modified — so you can diff and selectively promote changes afterwards. Opt-in only. Linux/bwrap only; degrades to **read-only** (with a warning) on macOS, and is disabled under `--lockdown` / browser mode. See [Overlay maps](#overlay-maps). |
| `--hide-dotdir <NAME>` | Never bind-mount the named home dotdir into the sandbox (e.g. `.my_secrets`). Leading dot is optional. Repeatable. Cannot hide dotdirs required for tool operation (`.cargo`, `.config`, `.cache`, etc.) — those emit a warning and stay visible. |
| `--mask <PATH\|GLOB>` | Replace `PATH` or glob matches inside the sandbox with an empty file (or empty tmpfs if the path is a directory). Relative paths resolve against the project directory. Repeatable. Supports `*`, `?`, `[a-z]`, and recursive `**`; quote glob masks in your shell. Useful for hiding sensitive files like `.env`, `**/*.env`, `credentials.json` from AI agents while keeping the rest of the project accessible. Missing paths/unmatched globs are skipped with a warning. |
| `--deny-path <PATH\|GLOB>` | Deny access to `PATH` or glob matches with permission denied instead of showing empty placeholders. Relative paths resolve against the project directory. Repeatable. Supports the same glob syntax as `--mask`. Recommended for project secrets when agents should not be able to read, list, or overwrite them. |
| `--allow-tcp-port <PORT>` | Permit outbound TCP to PORT in lockdown mode (repeatable). Skips `--unshare-net` and uses Landlock V4 `NetPort` rules to deny everything else. Requires Linux ≥ 6.5; hard-fails otherwise. No effect outside lockdown or on macOS. |
| `--private-home` / `--no-private-home` | Enable/disable private home mode. Private home skips automatic host dotdir passthrough while leaving the project writable and explicit maps active. Linux uses tmpfs `$HOME`; macOS uses seatbelt allowlists. |
| `--lockdown` / `--no-lockdown` | Enable/disable strict read-only lockdown mode |
| `--landlock` / `--no-landlock` | Enable/disable Landlock LSM (Linux 5.13+, default: on) |
| `--seccomp` / `--no-seccomp` | Enable/disable seccomp syscall filter (Linux, default: on) |
| `--rlimits` / `--no-rlimits` | Enable/disable resource limits (default: on) |
| `--systemd-user` / `--no-systemd-user` | Dangerous opt-in: expose the host `systemd --user` bus so tools like `systemd-run --user` can talk to the host user manager. Linux normal mode only; skipped in lockdown and browser profile mode. With `--no-display`, only the narrow user-bus sockets are mounted. |
| `--gpu` / `--no-gpu` | Enable/disable GPU passthrough |
| `--docker` / `--no-docker` | Enable/disable Docker socket |
| `--tailscale` / `--no-tailscale` | Enable/disable Tailscale socket passthrough (default: off). When enabled, maps `/var/run/tailscale/tailscaled.sock` for the `tailscale` CLI if it exists. |
| `--display` / `--no-display` | Enable/disable X11/Wayland |
| `--worktree` / `--no-worktree` | Enable/disable linked Git worktree metadata passthrough (default: on) |
| `--mise` / `--no-mise` | Enable/disable mise integration |
| `--ssh` / `--no-ssh` | Share `~/.ssh` read-only + forward `SSH_AUTH_SOCK` (default: off) |
| `--pictures` / `--no-pictures` | Share `~/Pictures` read-only (default: off) |
| `--browser[=PROFILE]` / `--no-browser` | Enable/disable browser isolation profile. `PROFILE` is `hard` (ephemeral, default) or `soft` (persistent under `~/.local/share/ai-jail/browsers/<browser>`). Common browser commands auto-enable `hard` unless disabled. |
| `--save-config` / `--no-save-config` | Enable/disable automatic `.ai-jail` writes |
| `--hide-config` / `--no-hide-config` | Auto-mask the project's `.ai-jail` file inside the sandbox so the agent can't read its own sandbox policy (default: on). Pass `--no-hide-config` to make it visible. |
| `--claude-dir <PATH>` | Use `PATH` as Claude Code's config directory (sets `CLAUDE_CONFIG_DIR`). Enables multiple independent profiles (e.g. `~/.claude` for work, `~/.claude-personal` for a separate account). Path is bind-mounted read-write inside the sandbox. Leading `~/` is expanded against `$HOME`. |
| `-s`, `--status-bar[=STYLE]` | Enable persistent status line. `STYLE` is `pastel` (default, random palette per session), `dark`, or `light` |
| `--no-status-bar` | Disable persistent status line |
| `--exec` | Direct execution mode (no PTY proxy, no status bar) |
| `--clean` | Ignore existing config, start fresh |
| `--dry-run` | Print the bwrap command without executing |
| `--init` | Create/update config and exit (don't run) |
| `--bootstrap` | Generate permission configs for AI tools |
| `-v`, `--verbose` | Show detailed mount decisions |
| `-h`, `--help` | Show help |
| `-V`, `--version` | Show version |

### Examples

```bash
# Share an extra library directory read-write
ai-jail --rw-map ~/Projects/shared-lib claude

# Read-only access to reference data
ai-jail --map /opt/datasets claude

# NixOS: ai-jail automatically follows /etc/hosts into /nix/store and
# mounts /nix early enough for the private hosts override to work.

# Let the agent experiment with ~/.claude without touching the real one
ai-jail --overlay-map ~/.claude claude

# No GPU, no Docker, just the basics
ai-jail --no-gpu --no-docker claude

# Disable linked Git worktree passthrough for this run
ai-jail --no-worktree claude

# Run a one-shot command and capture its output
result=$(ai-jail --exec -- my-script.sh --flag1 --flag2)

# Suspicious/untrusted workload mode
ai-jail --lockdown bash

# Writable project, but no automatic host home dotdirs
ai-jail --private-home bash

# See exactly what mounts are being set up
ai-jail --dry-run --verbose claude

# Create config without running
ai-jail --init --no-docker claude

# Allow SSH inside the sandbox (agent forwarding + keys read-only)
ai-jail --ssh claude

# Share ~/Pictures read-only (e.g. for image analysis)
ai-jail --pictures claude

# Run Chromium with an ephemeral browser profile
ai-jail chromium

# Run Firefox with a persistent ai-jail-only browser profile
ai-jail --browser=soft firefox

# Hide .env and other secrets from the agent
ai-jail --mask .env --mask .env.local claude

# Use a separate Claude profile (e.g. work vs personal account)
ai-jail --claude-dir ~/.claude-work --init claude
ai-jail claude   # subsequent runs reuse ~/.claude-work via .ai-jail

# Run without creating/updating .ai-jail
ai-jail --no-save-config claude

# Regenerate config from scratch
ai-jail --clean --init claude

# Pass flags through to the sub-command (after --)
ai-jail -- claude --model opus
```

## Overlay maps

`--overlay-map <PATH>` (config: `overlay_maps`) mounts a directory **copy-on-write**. Inside the sandbox the agent sees `PATH` as a normal read-write directory, but every write — new file, edit, or delete — lands on a private *upper* layer instead of the real directory. **The original `PATH` is never modified.**

This lets an agent freely experiment with something you care about (your `~/.claude` config, a dotfiles repo, a data directory) while you keep the original safe and decide afterwards what — if anything — to keep.

```bash
# The agent can rewrite ~/.claude all it wants; your real one is untouched
ai-jail --overlay-map ~/.claude claude
```

### Where the changes go

Writes are captured under the project directory:

```
<project>/.ai-jail-overlays/<sanitized-path>/upper/   # exactly what changed
<project>/.ai-jail-overlays/<sanitized-path>/work/    # overlayfs scratch (ignore)
```

The `upper/` layer contains *only* the files the agent created or changed — so it doubles as a precise diff. After a session you can inspect it and promote what you want:

```bash
# See what the agent changed
ls -R .ai-jail-overlays/home_you_.claude/upper/

# Promote a change you like back to the real directory
cp .ai-jail-overlays/home_you_.claude/upper/settings.json ~/.claude/settings.json

# Or throw the whole experiment away
rm -rf .ai-jail-overlays/
```

ai-jail drops a `.gitignore` (`*`) inside `.ai-jail-overlays/` automatically, so the layers are never accidentally committed. The storage directory is masked (empty tmpfs) inside the sandbox, so the agent cannot reach or tamper with the raw layers — it can only go through the overlay at the destination.

### Notes and limits

- **Opt-in only.** Nothing overlays unless you pass `--overlay-map` / set `overlay_maps`. All existing behavior is unchanged.
- **Multiple overlays** are allowed as long as their destinations don't overlap (a parent and its child are rejected with a warning).
- **Linux/bwrap only.** Backed by bubblewrap's `--overlay`, which needs unprivileged OverlayFS (Linux kernel ≥ 5.11). On **macOS** there is no equivalent, so overlay maps degrade to **read-only** with a warning (writes are denied, protecting the original).
- **Disabled under `--lockdown` and browser mode** (both are read-only/ephemeral by design); a warning is printed if overlay maps are configured there.
- Missing sources, unwritable storage, or overlapping destinations are skipped with a warning — never fatal.
- **Storage is created eagerly.** The `.ai-jail-overlays/` directory (with its auto `.gitignore`) is created as soon as an overlay map is configured — including under `--dry-run`, because the upper/work layers must exist on disk before OverlayFS can mount them. It is git-ignored automatically; delete it any time with `rm -rf .ai-jail-overlays/`.

## Config file (`.ai-jail`)

Created in the project directory on first run. Example:

```toml
# ai-jail sandbox configuration
# Edit freely. Regenerate with: ai-jail --clean --init

command = ["claude"]
rw_maps = ["/home/user/Projects/shared-lib"]
ro_maps = []
mask = [".env", ".env.local", "**/*.env"]
no_gpu = true
ssh = true
private_home = true
lockdown = true
```

### Merge behavior

When CLI flags and an existing config are both present:

- `command`: CLI replaces config for the current run, but a CLI-passed command is **not** auto-persisted when the project already has a stored command — so `ai-jail codex` after `ai-jail claude` runs codex for that session without rewriting `.ai-jail`'s stored default. Use `ai-jail --init <command>` to explicitly change the stored command. First-run bootstrap (no stored command yet) still persists the CLI command as the new default.
- `rw_maps` / `ro_maps` / `mask` / `deny_paths`: CLI values are appended (duplicates removed). Paths starting with `~/` or exactly `~` are expanded against `$HOME` at merge time, so you can write `ro_maps = ["~/.bashrc"]` in a config file. Relative paths in `rw_maps` / `ro_maps` (including `../sibling` style) are resolved against the project directory before being passed to the sandbox. Relative `mask` / `deny_paths` entries resolve against the project directory when the sandbox policy is built; glob masks/denies are expanded at that same point so committed configs can keep portable patterns.
- Boolean flags: CLI overrides config (`--no-gpu` sets `no_gpu = true`)
- `--save-config` / `--no-save-config` override `no_save_config`
- Project config is updated in normal mode when config saving is enabled; inherited values from `$HOME/.ai-jail` are used at runtime but are not copied into the project `.ai-jail`. Lockdown skips auto-save.

### Global command-specific config

The global user config (`~/.ai-jail`) may also contain command-scoped tables. These are **global-only**; project `.ai-jail` files stay flat.

```toml
rw_maps = ["~/common"]

[commands.pi]
rw_maps = ["~/.pi", "~/.pi-lens"]
tailscale = true
```

The command key is selected from the first available command name: CLI command, then project `command`, then global base `command`. Runtime merge order is global base config, matching `[commands.<name>]`, project config, then CLI flags. Vector fields append and deduplicate; scalar options in project config override command-scoped global values.

### Available fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `command` | string array | `["bash"]` | Default command to run inside sandbox. Set by first run or by `--init`; not overwritten when a different command is passed on the CLI. |
| `rw_maps` | path array | `[]` | Extra read-write mounts. `/` is refused; map explicit subpaths instead. |
| `ro_maps` | path array | `[]` | Extra read-only mounts. `/` is refused; map explicit subpaths instead. |
| `overlay_maps` | path array | `[]` | Extra copy-on-write overlay mounts (see [Overlay maps](#overlay-maps)). Writes go to a side layer; the source stays untouched. Linux/bwrap only. |
| `hide_dotdirs` | string array | `[]` | Extra home dotdirs to deny (e.g. `[".my_secrets"]`). Leading dot optional. Built-in deny list (`.ssh`, `.gnupg`, `.aws`, `.mozilla`) always applies. |
| `mask` | path array | `[]` | Paths or glob patterns to replace with empty files/tmpfs (e.g. `[".env", "**/*.env", "secrets.json"]`). Relative paths resolve against the project directory. |
| `deny_paths` | path array | `[]` | Paths or glob patterns to deny with permission errors (e.g. `[".env", "secrets/*.json"]`). Relative paths resolve against the project directory. |
| `allow_tcp_ports` | u16 array | `[]` | TCP ports permitted outbound in lockdown mode (e.g. `[32000, 8080]`). Requires Linux ≥ 6.5 for Landlock V4. No effect outside lockdown. |
| `private_home` | bool | not set (off) | `true` skips automatic host dotdir passthrough without enabling full lockdown. Project and explicit maps remain writable. Linux uses tmpfs `$HOME`; macOS uses seatbelt allowlists. |
| `no_gpu` | bool | not set (auto) | `true` disables GPU passthrough |
| `no_docker` | bool | not set (auto) | `true` disables Docker socket |
| `tailscale` | bool | not set (off) | `true` maps `/var/run/tailscale/tailscaled.sock` for the `tailscale` CLI if it exists. Opt-in for privacy/safety. |
| `no_display` | bool | not set (auto) | `true` disables X11/Wayland |
| `no_worktree` | bool | not set (auto) | `true` disables linked Git worktree metadata passthrough |
| `no_mise` | bool | not set (auto) | `true` disables mise integration |
| `ssh` | bool | not set (off) | `true` shares `~/.ssh` read-only + forwards `SSH_AUTH_SOCK` |
| `pictures` | bool | not set (off) | `true` shares `~/Pictures` read-only |
| `browser_profile` | string | not set (auto) | Browser isolation profile: `"hard"` for ephemeral state, `"soft"` for persistent ai-jail-only state, or `"off"` to disable browser auto-detection |
| `no_save_config` | bool | not set (enabled) | `true` disables automatic `.ai-jail` writes |
| `no_hide_config` | bool | not set (enabled) | `true` keeps the project's `.ai-jail` file visible to the agent. Default is to auto-mask it as an empty file (see security notes). |
| `claude_dir` | path | not set | Custom Claude Code config directory (sets `CLAUDE_CONFIG_DIR`). Bind-mounted read-write. Use for multiple Claude profiles per project. Leading `~/` expanded against `$HOME`. |
| `no_landlock` | bool | not set (auto) | `true` disables Landlock LSM (Linux only) |
| `no_seccomp` | bool | not set (auto) | `true` disables seccomp syscall filter (Linux only) |
| `no_rlimits` | bool | not set (auto) | `true` disables resource limits |
| `systemd_user` | bool | not set (off) | `true` exposes the host user D-Bus/systemd manager sockets for `systemd-run --user`. Dangerous: the sandboxed agent can ask the host user manager to start services outside the sandbox. Linux normal mode only; skipped in lockdown/browser mode. With `no_display = true`, only the narrow user-bus sockets are mounted. |
| `lockdown` | bool | not set (disabled) | `true` enables strict read-only lockdown mode |

Status bar preferences (`no_status_bar`, `status_bar_style`, `resize_redraw_key`) are stored in `$HOME/.ai-jail` (global user config), not in per-project `.ai-jail` files. `status_bar_style` accepts `"dark"`, `"light"`, or `"pastel"` — pastel rotates through a curated set of soft pastel palettes (with high-contrast foreground), picking a new one at random for each session. Set it back to `"dark"` or `"light"` to disable the rotation. `resize_redraw_key` is used only by the PTY/status-bar path on terminal resize; accepted values are `ctrl-l`, `ctrl-shift-l` (same wire encoding as `ctrl-l`), or `disabled`. If unset, `codex` gets the `ctrl-shift-l` default and other commands stay off.

When a boolean field is not set, the feature is in auto mode. For resource passthroughs, that means enabled if the resource exists on the host. For Git worktrees, that means enabled only when the current directory is a validated linked worktree. `no_save_config` is exception: when unset, config auto-save is enabled in normal mode.

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
git clone https://github.com/akitaonrails/ai-jail.git
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

### Docker Desktop in WSL 2

Docker passthrough needs both pieces to work inside the jail:

```bash
test -S /var/run/docker.sock
command -v docker
readlink -f "$(command -v docker)"
```

The socket is mounted automatically when it exists. Docker Desktop for Windows commonly injects `/usr/bin/docker` as a symlink to `/mnt/wsl/docker-desktop/cli-tools/usr/bin/docker`; ai-jail exposes that CLI tools directory read-only when it exists. If `docker` is still missing inside the jail, check Docker Desktop's WSL integration for your distro or install the Docker CLI package inside the WSL distro so the binary lives under `/usr/bin` directly.

## License

GPL-3.0. See [LICENSE](LICENSE).
