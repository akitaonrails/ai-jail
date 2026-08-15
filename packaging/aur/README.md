# AUR Packaging

This directory contains the package definitions for two Arch User Repository packages:

- `ai-jail-bin`: installs the prebuilt Linux x86_64 binary from GitHub Releases.
- `ai-jail`: builds from the GitHub source tag with the local Rust toolchain.

The files here are the source of truth for the AUR repos, but AUR still requires each package to be pushed to its own Git repository with a generated `.SRCINFO`.

## User Install

Use an AUR helper:

```bash
yay -S ai-jail-bin    # prebuilt binary, fastest on x86_64
yay -S ai-jail        # builds from source, supports x86_64/aarch64
```

Or clone/build manually:

```bash
git clone https://aur.archlinux.org/ai-jail-bin.git
cd ai-jail-bin
makepkg -si
```

## Maintainer Release Checklist

For every new upstream release:

1. Update `pkgver` in both `PKGBUILD` files and reset `pkgrel=1`.
2. Update source checksums.
3. Validate both package variants with `makepkg --verifysource` and `makepkg -Ccf`.
4. Generate `.SRCINFO` in each AUR checkout with `makepkg --printsrcinfo > .SRCINFO`.
5. Commit and push to the separate AUR repos: `ai-jail` and `ai-jail-bin`.

Checksum helpers for version `X.Y.Z`:

```bash
version=X.Y.Z

# Source package tarball
curl -fsSL "https://github.com/akitaonrails/ai-jail/archive/refs/tags/v${version}.tar.gz" | sha256sum

# Binary package release artifact
curl -fsSL "https://github.com/akitaonrails/ai-jail/releases/download/v${version}/ai-jail-linux-x86_64.tar.gz.sha256"

# Common files used by ai-jail-bin
curl -fsSL "https://raw.githubusercontent.com/akitaonrails/ai-jail/v${version}/LICENSE" | sha256sum
curl -fsSL "https://raw.githubusercontent.com/akitaonrails/ai-jail/v${version}/README.md" | sha256sum
```

`ai-jail-bin` is currently `x86_64` only because the release workflow publishes a Linux x86_64 binary. The source package includes `aarch64` because it compiles locally on Arch Linux ARM.

Use Rust `1.97.1` when validating the source package or reproducing the
release build. The PKGBUILD pins `RUSTUP_TOOLCHAIN=1.97.1` to match
`rust-toolchain.toml`; do not switch it back to `stable`. Do not update
`PKGBUILD` versions or checksums until the corresponding immutable upstream
release and its checksums exist.
