#!/usr/bin/env bash
# Build a Debian package (.deb) for ai-jail from a prebuilt release binary.
#
# Usage: build-deb.sh <version> <binary-path> <output-dir>
#
# Produces <output-dir>/ai-jail_<version>_amd64.deb and a matching .sha256.
# Depends only on dpkg-deb, which ships with every Debian/Ubuntu system and
# the release runner -- no new build tooling or Rust crate.
set -euo pipefail

version="${1:?usage: build-deb.sh <version> <binary-path> <output-dir>}"
binary="${2:?usage: build-deb.sh <version> <binary-path> <output-dir>}"
outdir="${3:?usage: build-deb.sh <version> <binary-path> <output-dir>}"

case "$version" in
  [0-9]*.[0-9]*.[0-9]*) ;;
  *)
    echo "version must be X.Y.Z, got: $version" >&2
    exit 1
    ;;
esac
[ -x "$binary" ] || {
  echo "binary not found or not executable: $binary" >&2
  exit 1
}

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
chmod 0755 "$stage"

install -Dm0755 "$binary" "$stage/usr/bin/ai-jail"
install -Dm0644 "$repo_root/README.md" "$stage/usr/share/doc/ai-jail/README.md"
install -Dm0644 "$repo_root/LICENSE" "$stage/usr/share/doc/ai-jail/copyright"

installed_kb="$(du -k -s "$stage/usr" | cut -f1)"

install -d "$stage/DEBIAN"
cat >"$stage/DEBIAN/control" <<EOF
Package: ai-jail
Version: $version
Section: utils
Priority: optional
Architecture: amd64
Depends: bubblewrap, libc6
Installed-Size: $installed_kb
Maintainer: AkitaOnRails <boss@akitaonrails.com>
Homepage: https://github.com/akitaonrails/ai-jail
Description: Sandbox for AI coding agents (bubblewrap on Linux)
 ai-jail wraps AI coding agents such as Claude Code and Codex in a
 bubblewrap sandbox so the project directory is a confident blast radius
 for auto-accept harnesses. It is a developer-friendly accident guard,
 not a hard-security boundary.
EOF

mkdir -p "$outdir"
deb="$outdir/ai-jail_${version}_amd64.deb"
dpkg-deb --root-owner-group --build "$stage" "$deb"
(cd "$outdir" && sha256sum "ai-jail_${version}_amd64.deb" \
  >"ai-jail_${version}_amd64.deb.sha256")
echo "built $deb"
