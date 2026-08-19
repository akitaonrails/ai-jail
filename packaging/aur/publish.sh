#!/usr/bin/env bash
# Publish the AUR packages for a released version.
#
# The PKGBUILDs in this directory are the source of truth, but AUR serves each
# package from its own git repository containing a PKGBUILD and a generated
# .SRCINFO at the root. This script does that assembly, validates what it is
# about to publish, and shows the diff. It pushes only with --push.
#
#   ./publish.sh              # prepare and validate, push nothing
#   ./publish.sh --push       # same, then push to AUR
#   ./publish.sh --push 1.2.3 # publish a specific version
#
# Requires makepkg (Arch) and an SSH key enrolled with AUR.
set -euo pipefail

# Resolve before the cd: --help reads this file back, and a relative $0
# stops resolving once the working directory changes.
self="$(readlink -f "$0")"
cd "$(dirname "$self")"

push=0
version=""
for arg in "$@"; do
    case "$arg" in
        --push) push=1 ;;
        # Print the header comment block, however long it grows.
        -h|--help)
            awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' \
                "$self"
            exit 0
            ;;
        *) version="$arg" ;;
    esac
done

# Default to the version this checkout builds, so the packages cannot
# accidentally be published against a different tag than was released.
if [ -z "$version" ]; then
    version="$(grep -m1 '^version = ' ../../Cargo.toml | cut -d '"' -f 2)"
fi
echo "==> Publishing AUR packages for v$version"

for file in PKGBUILD PKGBUILD-bin; do
    declared="$(grep -m1 '^pkgver=' "$file" | cut -d= -f2)"
    if [ "$declared" != "$version" ]; then
        echo "!! $file has pkgver=$declared, expected $version" >&2
        echo "   Update pkgver and the checksums first; see README.md." >&2
        exit 1
    fi
done

# The upstream tag has to exist and be immutable before the AUR points at it.
if ! curl -fsI "https://github.com/akitaonrails/ai-jail/releases/tag/v$version" \
        >/dev/null 2>&1; then
    echo "!! No upstream release v$version; publish that first." >&2
    exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

status=0
for pkg in ai-jail ai-jail-bin; do
    src=PKGBUILD
    [ "$pkg" = "ai-jail-bin" ] && src=PKGBUILD-bin

    echo
    echo "==> $pkg"
    git clone -q "ssh://aur@aur.archlinux.org/$pkg.git" "$work/$pkg"
    cp "$src" "$work/$pkg/PKGBUILD"
    # Checksums must match what upstream actually published; this is the
    # check that catches a stale or hand-edited sha256sums entry. Output is
    # kept back unless it fails, since makepkg and curl are chatty on stderr.
    if ! log="$(cd "$work/$pkg" && makepkg --verifysource 2>&1)"; then
        echo "!! $pkg: source verification failed" >&2
        echo "$log" >&2
        status=1
        continue
    fi
    (cd "$work/$pkg" && makepkg --printsrcinfo > .SRCINFO)

    # A .SRCINFO that disagrees with its PKGBUILD makes AUR advertise the
    # wrong version, so refuse rather than publish that.
    pv="$(grep -m1 '^pkgver=' "$work/$pkg/PKGBUILD" | cut -d= -f2)"
    sv="$(grep -m1 'pkgver = ' "$work/$pkg/.SRCINFO" | awk '{print $3}')"
    if [ "$pv" != "$sv" ]; then
        echo "!! $pkg: PKGBUILD $pv disagrees with .SRCINFO $sv" >&2
        status=1
        continue
    fi

    echo "    sources verified, .SRCINFO regenerated (pkgver=$pv)"
    git -C "$work/$pkg" add -A
    if git -C "$work/$pkg" diff --cached --quiet; then
        echo "    already published, nothing to do"
        continue
    fi
    git -C "$work/$pkg" --no-pager diff --cached --stat | sed 's/^/    /'

    if [ "$push" -eq 1 ]; then
        git -C "$work/$pkg" -c user.name=AkitaOnRails \
            -c user.email=boss@akitaonrails.com \
            commit -q -m "Update to v$version"
        git -C "$work/$pkg" push -q origin master
        echo "    pushed"
    else
        echo "    not pushed (re-run with --push)"
    fi
done

exit "$status"
