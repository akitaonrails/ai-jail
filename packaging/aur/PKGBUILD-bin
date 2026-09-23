# Maintainer: AkitaOnRails <boss@akitaonrails.com>

pkgname=ai-jail-bin
_pkgname=ai-jail
pkgver=2.1.0
pkgrel=1
pkgdesc="Sandbox wrapper for AI coding agents (prebuilt binary)"
arch=('x86_64')
url="https://github.com/akitaonrails/ai-jail"
license=('GPL-3.0-only')
depends=('bubblewrap' 'glibc' 'gcc-libs')
optdepends=(
    'mise: language version management inside the sandbox'
    'docker: Docker socket passthrough for sandboxed agents'
)
provides=("$_pkgname=$pkgver")
conflicts=("$_pkgname" "$_pkgname-debug")
# The GitHub release tarball ships a stripped binary, so re-stripping is a
# no-op and the auto-generated -debug split would be empty.
options=('!strip' '!debug')

source=(
    "LICENSE-$pkgver::$url/raw/v$pkgver/LICENSE"
    "README-$pkgver.md::$url/raw/v$pkgver/README.md"
)
source_x86_64=("$_pkgname-$pkgver-x86_64.tar.gz::$url/releases/download/v$pkgver/$_pkgname-linux-x86_64.tar.gz")
sha256sums=(
    '3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986'
    '0555b16ca187ea54b50ffc2fd84b90d4c521a7a3bcd0b2b82706fd90bbc9476c'
)
sha256sums_x86_64=('3bca37c5570a4f43fdff29e67db718caff069e454650525271a1e6e81e44b1a4')

package() {
    install -Dm0755 -t "$pkgdir/usr/bin/"                     "ai-jail"
    install -Dm0644 "README-$pkgver.md"                       "$pkgdir/usr/share/doc/$_pkgname/README.md"
    install -Dm0644 "LICENSE-$pkgver"                         "$pkgdir/usr/share/licenses/$_pkgname/LICENSE"
}
