# Maintainer: AkitaOnRails <boss@akitaonrails.com>

pkgname=ai-jail-bin
_pkgname=ai-jail
pkgver=2.11.2
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
    'd67722f2321327f809b1fe12679a4e0b63cb9a74dfad0763ab902757c10e6620'
)
sha256sums_x86_64=('7deebaef0bf195485ed3b8b93a23deea50edc1d34989b0e2960be4f88b3f9fc6')

package() {
    install -Dm0755 -t "$pkgdir/usr/bin/"                     "ai-jail"
    install -Dm0644 "README-$pkgver.md"                       "$pkgdir/usr/share/doc/$_pkgname/README.md"
    install -Dm0644 "LICENSE-$pkgver"                         "$pkgdir/usr/share/licenses/$_pkgname/LICENSE"
}
