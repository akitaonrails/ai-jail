# Maintainer: AkitaOnRails <boss@akitaonrails.com>

pkgname=ai-jail-bin
_pkgname=ai-jail
pkgver=1.22.0
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
    '85e3c47239811bb11e7494f1ce6e1d05f3949a320310a7139566899b8e29eb5d'
)
sha256sums_x86_64=('776d8182ea07740392767b1889d2760c11887a3c7f6ecafbe0b7c093aa542149')

package() {
    install -Dm0755 -t "$pkgdir/usr/bin/"                     "ai-jail"
    install -Dm0644 "README-$pkgver.md"                       "$pkgdir/usr/share/doc/$_pkgname/README.md"
    install -Dm0644 "LICENSE-$pkgver"                         "$pkgdir/usr/share/licenses/$_pkgname/LICENSE"
}
