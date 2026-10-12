#!/usr/bin/env bash
# Point the AUR package at a published GitHub release: sets pkgver, fills the
# checksums from the release's .sha256 files, and regenerates .SRCINFO.
# Usage: packaging/aur/update.sh 0.1.0   (then commit and push to the AUR repo)
set -euo pipefail
version="${1:?usage: update.sh <version>}"
dir="$(cd "$(dirname "$0")/visipass-bin" && pwd)"
base="https://github.com/VisiOffice/VisiPass/releases/download/v$version"
sum() { curl -fsSL "$base/visipass-$version-linux-$1.tar.gz.sha256" | cut -d' ' -f1; }
x86=$(sum x86_64)
arm=$(sum aarch64)
sed -i -e "s/^pkgver=.*/pkgver=$version/" -e "s/^pkgrel=.*/pkgrel=1/" \
  -e "s/^sha256sums_x86_64=.*/sha256sums_x86_64=('$x86')/" \
  -e "s/^sha256sums_aarch64=.*/sha256sums_aarch64=('$arm')/" "$dir/PKGBUILD"
(cd "$dir" && makepkg --printsrcinfo > .SRCINFO)
echo "Updated $dir for $version"
