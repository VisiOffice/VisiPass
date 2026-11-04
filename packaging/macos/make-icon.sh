#!/bin/sh
# Rebuilds VisiPass.icns from icon.svg. Needs ImageMagick (magick); the .icns is
# checked in, so building the app does not.
set -eu
cd "$(dirname "$0")"
set_dir=$(mktemp -d)/VisiPass.iconset
mkdir "$set_dir"
for size in 16 32 128 256 512; do
  magick -background none -density 384 icon.svg -resize ${size}x${size} "$set_dir/icon_${size}x${size}.png"
  double=$((size * 2))
  magick -background none -density 384 icon.svg -resize ${double}x${double} "$set_dir/icon_${size}x${size}@2x.png"
done
iconutil -c icns -o VisiPass.icns "$set_dir"
rm -r "$(dirname "$set_dir")"
