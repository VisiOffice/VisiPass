#!/bin/sh
# Builds VisiPass.app: the app, visipassd, visipass-prompt and vp side by side in
# Contents/MacOS, where visipassd trusts the app and the approval window (it runs
# helpers only from beside itself).
#
#   packaging/macos/build-app.sh            # target/release/VisiPass.app
#   packaging/macos/build-app.sh --install  # also to ~/Applications, with vp on PATH
#
# Signs ad hoc unless CODESIGN_IDENTITY names a Developer ID.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"

version=$(sed -n '/^\[workspace.package\]/,/^\[/s/^version = "\(.*\)"/\1/p' Cargo.toml)
cargo build --release -p vp-cli -p vp-daemon -p vp-gui

app=target/release/VisiPass.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
for bin in visipass-app visipassd visipass-prompt vp; do
  cp "target/release/$bin" "$app/Contents/MacOS/"
done
cp "$here/VisiPass.icns" "$app/Contents/Resources/"
sed "s/@VERSION@/$version/g" "$here/Info.plist" > "$app/Contents/Info.plist"
codesign --force --options runtime --timestamp=none \
  --sign "${CODESIGN_IDENTITY:--}" "$app/Contents/MacOS/"* "$app"
echo "built $app ($version)"

if [ "${1:-}" = "--install" ]; then
  dest="$HOME/Applications/VisiPass.app"
  mkdir -p "$HOME/Applications" "$HOME/.local/bin"
  # The running daemon is the old build; the next vp or app start runs this one.
  if [ -x "$HOME/.local/bin/vp" ]; then
    "$HOME/.local/bin/vp" daemon --stop >/dev/null 2>&1 || true
  fi
  rm -rf "$dest"
  cp -R "$app" "$dest"
  ln -sf "$dest/Contents/MacOS/vp" "$HOME/.local/bin/vp"
  # Links from an install that predates the app would start the old programs.
  for bin in visipassd visipass-app visipass-prompt; do
    if [ -L "$HOME/.local/bin/$bin" ]; then rm "$HOME/.local/bin/$bin"; fi
  done
  echo "installed $dest; vp links to it from ~/.local/bin"
fi
