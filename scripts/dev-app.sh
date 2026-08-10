#!/bin/bash
# auren — dev launcher.
#
# `electron .` runs the generic Electron binary, so the Dock shows the Electron
# icon and the "Electron" name. This script instead launches a private copy of
# Electron.app that has been given the auren identity (name + icon), so even
# unpackaged development runs look like the real app.
#
# The patched bundle is cached by Electron version in ~/Library/Caches/auren.
# Packaged builds don't need this — they get the name and icon from the bundle.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ELECTRON_DIST="$ROOT/node_modules/electron/dist"

if [ ! -d "$ELECTRON_DIST/Electron.app" ]; then
  echo "Electron is not installed. Run \`npm install\` first." >&2
  exit 1
fi

VERSION="$(cat "$ELECTRON_DIST/version" 2>/dev/null || echo dev)"
CACHE="${AUREN_DEV_APP:-$HOME/Library/Caches/auren/Electron-$VERSION.app}"

if [ ! -d "$CACHE" ]; then
  echo "Preparing the auren app bundle (one-time per Electron version)…"
  mkdir -p "$(dirname "$CACHE")"
  cp -R "$ELECTRON_DIST/Electron.app" "$CACHE"

  INFO="$CACHE/Contents/Info.plist"
  plutil -replace CFBundleName -string auren "$INFO"
  plutil -replace CFBundleDisplayName -string auren "$INFO"
  plutil -replace CFBundleIdentifier -string app.auren.guardrail "$INFO"
  if [ -f "$ROOT/build/icon.icns" ]; then
    cp "$ROOT/build/icon.icns" "$CACHE/Contents/Resources/electron.icns"
  fi

  # Editing Info.plist invalidates the ad-hoc signature; arm64 requires a valid
  # signature, so re-sign the whole bundle ad-hoc.
  codesign --force --deep --sign - "$CACHE" >/dev/null 2>&1 || true
fi

exec "$CACHE/Contents/MacOS/Electron" "$ROOT"
