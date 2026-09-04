#!/bin/bash
# Auren — double-click launcher for a quick user-level test run.
# macOS opens .command files in a fresh Terminal window when double-clicked.
#
# Behaviour (user-like):
#   - Builds/restores PATH so Finder-launched Terminal can find node/npm (brew, nvm, volta).
#   - If a packaged build already exists in release/ (from `npm run dist`), launches
#     that .app via `open` — exactly how a user opens the installed app (detached,
#     not tied to this Terminal).
#   - If no packaged build exists, builds one for the current arch (`--dir` unpacked
#     build — same .app contents as the dmg, but faster) then launches it.
#   - Falls back to the dev launcher (scripts/dev-app.sh) only if the build fails.
set -euo pipefail

# --- Restore PATH for Finder double-click ------------------------------------
# Finder gives a minimal PATH (/usr/bin:/bin:/usr/sbin:/sbin) so brew/nvm
# node is invisible. Prepend common locations and source nvm if present.
for p in "$HOME/homebrew/bin" "/opt/homebrew/bin" "/usr/local/bin" "$HOME/.nvm/versions/node" "$HOME/.volta/bin"; do
  case ":$PATH:" in *":$p:"*) ;; *) PATH="$p:$PATH" ;; esac
done
export PATH
# nvm (if installed) — load current default node into PATH
# nvm.sh does `set -e; return 3` on init when no default version — must not
# kill this script, so disable -e/-u around the source.
set +eu
if [ -s "$HOME/.nvm/nvm.sh" ]; then
  # shellcheck disable=SC1090
  . "$HOME/.nvm/nvm.sh" 2>/dev/null || true
fi
set -e -u
# Also try Homebrew shellenv if available (sets HOMEBREW_PREFIX etc.)
set +e
if [ -x "/opt/homebrew/bin/brew" ]; then
  eval "$(/opt/homebrew/bin/brew shellenv 2>/dev/null || true)"
elif [ -x "$HOME/homebrew/bin/brew" ]; then
  eval "$("$HOME/homebrew/bin/brew" shellenv 2>/dev/null || true)"
elif [ -x "/usr/local/bin/brew" ]; then
  eval "$(/usr/local/bin/brew shellenv 2>/dev/null || true)"
fi
set -e

cd "$(dirname "$0")"
ROOT="$(pwd)"

# --- Helpers -----------------------------------------------------------------
die() { echo "Error: $*" >&2; echo ""; echo "Press Enter to close this window."; read -r _ || true; exit 1; }
have_cmd() { command -v "$1" >/dev/null 2>&1; }

ARCH="$(uname -m 2>/dev/null || echo x64)"
case "$ARCH" in arm64|aarch64) ARCH="arm64" ;; *) ARCH="x64" ;; esac

# Where electron-builder --dir drops the unpacked .app (see electron-builder.yml)
if [ "$ARCH" = "arm64" ]; then
  CANDIDATES=("$ROOT/release/mac-arm64/auren.app" "$ROOT/release/mac/auren.app")
else
  CANDIDATES=("$ROOT/release/mac/auren.app" "$ROOT/release/mac-arm64/auren.app")
fi
# Also handle universal/mis-placed builds
CANDIDATES+=("$ROOT/release/mac/auren.app" "$ROOT/dist/mac/auren.app")

find_packaged_app() {
  for c in "${CANDIDATES[@]}"; do
    if [ -d "$c/Contents/MacOS" ]; then echo "$c"; return 0; fi
  done
  return 1
}

APP="$(find_packaged_app 2>/dev/null || true)"

# --- If no packaged app, build one (user-like build) ------------------------
if [ -z "${APP:-}" ]; then
  echo "No packaged build found in release/ — building one for this Mac ($ARCH)…"
  echo "This is the same build a user gets from the dmg (electron-builder),"
  echo "just without the dmg wrapper. First build can take a minute."
  echo ""

  if ! have_cmd node; then
    die "node not found (PATH=$PATH). Install Node.js from https://nodejs.org then double-click again."
  fi
  if ! have_cmd npm; then
    die "npm not found (PATH=$PATH)."
  fi

  if [ ! -d "$ROOT/node_modules/.bin" ]; then
    echo "Installing dependencies (Electron)…"
    npm install || die "npm install failed — see output above."
  fi

  # Ensure icons exist (dist does `npm run icon` first)
  if [ ! -f "$ROOT/build/icon.icns" ] || [ ! -f "$ROOT/build/icon.ico" ]; then
    echo "Generating app icons…"
    npm run icon || echo "Warning: icon generation failed — continuing with existing icons." >&2
  fi

  echo "Building unpacked app (electron-builder --dir)…"
  # Build only current arch as unpacked dir — identical .app to the dmg, faster.
  BUILD_ARGS=(--mac --dir)
  if [ "$ARCH" = "arm64" ]; then BUILD_ARGS+=(--arm64); else BUILD_ARGS+=(--x64); fi

  if ! npx --yes electron-builder "${BUILD_ARGS[@]}"; then
    echo "" >&2
    echo "Packaged build failed — falling back to dev launcher (still looks like user build)." >&2
    echo "" >&2
    echo "Starting Auren (dev)…"
    echo ""
    # Detach dev app so closing this Terminal doesn't kill it (nohup + open-like)
    # scripts/dev-app.sh does the auren-identity patch + exec; run it detached.
    nohup bash "$ROOT/scripts/dev-app.sh" >/tmp/auren-dev.log 2>&1 &
    DEV_PID=$!
    disown 2>/dev/null || true
    echo "Auren (dev) launched (pid $DEV_PID). Log: /tmp/auren-dev.log"
    echo "You can close this window — the app will stay open."
    exit 0
  fi

  APP="$(find_packaged_app 2>/dev/null || true)"
  if [ -z "${APP:-}" ]; then
    die "Build finished but no .app found in release/. Tried: ${CANDIDATES[*]}"
  fi
  echo ""
  echo "Built $APP"
  echo ""
fi

echo "Starting Auren — packaged build (what a user runs)…"
echo "  $APP"
echo ""
echo "You're testing it just like a user would. Things to try:"
echo "  • Flip Protection Mode ON (first time will ask for your password)."
echo "  • Add a site like example.com to the block list."
echo "  • Check Recent activity after a few actions."
echo "  • Flip Protection OFF (asks for Touch ID / your passcode)."
echo ""

# Clear quarantine (ad-hoc signed / unsigned builds are quarantined after build)
xattr -cr "$APP" 2>/dev/null || true

# Launch detached exactly like Finder double-click — not tied to this Terminal.
# `open` hands off to LaunchServices and returns immediately.
if ! open "$APP"; then
  die "Failed to open $APP"
fi

echo "Auren is running. You can close this window — the app will stay open."
# Give the user a moment to see the message; then exit so Terminal can be closed.
# (Don't `exec` or block — we want this shell to exit cleanly.)
exit 0
