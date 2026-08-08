#!/bin/bash
# Install or update the Auren DNS daemon (a root LaunchDaemon).
#
# Run as root, e.g.:  sudo bash scripts/install-daemon.sh
# The daemon then runs persistently at boot and starts/stops DNS interception
# based on config.json (mode + block list) — no per-toggle admin needed.
#
# Overrides (all optional):
#   AUREN_NODE=<node or electron binary>   interpreter to run daemon.js with
#   AUREN_CONFIG / AUREN_ACTIVITY          paths for the shared config + log
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
NODE_BIN="$(command -v node || echo "${AUREN_NODE:-}")"
if [ -z "$NODE_BIN" ]; then
  echo "error: no node found on PATH. Pass AUREN_NODE=/path/to/electron (runs in node mode)." >&2
  exit 1
fi

# sudo resets $HOME to the target user's (root). Resolve the *invoking* user's
# home so the daemon reads/writes the right config + activity files.
if [ -n "${AUREN_USER_HOME:-}" ]; then
  TARGET_HOME="$AUREN_USER_HOME"
elif [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  TARGET_HOME="$(dscl . -read "/Users/$SUDO_USER" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
  TARGET_HOME="${TARGET_HOME:-$HOME}"
else
  TARGET_HOME="$HOME"
fi

export AUREN_NODE="$NODE_BIN"
export AUREN_CONFIG="${AUREN_CONFIG:-$TARGET_HOME/Library/Application Support/Auren/config.json}"
export AUREN_ACTIVITY="${AUREN_ACTIVITY:-$TARGET_HOME/Library/Application Support/Auren/activity.jsonl}"
export AUREN_STATE="${AUREN_STATE:-/Library/Application Support/Auren/state.json}"

cd "$ROOT_DIR"
node -e '
const dns = require("./src/platform/dns-controller");
const out = dns.installDaemonCli({
  nodeBin: process.env.AUREN_NODE,
  configPath: process.env.AUREN_CONFIG,
  activityPath: process.env.AUREN_ACTIVITY,
  statePath: process.env.AUREN_STATE
});
process.stdout.write(out);
'
echo "Auren DNS daemon installed."
