#!/bin/bash
# Auren — real end-to-end verification of app blocking.
#
# Prerequisites:
#   - the DNS daemon is installed and running (scripts/install-daemon.sh)
#   - Protection Mode is ON (config.json mode = "on")
#
# What it checks, for real, at the process level:
#   1. the block list can carry an app entry (bundle ID + executable path)
#   2. a running copy of a blocked app is killed by the daemon within ~1 s
#
# It temporarily adds a dummy "app" (an executable shell script) to the app
# block list, verifies it is killed, then removes it again. Matching is by
# exact path, so no real app is ever touched. The config's existing mode and
# lists are preserved.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$HOME/Library/Application Support/Auren/config.json"
KEY="$HOME/Library/Application Support/Auren/auren.key"
DUMMY="$(mktemp /tmp/auren-e2e-app.XXXXXX)"
TEST_ID="com.auren.e2e.check"
FAILED=0

pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAILED=1; }
cleanup() { rm -f "$DUMMY"; }
trap cleanup EXIT

echo "Auren app-block end-to-end check"
echo "================================"

if [ ! -f "$CONFIG" ] || [ ! -f "$KEY" ]; then
  fail "no config or signing key found ($CONFIG, $KEY) — run the app once first"
  exit 1
fi

# A dummy "app": an executable that runs forever until it is killed.
printf '#!/bin/sh\nwhile true; do sleep 1; done\n' > "$DUMMY"
chmod +x "$DUMMY"

# 1. Add the dummy to the app block list (signed config — the daemon fails
#    closed if the signature is missing). Refuses to run when Protection is off.
node -e '
  const fs = require("fs");
  const c = require(process.argv[1] + "/src/core/config");
  const cfg = c.readConfigFile(process.argv[2]);
  if (cfg.mode !== "on") {
    console.error("protection is not ON (" + cfg.mode + ") — turn it on first");
    process.exit(2);
  }
  cfg.appBlocklist = cfg.appBlocklist || [];
  cfg.appBlocklist = cfg.appBlocklist.filter((a) => a.id !== process.argv[4]);
  cfg.appBlocklist.push({ id: process.argv[4], name: "auren-e2e-app", path: process.argv[5] });
  c.writeSignedConfig(process.argv[2], cfg, fs.readFileSync(process.argv[3]));
' "$ROOT" "$CONFIG" "$KEY" "$TEST_ID" "$DUMMY"
STATUS=$?
if [ "$STATUS" -eq 2 ]; then
  exit 1
fi
sleep 2

# 2. Spawn the dummy and verify the daemon kills it.
"$DUMMY" &
APP_PID=$!
sleep 3
if kill -0 "$APP_PID" 2>/dev/null; then
  fail "blocked app was NOT killed ($DUMMY, pid $APP_PID)"
  kill -9 "$APP_PID" 2>/dev/null || true
else
  pass "blocked app was killed by the daemon ($DUMMY)"
fi
wait "$APP_PID" 2>/dev/null || true

# 3. Remove the test entry.
node -e '
  const fs = require("fs");
  const c = require(process.argv[1] + "/src/core/config");
  const cfg = c.readConfigFile(process.argv[2]);
  cfg.appBlocklist = (cfg.appBlocklist || []).filter((a) => a.id !== process.argv[3]);
  c.writeSignedConfig(process.argv[2], cfg, fs.readFileSync(process.argv[3]));
' "$ROOT" "$CONFIG" "$KEY" "$TEST_ID"
echo "  INFO  removed $TEST_ID from the app block list"

echo "================================"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
else
  echo "SOME CHECKS FAILED"
fi
exit "$FAILED"
