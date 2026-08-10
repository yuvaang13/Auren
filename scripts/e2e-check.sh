#!/bin/bash
# Auren — real end-to-end verification of system-wide DNS blocking.
#
# Prerequisites:
#   - the DNS daemon is installed and running (scripts/install-daemon.sh)
#   - Protection Mode is ON (config.json mode = "on")
#
# What it checks, for real, at the network layer:
#   1. the Mac's DNS points at Auren (127.0.0.1)
#   2. a blocked domain returns NXDOMAIN via the local resolver
#   3. a normal domain still resolves via the upstream forwarder
#
# It temporarily adds a harmless test domain (auren-e2e-check.test) to the
# block list, verifies, then removes it again.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$HOME/Library/Application Support/Auren/config.json"
KEY="$HOME/Library/Application Support/Auren/auren.key"
TEST_DOMAIN="auren-e2e-check.test"
FAILED=0

pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAILED=1; }

echo "Auren end-to-end check"
echo "======================"

# 1. DNS pointed at Auren?
if scutil --dns 2>/dev/null | grep -q "nameserver\[[0-9]*\] *: *127.0.0.1"; then
  pass "system DNS points at the Auren resolver (127.0.0.1)"
else
  fail "system DNS does NOT point at 127.0.0.1 — is the daemon running and Protection ON?"
fi

# 2/3. Add the test domain to the block list, wait for the daemon to pick it up.
# Writes a SIGNED config (the daemon fails closed if the signature is missing).
if [ -f "$CONFIG" ] && [ -f "$KEY" ]; then
  node -e '
    const fs = require("fs");
    const c = require(process.argv[1] + "/src/core/config");
    const cfg = c.readConfigFile(process.argv[2]);
    if (!cfg.blocklist.includes(process.argv[4])) cfg.blocklist.push(process.argv[4]);
    c.writeSignedConfig(process.argv[2], cfg, fs.readFileSync(process.argv[3]));
  ' "$ROOT" "$CONFIG" "$KEY" "$TEST_DOMAIN"
  sleep 2

  BLOCKED_STATUS="$(dig @127.0.0.1 "$TEST_DOMAIN" +time=3 +tries=1 2>/dev/null | sed -n 's/.*status: \([A-Z][A-Z]*\).*/\1/p' | head -1)"
  if [ "$BLOCKED_STATUS" = "NXDOMAIN" ]; then
    pass "blocked domain returns NXDOMAIN ($TEST_DOMAIN -> NXDOMAIN)"
  else
    fail "blocked domain did not return NXDOMAIN (got: ${BLOCKED_STATUS:-none})"
  fi

  ALLOWED_STATUS="$(dig @127.0.0.1 example.com +time=3 +tries=1 2>/dev/null | sed -n 's/.*status: \([A-Z][A-Z]*\).*/\1/p' | head -1)"
  ALLOWED_A="$(dig @127.0.0.1 example.com +short 2>/dev/null | head -1)"
  if [ "$ALLOWED_STATUS" = "NOERROR" ] && [ -n "$ALLOWED_A" ]; then
    pass "non-blocked domain resolves via upstream (example.com -> $ALLOWED_A)"
  else
    fail "non-blocked domain did not resolve (status: ${ALLOWED_STATUS:-none})"
  fi

  # Clean up the test domain.
  node -e '
    const fs = require("fs");
    const c = require(process.argv[1] + "/src/core/config");
    const cfg = c.readConfigFile(process.argv[2]);
    cfg.blocklist = cfg.blocklist.filter((d) => d !== process.argv[4]);
    c.writeSignedConfig(process.argv[2], cfg, fs.readFileSync(process.argv[3]));
  ' "$ROOT" "$CONFIG" "$KEY" "$TEST_DOMAIN"
  echo "  INFO  removed $TEST_DOMAIN from the block list"
else
  fail "no config or signing key found ($CONFIG, $KEY) — run the app once first"
fi

echo "======================"
if [ "$FAILED" -eq 0 ]; then
  echo "ALL CHECKS PASSED"
else
  echo "SOME CHECKS FAILED"
fi
exit "$FAILED"
