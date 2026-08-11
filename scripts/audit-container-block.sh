#!/bin/bash
# Auren — VM/container isolation audit (Docker).
#
# Honest-limits check: Auren's pf anchor only blocks traffic from processes on
# the HOST. Container runtimes run their own network stack, so traffic from
# inside a container may bypass the host's pf anchor entirely. This script
# empirically tests, from inside a real container, whether Auren's blocking
# covers container traffic while Protection Mode is ON:
#   1. DNS bypass: does a blocked domain still resolve inside the container?
#   2. pf bypass: is a blocked command port (22) reachable from the container?
#   3. positive control: does HTTPS (443) still work from the container?
#
# Run it with Protection Mode ON (the daemon must have loaded the pf anchor).
# The output tells us whether the VM/container caveat in README "Honest limits"
# is real on your setup — paste it where it's requested.
#
# Usage (from the repo root):
#   bash scripts/audit-container-block.sh
#   AUREN_AUDIT_DOMAIN=blocked.example.com bash scripts/audit-container-block.sh
#
# The first blocked domain is read from the app's config automatically.
set -u

IMAGE="busybox:latest"
AUDIT_DOMAIN="${AUREN_AUDIT_DOMAIN:-}"
# A public IP that is NOT a known DoH endpoint, so the port-22 result tests the
# pf port block specifically (DoH endpoints are blocked for other reasons).
# 93.184.216.34 is example.com — an ordinary web host.
PORT22_TARGET="93.184.216.34"

echo "Auren container-isolation audit"
echo "==============================="

if ! command -v docker >/dev/null 2>&1; then
  echo "FAIL  docker is not installed or not on PATH"
  echo "      (this audit is Docker-specific; for Parallels/VMware/UTM run the"
  echo "       equivalent tests from inside a guest VM instead)"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "FAIL  docker daemon is not running"
  exit 1
fi

CONFIG_FILE="${HOME}/Library/Application Support/Auren/config.json"
if [ -z "$AUDIT_DOMAIN" ] && [ -f "$CONFIG_FILE" ]; then
  AUDIT_DOMAIN="$(node -e 'try { const c = require(process.argv[1]); const b = (c.blocklist || []).map(String).filter(Boolean); console.log(b[0] || "") } catch (e) { console.log("") }' "$CONFIG_FILE")"
fi
if [ -z "$AUDIT_DOMAIN" ]; then
  echo "NOTE  no blocked domain found in config.json — using example.invalid (always NXDOMAIN)"
  AUDIT_DOMAIN="example.invalid"
fi

echo "blocked domain under test : $AUDIT_DOMAIN"
echo "image under test          : $IMAGE"
echo ""

echo "pulling $IMAGE ..."
docker pull "$IMAGE" >/dev/null 2>&1 || { echo "FAIL  could not pull $IMAGE"; exit 1; }

# Run the same three probes from inside a container, twice: once on the default
# bridge, once on the host network. Heredoc keeps the quoting honest — the
# commands genuinely run inside the container.
run_in_container() {
  local label="$1"
  local mode="$2"
  echo "-- $label ($mode) --"
  docker run --rm $mode "$IMAGE" sh -s <<EOF
getent hosts "$AUDIT_DOMAIN" >/dev/null 2>&1 && echo "DNS:    REACHABLE" || echo "DNS:    BLOCKED"
nc -z -w 3 "$PORT22_TARGET" 22 >/dev/null 2>&1 && echo "PORT22: REACHABLE" || echo "PORT22: BLOCKED"
nc -z -w 3 example.com 443 >/dev/null 2>&1 && echo "HTTPS:  REACHABLE" || echo "HTTPS:  BLOCKED"
EOF
  echo ""
}

run_in_container "default bridge" ""
run_in_container "host network" "--network host"

echo "==============================="
echo "How to read this:"
echo "  - DNS:    BLOCKED  => container DNS transits Auren's resolver; blocked domains stay blocked."
echo "  - DNS:    REACHABLE=> container uses its own/upstream DNS and BYPASSES the block list."
echo "  - PORT22: BLOCKED  => the host pf anchor covers container traffic for this port."
echo "  - PORT22: REACHABLE=> container traffic bypasses the host pf anchor (not covered)."
echo "  - HTTPS:  REACHABLE=> positive control: normal browsing still works from the container."
echo "Any BYPASS result means Auren does NOT fully protect this container setup."
