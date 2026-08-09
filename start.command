#!/bin/bash
# Auren — double-click launcher for a quick user-level test run.
# macOS opens .command files in a fresh Terminal window when double-clicked.
set -u

cd "$(dirname "$0")"

if [ ! -d node_modules/.bin ]; then
  echo "First run: installing dependencies (Electron) — this can take a minute…"
  npm install
fi

echo ""
echo "Starting Auren…"
echo "You're testing it just like a user would. Things to try:"
echo "  • Flip Protection Mode ON (first time will ask for your password)."
echo "  • Add a site like example.com to the block list."
echo "  • Check Recent activity after a few actions."
echo "  • Flip Protection OFF (asks for Touch ID / your passcode)."
echo ""
echo "Close this window when you're done testing (the app stays open)."
echo ""

npm start
