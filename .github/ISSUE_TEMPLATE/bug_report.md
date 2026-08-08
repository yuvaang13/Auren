name: Bug report
about: Something isn't behaving as documented
title: ''
labels: bug
assignees: ''

---

**Describe the bug**
A clear and concise description of what happens vs. what you expected.

**Steps to reproduce**
1. Start the app (`npm start`).
2. Add a domain to the block list / toggle Protection Mode.
3. ...

**Expected vs. actual**
What should happen, and what actually happens. Include the relevant entries
from `~/Library/Application Support/Auren/activity.jsonl` (redact anything
you don't want shared — though Auren never writes sensitive data there).

**Environment**
- macOS version
- Auren version or commit
- Touch ID available? (yes/no — affects the toggle-off path)

**Relevant code**
Which file/function seems involved (e.g. `src/dns/daemon.js:applyDns`).

**Screenshots / logs**
If applicable (e.g. `/Library/Application Support/Auren/daemon.log`).
