name: Feature request
about: Suggest a change to Auren
title: ''
labels: enhancement
assignees: ''

---

**Problem**
What gap does this fill? (e.g. "blocking a whole subdomain list at once").

**Proposed behavior**
What should Auren do differently.

**Scope check (please read before posting)**
- Does this require reading page content or form data? If yes, that needs a
  proxy layer, which is explicitly out of scope for the current DNS-level
  architecture — it would need its own issue and privacy story.
- Does it touch the biometric gate? Any change must keep using OS-native APIs
  and consume pass/fail results only.
- Does it weaken fail-closed behavior (failed/cancelled verification leaves
  protection ON)?
- Does it imply stronger protection than the README honestly claims?

**Alternatives considered**
Anything you tried or thought of.
