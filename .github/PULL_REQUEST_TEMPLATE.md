## What this PR does

Briefly describe the change and why.

## Scope / privacy check

- [ ] No code path handles, stores, or transmits biometric or credential data
      (OS-native auth only, pass/fail results only).
- [ ] Fail-closed invariant preserved (failed/cancelled verification keeps
      Protection ON; turning ON stays un-gated).
- [ ] Activity log contains only domain, timestamp, and outcome.
- [ ] If behavior changed, README's "What this does NOT do yet" is updated if
      the bypass surface changed.

## Tests

- [ ] `npm run test:unit` passes (16 assertions).
- [ ] `npm run test:dns` passes (8 assertions) for blocking/daemon changes.
- [ ] Manual flows from `docs/MANUAL_TEST.md` verified if UI or gating changed.

## Related issues

Fixes #<issue>

## Changelog note

One-line description for the release notes, if this is user-visible.
