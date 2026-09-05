# Auren — File System Guard & Virtual Isolation

> Zero-knowledge, local-only, default-deny file isolation for AI-agent sessions.

## Core philosophy

- **ZERO-KNOWLEDGE:** 100% local. No path, mount, or exclusion ever leaves the machine. No telemetry, no remote DB.
- **Default-Deny:** Agent runtime starts with **zero** file-system access. Access is granted only to explicit Virtual Mount Points chosen by the user in Tab 3, minus the forced exclusion list.
- **Scope:** this gates *AI-agent file access routed through Auren* — the loopback bridge (`POST /v1/check/fs`, `/v1/check/command`), the Electron IPC gates (`fsguard:check`, `agent:inspect-command`), and the live path tester. It is **not** OS-level mandatory access control: opening other folders directly in Finder / File Explorer still works, because those opens never pass through Auren.
- **Canonical-first:** Every path is canonicalized (symlink + lexical resolution) before any decision.
- **Encrypted at rest:** Policy lives in the OS-standard app-data directory (`~/Library/Application Support/Auren` on macOS, `%APPDATA%/Auren` on Windows) inside the existing encrypted store `guardrail.dat` (AES-256-GCM, key `auren.key`, mode 0600) and the HMAC-signed `config.json`.

---

## Project directory structure (relevant subtree)

```
src/
  main.js                    # Electron main — owns canonical state, IPC, persistence
  preload.js                 # Minimal contextBridge (no direct FS access)
  bridge/http.js             # Loopback agent bridge (adds POST /v1/check/fs)
  core/
    path-normalize.js        # ← NEW: canonical path engine (lexical + realpath)
    fsguard.js               # ← NEW: isolation models, forced exclusions, enforcement
    isolation.js             # (re-export alias if needed — canonical logic is in fsguard)
    config.js                # config.json R/W + HMAC (now carries fsGuard)
    store.js                 # guardrail.dat AES-256-GCM
    agentgate.js             # shared agent gates (now also covers FS)
    sensitive.js / commands.js / policy.js
  platform/
    sandbox.js               # ← NEW: Local Runtime & Sandbox Monitor (App Sandbox / AppContainer)
    paths.js                 # OS-standard dirs (userData, systemSpool, daemonDir)
    biometrics.js            # TouchID / Hello gate for turning protection off
    dns-controller.js etc.
  renderer/
    index.html               # ← UPDATED: sidebar tab shell (4 modules)
    style.css                # ← UPDATED: sidebar + FS + sandbox styles
    app.js                   # ← UPDATED: tab controller, FS mounts, sanitizer, sandbox polling
  dns/  proxy/               # DNS resolver, pf firewall, SNI proxy

test/
  unit.test.js               # existing 80+30+30 tests (still green)
  fsguard.test.js            # (optional) — see note below

docs/
  FILESYSTEM_GUARD.md        # ← this file
```

---

## Data models

### VirtualMountPoint
```ts
type VirtualMount = {
  id: string;            // 16 hex chars, crypto.randomBytes(8)
  path: string;          // canonical absolute path (via path-normalize)
  displayName: string;   // basename for UI
  addedAt: number;       // Date.now()
  scope: 'read' | 'readwrite'; // default readwrite, future: read-only mounts
  bookmark: string | null; // macOS Security-Scoped Bookmark (base64), null on Windows
}
```

### FsGuardPolicy
```ts
type FsGuardPolicy = {
  version: 1;
  mounts: VirtualMount[];   // empty = default deny-all
  defaultDeny: true;        // invariant — never false
  blockTraversal: true;     // invariant — lexical + realpath collapse
  enforceCanonical: true;   // invariant — realpath on ancestor if leaf missing
}
```

### Forced exclusion rule (not user-removable)
```ts
// Evaluated AFTER mount containment — even inside a mount, these deny.
FORCED_BASENAMES      = { '.env' }
FORCED_BASENAME_GLOBS = { '.env.*' }          // prefix '.env.'
FORCED_EXTENSIONS     = { '.pem','.key','.p12','.pfx','.kdbx' }
FORCED_DIR_SEGMENTS   = { '.ssh','.aws','.gnupg','.azure','.gcloud','.kube' }
FORCED_BROWSER_FILES  = { 'login data','cookies','web data','history', ... }
FORCED_SUBSTRINGS     = { 'keychain','credentials','id_rsa', ... } // basename match
```

### SandboxProfile
```ts
type SandboxProfile =
  | { platform:'darwin', appSandbox:boolean, hardenedRuntime:boolean,
      entitlements:string[], pfAnchorActive:boolean, proxyActive:boolean }
  | { platform:'win32',  appContainer:boolean, integrityLevel:string,
      firewallActive:boolean, proxyActive:boolean }
```

### RuntimeEvent (ephemeral only)
```ts
type RuntimeEvent = {
  ts: number; kind:'fs_block'|'info'; path:string|null; reason:string; pid:number|null;
}
// Stored in a 200-entry in-memory ring buffer (platform/sandbox.js).
// Never written to disk, never transmitted.
```

---

## Path Normalization Module (`src/core/path-normalize.js`)

Order (must be exactly this):

1. **Validate** — reject empty, null-byte.
2. **Expand `~`** → `os.homedir()`.
3. **Lexical normalize** — `path.resolve` + `..`/`.` collapse, duplicate separators, drive-letter upper-case, trailing-slash strip, `\\?\` strip.
4. **Realpath resolve** — `fs.realpathSync.native` on the full path; if ENOENT, walk up to the nearest existing ancestor, realpath that ancestor, re-append the suffix. This collapses symlink escapes even when the leaf doesn't exist yet (the same technique Chromium's sandbox uses).
5. **Containment check** — `isWithinMount(canonical, mountRoot)` uses lower-casing on Windows and separator-aware prefix test (`mount + '/'`).

Exported helpers:

- `canonicalize(input, opts)` → `{ ok, canonical, error }` — the only entry point guards should call.
- `lexicalNormalize(input, platform)`
- `resolveSymlinks(lexicalAbs, platform)`
- `isWithinMount(candidate, mountRoot, platform)`
- `hasTraversalSequence(input)` — fast `..` segment scan (decoded).
- `sanitizeForLog(p, opts)` and `expandTilde`.

---

## Enforcement order (`src/core/fsguard.js`)

```js
isAccessAllowed(inputPath, policy):
  canonical = canonicalize(inputPath)
  if isForcedExcluded(canonical)   → DENY (rule + reason)
  if policy.mounts.length === 0    → DENY (default-deny)
  if isWithinMount(canonical, anyMount) → ALLOW
  else                             → DENY (outside mounts)
```

All denied paths push an entry to `platform/sandbox.js`'s ephemeral ring and (throttled) to the activity JSONL for the UI. Allowed paths return immediately with no logging of contents — only the basename is ever logged, per privacy invariant.

### IPC surface (main.js)

- `fsguard:pick` — `dialog.showOpenDialog(openDirectory)` → `addMount` → persist → `state` push
- `fsguard:add`  — programmatic mount by path (validated)
- `fsguard:remove`
- `fsguard:check` — agent gate: `{ path, op }` → `isAccessAllowed` + ephemeral event
- `fsguard:exclusions` — read-only forced list for the UI
- `path:canonicalize` — diagnostic
- `sandbox:get` / `sandbox:events` / `sandbox:clear`
- Bridge: `POST /v1/check/fs` → `fsguard.isAccessAllowed(path, policy)`

Persistence: `store.saveSecureStore` + `config.writeSignedConfig` both carry `fsGuard`. `store.loadSecureStore` → `normalizePolicy` ensures forward-compat.

---

## UI (renderer)

Sidebar (4 tabs):

1. **Network & Domain Blocker** — domain blocklist + transport controls (SSH, ICMP, DoH, SNI proxy).
2. **Application & Process Controls** — app blocklist + autofill + keystroke isolation.
3. **File System Guard** — mounts, forced exclusions grid, live path sanitizer tester.
4. **Sandbox Monitor** — App Sandbox / AppContainer profile + in-memory blocked-call log.

Global hero (Protection toggle) stays above the tabs. All tabs share the same `state` pushed over `state` IPC.

---

## Security properties

- Mount picker is the **only** way to grant FS access; there is no “allow all” toggle.
- Forced exclusions cannot be removed via UI or API; they are constants in `fsguard.js`.
- Encrypted store + signed config means a tampered `config.json` is ignored (daemon keeps last verified policy).
- Sandbox monitor is read-only; Windows ACLs on `%APPDATA%` already scope the store to the user, and `%ProgramData%` writes are SYSTEM-only.

---

## Testing

- Manual: add a workspace, try to `cat` a file inside it (allowed), try `cat ~/.ssh/id_rsa` and `cat workspace/../.env` (both blocked), create a symlink from workspace to `/etc` and observe it blocked (canonical escapes mount).
- `sandbox:events` shows only the basename + reason, never file contents, and disappears on quit.
