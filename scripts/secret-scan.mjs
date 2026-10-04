// Auren — cross-platform secret scan (CI + local).
//
// Replaces the old `grep`-based CI step, which had two defects:
//   1. macOS: it flagged the intentional dummy fixtures in
//      test/sensitive.test.js (e.g. 'sk-live-abc...', 'AKIA...EXAMPLE'),
//      which exist to exercise the sensitive-data classifier.
//   2. Windows: the step used bash-only syntax (`! grep ...`), which
//      PowerShell cannot parse, so it failed before scanning anything.
//
// Usage: node scripts/secret-scan.mjs (exit 0 = clean, exit 1 = leak found)
//
// Scope: scans tracked source in src/, scripts/ and test/. Known dummy
// fixture values (see ALLOWLIST below) are skipped; anything else matching
// a real-token shape fails the scan.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCAN_DIRS = ['src', 'scripts', 'test'];
const SCAN_EXTS = new Set([
  '.js', '.mjs', '.cjs', '.ts', '.tsx', '.json',
  '.yml', '.yaml', '.sh', '.ps1', '.cmd', '.html',
]);

const PATTERNS = [
  { name: 'GitHub PAT (ghp_)', re: /ghp_[A-Za-z0-9]{20,}/ },
  { name: 'GitHub OAuth (gho_)', re: /gho_[A-Za-z0-9]{20,}/ },
  { name: 'live secret key (sk-live-)', re: /sk-live-[A-Za-z0-9]{10,}/ },
  { name: 'AWS access key (AKIA)', re: /AKIA[0-9A-Z]{16}/ },
  { name: 'Slack token (xox...)', re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
];

// Intentional dummy fixtures used by the classifier tests — these look like
// tokens by design so the detector has something to catch. They must never
// be treated as leaked secrets.
const ALLOWLIST = [
  'sk-live-abcdefghijklmnopqrstuvwxyz123456',
  'AKIAIOSFODNN7EXAMPLE',
  'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij',
];

function isAllowed(line) {
  return ALLOWLIST.some((dummy) => line.includes(dummy));
}

function walk(dir, out) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (SCAN_EXTS.has(path.extname(entry.name))) out.push(full);
  }
}

const files = [];
for (const dir of SCAN_DIRS) {
  const abs = path.join(ROOT, dir);
  if (fs.existsSync(abs)) walk(abs, files);
}

const hits = [];
for (const file of files) {
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, i) => {
    if (isAllowed(line)) return;
    for (const { name, re } of PATTERNS) {
      if (re.test(line)) {
        hits.push(`${path.relative(ROOT, file)}:${i + 1}: [${name}]`);
        break;
      }
    }
  });
}

if (hits.length > 0) {
  console.error('secret scan FAILED — possible hardcoded secret:');
  for (const hit of hits) console.error('  ' + hit);
  process.exit(1);
}

console.log(`secret scan clean (${files.length} files checked)`);
