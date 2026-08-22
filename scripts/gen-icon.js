'use strict';
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const root = path.join(__dirname, '..');
const pngPath = path.join(root, 'build', 'icon.png');
const icnsPath = path.join(root, 'build', 'icon.icns');
const aurenIcns = path.join(root, 'auren.icns');

// If the canonical auren.icns exists at the repo root, use it directly — it is the source of truth for the Dock/app icon.
if (fs.existsSync(aurenIcns)) {
  try { fs.copyFileSync(aurenIcns, icnsPath); } catch {}
  console.log('ICNS copied from auren.icns to build/icon.icns');
  process.exit(0);
}

try {
  fs.accessSync(pngPath);
} catch {
  console.error('build/icon.png not found — run make-icon.js first');
  process.exit(1);
}

// Remove old icns if present
try { fs.unlinkSync(icnsPath); } catch {}

const sizes = ['16', '16@2', '32', '32@2', '64', '64@2', '128', '128@2', '256', '256@2', '512', '512@2', '1024', '1024@2'];

const iconsetDir = '/tmp/auren.iconset';
try { fs.rmSync(iconsetDir, { recursive: true }); } catch {}

fs.mkdirSync(iconsetDir, { recursive: true });

for (const size of sizes) {
  const dim = size.includes('@2') ? size.replace('@2', '') * 2 : size.replace('', '');
  const outPath = path.join(iconsetDir, `icon_${size}.png`);
  const dimNum = parseInt(dim, 10);
  execSync(`sips -z ${dimNum} ${dimNum} "${pngPath}" --out "${outPath}"`, { stdio: 'ignore' });
}

execSync(`iconutil -c icns -o "${icnsPath}" ${iconsetDir}`, { stdio: 'ignore' });
console.log('ICNS regenerated at build/icon.icns');