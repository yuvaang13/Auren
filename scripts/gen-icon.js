'use strict';
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const root = path.join(__dirname, '..');
const pngPath = path.join(root, 'build', 'icon.png');
const icnsPath = path.join(root, 'build', 'icon.icns');
const aurenIcns = path.join(root, 'auren.icns');

// build/icon.png is the source of truth (matte squircle + enlarged mark,
// see build/icon-source.html). Always regenerate .icns from it.

try {
  fs.accessSync(pngPath);
} catch {
  console.error('build/icon.png not found — run make-icon.js first');
  process.exit(1);
}

// Remove old icns if present
try { fs.unlinkSync(icnsPath); } catch {}

const iconsetDir = '/tmp/auren.iconset';
try { fs.rmSync(iconsetDir, { recursive: true }); } catch {}

fs.mkdirSync(iconsetDir, { recursive: true });

const targets = [
  ['icon_16x16.png', 16],
  ['icon_16x16@2x.png', 32],
  ['icon_32x32.png', 32],
  ['icon_32x32@2x.png', 64],
  ['icon_128x128.png', 128],
  ['icon_128x128@2x.png', 256],
  ['icon_256x256.png', 256],
  ['icon_256x256@2x.png', 512],
  ['icon_512x512.png', 512],
  ['icon_512x512@2x.png', 1024],
];

for (const [name, dim] of targets) {
  const outPath = path.join(iconsetDir, name);
  execSync(`sips -z ${dim} ${dim} "${pngPath}" --out "${outPath}"`, { stdio: 'ignore' });
}

execSync(`iconutil -c icns -o "${icnsPath}" ${iconsetDir}`, { stdio: 'ignore' });
// Keep the root copy in sync — electron-builder reads build/icon.icns.
try { fs.copyFileSync(icnsPath, aurenIcns); } catch {}
console.log('ICNS regenerated at build/icon.icns');