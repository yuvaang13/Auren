/* auren — generate build/icon.ico from build/icon.png.
 *
 * A single 256x256 PNG entry in an ICO container is valid and accepted by
 * Windows and electron-builder (the PNG is stored uncompressed inside the ICO,
 * which is the standard for 256px icons). Pure Node — no ImageMagick needed.
 *
 * Run: node scripts/make-ico.js
 */

'use strict';
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const pngPath = path.join(root, 'build', 'icon.png');
const icoPath = path.join(root, 'build', 'icon.ico');

const png = fs.readFileSync(pngPath);
if (!Buffer.isBuffer(png) || png.length < 8 || png.toString('ascii', 1, 4) !== 'PNG') {
  console.error('build/icon.png missing or not a PNG — run the icon renderer first.');
  process.exit(1);
}

// ICONDIR
const header = Buffer.alloc(6);
header.writeUInt16LE(0, 0); // reserved
header.writeUInt16LE(1, 2); // type: icon
header.writeUInt16LE(1, 4); // count

// ICONDIRENTRY
const entry = Buffer.alloc(16);
entry.writeUInt8(0, 0);   // width 0 == 256
entry.writeUInt8(0, 1);   // height 0 == 256
entry.writeUInt8(0, 2);   // palette count
entry.writeUInt8(0, 3);   // reserved
entry.writeUInt16LE(1, 4);   // color planes
entry.writeUInt16LE(32, 6);  // bits per pixel
entry.writeUInt32LE(png.length, 8);  // data size
entry.writeUInt32LE(22, 12);  // data offset (header + entry)

fs.writeFileSync(icoPath, Buffer.concat([header, entry, png]));
console.log('wrote', icoPath, (header.length + entry.length + png.length) + ' bytes');
