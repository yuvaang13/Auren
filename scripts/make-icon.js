/* auren — one-off build script: render build/icon-source.html and capture it
 * as build/icon.png. Run with: node_modules/.bin/electron scripts/make-icon.js
 */

'use strict';
const { app, BrowserWindow } = require('electron');
const path = require('path');
const fs = require('fs');

app.disableHardwareAcceleration();

async function main() {
  const win = new BrowserWindow({
    width: 1024,
    height: 1024,
    show: false,
    frame: false,
    transparent: true,
    backgroundColor: '#00000000',
    useContentSize: true,
    webPreferences: {
      offscreen: true,
      backgroundThrottling: false,
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });
  win.setBackgroundColor('#00000000');
  await win.loadFile(path.join(__dirname, '..', 'build', 'icon-source.html'));
  await new Promise((r) => setTimeout(r, 800));
  const image = await win.webContents.capturePage();
  const out = path.join(__dirname, '..', 'build', 'icon.png');
  fs.writeFileSync(out, image.toPNG());
  const size = image.getSize();
  console.log('wrote', out, size.width + 'x' + size.height, image.toPNG().length + ' bytes');
  app.exit(0);
}

app.whenReady().then(main).catch((err) => {
  console.error(err);
  app.exit(1);
});
