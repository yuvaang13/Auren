'use strict';
// electron-builder afterPack hook: ad-hoc sign mac bundles.
//
// Why: without a Developer ID, electron-builder skips signing, leaving
// Electron's stale linker signature on our modified bundle (new Info.plist,
// icons, app.asar). Gatekeeper reads that as corruption and reports the app
// as "damaged" with no bypass. A fresh ad-hoc signature instead yields the
// ordinary "unidentified developer" dialog, which right-click → Open bypasses.
//
// Safe to keep once real signing lands: electron-builder's own sign step runs
// after this hook and replaces the ad-hoc signature.
const { execFileSync } = require('node:child_process');

exports.default = async function (context) {
  const platform =
    context && context.packager && context.packager.platform
      ? context.packager.platform.name
      : '';
  if (platform !== 'mac') return;
  const productFilename =
    context.packager.appInfo && context.packager.appInfo.productFilename
      ? context.packager.appInfo.productFilename
      : 'auren';
  const appPath = `${context.appOutDir}/${productFilename}.app`;
  execFileSync('codesign', ['--force', '--deep', '--sign', '-', appPath], {
    stdio: 'inherit',
  });
};
