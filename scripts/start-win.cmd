@echo off
REM auren — dev launcher for Windows.
REM Runs the generic Electron binary against the repo. Packaged builds don't
REM need this; they get the name, icon and metadata from the installer.
npx electron .
