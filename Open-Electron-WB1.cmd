@echo off
if not exist "%~dp0electron-client\node_modules\.bin\electron.cmd" (
  echo Install dependencies first: cd electron-client ^&^& npm install
  pause
  exit /b 1
)
start "Electron WB1" /d "%~dp0electron-client" "%~dp0electron-client\node_modules\.bin\electron.cmd" . --profile=WB1
