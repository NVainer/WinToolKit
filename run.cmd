@echo off
rem Device Control Console -- start the local web console.
rem Runs as the current user; write actions raise a UAC prompt when needed.
setlocal
cd /d "%~dp0"

set "PY="
where py.exe >nul 2>&1 && set "PY=py -3"
if not defined PY (where python.exe >nul 2>&1 && set "PY=python")
if not defined PY (
  echo Python 3.10 or newer is required but was not found on PATH.
  echo Install it from https://www.python.org/downloads/windows/ and try again.
  pause
  exit /b 1
)

%PY% dcc.py %*
endlocal
