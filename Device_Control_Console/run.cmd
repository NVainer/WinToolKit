@echo off
rem Device Control Console -- start the local web console (Python build).
rem Runs as the current user; write actions raise a UAC prompt when needed.
setlocal
cd /d "%~dp0"

set "PY="
where py.exe >nul 2>&1 && set "PY=py -3"
if not defined PY (where python.exe >nul 2>&1 && set "PY=python")
if not defined PY (
  echo Python 3.10 or newer is required but was not found on PATH.
  echo.
  echo Either install it from https://www.python.org/downloads/windows/
  echo or use the native build, which needs nothing at all:
  echo     native\build.cmd
  pause
  exit /b 1
)

echo ============================================================
echo  This window IS the console. Leave it open.
echo  Closing it, or pressing Ctrl+C, stops the server.
echo ============================================================
echo.

%PY% dcc.py %*

rem Without this the window vanishes on error when double-clicked from Explorer.
echo.
echo The console has stopped (exit code %errorlevel%).
pause
endlocal
