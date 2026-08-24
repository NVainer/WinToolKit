@echo off
rem Start the native console and keep this window open while it serves.
rem Builds the exe first if it is not there yet.
setlocal
cd /d "%~dp0"

set "EXE=%~dp0bin\DeviceControlConsole.exe"

if not exist "%EXE%" (
  echo The console has not been built yet - building it now...
  echo.
  call "%~dp0build.cmd"
  if errorlevel 1 (
    echo.
    echo Build failed, so there is nothing to run.
    pause
    exit /b 1
  )
  echo.
)

echo ============================================================
echo  This window IS the console. Leave it open.
echo  Closing it, or pressing Ctrl+C, stops the server.
echo ============================================================
echo.

"%EXE%" serve %*

rem If the server stops for any reason, say why before the window disappears.
echo.
echo The console has stopped (exit code %errorlevel%).
pause
endlocal
