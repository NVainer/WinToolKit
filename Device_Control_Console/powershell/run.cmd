@echo off
rem Device Control Console -- PowerShell build.
rem
rem Runs under Windows PowerShell, which is signed by Microsoft and permitted
rem by Smart App Control and by the usual WDAC/AppLocker policies.  Nothing
rem here is compiled, so there is no unsigned binary for a policy to block.
setlocal
cd /d "%~dp0"

set "PS=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if not exist "%PS%" (
  echo Windows PowerShell was not found at:
  echo   %PS%
  pause
  exit /b 1
)

echo ============================================================
echo  This window IS the console. Leave it open.
echo  Closing it, or pressing Ctrl+C, stops the server.
echo ============================================================
echo.

rem -ExecutionPolicy Bypass applies to this process only; it does not change
rem any machine or user policy.
"%PS%" -NoProfile -ExecutionPolicy Bypass -File "%~dp0DeviceControlConsole.ps1" serve %*

echo.
echo The console has stopped (exit code %errorlevel%).
pause
endlocal
