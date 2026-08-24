@echo off
rem Device Control Console -- start elevated, so delete/disable/remove run
rem without a UAC prompt per action.
setlocal
cd /d "%~dp0"

net session >nul 2>&1
if %errorlevel% equ 0 goto :run

powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
exit /b 0

:run
call "%~dp0run.cmd" %*
endlocal
