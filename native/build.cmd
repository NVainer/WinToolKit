@echo off
rem Build the single-file native console.
rem
rem Uses the C# compiler that ships inside Windows itself -- no SDK, no
rem NuGet, no downloads.  Output is one self-contained .exe that runs on any
rem Windows 10/11 (the .NET Framework 4.x runtime is in-box there).
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem Double-clicked from Explorer?  Then this window closes the moment the
rem script ends, so hold it open at the end.  Launched from a terminal there
rem is nothing to hold, and a pause would just be in the way.
set "HOLD="
echo %cmdcmdline% | find /i "%~f0" >nul 2>&1 && set "HOLD=1"

set "CSC=%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo Could not find the in-box C# compiler:
  echo   %SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
  echo This needs the .NET Framework 4.x runtime, which ships with Windows 10 and 11.
  goto :done_fail
)

set "OUTDIR=%~dp0bin"
set "OUT=%OUTDIR%\DeviceControlConsole.exe"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"

rem The UI is shared with the Python build rather than duplicated: the same
rem three files are embedded here as resources.
set "WEB=%~dp0..\dcc\web"
for %%F in ("%WEB%\index.html" "%WEB%\app.js" "%WEB%\style.css") do (
  if not exist "%%~F" (
    echo Missing web asset: %%~F
    goto :done_fail
  )
)

echo Compiling...
"%CSC%" /nologo /target:exe /platform:anycpu /optimize+ /warn:4 ^
  /out:"%OUT%" ^
  /win32manifest:"%~dp0app.manifest" ^
  /resource:"%WEB%\index.html",index.html ^
  /resource:"%WEB%\app.js",app.js ^
  /resource:"%WEB%\style.css",style.css ^
  "%~dp0src\*.cs"

if errorlevel 1 goto :done_fail

echo.
for %%A in ("%OUT%") do echo Built %%~fA  (%%~zA bytes^)
echo.
echo Start the console with:
echo    run.cmd
echo or double-click bin\DeviceControlConsole.exe
echo.
echo That single .exe is self-contained - copy it anywhere.
goto :done_ok

:done_fail
echo.
echo BUILD FAILED
if defined HOLD pause
exit /b 1

:done_ok
if defined HOLD pause
exit /b 0
