@echo off
setlocal
rem win-debug launcher (ASCII only, CRLF). Usage: WinDebug.cmd [inventory|disk|monitor|analyze|all] [options]
rem Without arguments the interactive menu opens. Options are passed through to WinDebug.ps1.
rem When the first argument starts with "-" everything is passed through unchanged (e.g. WinDebug.cmd -Mode Disk -Drives C).

set "HERE=%~dp0"
if "%HERE:~0,2%"=="\\" goto unc
cd /d "%HERE%" 2>nul
if errorlevel 1 goto unc

set "MODE=%~1"
if "%MODE%"=="" set "MODE=Menu"
if "%MODE:~0,1%"=="-" goto passthrough

rem Forward everything after the mode word verbatim. Re-tokenizing through %1/shift would let cmd.exe split
rem "-Drives C,D" into "-Drives C D" (commas are argument separators for cmd, not for PowerShell).
set "ARGS=%*"
set "REST="
if defined ARGS call set "REST=%%ARGS:*%1=%%"
set "PSARGS=-Mode %MODE% %REST%"
goto launch

:passthrough
set "PSARGS=%*"
set "MODE=options"
echo %*| find /i "-Mode Monitor" >nul && set "MODE=monitor"

:launch
rem Fully qualified host: cmd.exe resolves a bare "powershell.exe" from the current directory first (the tool
rem folder is user-writable because reports\ lives there), then through PATH.
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%HERE%WinDebug.ps1" %PSARGS%
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" (
  echo.
  echo WinDebug exited with code %RC%.
)
if /i not "%MODE%"=="monitor" pause
endlocal & exit /b %RC%

:unc
echo This folder is on a network/UNC path (%HERE%).
echo Copy win-debug to a local folder (for example C:\Tools\win-debug) and run it from there.
pause
endlocal & exit /b 2
