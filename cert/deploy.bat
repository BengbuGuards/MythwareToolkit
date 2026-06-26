@echo off
set "HERE=%~dp0"
set "TARGET=C:\Program Files\MythwareToolkit"

:: Check admin rights
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Admin required, elevating...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -WorkingDirectory '%HERE%'"
    exit /b
)

echo ==========================================
echo   MythwareToolkit v2.0 Deploy
echo ==========================================
echo.

:: [1] Find EXE (any .exe in current dir, excluding myself)
set "EXE="
for %%f in ("%HERE%*.exe") do (
    if not "%%~nxf"=="%~nx0" set "EXE=%%f"
)
if not defined EXE (
    echo [ERROR] No EXE found in %HERE%
    pause
    exit /b 1
)
for %%f in ("%EXE%") do set "EXENAME=%%~nxf"
echo [1/4] Copy EXE (%EXENAME%)...
mkdir "%TARGET%" 2>nul
copy /Y "%EXE%" "%TARGET%\" >nul
echo   %EXE% -^> %TARGET%\

:: [2] Install cert
echo [2/4] Install certificate...
set "CERT="
if exist "%HERE%mythware.cer" set "CERT=%HERE%mythware.cer"
if not defined CERT (
    if exist "%HERE%..\bin\MythwareToolkit.cer" set "CERT=%HERE%..\bin\MythwareToolkit.cer"
)
if defined CERT (
    certutil -addstore -f -enterprise Root "%CERT%" >nul 2>&1
    echo   %CERT% installed
) else (
    echo   mythware.cer not found, skipped
)

:: [3] RootCA.reg fallback
echo [3/4] Import RootCA.reg...
set "REG="
if exist "%HERE%RootCA.reg" set "REG=%HERE%RootCA.reg"
if defined REG (
    reg import "%REG%" >nul 2>&1
    echo   RootCA.reg imported
) else (
    echo   RootCA.reg not found, skipped
)

:: [4] Desktop shortcut
echo [4/4] Create desktop shortcut...
powershell -Command "$ws=New-Object -ComObject WScript.Shell;$s=$ws.CreateShortcut([Environment]::GetFolderPath('Desktop')+'\MythwareToolkit.lnk');$s.TargetPath='%TARGET%\%EXENAME%';$s.WorkingDirectory='%TARGET%';$s.Save()"
echo   Done

echo.
echo ==========================================
echo   Deploy OK!
echo   %TARGET%\%EXENAME%
echo ==========================================
pause
