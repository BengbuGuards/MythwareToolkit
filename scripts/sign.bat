@echo off
cd /d "%~dp0.."

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Admin required, elevating...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -WorkingDirectory '%~dp0..'"
    exit /b
)

if not exist "bin\MythwareToolkit.exe" (
    echo [ERROR] bin\MythwareToolkit.exe not found
    echo   Run scripts\build.bat first!
    pause
    exit /b 1
)

echo ========================================
echo   MythwareToolkit Code Signing
echo ========================================
echo   Target: bin\MythwareToolkit.exe
echo.

set "PS=pwsh"
where pwsh >nul 2>&1
if %ERRORLEVEL% NEQ 0 (set "PS=powershell")

%PS% -NoProfile -ExecutionPolicy Bypass -File scripts\sign.ps1

if %ERRORLEVEL% NEQ 0 (
    echo [FAILED] Signing error - check output above
    pause
    exit /b 1
)

echo ========================================
echo   Signing SUCCESS!
echo ========================================
echo   Cert: cert\mythware.cer
echo   EXE : bin\MythwareToolkit.exe
echo   Next: cert\deploy.bat
echo ========================================
pause
