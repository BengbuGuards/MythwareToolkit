@echo off
cd /d "%~dp0.."

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Admin required, elevating...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -WorkingDirectory '%~dp0..'"
    exit /b
)

set "PS=pwsh"
where pwsh >nul 2>&1
if %ERRORLEVEL% NEQ 0 (set "PS=powershell")

echo ========================================
echo   MythwareToolkit Code Signing
echo ========================================
echo.

set SIGNED=0
for %%A in (x64 x86) do (
    if exist "bin\MythwareToolkit.v*.%%A.exe" (
        echo [*] Signing %%A...
        %PS% -NoProfile -ExecutionPolicy Bypass -File scripts\sign.ps1 -Arch %%A
        if errorlevel 1 (
            echo [FAILED] Signing %%A error - check output above
            pause
            exit /b 1
        )
        set SIGNED=1
    )
)

if "%SIGNED%"=="0" (
    echo [ERROR] bin\MythwareToolkit.v*.x64.exe / .x86.exe not found
    echo   Run scripts\build.bat first!
    pause
    exit /b 1
)

echo ========================================
echo   Signing SUCCESS!
echo ========================================
echo   Cert: cert\mythware.cer
echo   Next: cert\deploy.bat
echo ========================================
pause
