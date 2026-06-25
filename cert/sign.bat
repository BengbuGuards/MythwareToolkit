@echo off
cd /d "%~dp0.."

:: Check admin rights
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Admin required, elevating...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -WorkingDirectory '%~dp0..'"
    exit /b
)

:: Check EXE exists
if not exist "bin\MythwareToolkit.exe" (
    echo [ERROR] bin\MythwareToolkit.exe not found
    echo   Run scripts\build.bat first!
    pause
    exit /b 1
)

echo ========================================
echo   MythwareToolkit Self-Signing
echo ========================================
echo.
echo   Target: %CD%\bin\MythwareToolkit.exe
echo.

:: Prefer PS7, fallback to PS5
set "PS=pwsh"
where pwsh >nul 2>&1
if %ERRORLEVEL% NEQ 0 (set "PS=powershell")

echo   Running: %PS% scripts\sign.ps1
echo.

%PS% -NoProfile -ExecutionPolicy Bypass -File scripts\sign.ps1

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [FAILED] Signing error - check output above
    pause
    exit /b 1
)

echo.
echo ========================================
echo   Signing SUCCESS!
echo ========================================
echo.
echo   Cert: %CD%\cert\mythware.cer
echo   EXE : %CD%\bin\MythwareToolkit.exe
echo.
echo   Verify: right-click EXE -^> Properties -^> Digital Signatures
echo.
echo   Next step: cert\deploy.bat
echo.
pause
