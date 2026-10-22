@echo off
setlocal
cd /d "%~dp0.."
title MythwareToolkit Cleanup

echo ========================================
echo   MythwareToolkit Cleanup
echo ========================================
echo.
echo This will remove:
echo   1. C:\Program Files\MythwareToolkit
echo   2. Desktop shortcuts
echo   3. Trusted root certificates
echo   4. Code signing certificates
echo   5. Temp files (logs, extracted tools, exported log)
echo.

:: ---- Elevate automatically ----
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Admin required, elevating...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -WorkingDirectory '%CD%'"
    exit /b
)
:: ---- Refuse to run while the app is active: its process protection blocks deletion ----
tasklist 2>nul | findstr /i "MythwareToolkit" >nul
if not errorlevel 1 (
    echo [ERROR] MythwareToolkit is still running.
    echo   Exit it first, then run this script again.
    pause
    exit /b 1
)

echo [1/5] Removing program directory...
if exist "C:\Program Files\MythwareToolkit" (
    rmdir /s /q "C:\Program Files\MythwareToolkit"
    echo   Removed
) else (
    echo   Not found, skip
)

echo [2/5] Removing desktop shortcuts...
if exist "%USERPROFILE%\Desktop\MythwareToolkit.lnk" del /f /q "%USERPROFILE%\Desktop\MythwareToolkit.lnk"
if exist "%PUBLIC%\Desktop\MythwareToolkit.lnk" del /f /q "%PUBLIC%\Desktop\MythwareToolkit.lnk"
echo   Done

echo [3/5] Removing trusted root certificates...
powershell -NoProfile -Command "$n=0; Get-ChildItem Cert:\LocalMachine\Root,Cert:\CurrentUser\Root -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like '*MythwareToolkit*' -or $_.Subject -like '*BengbuGuards*' } | ForEach-Object { Remove-Item -Path $_.PSPath -Force -ErrorAction SilentlyContinue; $n++ }; Write-Host ('  Removed ' + $n + ' cert(s)')"

echo [4/5] Removing code signing certificates...
powershell -NoProfile -Command "$n=0; Get-ChildItem Cert:\CurrentUser\My,Cert:\LocalMachine\My -ErrorAction SilentlyContinue | Where-Object { $_.Subject -like '*MythwareToolkit*' } | ForEach-Object { Remove-Item -Path $_.PSPath -Force -ErrorAction SilentlyContinue; $n++ }; Write-Host ('  Removed ' + $n + ' cert(s)')"

echo [5/5] Cleaning temp files...
del /f /q "%TEMP%\MythwareToolkit*.log*" >nul 2>&1
del /f /q "%TEMP%\MeltdownDFC.exe" >nul 2>&1
del /f /q "%TEMP%\crdisk.exe" >nul 2>&1
del /f /q "%TEMP%\ToolkitLog.txt" >nul 2>&1
echo   Done

echo.
echo ========================================
echo   Cleanup complete!
echo ========================================
pause
