@echo off
cd /d "%~dp0"
title MythwareToolkit Cleanup

echo ========================================
echo   MythwareToolkit Cleanup
echo ========================================
echo.
echo This will remove:
echo   1. C:\Program Files\MythwareToolkit
echo   2. Desktop shortcut
echo   3. Trusted root certificates
echo   4. Code signing certificates
echo   5. Temp files (logs, extracted tools)
echo.

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Run as Administrator!
    pause
    exit /b 1
)

echo [1/5] Removing program directory...
if exist "C:\Program Files\MythwareToolkit" (
    rmdir /s /q "C:\Program Files\MythwareToolkit"
    echo   Removed C:\Program Files\MythwareToolkit
) else (
    echo   Not found, skip
)

echo [2/5] Removing desktop shortcut...
if exist "%USERPROFILE%\Desktop\MythwareToolkit.lnk" (
    del /f /q "%USERPROFILE%\Desktop\MythwareToolkit.lnk"
    echo   Removed user desktop shortcut
)
if exist "%PUBLIC%\Desktop\MythwareToolkit.lnk" (
    del /f /q "%PUBLIC%\Desktop\MythwareToolkit.lnk"
    echo   Removed public desktop shortcut
)

echo [3/5] Removing trusted root certificates...
certutil -delstore -enterprise Root "MythwareToolkit" >nul 2>&1
certutil -delstore -enterprise Root "BengbuGuards Root CA" >nul 2>&1
echo   Done

echo [4/5] Removing code signing certificates...
certutil -delstore My "MythwareToolkit" >nul 2>&1
echo   Done

echo [5/5] Cleaning temp files...
del /f /q "%TEMP%\MythwareToolkit*.log" >nul 2>&1
del /f /q "%TEMP%\MeltdownDFC.exe" >nul 2>&1
del /f /q "%TEMP%\crdisk.exe" >nul 2>&1
echo   Done

echo.
echo ========================================
echo   Cleanup complete!
echo ========================================
pause
