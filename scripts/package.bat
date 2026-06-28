@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0.."
echo ========================================
echo   Package: UIAccess (Super Topmost)
echo ========================================
echo.

echo [1/2] Build + Sign...
call scripts\build.bat
if %ERRORLEVEL% NEQ 0 (
    echo Build failed, aborting.
    pause & exit /b 1
)

echo.
echo [2/2] Packaging...

set PKGDIR=bin\pkg\MythwareToolkit
if exist "%PKGDIR%" rmdir /s /q "%PKGDIR%"
mkdir "%PKGDIR%"

copy /Y "bin\MythwareToolkit.exe" "%PKGDIR%\" >nul
copy /Y "cert\deploy.bat"         "%PKGDIR%\" >nul
copy /Y "cert\mythware.cer"       "%PKGDIR%\" >nul

echo [*] Creating ZIP...
set ZIPFILE=%CD%\bin\pkg\MythwareToolkit.zip
if exist "%ZIPFILE%" del /f /q "%ZIPFILE%"
powershell -NoProfile -Command "Compress-Archive -Path '%PKGDIR%\*' -DestinationPath '%ZIPFILE%'"

echo ========================================
echo   Package: %ZIPFILE%
echo   Contains: MythwareToolkit.exe + deploy.bat + mythware.cer
echo ========================================
pause
