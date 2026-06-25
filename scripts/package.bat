@echo off
cd /d "%~dp0.."
echo ========================================
echo   Package: UIAccess (Super Topmost)
echo ========================================
echo.
echo [1/3] Build + Sign...
call scripts\build.bat
if %ERRORLEVEL% NEQ 0 (
    echo Build failed, aborting.
    pause & exit /b 1
)

echo.
echo [2/3] Verify digital signature...
powershell -NoProfile -Command "$sig = Get-AuthenticodeSignature 'bin\MythwareToolkit.exe'; if ($sig.Status -eq 'Valid') { Write-Host '  Signature: VALID' -ForegroundColor Green } else { Write-Host '  Signature: MISSING or INVALID!' -ForegroundColor Red; exit 1 }"
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: EXE is not signed! Run build.bat first.
    pause & exit /b 1
)

set PKGDIR=bin\pkg\MythwareToolkit
if exist "%PKGDIR%" rmdir /s /q "%PKGDIR%"
mkdir "%PKGDIR%"

copy /Y "bin\MythwareToolkit.exe" "%PKGDIR%\" >nul
copy /Y "cert\deploy.bat"         "%PKGDIR%\" >nul
copy /Y "cert\mythware.cer"       "%PKGDIR%\" >nul

echo.
echo [3/3] Creating ZIP...
set ZIPFILE=%CD%\bin\pkg\MythwareToolkit.zip
if exist "%ZIPFILE%" del /f /q "%ZIPFILE%"
powershell -NoProfile -Command "Compress-Archive -Path '%PKGDIR%\*' -DestinationPath '%ZIPFILE%'"

echo.
echo ========================================
echo   Package SUCCESS!
echo ========================================
echo   File: %ZIPFILE%
echo   Contains:
echo     - MythwareToolkit.exe
echo     - deploy.bat
echo     - mythware.cer
echo ========================================
pause
