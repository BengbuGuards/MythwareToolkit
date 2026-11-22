@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0.."
title MythwareToolkit Package (x64 + x86)

:: Signing needs admin; elevate only once for the whole run.
:: When NOSIGN=1 is set, skip elevation and produce unsigned packages.
if not defined NOSIGN (
    net session >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (
        echo [*] Admin required, elevating...
        powershell -Command "Start-Process '%~f0' -Verb RunAs -WorkingDirectory '%CD%'"
        exit /b
    )
)

echo ========================================
echo   Package: UIAccess x64 + x86
echo ========================================
echo.

set "NOPAUSE=1"

:: Clean previous outputs so bin\pkg ends up with exactly 2 exe + 2 zip
echo [*] Cleaning old package artifacts...
if exist bin\pkg (
    rmdir /s /q "bin\pkg\MythwareToolkit"       2>nul
    rmdir /s /q "bin\pkg\MythwareToolkit.x64"   2>nul
    rmdir /s /q "bin\pkg\MythwareToolkit.x86"   2>nul
    del /f /q "bin\pkg\MythwareToolkit*.exe"    2>nul
    del /f /q "bin\pkg\MythwareToolkit*.zip"    2>nul
    del /f /q "bin\pkg\SHA256SUMS.txt"          2>nul
)
echo.

echo [1/4] Build + Sign x64...
call scripts\build.bat x64
if errorlevel 1 goto :fail

echo.
echo [2/4] Build + Sign x86...
call scripts\build.bat x86
if errorlevel 1 goto :fail

for /f "tokens=3" %%a in ('findstr /c:"#define TOOLKIT_VERSION_STR" include\version.h') do set VERSIONSTR=%%~a
set VERSION=v%VERSIONSTR%

echo.
echo [3/4] Package x64...
call :pack x64
if errorlevel 1 goto :fail

echo.
echo [4/4] Package x86...
call :pack x86
if errorlevel 1 goto :fail

echo.
echo ========================================
echo   Package SUCCESS!
echo   bin\pkg\MythwareToolkit.%VERSION%.x64.zip
echo   bin\pkg\MythwareToolkit.%VERSION%.x86.zip
echo ========================================
echo.
echo [*] SHA-256 checksums...
powershell -NoProfile -Command "$files = @(Get-ChildItem 'bin\pkg\MythwareToolkit.*.exe') + @(Get-ChildItem 'bin\pkg\*.zip'); foreach ($f in $files) { ((Get-FileHash $f.FullName -Algorithm SHA256).Hash.ToLower() + '  ' + $f.Name) }"
echo ========================================
pause
exit /b 0

:: ---- Pack one architecture: EXE + deploy.bat + mythware.cer ----
:pack
set "ARCH=%~1"
set "PKGDIR=bin\pkg\MythwareToolkit.%ARCH%"
if exist "%PKGDIR%" rmdir /s /q "%PKGDIR%"
mkdir "%PKGDIR%" || exit /b 1
copy /Y "bin\MythwareToolkit.%VERSION%.%ARCH%.exe" "%PKGDIR%\" >nul
if errorlevel 1 (
    echo [ERROR] bin\MythwareToolkit.%VERSION%.%ARCH%.exe not found
    exit /b 1
)
copy /Y "cert\deploy.bat"   "%PKGDIR%\" >nul
copy /Y "cert\mythware.cer" "%PKGDIR%\" >nul
set "ZIPFILE=%CD%\bin\pkg\MythwareToolkit.%VERSION%.%ARCH%.zip"
if exist "%ZIPFILE%" del /f /q "%ZIPFILE%"
powershell -NoProfile -Command "Compress-Archive -Path '%PKGDIR%\*' -DestinationPath '%ZIPFILE%'"
if errorlevel 1 exit /b 1
:: Remove the staging folder; only the exe and zip stay in bin\pkg
rmdir /s /q "%PKGDIR%" 2>nul
echo   %ZIPFILE%
exit /b 0

:fail
echo.
echo Package FAILED!
if not defined NOPAUSE pause
exit /b 1
