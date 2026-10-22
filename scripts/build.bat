@echo off
cd /d "%~dp0.."
setlocal enabledelayedexpansion

:: ============================================================
::  Usage: scripts\build.bat [x64^|x86]
::  Default arch is x64.
::  Set NOPAUSE=1 to skip the final pause (used by package.bat).
::  Set NOSIGN=1 to skip code signing.
:: ============================================================
set ARCH=%~1
if "%ARCH%"=="" (
    if defined NOPAUSE (
        rem Non-interactive call: default to x64
        set ARCH=x64
    ) else (
        echo Select target architecture:
        echo   [1] x64 - 64-bit Windows
        echo   [2] x86 - 32-bit Windows
        choice /c 12 /n /m "Enter choice [1/2]: "
        if errorlevel 2 (set ARCH=x86) else (set ARCH=x64)
    )
)
if /i not "%ARCH%"=="x64" if /i not "%ARCH%"=="x86" (
    echo ERROR: arch must be x64 or x86
    if not defined NOPAUSE pause
    exit /b 1
)

set OUTDIR=bin
set OBJDIR=bin\obj_%ARCH%
set CFLAGS=-O3 -pipe -lntdll -fexec-charset=UTF-8 -Iinclude -DUIACCESS_BUILD
set LFLAGS=-s -mwindows -lcomctl32 -lgdi32 -static

:: ---- Locate a matching MinGW toolchain ----
set MINGW=
if /i "%ARCH%"=="x64" (
    for %%d in (
        "D:\Dev\msys64\ucrt64"
        "C:\msys64\ucrt64"
        "D:\Dev\mingw64"
        "C:\mingw64"
        "C:\msys64\mingw64"
        "C:\Program Files\mingw64"
        "C:\Program Files (x86)\mingw64"
    ) do (
        if exist "%%~d\bin\g++.exe" (set "MINGW=%%~d\bin" & goto :found)
    )
    where g++ >nul 2>&1
    if !ERRORLEVEL!==0 (set MINGW= & goto :found)
) else (
    for %%d in (
        "D:\Dev\msys64\mingw32"
        "D:\Dev\mingw32"
        "C:\mingw32"
        "C:\msys64\mingw32"
        "C:\Program Files\mingw32"
        "C:\Program Files (x86)\mingw32"
    ) do (
        if exist "%%~d\bin\g++.exe" (set "MINGW=%%~d\bin" & goto :found)
    )
)
echo ERROR: %ARCH% MinGW not found!
echo   For x86 install MSYS2 mingw-w64-i686-gcc (pacman -S mingw-w64-i686-gcc).
if not defined NOPAUSE pause
exit /b 1

:found
if defined MINGW (set "CXX=%MINGW%\g++.exe" & set "WR=%MINGW%\windres.exe") else (set CXX=g++ & set WR=windres)
:: windres needs the toolchain on PATH for its preprocessor step
if defined MINGW set "PATH=%MINGW%;%PATH%"
echo MinGW: %MINGW%

:: ---- Verify toolchain architecture ----
set TRIPLE=
for /f "delims=" %%a in ('"%CXX%" -dumpmachine') do set TRIPLE=%%a
echo Target: %TRIPLE%
set ARCHOK=0
if /i "%ARCH%"=="x64" (
    echo !TRIPLE! | findstr /c:"x86_64" >nul && set ARCHOK=1
) else (
    echo !TRIPLE! | findstr /c:"i686" >nul && set ARCHOK=1
)
if "!ARCHOK!"=="0" (
    echo ERROR: toolchain architecture does not match %ARCH%
    if not defined NOPAUSE pause
    exit /b 1
)

if not exist %OUTDIR% mkdir %OUTDIR%
if not exist %OBJDIR% mkdir %OBJDIR%

for /f "tokens=3" %%a in ('findstr /c:"#define TOOLKIT_VERSION_STR" include\version.h') do set VERSIONSTR=%%~a
set VERSION=v%VERSIONSTR%

echo.
echo === UIAccess Build (%ARCH%) ===
echo [ 1/12] resource.res & %WR% -i res\resource.rc --input-format=rc -o %OBJDIR%\resource.res -O coff -I res -I include || goto :err
echo [ 2/12] utils.o      & %CXX% -c src\utils.cpp     -o %OBJDIR%\utils.o     %CFLAGS% || goto :err
echo [ 3/12] process.o    & %CXX% -c src\process.cpp   -o %OBJDIR%\process.o   %CFLAGS% || goto :err
echo [ 4/12] bypass.o     & %CXX% -c src\bypass.cpp    -o %OBJDIR%\bypass.o    %CFLAGS% || goto :err
echo [ 5/12] assistant.o  & %CXX% -c src\assistant.cpp -o %OBJDIR%\assistant.o %CFLAGS% || goto :err
echo [ 6/12] mythware.o   & %CXX% -c src\mythware.cpp  -o %OBJDIR%\mythware.o  %CFLAGS% || goto :err
echo [ 7/12] hooks.o      & %CXX% -c src\hooks.cpp     -o %OBJDIR%\hooks.o     %CFLAGS% || goto :err
echo [ 8/12] psd.o        & %CXX% -c src\psd.cpp       -o %OBJDIR%\psd.o       %CFLAGS% || goto :err
echo [ 9/12] ui.o         & %CXX% -c src\ui.cpp        -o %OBJDIR%\ui.o        %CFLAGS% || goto :err
echo [10/12] floating.o   & %CXX% -c src\floating.cpp  -o %OBJDIR%\floating.o  %CFLAGS% || goto :err
echo [11/12] main.o       & %CXX% -c src\main.cpp      -o %OBJDIR%\main.o      %CFLAGS% || goto :err
echo [12/12] Linking...
%CXX% %OBJDIR%\main.o %OBJDIR%\utils.o %OBJDIR%\process.o %OBJDIR%\bypass.o %OBJDIR%\assistant.o %OBJDIR%\mythware.o %OBJDIR%\hooks.o %OBJDIR%\psd.o %OBJDIR%\ui.o %OBJDIR%\floating.o %OBJDIR%\resource.res -o %OUTDIR%\MythwareToolkit.%VERSION%.%ARCH%.exe %LFLAGS% || goto :err

set "EXEFILE=%CD%\%OUTDIR%\MythwareToolkit.%VERSION%.%ARCH%.exe"
for %%f in ("%EXEFILE%") do set FILESIZE=%%~zf
echo.
echo ========================================
echo   Build SUCCESS! (%ARCH%)
echo ========================================
echo   File : %EXEFILE%
echo   Size : %FILESIZE% bytes
echo.

:: ---- Code signing (skip with NOSIGN=1) ----
if defined NOSIGN (
    echo   [*] NOSIGN set - skipping signing
) else (
    set "PS=pwsh"
    where pwsh >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (set "PS=powershell")

    net session >nul 2>&1
    if !ERRORLEVEL! NEQ 0 (
        echo   [*] Elevating for code signing...
        !PS! -Command "Start-Process '!PS!' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File scripts\sign.ps1 -Arch %ARCH%' -Verb RunAs -Wait -WorkingDirectory '%CD%'" 2>nul
    ) else (
        echo   [*] Signing EXE...
        !PS! -NoProfile -ExecutionPolicy Bypass -File scripts\sign.ps1 -Arch %ARCH%
    )
)

echo.
echo ========================================
echo   Build + Sign SUCCESS! (%ARCH%)
echo ========================================
echo   File : %EXEFILE%
echo   Size : %FILESIZE% bytes
echo   Next : cert\deploy.bat
echo ========================================
if not exist bin\pkg mkdir bin\pkg
copy /Y "%EXEFILE%" "bin\pkg\" >nul
echo   Output: bin\pkg\MythwareToolkit.%VERSION%.%ARCH%.exe
echo ========================================
if not defined NOPAUSE pause
exit /b 0

:err
echo Build FAILED!
if not defined NOPAUSE pause
exit /b 1
