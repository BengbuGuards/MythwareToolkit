@echo off
cd /d "%~dp0.."
setlocal enabledelayedexpansion
set OUTDIR=bin
set CFLAGS=-O3 -pipe -lntdll -fexec-charset=UTF-8 -Iinclude
set LFLAGS=-s -mwindows -lcomctl32 -lgdi32 -lgdiplus -lole32 -static

set MINGW=
for %%d in (
    "D:\Dev\mingw64"
    "C:\mingw64"
    "C:\msys64\mingw64"
    "C:\Program Files\mingw64"
    "C:\Program Files (x86)\mingw64"
) do (
    if exist "%%~d\bin\g++.exe" (set "MINGW=%%~d\bin" & goto :found)
)
where g++ >nul 2>&1
if %ERRORLEVEL%==0 (set MINGW= & goto :found)
echo ERROR: MinGW64 not found!
pause & exit /b 1

:found
if defined MINGW (set "CXX=%MINGW%\g++" & set "WR=%MINGW%\windres") else (set CXX=g++ & set WR=windres)
echo MinGW: %MINGW%
if not exist %OUTDIR% mkdir %OUTDIR%

echo.
echo === UIAccess Build (needs signing) ===
echo [ 1/11] resource.res & %WR% -i res\resource.rc --input-format=rc -o %OUTDIR%\resource.res -O coff || goto :err
echo [ 2/11] utils.o      & %CXX% -c src\utils.cpp     -o %OUTDIR%\utils.o     %CFLAGS% || goto :err
echo [ 3/11] process.o    & %CXX% -c src\process.cpp   -o %OUTDIR%\process.o   %CFLAGS% || goto :err
echo [ 4/11] bypass.o     & %CXX% -c src\bypass.cpp    -o %OUTDIR%\bypass.o    %CFLAGS% || goto :err
echo [ 5/11] assistant.o  & %CXX% -c src\assistant.cpp -o %OUTDIR%\assistant.o %CFLAGS% || goto :err
echo [ 6/11] mythware.o   & %CXX% -c src\mythware.cpp  -o %OUTDIR%\mythware.o  %CFLAGS% || goto :err
echo [ 7/11] hooks.o      & %CXX% -c src\hooks.cpp     -o %OUTDIR%\hooks.o     %CFLAGS% || goto :err
echo [ 8/11] psd.o        & %CXX% -c src\psd.cpp       -o %OUTDIR%\psd.o       %CFLAGS% || goto :err
echo [ 9/11] floating.o   & %CXX% -c src\floating.cpp  -o %OUTDIR%\floating.o  %CFLAGS% || goto :err
echo [10/11] main.o       & %CXX% -c src\main.cpp      -o %OUTDIR%\main.o      %CFLAGS% || goto :err
echo [11/11] Linking...
%CXX% %OUTDIR%\main.o %OUTDIR%\utils.o %OUTDIR%\process.o %OUTDIR%\bypass.o %OUTDIR%\assistant.o %OUTDIR%\mythware.o %OUTDIR%\hooks.o %OUTDIR%\psd.o %OUTDIR%\floating.o %OUTDIR%\resource.res -o %OUTDIR%\MythwareToolkit.exe %LFLAGS% || goto :err

set "EXEFILE=%CD%\%OUTDIR%\MythwareToolkit.exe"
for %%f in ("%EXEFILE%") do set FILESIZE=%%~zf
echo.
echo ========================================
echo   Build Successful!
echo ========================================
echo   File : %EXEFILE%
echo   Size : %FILESIZE% bytes
echo.

:: ── 自动签名 ──────────────────────────────────────
set "PS=pwsh"
where pwsh >nul 2>&1
if %ERRORLEVEL% NEQ 0 (set "PS=powershell")

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    :: 没有管理员权限 → 提权运行签名
    echo   [*] Elevating for code signing...
    %PS% -Command "Start-Process '%PS%' -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File scripts\sign.ps1' -Verb RunAs -Wait -WorkingDirectory '%CD%'" 2>nul
) else (
    :: 已有管理员权限 → 直接签名
    echo   [*] Signing EXE...
    %PS% -NoProfile -ExecutionPolicy Bypass -File scripts\sign.ps1
)

echo.
echo ========================================
echo   File : %EXEFILE%
echo   Size : %FILESIZE% bytes
echo ========================================
echo   Next: cert\deploy.bat
echo ========================================
goto :end

:err
echo Build FAILED!
pause
:end
