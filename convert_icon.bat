@echo off
cd /d "%~dp0"
chcp 65001 >nul 2>&1

set PS=pwsh
where pwsh >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    where powershell >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: PowerShell not found
        pause & exit /b 1
    )
    set PS=powershell
)

if "%~1"=="" (
    echo.
    echo Usage: convert_icon.bat source_image [output_ico]
    echo.
    echo   source_image: PNG / JPG / BMP file
    echo   output_ico:   default res\float.ico
    echo.
    echo Example:
    echo   convert_icon.bat icon.png
    echo   convert_icon.bat mypic.jpg res\mytool.ico
    pause
    exit /b 0
)

set SRC=%~1
set DST=res\float.ico
if not "%~2"=="" set DST=%~2

%PS% -NoProfile -ExecutionPolicy Bypass -File "%~dp0convert_icon.ps1" "%SRC%" "%DST%"
if %ERRORLEVEL% NEQ 0 pause
