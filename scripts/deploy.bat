@echo off
cd /d "%~dp0.."
set TARGET=C:\Program Files\MythwareToolkit

net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs -WorkingDirectory '%~dp0'"
    exit /b
)

echo [1/4] Create folder...
mkdir "%TARGET%" 2>nul

echo [2/4] Copy exe...
if exist "bin\MythwareToolkit.exe" (
    copy /Y "bin\MythwareToolkit.exe" "%TARGET%\" >nul
) else if exist "MythwareToolkit.exe" (
    copy /Y "MythwareToolkit.exe" "%TARGET%\" >nul
) else (
    echo ERROR: MythwareToolkit.exe not found
    pause & exit /b 1
)

echo [3/4] Install certificate...
if exist "bin\MythwareToolkit.cer" (
    certutil -addstore -f -enterprise Root "bin\MythwareToolkit.cer" >nul 2>&1
) else if exist "cert\mythware.cer" (
    certutil -addstore -f -enterprise Root "cert\mythware.cer" >nul 2>&1
)
echo    Done

echo [4/4] Create desktop shortcut...
powershell -Command "$ws=New-Object -ComObject WScript.Shell;$s=$ws.CreateShortcut([Environment]::GetFolderPath('Desktop')+'\MythwareToolkit.lnk');$s.TargetPath='%TARGET%\MythwareToolkit.exe';$s.WorkingDirectory='%TARGET%';$s.Save()"
echo    Done

echo.
echo Install OK: %TARGET%\MythwareToolkit.exe
pause
