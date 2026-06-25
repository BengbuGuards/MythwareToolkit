@echo off
set "HERE=%~dp0"
set "TARGET=C:\Program Files\MythwareToolkit"

:: ── 检查管理员权限 ────────────────────────────────────
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [*] Admin required, elevating...
    powershell -Command "Start-Process '%~f0' -Verb RunAs -WorkingDirectory '%HERE%'"
    exit /b
)

echo ==========================================
echo   MythwareToolkit v2.0 Deploy
echo ==========================================
echo.

:: ── [1] 找 EXE ────────────────────────────────────────
set "EXE="
if exist "%HERE%MythwareToolkit.exe" (
    set "EXE=%HERE%MythwareToolkit.exe"
) else if exist "%HERE%..\bin\MythwareToolkit.exe" (
    set "EXE=%HERE%..\bin\MythwareToolkit.exe"
)
if not defined EXE (
    echo [ERROR] MythwareToolkit.exe not found!
    echo   Put deploy.bat next to MythwareToolkit.exe, or build first.
    pause & exit /b 1
)
echo [1/4] Copy EXE...
mkdir "%TARGET%" 2>nul
copy /Y "%EXE%" "%TARGET%\" >nul
echo   %EXE% -^> %TARGET%\

:: ── [2] 安装证书 ──────────────────────────────────────
echo [2/4] Install certificate...

set "CERT="
if exist "%HERE%mythware.cer"   set "CERT=%HERE%mythware.cer"
if not defined CERT (
    if exist "%HERE%..\bin\MythwareToolkit.cer" set "CERT=%HERE%..\bin\MythwareToolkit.cer"
)

if defined CERT (
    certutil -addstore -f -enterprise Root "%CERT%" >nul 2>&1
)

:: [3] RootCA.reg 兜底
echo [3/4] Import RootCA.reg (fallback)...

set "REG="
if exist "%HERE%RootCA.reg" set "REG=%HERE%RootCA.reg"

if defined REG (
    reg import "%REG%" >nul 2>&1
    echo   RootCA.reg imported
) else (
    echo   RootCA.reg not found, skipped
)

:: ── [4] 桌面快捷方式 ──────────────────────────────────
echo [4/4] Create desktop shortcut...
powershell -Command "$ws=New-Object -ComObject WScript.Shell;$s=$ws.CreateShortcut([Environment]::GetFolderPath('Desktop')+'\MythwareToolkit.lnk');$s.TargetPath='%TARGET%\MythwareToolkit.exe';$s.WorkingDirectory='%TARGET%';$s.Save()"
echo   Done

echo.
echo ==========================================
echo   Deploy OK!
echo   %TARGET%\MythwareToolkit.exe
echo ==========================================
pause
