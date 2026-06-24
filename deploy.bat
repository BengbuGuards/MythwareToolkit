@echo off
:: MythwareToolkit UIAccess 版 部署脚本
:: 使用方法：把 MythwareToolkit.exe + MythwareToolkit.cer + deploy.bat 放同一目录，右键→管理员运行
:: 或 cmd 管理员模式运行: deploy.bat

echo ==========================================
echo   MythwareToolkit v2.0 部署
echo ==========================================
echo.

set TARGET=C:\Program Files\MythwareToolkit

:: 检查管理员权限
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [错误] 请以管理员身份运行此脚本！
    echo 右键 deploy.bat → 以管理员身份运行
    pause & exit /b 1
)

:: 创建目录
echo [1/3] 创建目录 %TARGET%...
mkdir "%TARGET%" 2>nul

:: 复制文件
echo [2/3] 复制文件...
if not exist "MythwareToolkit.exe" (
    echo [错误] 找不到 MythwareToolkit.exe！请确保 exe 与此脚本在同一目录。
    pause & exit /b 1
)
copy /Y "MythwareToolkit.exe" "%TARGET%\" >nul
if exist "MythwareToolkit.cer" (
    copy /Y "MythwareToolkit.cer" "%TARGET%\" >nul
)

:: 安装证书
echo [3/3] 安装证书...
if exist "MythwareToolkit.cer" (
    certutil -addstore Root "MythwareToolkit.cer" >nul 2>&1
    echo   证书已安装
) else (
    echo   [跳过] 未找到 MythwareToolkit.cer
)

echo.
echo ==========================================
echo   部署完成！
echo   运行：%TARGET%\MythwareToolkit.exe
echo ==========================================
pause
