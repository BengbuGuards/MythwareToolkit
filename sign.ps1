# MythwareToolkit 自签名脚本 (管理员 PowerShell 运行)
$ErrorActionPreference = "Stop"
$exe = "bin\MythwareToolkit.exe"

if (-not (Test-Path $exe)) {
    Write-Host "错误: 找不到 $exe，请先编译！" -ForegroundColor Red
    Read-Host; exit 1
}

Write-Host "[1/3] 生成自签名证书..." -ForegroundColor Cyan
$cert = New-SelfSignedCertificate -Type CodeSigningCert `
    -Subject "CN=MythwareToolkit" `
    -FriendlyName "MythwareToolkit Signing Cert" `
    -CertStoreLocation Cert:\CurrentUser\My `
    -NotAfter (Get-Date).AddYears(30)

Write-Host "  证书指纹: $($cert.Thumbprint)" -ForegroundColor Green

Write-Host "[2/3] 导入根证书到本地计算机..." -ForegroundColor Cyan
# 导出 cer
$cerPath = "bin\MythwareToolkit.cer"
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
# 导入到 LocalMachine Root（UIAccess 要求机器级别信任）
certutil -addstore -f -enterprise Root $cerPath 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  自动导入失败，尝试备用方式..." -ForegroundColor Yellow
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $rootStore.Open("ReadWrite")
    $rootStore.Add($cert)
    $rootStore.Close()
}
Write-Host "  根证书已导入到本地计算机受信任根" -ForegroundColor Green

Write-Host "[3/3] 签名 EXE..." -ForegroundColor Cyan
Set-AuthenticodeSignature -FilePath $exe -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
Write-Host "  签名完成: $exe" -ForegroundColor Green

Write-Host "`n全部完成！部署到 C:\Program Files\MythwareToolkit\ 即可运行" -ForegroundColor Green
Read-Host
