# MythwareToolkit 自签名脚本 (以管理员身份运行)
$ErrorActionPreference = "Stop"
Set-Location "$PSScriptRoot\.."
$exe = "bin\MythwareToolkit.exe"

if (-not (Test-Path $exe)) {
    Write-Host "错误: 找不到 $exe，请先编译！" -ForegroundColor Red
    Read-Host; exit 1
}

# ── 1. 获取或创建证书 ──────────────────────────────────
Write-Host "[1/3] 查找已有证书..." -ForegroundColor Cyan
$cert = Get-ChildItem -Path Cert:\CurrentUser\My |
        Where-Object { $_.Subject -like "*MythwareToolkit*" -and $_.EnhancedKeyUsageList.FriendlyName -eq "Code Signing" } |
        Select-Object -First 1

if ($cert) {
    Write-Host "  复用已有证书: $($cert.Thumbprint)" -ForegroundColor Green
} else {
    Write-Host "  未找到，生成新证书..." -ForegroundColor Yellow
    $cert = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject "CN=MythwareToolkit" `
        -FriendlyName "MythwareToolkit Signing Cert" `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(30)
    Write-Host "  新证书指纹: $($cert.Thumbprint)" -ForegroundColor Green
}

# ── 2. 安装证书到本地计算机受信任根 ────────────────────
Write-Host "[2/3] 安装证书到本地计算机受信任根..." -ForegroundColor Cyan
$cerPath = "cert\mythware.cer"
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
certutil -addstore -f -enterprise Root $cerPath 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  certutil 失败，尝试备用方式..." -ForegroundColor Yellow
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $rootStore.Open("ReadWrite")
    $rootStore.Add($cert)
    $rootStore.Close()
}
Write-Host "  证书已导出到 $cerPath" -ForegroundColor Green

# ── 3. 签名 ────────────────────────────────────────────
Write-Host "[3/3] 签名 EXE..." -ForegroundColor Cyan
Set-AuthenticodeSignature -FilePath $exe -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
Write-Host "  签名完成: $exe" -ForegroundColor Green

Write-Host "`n全部完成！" -ForegroundColor Green
Write-Host "  下一步: cert\deploy.bat" -ForegroundColor Green
