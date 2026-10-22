# MythwareToolkit code signing script (run as administrator)
param(
    [ValidateSet("x64","x86")]
    [string]$Arch = "x64"
)
$ErrorActionPreference = "Stop"
Set-Location "$PSScriptRoot\.."

# Version comes from include\version.h; fall back to the legacy fixed name.
$verLine = Get-Content "include\version.h" -ErrorAction SilentlyContinue |
           Where-Object { $_ -match 'TOOLKIT_VERSION_STR' } | Select-Object -First 1
$version = if ($verLine -match '"([^"]+)"') { $Matches[1] } else { $null }
$exe = if ($version) { "bin\MythwareToolkit.v$version.$Arch.exe" } else { "bin\MythwareToolkit.exe" }

if (-not (Test-Path $exe)) {
    Write-Host "ERROR: $exe not found, build it first." -ForegroundColor Red
    exit 1
}

# ---- 1. Find or create the signing certificate ----
Write-Host "[1/3] Looking for an existing certificate..." -ForegroundColor Cyan
# Match by the Code Signing EKU OID (1.3.6.1.5.5.7.3.3): FriendlyName is
# localized on some systems, which previously caused a new cert every run.
$cert = Get-ChildItem -Path Cert:\CurrentUser\My |
        Where-Object {
            $_.Subject -like "*MythwareToolkit*" -and
            $_.HasPrivateKey -and
            ($_.EnhancedKeyUsageList.ObjectId -contains "1.3.6.1.5.5.7.3.3")
        } |
        Sort-Object NotAfter -Descending | Select-Object -First 1

if ($cert) {
    Write-Host "  Reusing certificate: $($cert.Thumbprint)" -ForegroundColor Green
} else {
    Write-Host "  Not found, creating a new one..." -ForegroundColor Yellow
    $cert = New-SelfSignedCertificate -Type CodeSigningCert `
        -Subject "CN=MythwareToolkit" `
        -FriendlyName "MythwareToolkit Signing Cert" `
        -CertStoreLocation Cert:\CurrentUser\My `
        -NotAfter (Get-Date).AddYears(30)
    Write-Host "  New certificate: $($cert.Thumbprint)" -ForegroundColor Green
}

# ---- 2. Trust the certificate on this machine ----
Write-Host "[2/3] Installing certificate into LocalMachine Root..." -ForegroundColor Cyan
$cerPath = "cert\mythware.cer"
Export-Certificate -Cert $cert -FilePath $cerPath | Out-Null
certutil -addstore -f -enterprise Root $cerPath 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  certutil failed, trying fallback..." -ForegroundColor Yellow
    $rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
    $rootStore.Open("ReadWrite")
    $rootStore.Add($cert)
    $rootStore.Close()
}
Write-Host "  Certificate exported to $cerPath" -ForegroundColor Green

# ---- 3. Sign ----
Write-Host "[3/3] Signing EXE..." -ForegroundColor Cyan
Set-AuthenticodeSignature -FilePath $exe -Certificate $cert -TimestampServer "http://timestamp.digicert.com"
Write-Host "  Signed: $exe" -ForegroundColor Green

Write-Host "`nDone." -ForegroundColor Green
Write-Host "  Next: cert\deploy.bat" -ForegroundColor Green
