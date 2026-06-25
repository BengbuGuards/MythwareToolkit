Add-Type -AssemblyName System.Drawing
$png = [System.Drawing.Image]::FromFile('D:\Users\Ausu\Downloads\47308278.png')
$bmp = New-Object System.Drawing.Bitmap($png, 32, 32)
$ico = [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
$fs = [System.IO.File]::Create('res\float.ico')
$ico.Save($fs)
$fs.Close()
$png.Dispose()
$bmp.Dispose()
Write-Host "OK: res/float.ico created"
