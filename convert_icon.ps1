# 高质量 PNG/JPEG → ICO 转换脚本
# 生成多分辨率 ICO（BMP DIB 格式，兼容 windres 和 LoadImage）
# 用法: pwsh -File convert_icon.ps1 [源图片] [输出.ico]

param(
    [string]$Source,
    [string]$Dest = "res\float.ico"
)

Add-Type -AssemblyName System.Drawing

if (-not (Test-Path $Source)) {
    $candidates = @(Get-ChildItem -Path "res" -Filter "*.png" 2>$null; Get-ChildItem -Path "res" -Filter "*.jpg" 2>$null)
    if ($candidates.Count -gt 0) {
        Write-Host "源文件未指定，找到以下候选：" -ForegroundColor Yellow
        $candidates | ForEach-Object { Write-Host "  $_" }
    }
    Write-Host "用法: pwsh -File convert_icon.ps1 <源图片路径> [输出.ico]" -ForegroundColor Yellow
    exit 1
}

Write-Host "源文件: $Source" -ForegroundColor Cyan
$srcImage = [System.Drawing.Image]::FromFile((Resolve-Path $Source))

# ── 多分辨率帧（从小到大，Windows 自动选最佳匹配） ──
$sizes = @(16, 24, 32, 48, 64, 128)
Write-Host "生成分辨率: $($sizes -join ', ')" -ForegroundColor Cyan

$ms = [System.IO.MemoryStream]::new()
$bw = [System.IO.BinaryWriter]::new($ms)

# ICONDIR 头
$bw.Write([uint16]0)                # idReserved
$bw.Write([uint16]1)                # idType = ICO
$bw.Write([uint16]$sizes.Count)     # idCount

$imageBlocks = [System.Collections.ArrayList]::new()

foreach ($sz in $sizes) {
    # 高质量缩放：用原图作为源，每次从原图重新采样
    $bmp = New-Object System.Drawing.Bitmap($srcImage, $sz, $sz)

    # 用高质量插值重新绘制以保持清晰度
    $final = New-Object System.Drawing.Bitmap($sz, $sz, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($final)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
    $g.DrawImage($bmp, 0, 0, $sz, $sz)
    $g.Dispose()
    $bmp.Dispose()

    # 逐行读像素（ARGB → BGRA DIB 格式，bottom-up）
    $data = $final.LockBits(
        [System.Drawing.Rectangle]::new(0, 0, $sz, $sz),
        [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb
    )

    # XOR 像素：BGRA，bottom-up
    $xorSize = $sz * $sz * 4
    $xor = New-Object byte[] $xorSize
    $rowBytes = $sz * 4
    for ($y = 0; $y -lt $sz; $y++) {
        $srcOffset = ($sz - 1 - $y) * $data.Stride   # 翻转行（top-down → bottom-up）
        $dstOffset = $y * $rowBytes
        [System.Runtime.InteropServices.Marshal]::Copy(
            [IntPtr]($data.Scan0.ToInt64() + $srcOffset),
            $xor, $dstOffset, $rowBytes
        )
    }
    $final.UnlockBits($data)
    $final.Dispose()

    # AND mask（1bpp，4 字节对齐，全 0 = 无透明掩码，32bpp 用 alpha 通道）
    $andRowBytes = [Math]::Ceiling($sz / 8.0)
    $andStride = ($andRowBytes + 3) -band -4
    $andSize = $andStride * $sz

    # 组装 DIB 帧
    $dibSize = 40 + $xorSize + $andSize
    $dib = New-Object byte[] $dibSize

    # BITMAPINFOHEADER
    [BitConverter]::GetBytes([int32]40).CopyTo($dib, 0)        # biSize
    [BitConverter]::GetBytes([int32]$sz).CopyTo($dib, 4)       # biWidth
    [BitConverter]::GetBytes([int32]($sz * 2)).CopyTo($dib, 8) # biHeight（ICO 需要双倍高度）
    [BitConverter]::GetBytes([uint16]1).CopyTo($dib, 12)       # biPlanes
    [BitConverter]::GetBytes([uint16]32).CopyTo($dib, 14)      # biBitCount
    [Buffer]::BlockCopy($xor, 0, $dib, 40, $xorSize)          # XOR 像素
    # AND mask 保持全零（32bpp 用 alpha 通道，无需额外掩码）

    $frameSize = $dibSize
    $w = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }
    $h = if ($sz -ge 256) { [byte]0 } else { [byte]$sz }
    [void]$imageBlocks.Add(@{
        Width     = $w
        Height    = $h
        DIB       = $dib
        FrameSize = $frameSize
    })
    Write-Host "  ${sz}x${sz} done ($frameSize bytes)" -ForegroundColor Green
}

# 计算各帧在文件中的偏移
$offset = 6 + 16 * $sizes.Count
foreach ($blk in $imageBlocks) {
    $blk.Offset = $offset
    $offset += $blk.FrameSize
}

# 写 ICONDIRENTRY
foreach ($blk in $imageBlocks) {
    $bw.Write($blk.Width)
    $bw.Write($blk.Height)
    $bw.Write([byte]0)                   # bColorCount
    $bw.Write([byte]0)                   # bReserved
    $bw.Write([uint16]1)                 # wPlanes = 1
    $bw.Write([uint16]32)                # wBitCount = 32
    $bw.Write([int32]$blk.FrameSize)     # dwBytesInRes
    $bw.Write([int32]$blk.Offset)        # dwImageOffset
}

# 写图像数据
foreach ($blk in $imageBlocks) {
    $bw.Write($blk.DIB)
}

$bw.Flush()
[System.IO.File]::WriteAllBytes($Dest, $ms.ToArray())
$bw.Close()
$ms.Close()
$srcImage.Dispose()

$fileSize = (Get-Item $Dest).Length
Write-Host "`n完成: $Dest ($fileSize bytes, $($sizes.Count)帧: $($sizes -join 'x '))" -ForegroundColor Green
Write-Host "  格式: BMP DIB, wPlanes=1, 32bpp ARGB" -ForegroundColor Green
Write-Host "  Windows 会根据显示需要自动选择最佳分辨率帧" -ForegroundColor Green
