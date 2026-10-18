# Draws the app icon (three bars, as in the window header) and builds icon.ico
# from 16/24/32/48/64/256 PNG frames. Only needed when the icon changes.
param([string]$Out = (Join-Path (Split-Path -Parent $PSScriptRoot) 'crates\tm-app\icons'))
Add-Type -AssemblyName System.Drawing
New-Item -ItemType Directory -Force $Out | Out-Null
$sizes = 16, 24, 32, 48, 64, 256
$frames = @()
foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap $s, $s, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)
    $k = $s / 16.0
    $bars = @(@(1, 9, 3, 6, 255), @(6.5, 5, 3, 10, 200), @(12, 1, 3, 14, 150))
    foreach ($b in $bars) {
        $brush = New-Object System.Drawing.SolidBrush ([System.Drawing.Color]::FromArgb($b[4], 0x4c, 0xc2, 0xff))
        $r = [Math]::Max(1, $k)
        $path = New-Object System.Drawing.Drawing2D.GraphicsPath
        $x = $b[0] * $k; $y = $b[1] * $k; $w = $b[2] * $k; $h = $b[3] * $k
        $path.AddArc($x, $y, $r, $r, 180, 90); $path.AddArc($x + $w - $r, $y, $r, $r, 270, 90)
        $path.AddArc($x + $w - $r, $y + $h - $r, $r, $r, 0, 90); $path.AddArc($x, $y + $h - $r, $r, $r, 90, 90)
        $path.CloseFigure(); $g.FillPath($brush, $path)
    }
    $g.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    if ($s -eq 32) { $bmp.Save((Join-Path $Out '32x32.png'), [System.Drawing.Imaging.ImageFormat]::Png) }
    if ($s -eq 256) { $bmp.Save((Join-Path $Out 'icon.png'), [System.Drawing.Imaging.ImageFormat]::Png) }
    $frames += , @($s, $ms.ToArray())
    $bmp.Dispose()
}
# ICO: header, directory, then the PNG data of the frames
$fs = [System.IO.File]::Create((Join-Path $Out 'icon.ico'))
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([UInt16]0); $bw.Write([UInt16]1); $bw.Write([UInt16]$frames.Count)
$offset = 6 + 16 * $frames.Count
foreach ($f in $frames) {
    $s = $f[0]; $d = $f[1]
    $bw.Write([Byte]($(if ($s -ge 256) { 0 } else { $s }))); $bw.Write([Byte]($(if ($s -ge 256) { 0 } else { $s })))
    $bw.Write([Byte]0); $bw.Write([Byte]0); $bw.Write([UInt16]1); $bw.Write([UInt16]32)
    $bw.Write([UInt32]$d.Length); $bw.Write([UInt32]$offset); $offset += $d.Length
}
foreach ($f in $frames) { $bw.Write([byte[]]$f[1]) }
$bw.Close()
Get-ChildItem $Out | Select-Object Name, Length
