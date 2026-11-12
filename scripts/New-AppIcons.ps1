[CmdletBinding()]
param()
# Renders web\IisVault\favicon.ico (16/32/48 px) and icon-180.png from the same geometry as icon.svg (64x64 grid).
# Run after changing icon.svg; the generated files are part of the website source.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing
$web = Join-Path (Split-Path -Parent $PSScriptRoot) 'web\IisVault'

function New-IconBitmap([int]$Size) {
    $bitmap = New-Object System.Drawing.Bitmap($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bitmap)
    try {
        $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $g.Clear([System.Drawing.Color]::Transparent)
        $s = $Size / 64.0
        $g.ScaleTransform([float]$s, [float]$s)
        $dark = [System.Drawing.ColorTranslator]::FromHtml('#00646b')

        # Rounded square with diagonal gradient
        $r = 14.0
        $box = New-Object System.Drawing.Drawing2D.GraphicsPath
        $box.AddArc(0, 0, 2 * $r, 2 * $r, 180, 90); $box.AddArc(64 - 2 * $r, 0, 2 * $r, 2 * $r, 270, 90)
        $box.AddArc(64 - 2 * $r, 64 - 2 * $r, 2 * $r, 2 * $r, 0, 90); $box.AddArc(0, 64 - 2 * $r, 2 * $r, 2 * $r, 90, 90); $box.CloseFigure()
        $gradient = New-Object System.Drawing.Drawing2D.LinearGradientBrush((New-Object System.Drawing.PointF(0, 0)), (New-Object System.Drawing.PointF(64, 64)), [System.Drawing.ColorTranslator]::FromHtml('#18b6a7'), $dark)
        $g.FillPath($gradient, $box)

        # Shield: M32 9 L51 16.5 V31 C51 43.5 42.8 51.8 32 56 C21.2 51.8 13 43.5 13 31 V16.5 Z
        $shield = New-Object System.Drawing.Drawing2D.GraphicsPath
        $shield.AddLine(32, 9, 51, 16.5); $shield.AddLine(51, 16.5, 51, 31)
        $shield.AddBezier(51, 31, 51, 43.5, 42.8, 51.8, 32, 56)
        $shield.AddBezier(32, 56, 21.2, 51.8, 13, 43.5, 13, 31)
        $shield.AddLine(13, 31, 13, 16.5); $shield.CloseFigure()
        $g.FillPath([System.Drawing.Brushes]::White, $shield)

        # Keyhole
        $hole = New-Object System.Drawing.SolidBrush($dark)
        $g.FillEllipse($hole, 26.5, 23, 11, 11)
        $g.FillPolygon($hole, [System.Drawing.PointF[]]@((New-Object System.Drawing.PointF(29.6, 32)), (New-Object System.Drawing.PointF(34.4, 32)), (New-Object System.Drawing.PointF(36, 44)), (New-Object System.Drawing.PointF(28, 44))))
    } finally { $g.Dispose() }
    return $bitmap
}

function Get-PngBytes($Bitmap) {
    $stream = New-Object System.IO.MemoryStream
    $Bitmap.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    return $stream.ToArray()
}

# favicon.ico with PNG-compressed entries (supported by all current browsers and Windows Vista+)
$sizes = @(16, 32, 48)
$images = @($sizes | ForEach-Object { $b = New-IconBitmap $_; try { ,(Get-PngBytes $b) } finally { $b.Dispose() } })
$ico = New-Object System.IO.MemoryStream
$w = New-Object System.IO.BinaryWriter($ico)
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $w.Write([byte]$sizes[$i]); $w.Write([byte]$sizes[$i]); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32); $w.Write([uint32]$images[$i].Length); $w.Write([uint32]$offset)
    $offset += $images[$i].Length
}
foreach ($image in $images) { $w.Write([byte[]]$image) }
$w.Flush()
[System.IO.File]::WriteAllBytes((Join-Path $web 'favicon.ico'), $ico.ToArray())

$touch = New-IconBitmap 180
try { [System.IO.File]::WriteAllBytes((Join-Path $web 'icon-180.png'), (Get-PngBytes $touch)) } finally { $touch.Dispose() }
Write-Host "Icons written to $web (favicon.ico, icon-180.png)."
