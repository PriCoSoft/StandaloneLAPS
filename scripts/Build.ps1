[CmdletBinding()]
param([switch]$Publish)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
& (Join-Path $PSScriptRoot 'Test-IisBackend.ps1')
if ($Publish) {
    $destination = Join-Path $root 'artifacts\IisVault-AppData'
    if (Test-Path -LiteralPath $destination) { throw 'Website staging directory exists; review previous staging output before replacing it.' }
    Copy-Item -LiteralPath (Join-Path $root 'web\IisVault') -Destination $destination -Recurse
    Write-Host 'Ready: artifacts/Agent-Net472 and source-only artifacts/IisVault-AppData. No additional .NET runtime is required on Server 2019.'
}
