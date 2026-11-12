[CmdletBinding()]
param([string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'artifacts\Agent-Net472' }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$compiler = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$sources = @(Get-ChildItem -LiteralPath (Join-Path $root 'src\StandaloneLaps.Agent.Framework') -File -Filter '*.cs' | ForEach-Object { $_.FullName })
$sources += @((Join-Path $root 'web\IisVault\App_Code\EnvelopeModels.cs'), (Join-Path $root 'web\IisVault\App_Code\EnvelopeCrypto.cs'), (Join-Path $root 'web\IisVault\App_Code\AppVersion.cs'))
& $compiler /nologo /target:exe /platform:x64 /langversion:5 /optimize+ /warnaserror+ /main:StandaloneLaps.FrameworkAgent.Program "/out:$(Join-Path $OutputDirectory 'StandaloneLaps.Agent.exe')" /reference:System.Core.dll /reference:System.ServiceProcess.dll /reference:System.Runtime.Serialization.dll $sources
if ($LASTEXITCODE -ne 0) { throw 'Framework agent compilation failed.' }
Copy-Item -LiteralPath (Join-Path $root 'src\StandaloneLaps.Agent.Framework\StandaloneLaps.Agent.exe.config') -Destination $OutputDirectory -Force
Write-Host 'Framework 4.7.2 agent built. No additional .NET runtime or NuGet packages are required.'
