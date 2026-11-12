[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$compiler = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$aspnet = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\aspnet_compiler.exe'
$work = Join-Path $root ('artifacts\verification\' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work -Force | Out-Null
try {
    & (Join-Path $PSScriptRoot 'Build-FrameworkAgent.ps1')
    $backend = Join-Path $root 'web\IisVault'
    $testAssembly = Join-Path $work 'FrameworkTests.dll'
    $sources = @(Get-ChildItem -LiteralPath (Join-Path $backend 'App_Code') -Filter '*.cs' -File | ForEach-Object { $_.FullName })
    $sources += @(Get-ChildItem -LiteralPath (Join-Path $root 'src\StandaloneLaps.Agent.Framework') -Filter '*.cs' -File | ForEach-Object { $_.FullName })
    $sources += @((Join-Path $root 'tests\FrameworkTests.cs'), (Join-Path $root 'tests\FrameworkAgentTests.cs'), (Join-Path $root 'tests\FrameworkPortalTests.cs'))
    & $compiler /nologo /target:library /langversion:5 /warnaserror+ "/out:$testAssembly" /reference:System.Web.dll /reference:System.Web.Extensions.dll /reference:System.Configuration.dll /reference:System.Core.dll /reference:System.ServiceProcess.dll /reference:System.Runtime.Serialization.dll /reference:System.IO.Compression.dll $sources
    if ($LASTEXITCODE -ne 0) { throw 'Framework source compilation failed.' }
    & (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -File (Join-Path $PSScriptRoot 'Run-FrameworkTests.ps1') -AssemblyPath $testAssembly -FixtureDirectory $work
    if ($LASTEXITCODE -ne 0) { throw 'Framework tests failed.' }
    & $aspnet -v /StandaloneLaps -p $backend (Join-Path $work 'compiled-check')
    if ($LASTEXITCODE -ne 0) { throw 'ASPX compilation check failed.' }
    foreach ($script in Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File) {
        $tokens = $null; $errors = $null
        [System.Management.Automation.Language.Parser]::ParseFile($script.FullName, [ref]$tokens, [ref]$errors) | Out-Null
        if ($errors.Count -gt 0) { throw ('PowerShell syntax error in ' + $script.Name + ': ' + $errors[0].Message) }
    }
    # The server installer compiles the CA helper with Windows PowerShell 5.1 Add-Type; verify that path too.
    $caSource = Join-Path $backend 'App_Code\SlapsCertificateAuthority.cs'
    & (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -Command "Add-Type -Path '$caSource' -ReferencedAssemblies 'System.Core'; if (-not ('StandaloneLapsWeb.SlapsCertificateAuthority' -as [type])) { exit 1 }"
    if ($LASTEXITCODE -ne 0) { throw 'Add-Type compilation of SlapsCertificateAuthority.cs failed in Windows PowerShell 5.1.' }
    Write-Host 'Framework agent/backend tests and ASPX precompilation passed. No .NET SDK was used.'
} finally {
    foreach ($name in @('recovery.pfx', 'envelope.json', 'slaps-ca.crl')) {
        $fixture = Join-Path $work $name
        if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture }
    }
}
