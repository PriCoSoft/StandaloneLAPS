#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Agent')][string]$Role = 'Agent',
    [Parameter(Mandatory)][string]$PublishedDirectory
)
$ErrorActionPreference = 'Stop'
$serviceName = 'StandaloneLaps' + $Role
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) { throw 'Service already exists. Stop it and use a reviewed upgrade procedure.' }
$source = (Resolve-Path -LiteralPath $PublishedDirectory).Path
$executable = 'StandaloneLaps.' + $Role + '.exe'
if (-not (Test-Path -LiteralPath (Join-Path $source $executable))) { throw 'Publish output not found.' }
$destination = Join-Path $env:ProgramFiles $serviceName
$data = Join-Path $env:ProgramData $serviceName
if (Test-Path -LiteralPath $destination) { throw 'Installation directory already exists.' }
New-Item -ItemType Directory -Path $destination | Out-Null
# Lock down the destination before copying service binaries and configuration.
& icacls.exe $destination /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to secure installation directory.' }
Copy-Item -Path (Join-Path $source '*') -Destination $destination -Recurse
if ($Role -eq 'Agent') { $data = Join-Path $env:ProgramData 'StandaloneLaps' }
if (Test-Path -LiteralPath $data) { throw 'Data directory already exists; review its contents and ACLs before manual installation.' }
New-Item -ItemType Directory -Path $data | Out-Null
& icacls.exe $data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to secure data directory.' }
if ($Role -eq 'Api') { New-Item -ItemType Directory -Path (Join-Path $data 'data') | Out-Null }
if (-not [System.Diagnostics.EventLog]::SourceExists('StandaloneLapsAgent')) { New-EventLog -LogName Application -Source StandaloneLapsAgent }
New-Service -Name $serviceName -BinaryPathName ('"' + (Join-Path $destination $executable) + '"') `
    -DisplayName ('Standalone LAPS ' + $Role) -StartupType Automatic | Out-Null
& sc.exe failure $serviceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to configure service recovery.' }
Write-Host 'Installed as LocalSystem and left stopped. Configure certificates and policy/API settings before starting.'
