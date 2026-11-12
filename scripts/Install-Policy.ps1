# No template is installed or replaced: use the Windows-supplied LAPS.admx.
$ErrorActionPreference = 'Stop'
$path = Join-Path $env:windir 'PolicyDefinitions\LAPS.admx'
if (-not (Test-Path -LiteralPath $path)) { throw 'Windows LAPS.admx is missing. Install current Windows updates or obtain the supported template through your normal Windows management process.' }
Write-Host 'Use gpedit.msc > Computer Configuration > Administrative Templates > System > LAPS.'
Write-Host 'Configure Password Settings and optionally Administrator Account Name. Leave native BackupDirectory Disabled (0).'
Write-Host 'Set API connection/certificate settings and Enabled in 64-bit HKLM\SOFTWARE\PriCoSoft\SLAPS (Configure-Agent.ps1).'