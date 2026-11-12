[CmdletBinding()]
param(
    [Parameter(Mandatory)][uri]$ApiUrl,
    [Parameter(Mandatory)][guid]$DeviceId,
    [Parameter(Mandatory)][string]$ReaderCertificateThumbprint,
    [guid]$RotationId,
    [string]$OutputFile,
    [ValidateRange(0, 2147483647)][int]$Skip = 0
)
$ErrorActionPreference = 'Stop'
if ($ApiUrl.Scheme -ne 'https' -or -not $ApiUrl.AbsolutePath.EndsWith('/') -or $ApiUrl.Query -or $ApiUrl.Fragment -or $ApiUrl.UserInfo) { throw 'Use an HTTPS application URL ending in /.' }
$certificate = Get-Item -LiteralPath ('Cert:\CurrentUser\My\' + $ReaderCertificateThumbprint)
$base = $ApiUrl.AbsoluteUri + 'api.aspx?device=' + $DeviceId.ToString('D')
if ($RotationId -eq [guid]::Empty) {
    Invoke-RestMethod -Uri ($base + '&skip=' + $Skip + '&take=100') -Certificate $certificate -MaximumRedirection 0
} else {
    if (-not $OutputFile) { throw 'OutputFile is required when downloading an encrypted envelope.' }
    if (Test-Path -LiteralPath $OutputFile) { throw 'Output file already exists.' }
    Invoke-WebRequest -Uri ($base + '&rotation=' + $RotationId.ToString('D')) -Certificate $certificate -MaximumRedirection 0 -OutFile $OutputFile
    Write-Host 'Encrypted envelope downloaded. Decrypt only on the recovery workstation.'
}
