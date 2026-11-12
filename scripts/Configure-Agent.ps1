#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$DeviceId,
    [Parameter(Mandatory)][uri]$ApiUrl,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ClientCertificateSha256,
    [Parameter(Mandatory)][string]$RecoveryCertificatePath,
    [Parameter(Mandatory)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$RecoveryCertificateSha256,
    [switch]$Enable
)
$ErrorActionPreference = 'Stop'
if ($DeviceId -eq [guid]::Empty -or $ApiUrl.Scheme -ne 'https' -or -not $ApiUrl.AbsolutePath.EndsWith('/') -or $ApiUrl.Query -or $ApiUrl.Fragment -or $ApiUrl.UserInfo) { throw 'Use a unique GUID and an HTTPS application URL ending in /.' }
if ($RecoveryCertificatePath -notmatch '^[A-Za-z]:\\') { throw 'Use an absolute local certificate path.' }
$base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
try {
    $key = $base.CreateSubKey('SOFTWARE\PriCoSoft\SLAPS')
    try {
        $security = New-Object System.Security.AccessControl.RegistrySecurity
        $security.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($identity, [System.Security.AccessControl.RegistryRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
            $security.AddAccessRule($rule)
        }
        $key.SetAccessControl($security)
        # Disable first: a failed configuration write must not leave a partially updated active agent.
        $key.SetValue('Enabled', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
        foreach ($entry in @{DeviceId=$DeviceId.ToString('D');ApiUrl=$ApiUrl.AbsoluteUri;ClientCertificateSha256=$ClientCertificateSha256.ToUpperInvariant();RecoveryCertificatePath=$RecoveryCertificatePath;RecoveryCertificateSha256=$RecoveryCertificateSha256.ToUpperInvariant()}.GetEnumerator()) {
            $key.SetValue($entry.Key, $entry.Value, [Microsoft.Win32.RegistryValueKind]::String)
        }
        $key.SetValue('Enabled', [int]$Enable.IsPresent, [Microsoft.Win32.RegistryValueKind]::DWord)
    } finally { $key.Dispose() }
} finally { $base.Dispose() }
Write-Host 'Registry configuration saved in 64-bit HKLM\SOFTWARE\PriCoSoft\SLAPS. Password policy remains under System > LAPS.'
