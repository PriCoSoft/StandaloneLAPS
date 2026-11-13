#Requires -Version 5.1
<#
.SYNOPSIS
Installs, upgrades or removes the SLAPS agent from a client package created by the SLAPS portal ("Add client").

.DESCRIPTION
All settings are predefined in slaps-settings.json next to this script. Parameters override them.
The agent runs as the Windows service StandaloneLapsAgent (LocalSystem). Password rules come from the
local policy Computer Configuration > Administrative Templates > System > LAPS.

.EXAMPLE
.\Install-SlapsAgent.ps1
.EXAMPLE
.\Install-SlapsAgent.ps1 -ApiUrl https://slaps.example.com/ -NoStart
.EXAMPLE
.\Install-SlapsAgent.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$ApiUrl,
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles 'StandaloneLapsAgent'),
    [System.Security.SecureString]$PfxPassword,
    [switch]$NoStart,
    [switch]$SkipConnectivityTest,
    [switch]$Uninstall,
    [switch]$KeepCertificate
)
$ErrorActionPreference = 'Stop'
$ServiceName = 'StandaloneLapsAgent'
$SettingsKeyPath = 'SOFTWARE\PriCoSoft\SLAPS'
$DataDirectory = Join-Path $env:ProgramData 'StandaloneLaps'
$LapsPolicyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS'
$LegacyPolicyPath = 'SOFTWARE\Policies\Microsoft Services\AdmPwd'
$LegacyExtensionPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{D76B9641-3288-4f75-942D-087DE603E3EA}'
$LapsStatePath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State'

function Write-Step([string]$Text) { Write-Host ('==> ' + $Text) -ForegroundColor Cyan }
function Get-Sha256([byte[]]$Raw) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash($Raw)).Replace('-', '') } finally { $sha.Dispose() }
}
function Assert-Administrator {
    $principal = New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this installer as administrator (right-click Install.cmd > Run as administrator).' }
}
function Protect-Directory([string]$Path) {
    & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to secure $Path." }
}
function Open-Hklm64 { [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64) }
function Get-ConfiguredCertificateSha {
    $base = Open-Hklm64
    try {
        $key = $base.OpenSubKey($SettingsKeyPath)
        if ($null -eq $key) { return $null }
        try { return [string]$key.GetValue('ClientCertificateSha256', $null) } finally { $key.Dispose() }
    } finally { $base.Dispose() }
}
function Remove-MachineCertificate([string]$Sha) {
    if (-not $Sha) { return }
    Get-ChildItem Cert:\LocalMachine\My | Where-Object { (Get-Sha256 $_.RawData) -eq $Sha } | ForEach-Object {
        Remove-Item -LiteralPath $_.PSPath -DeleteKey
        Write-Host "    Removed certificate $($_.Subject)"
    }
}
function Stop-AgentService {
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($service -and $service.Status -ne 'Stopped') { Stop-Service -Name $ServiceName -Force; $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(60)) }
    return $service
}
function Get-JoinedDirectory {
    # SLAPS is for standalone servers only; joined devices must use Windows LAPS.
    if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) { return @('Active Directory', 'https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-windows-server-active-directory') }
    $dsreg = & dsregcmd.exe /status 2>$null
    if ($dsreg -match '^\s*AzureAdJoined\s*:\s*YES') { return @('Microsoft Entra ID', 'https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-azure-active-directory') }
    return $null
}
function Remove-LapsSignal {
    # Removes what this installer and the agent wrote to signal LAPS management (legacy AdmPwdEnabled, Windows LAPS state values).
    $base = Open-Hklm64
    try {
        $marker = $null
        $key = $base.OpenSubKey($SettingsKeyPath)
        if ($key) { try { $marker = $key.GetValue('LegacyLapsSignal', $null) } finally { $key.Dispose() } }
        if ($marker -eq 1) {
            $legacy = $base.OpenSubKey($LegacyPolicyPath, $true)
            if ($legacy) {
                try { $legacy.DeleteValue('AdmPwdEnabled', $false); $empty = $legacy.ValueCount -eq 0 -and $legacy.SubKeyCount -eq 0 } finally { $legacy.Dispose() }
                if ($empty) { $base.DeleteSubKey($LegacyPolicyPath, $false) }
                Write-Host '    Legacy LAPS signal (AdmPwdEnabled) removed.'
            }
        }
        if (-not (Get-JoinedDirectory)) {
            $state = $base.OpenSubKey($LapsStatePath, $true)
            if ($state) {
                try { foreach ($name in 'PolicySource', 'DSRMMode', 'LastManagedAccountRid', 'LastAccountRidUpdated', 'LastPasswordUpdateTime') { $state.DeleteValue($name, $false) } } finally { $state.Dispose() }
                Write-Host '    Windows LAPS compatible state values removed.'
            }
        }
    } finally { $base.Dispose() }
}
function Invoke-ApiProbe([string]$Method, [string]$Uri, $Certificate, [string]$Body) {
    try {
        $parameters = @{ Uri = $Uri; Method = $Method; Certificate = $Certificate; UseBasicParsing = $true; MaximumRedirection = 0; TimeoutSec = 30 }
        if ($Body) { $parameters.Body = $Body; $parameters.ContentType = 'application/json' }
        return [int](Invoke-WebRequest @parameters).StatusCode
    } catch {
        if ($_.Exception.Response) { return [int]$_.Exception.Response.StatusCode }
        return $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------------------------------
if ($Uninstall) {
    Assert-Administrator
    Write-Step 'Removing the SLAPS agent'
    $previousSha = Get-ConfiguredCertificateSha
    if (Stop-AgentService) { & sc.exe delete $ServiceName | Out-Null; Write-Host '    Service removed.' }
    Remove-LapsSignal
    $base = Open-Hklm64
    try { if ($base.OpenSubKey($SettingsKeyPath)) { $base.DeleteSubKeyTree($SettingsKeyPath); Write-Host '    Registry settings removed.' } } finally { $base.Dispose() }
    if (-not $KeepCertificate) { Remove-MachineCertificate $previousSha }
    foreach ($path in @($InstallDirectory, $DataDirectory)) { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force; Write-Host "    Removed $path" } }
    Write-Host 'The SLAPS agent was removed. Delete the device in the SLAPS portal if it is retired.' -ForegroundColor Green
    return
}

Assert-Administrator
$packageRoot = $PSScriptRoot
$settingsPath = Join-Path $packageRoot 'slaps-settings.json'
if (-not (Test-Path -LiteralPath $settingsPath)) { throw 'slaps-settings.json was not found next to this script. Use the package downloaded from the SLAPS portal.' }
$settings = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
if ($ApiUrl) { $settings.apiUrl = $ApiUrl }
$deviceId = [guid]$settings.deviceId
$api = [uri]$settings.apiUrl
if ($deviceId -eq [guid]::Empty -or $api.Scheme -ne 'https' -or -not $api.AbsolutePath.EndsWith('/') -or $api.Query -or $api.Fragment) { throw 'Invalid device ID or API URL (HTTPS, ending in /).' }
foreach ($hash in @($settings.clientCertificateSha256, $settings.recoveryCertificateSha256)) { if ($hash -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid certificate fingerprint in slaps-settings.json.' } }
$clientSha = $settings.clientCertificateSha256.ToUpperInvariant()
$recoverySha = $settings.recoveryCertificateSha256.ToUpperInvariant()

Write-Host ''
Write-Host "SLAPS agent installation for $($settings.displayName)" -ForegroundColor White
Write-Host "  Device ID:   $deviceId"
Write-Host "  API URL:     $($api.AbsoluteUri)"
Write-Host "  Install to:  $InstallDirectory"
Write-Host ''

Write-Step 'Checking prerequisites'
if (-not [Environment]::Is64BitOperatingSystem) { throw 'A 64-bit Windows Server is required.' }
$release = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
if (-not $release -or $release -lt 461808) { throw '.NET Framework 4.7.2 or later is required (included in Windows Server 2019).' }
if ((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2) { throw 'Domain controllers are not supported.' }
$joined = Get-JoinedDirectory
if ($joined) { throw ("This computer is joined to {0}. Standalone LAPS is only for standalone (workgroup) servers; nothing was installed. Use Windows LAPS with password backup to {0} instead: {1} (overview: https://learn.microsoft.com/windows-server/identity/laps/laps-overview)" -f $joined[0], $joined[1]) }
Write-Host '    Standalone server (not joined to Active Directory or Microsoft Entra ID).'
if ((Test-Path -LiteralPath $LegacyExtensionPath) -and (Get-ItemProperty -Path ('HKLM:\' + $LegacyPolicyPath) -ErrorAction SilentlyContinue).AdmPwdEnabled -eq 1) { throw 'Legacy Microsoft LAPS (AdmPwd client-side extension) is installed and enabled. Uninstall it first.' }
$policy = Get-ItemProperty -Path $LapsPolicyPath -ErrorAction SilentlyContinue
function Get-PolicyValue([string]$Name, $Default) { if ($policy -and $null -ne $policy.$Name) { return $policy.$Name } return $Default }
if ((Get-PolicyValue 'BackupDirectory' 0) -ne 0) { throw 'System > LAPS "Configure password backup directory" must be Disabled (BackupDirectory=0). SLAPS backs up to its own server.' }
if ((Get-PolicyValue 'AutomaticAccountManagementEnabled' 0) -ne 0) { throw 'Automatic account management in System > LAPS is not supported. Set it to Not configured.' }
# Post-authentication actions: same defaults as Windows LAPS (24 hours, reset password and sign out); grace period 0 disables them.
$postDelay = Get-PolicyValue 'PostAuthenticationResetDelay' 24
if ($postDelay -lt 0 -or $postDelay -gt 24) { $postDelay = 24 }
$postAction = Get-PolicyValue 'PostAuthenticationActions' 3
$postNames = @{ 1 = 'reset password'; 3 = 'reset password and sign out'; 5 = 'reset password and restart'; 11 = 'reset password, sign out and terminate processes' }
if (-not $postNames.ContainsKey([int]$postAction)) { $postAction = 3 }
$complexity = Get-PolicyValue 'PasswordComplexity' 4
if ($complexity -lt 1 -or $complexity -gt 4) { throw 'PasswordComplexity 5-8 (passphrases/readable passwords) is not supported.' }
$account = Get-PolicyValue 'AdministratorAccountName' ''
Write-Host ("    Password policy: age {0} days, length {1}, complexity {2}, account {3}{4}" -f (Get-PolicyValue 'PasswordAgeDays' 30), (Get-PolicyValue 'PasswordLength' 14), $complexity, $(if ($account) { $account } else { 'built-in Administrator (RID 500)' }), $(if ($policy) { '' } else { ' (Windows defaults; set via gpedit.msc > System > LAPS)' }))
Write-Host ('    Post-authentication: ' + $(if ($postDelay -eq 0) { 'disabled (grace period 0)' } else { $postNames[[int]$postAction] + ' ' + $postDelay + ' hours after the account is used' }))

Get-ChildItem -LiteralPath $packageRoot -Recurse -File | Unblock-File

Write-Step 'Importing the agent certificate into LocalMachine\My'
$certificate = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and (Get-Sha256 $_.RawData) -eq $clientSha } | Select-Object -First 1
if ($certificate) { Write-Host '    Already present.' }
else {
    $pfxPath = Join-Path $packageRoot 'agent.pfx'
    if (-not (Test-Path -LiteralPath $pfxPath)) { throw 'agent.pfx is missing from the package.' }
    if (-not $PfxPassword) { $PfxPassword = Read-Host 'PFX password (shown once in the SLAPS portal)' -AsSecureString }
    $imported = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $PfxPassword
    $certificate = $imported | Where-Object { (Get-Sha256 $_.RawData) -eq $clientSha } | Select-Object -First 1
    if (-not $certificate -or -not $certificate.HasPrivateKey) {
        $imported | ForEach-Object { Remove-Item -LiteralPath $_.PSPath -DeleteKey -ErrorAction SilentlyContinue }
        throw 'The PFX does not contain the expected agent certificate.'
    }
    Write-Host "    Imported $($certificate.Subject) (private key not exportable)."
}

Write-Step 'Installing agent files'
$previousSha = Get-ConfiguredCertificateSha
$service = Stop-AgentService
if (-not (Test-Path -LiteralPath $InstallDirectory)) { New-Item -ItemType Directory -Path $InstallDirectory | Out-Null; Protect-Directory $InstallDirectory }
Copy-Item -Path (Join-Path $packageRoot 'bin\*') -Destination $InstallDirectory -Force
$recoveryPath = Join-Path $InstallDirectory 'recovery.cer'
Copy-Item -LiteralPath (Join-Path $packageRoot 'recovery.cer') -Destination $recoveryPath -Force
$recoveryCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[IO.File]::ReadAllBytes($recoveryPath))
if ((Get-Sha256 $recoveryCertificate.RawData) -ne $recoverySha) { throw 'recovery.cer does not match the fingerprint in slaps-settings.json.' }
if (-not (Test-Path -LiteralPath $DataDirectory)) { New-Item -ItemType Directory -Path $DataDirectory | Out-Null; Protect-Directory $DataDirectory }
if (-not [System.Diagnostics.EventLog]::SourceExists($ServiceName)) { New-EventLog -LogName Application -Source $ServiceName }
$executable = Join-Path $InstallDirectory 'StandaloneLaps.Agent.exe'
if (-not $service) {
    New-Service -Name $ServiceName -BinaryPathName ('"' + $executable + '"') -DisplayName 'Standalone LAPS Agent' -Description 'Rotates the local administrator password and backs it up to the SLAPS server.' -StartupType Automatic | Out-Null
    Write-Host '    Service created (LocalSystem, automatic start).'
} else {
    Set-Service -Name $ServiceName -StartupType Automatic
    Write-Host '    Existing service updated.'
}
# Always write the quoted image path directly: Windows PowerShell 5.1 drops embedded quotes when passing
# arguments to native tools (sc.exe binPath=), which left an unquoted path under "Program Files" (CWE-428).
$servicePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\' + $ServiceName
$quotedImage = '"' + $executable + '"'
Set-ItemProperty -LiteralPath $servicePath -Name ImagePath -Value $quotedImage -Type ExpandString
if ((Get-ItemProperty -LiteralPath $servicePath -Name ImagePath).ImagePath -ne $quotedImage) { throw 'Unable to set the quoted service image path.' }
Write-Host "    Service path (quoted): $quotedImage"
& sc.exe failure $ServiceName reset= 86400 actions= restart/60000/restart/60000/restart/60000 | Out-Null

Write-Step 'Writing settings to HKLM\SOFTWARE\PriCoSoft\SLAPS (64-bit)'
$base = Open-Hklm64
try {
    $key = $base.CreateSubKey($SettingsKeyPath)
    try {
        $security = New-Object System.Security.AccessControl.RegistrySecurity
        $security.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
            $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $security.AddAccessRule((New-Object System.Security.AccessControl.RegistryAccessRule($identity, [System.Security.AccessControl.RegistryRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::ContainerInherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)))
        }
        $key.SetAccessControl($security)
        $key.SetValue('Enabled', 0, [Microsoft.Win32.RegistryValueKind]::DWord)
        $values = [ordered]@{ DeviceId = $deviceId.ToString('D'); ApiUrl = $api.AbsoluteUri; ClientCertificateSha256 = $clientSha; RecoveryCertificatePath = $recoveryPath; RecoveryCertificateSha256 = $recoverySha }
        foreach ($entry in $values.GetEnumerator()) { $key.SetValue($entry.Key, $entry.Value, [Microsoft.Win32.RegistryValueKind]::String) }
        $key.SetValue('LegacyLapsSignal', [int][bool]$policy, [Microsoft.Win32.RegistryValueKind]::DWord)
        $key.SetValue('Enabled', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
    } finally { $key.Dispose() }
    # "LAPS enabled" signal for inventory/compliance tools (legacy policy value). Windows LAPS ignores it while the
    # System > LAPS policy has settings, and the legacy client-side extension is not installed (checked above).
    # Without System > LAPS settings Windows LAPS would fall back to the legacy policy, so it is not set then.
    if ($policy) {
        $legacy = $base.CreateSubKey($LegacyPolicyPath)
        try { $legacy.SetValue('AdmPwdEnabled', 1, [Microsoft.Win32.RegistryValueKind]::DWord) } finally { $legacy.Dispose() }
        Write-Host '    LAPS signal: AdmPwdEnabled=1 (legacy policy value; agent also maintains the Windows LAPS state and log).'
    } else { Write-Warning 'No System > LAPS policy settings found: the legacy AdmPwdEnabled signal was not set. Configure System > LAPS and rerun the installer.' }
} finally { $base.Dispose() }
if ($previousSha -and $previousSha -ne $clientSha -and -not $KeepCertificate) { Write-Host '    Removing the superseded agent certificate.'; Remove-MachineCertificate $previousSha }

Write-Step 'Validating configuration'
& $executable validate-config
if ($LASTEXITCODE -ne 0) { throw 'validate-config failed. Fix the reported setting and run the installer again.' }

$connectivityOk = $true
if (-not $SkipConnectivityTest) {
    Write-Step "Testing the connection to $($api.Host)"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $probeBase = $api.AbsoluteUri + 'api.aspx?device=' + $deviceId.ToString('D')
    $read = Invoke-ApiProbe 'GET' ($probeBase + '&skip=0&take=1') $certificate $null
    $upload = Invoke-ApiProbe 'PUT' ($probeBase + '&rotation=' + [guid]::NewGuid().ToString('D')) $certificate ('x' * 30000)
    Write-Host "    History read: $read (expected 200); upload check: $upload (expected 400 = authenticated, test body rejected)"
    if ($read -ne 200 -or $upload -ne 400) {
        $connectivityOk = $false
        $hint = if ($read -eq 403 -or $upload -eq 403) { 'The server rejected the agent certificate: check that the device is active in the portal and that IIS trusts the SLAPS CA and its CRL.' }
                elseif ($upload -eq 413) { 'Uploads are rejected (413): rerun the server installer so uploadReadAheadSize is applied.' }
                elseif ($read -is [string]) { 'No HTTPS connection: check DNS, firewall (TCP 443) and that this server trusts the CA of the IIS TLS certificate.' }
                else { 'Unexpected response; check the IIS logs on the SLAPS server.' }
        Write-Warning $hint
    }
}

if (-not $NoStart) {
    Write-Step 'Starting the agent'
    Start-Service -Name $ServiceName
    Write-Host '    Service started. Without previous local state the first rotation runs within a few seconds.'
}

Write-Host ''
if ($connectivityOk) { Write-Host 'Installation complete.' -ForegroundColor Green } else { Write-Host 'Installation complete, but the connection test failed (see warning). The agent retries every five minutes; no password is changed before a verified backup.' -ForegroundColor Yellow }
Write-Host 'Delete this package folder and ZIP now: agent.pfx contains the agent private key.'
Write-Host 'Events: Event Viewer > Windows Logs > Application, source StandaloneLapsAgent; processing summary like Windows LAPS in Applications and Services Logs > Microsoft > Windows > LAPS > Operational.'
