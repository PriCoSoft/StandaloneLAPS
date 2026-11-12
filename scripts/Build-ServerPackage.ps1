[CmdletBinding()]
param(
    [switch]$SkipTests,
    # Authenticode signing of the agent EXE and the PowerShell installers (Defender/ASR). Required for release packages.
    [switch]$SkipSigning,
    [string]$SignCode = 'C:\Program Files (x86)\PriCoSoft\SignCode\signcode.cmd'
)
# Builds the agent, runs all checks and creates artifacts\StandaloneLaps-Server-<timestamp>.zip:
#   Install-SlapsServer.ps1, website\ (source-only IIS site), agent\ (Framework agent), client\Install-SlapsAgent.ps1, docs\
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if ($SkipTests) { & (Join-Path $PSScriptRoot 'Build-FrameworkAgent.ps1') } else { & (Join-Path $PSScriptRoot 'Test-IisBackend.ps1') }
& (Join-Path $PSScriptRoot 'Build-LinuxAgent.ps1')
$version = [regex]::Match((Get-Content -LiteralPath (Join-Path $root 'web\IisVault\App_Code\AppVersion.cs') -Raw), 'Number\s*=\s*"([0-9.]+)"').Groups[1].Value
if (-not $version) { throw 'Version not found in web\IisVault\App_Code\AppVersion.cs.' }
$name = 'StandaloneLaps-Server-' + $version + '-' + (Get-Date -Format 'yyyyMMdd-HHmm')
$stage = Join-Path $root ('artifacts\' + $name)
$zip = $stage + '.zip'
if ((Test-Path -LiteralPath $stage) -or (Test-Path -LiteralPath $zip)) { throw "$name already exists; wait a minute or review the existing output." }
New-Item -ItemType Directory -Path $stage | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-SlapsServer.ps1') -Destination $stage
Copy-Item -LiteralPath (Join-Path $root 'web\IisVault') -Destination (Join-Path $stage 'website') -Recurse
Get-ChildItem -LiteralPath (Join-Path $stage 'website\App_Data\Vault') -Force | Where-Object { $_.Name -ne 'DEPLOYMENT.txt' } | Remove-Item -Recurse -Force
Set-Content -LiteralPath (Join-Path $stage 'website\App_Data\clients.json') -Value '[]' -Encoding ASCII
New-Item -ItemType Directory -Path (Join-Path $stage 'agent'), (Join-Path $stage 'client'), (Join-Path $stage 'docs') | Out-Null
Copy-Item -Path (Join-Path $root 'artifacts\Agent-Net472\*') -Destination (Join-Path $stage 'agent')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Install-SlapsAgent.ps1') -Destination (Join-Path $stage 'client')
Copy-Item -LiteralPath (Join-Path $root 'artifacts\Agent-Linux') -Destination (Join-Path $stage 'linux') -Recurse
Copy-Item -LiteralPath (Join-Path $root 'README.md'), (Join-Path $root 'docs\Migration.md') -Destination (Join-Path $stage 'docs')

# Sign the staged copies (sources stay unsigned). The website copies agent EXE and Install-SlapsAgent.ps1
# byte-for-byte into every client package, so the signatures stay valid there.
$toSign = @((Join-Path $stage 'agent\StandaloneLaps.Agent.exe'), (Join-Path $stage 'client\Install-SlapsAgent.ps1'), (Join-Path $stage 'Install-SlapsServer.ps1'))
if ($SkipSigning) {
    Write-Warning 'Signing skipped: the package contains unsigned files and may be blocked by Defender/ASR. Do not distribute it.'
    $zip = $stage + '-UNSIGNED.zip'
} else {
    if (-not (Test-Path -LiteralPath $SignCode)) { throw "Signing tool not found: $SignCode. Install it or pass -SignCode, or use -SkipSigning for a local test build." }
    foreach ($file in $toSign) {
        Write-Host "Signing $file"
        # signcode.cmd ends with 'pause'; feed it an empty stdin so the build does not wait.
        & cmd.exe /d /c ('"' + $SignCode + '" "' + $file + '" < nul') | ForEach-Object { if ($_ -match 'Error|Fehler|Successfully|signed') { Write-Host ('    ' + $_) } }
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        if ($signature.Status -ne 'Valid') { throw "Signing $file failed: $($signature.Status) $($signature.StatusMessage)" }
        if (-not $signature.TimeStamperCertificate) { throw "Signature of $file has no timestamp." }
        Write-Host ('    Valid, signer: ' + $signature.SignerCertificate.Subject)
    }
}
$installText = @'
SLAPS server package {VERSION}
====================

Step 1 - Microsoft Entra app registration (one app, Entra admin center)
-----------------------------------------------------------------------
No client secret, no certificate, no "Expose an API" and no second app are needed.

 a) App registrations > New registration
      Name:                     SLAPS
      Supported account types:  Accounts in this organizational directory only
      Redirect URI:             platform "Web", https://<host>/signin.aspx

 b) Authentication
      Enable "ID tokens (used for implicit and hybrid flows)".
      Leave "Access tokens" disabled.

 c) App roles > Create app role (twice, allowed member types: Users/Groups)
      Display name "SLAPS Admin",  value exactly: SLAPS.Admin
        -> full access: Add client, delete/restore devices, reveal passwords
      Display name "SLAPS Reader", value exactly: SLAPS.Reader
        -> view history, download envelopes, reveal passwords

 d) API permissions
      Keep "Microsoft Graph > User.Read" (delegated), no other permissions.
      Click "Grant admin consent".

 e) Enterprise applications > SLAPS > Properties
      Assignment required = Yes
      (optional) Visible to users = No

 f) Enterprise applications > SLAPS > Users and groups > Add user/group
      Assign users or groups with the role "SLAPS Admin" or "SLAPS Reader".
      Assigned users without one of these roles are denied.
      Group assignment requires Microsoft Entra ID P1 or higher.

 g) Note the Directory (tenant) ID and the Application (client) ID.
    The installer asks for both.

 Notes:
  - The IIS server needs outbound HTTPS to login.microsoftonline.com
    (set OutboundProxyUrl in web.config if a proxy is required).
  - Conditional Access policies (e.g. MFA) for this app apply as usual.
  - If the host name changes later, add the new redirect URI to the app.

Step 2 - TLS certificate
------------------------
Import the TLS certificate for <host> (with private key) into LocalMachine\My.
DMZ servers must trust its issuing CA.

Step 3 - Run the installer
--------------------------
Extract this ZIP on the IIS server and run in an elevated Windows PowerShell 5.1:

   powershell.exe -ExecutionPolicy Bypass -File .\Install-SlapsServer.ps1 -TargetDirectory D:\Web\SLAPS -HostName slaps.example.com

The installer asks once for the Entra tenant ID, client ID, the internal admin
networks (CIDR list, e.g. 10.0.0.0/8;192.168.10.0/24) and a password for the
key backup. Move the key backup PFX files and the password to an offline safe;
the keys on the server are made non-exportable afterwards.

Step 4 - First use
------------------
Sign in at https://<host>/ from an internal network as a user with the
SLAPS.Admin role, open "Add client", note the one-time PFX password and
download the package. On the DMZ server run Install.cmd as administrator;
the connectivity test at the end must report GET 200 / PUT 400.

Linux servers: choose "Linux (systemd)" in "Add client". The package contains
install.sh and a .deb (Debian/Ubuntu); run "sudo sh install.sh" on the server.
Needs python3 (3.6+), openssl and systemd. Password rules: /etc/slaps/agent.conf
(default: root, 14 characters, complexity 4, 30 days). The linux\ folder of this
package also contains the .deb for distribution tools (enroll with
"slaps-agent enroll <extracted client package>").

Browsers are never asked for a client certificate on the portal: only the
agent API (api.aspx) requests one. If a browser still shows a certificate
selection dialog after an update, close all browser windows once (the TLS
connection to the old configuration is cached).

Updating: extract a newer package and run the same command again. The installer
backs up the target directory, keeps App_Data\Vault (data, settings.json),
clients.json and the web.config values, and shows the old and new version.

Details: docs\README.md and docs\Migration.md
'@
Set-Content -LiteralPath (Join-Path $stage 'INSTALL.txt') -Encoding UTF8 -Value $installText.Replace('{VERSION}', $version)
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
Write-Host "Server package: $zip"
