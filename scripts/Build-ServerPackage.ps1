[CmdletBinding()]
param(
    [switch]$SkipTests,
    # Authenticode signing of the agent EXE and the PowerShell installers (Defender/ASR). Required for release packages.
    [switch]$SkipSigning,
    [string]$SignCode = 'C:\Program Files (x86)\PriCoSoft\SignCode\signcode.cmd'
)
# Builds the agent, runs all checks and creates artifacts\StandaloneLaps-Server-<version>-<timestamp>.zip:
#   Install-SlapsServer.ps1, website\ (source-only IIS site), agent\ (Framework agent), client\Install-SlapsAgent.ps1, docs\
# and artifacts\StandaloneLaps-Container-<version>-<timestamp>.zip (Docker alternative to IIS, see docs\Container.md).
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
Copy-Item -LiteralPath (Join-Path $root 'README.md'), (Join-Path $root 'docs\Migration.md'), (Join-Path $root 'docs\Container.md') -Destination (Join-Path $stage 'docs')

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

# Container package: published server (framework-dependent, runs in mcr.microsoft.com/dotnet/aspnet:10.0), the signed
# agent files from the server stage and a runtime-only Dockerfile, so "docker compose up -d --build" needs no SDK.
$dotnet = (Get-Command dotnet -ErrorAction SilentlyContinue).Source
if (-not $dotnet) { throw 'The .NET 10 SDK (dotnet) is required to build the container package.' }
if (-not $SkipTests) {
    $testOutput = Join-Path $root 'artifacts\verification\server-tests'
    & $dotnet build (Join-Path $root 'tests\StandaloneLaps.Server.Tests\StandaloneLaps.Server.Tests.csproj') -c Release -o $testOutput --nologo -v quiet
    if ($LASTEXITCODE -ne 0) { throw 'Building the container server tests failed.' }
    & $dotnet (Join-Path $testOutput 'StandaloneLaps.Server.Tests.dll')
    if ($LASTEXITCODE -ne 0) { throw 'Container server tests failed.' }
}
$containerName = 'StandaloneLaps-Container-' + $version + '-' + (Get-Date -Format 'yyyyMMdd-HHmm')
$containerStage = Join-Path $root ('artifacts\' + $containerName)
New-Item -ItemType Directory -Path $containerStage | Out-Null
& $dotnet publish (Join-Path $root 'src\StandaloneLaps.Server\StandaloneLaps.Server.csproj') -c Release -o (Join-Path $containerStage 'app') -p:UseAppHost=false --nologo -v quiet
if ($LASTEXITCODE -ne 0) { throw 'Publishing the container server failed.' }
Get-ChildItem -LiteralPath (Join-Path $containerStage 'app') -Filter '*.pdb' | Remove-Item
$agentPackage = Join-Path $containerStage 'agent-package'
New-Item -ItemType Directory -Path (Join-Path $agentPackage 'linux') -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $stage 'agent\StandaloneLaps.Agent.exe'), (Join-Path $stage 'agent\StandaloneLaps.Agent.exe.config'), (Join-Path $stage 'client\Install-SlapsAgent.ps1') -Destination $agentPackage
foreach ($file in 'slaps-agent', 'slaps-agent.service', 'agent.conf', 'install.sh') { Copy-Item -LiteralPath (Join-Path $stage ('linux\' + $file)) -Destination (Join-Path $agentPackage 'linux') }
Copy-Item -LiteralPath (Get-ChildItem -LiteralPath (Join-Path $stage 'linux') -Filter 'slaps-agent_*_all.deb' | Select-Object -First 1).FullName -Destination (Join-Path $agentPackage 'linux\slaps-agent.deb')
$runtimeDockerfile = @'
# SLAPS container server {VERSION} (prebuilt). docker compose up -d --build
FROM mcr.microsoft.com/dotnet/aspnet:10.0
# Optional Windows LAPS lookup: libldap for System.DirectoryServices.Protocols, Python with dpapi-ng to decrypt
# encrypted Windows LAPS passwords. --build-arg SLAPS_DPAPI_KERBEROS=true adds Kerberos (default: NTLM via pyspnego).
ARG SLAPS_DPAPI_KERBEROS=false
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
 && (apt-get install -y --no-install-recommends libldap2 || apt-get install -y --no-install-recommends libldap-2.5-0) \
 && python3 -m venv /opt/dpapi \
 && if [ "$SLAPS_DPAPI_KERBEROS" = "true" ]; then \
      apt-get install -y --no-install-recommends gcc python3-dev libkrb5-dev krb5-user \
      && /opt/dpapi/bin/pip install --no-cache-dir "dpapi-ng[kerberos]>=0.2,<1"; \
    else /opt/dpapi/bin/pip install --no-cache-dir "dpapi-ng>=0.2,<1"; fi \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app/ ./
COPY agent-package/ /app/agent-package/
RUN mkdir -p /data && chown "$APP_UID" /data
ENV ASPNETCORE_ENVIRONMENT=Production \
    ASPNETCORE_HTTP_PORTS= \
    Slaps__DataDirectory=/data \
    Slaps__AgentPackageDirectory=/app/agent-package \
    Slaps__WindowsLapsPython=/opt/dpapi/bin/python
USER $APP_UID
VOLUME /data
EXPOSE 8443 8444
HEALTHCHECK --interval=60s --timeout=10s --start-period=60s CMD ["dotnet", "StandaloneLaps.Server.dll", "health"]
ENTRYPOINT ["dotnet", "StandaloneLaps.Server.dll"]
'@
Set-Content -LiteralPath (Join-Path $containerStage 'Dockerfile') -Value $runtimeDockerfile.Replace('{VERSION}', $version) -Encoding UTF8
$compose = Get-Content -LiteralPath (Join-Path $root 'container\compose.yaml') -Raw
if ($compose -notmatch ('slaps-server:' + [regex]::Escape($version))) { throw "container\compose.yaml must use the image tag slaps-server:$version." }
$compose = [regex]::Replace($compose, '(?m)^    build:\r?\n      context: \.\.\r?\n      dockerfile: container/Dockerfile\r?\n', "    build: .`n")
if ($compose -match 'container/Dockerfile') { throw 'Could not rewrite the build section of compose.yaml.' }
Set-Content -LiteralPath (Join-Path $containerStage 'compose.yaml') -Value $compose -Encoding UTF8
Copy-Item -LiteralPath (Join-Path $root 'container\compose.postgres.yaml'), (Join-Path $root 'container\compose.image.yaml'), (Join-Path $root 'docs\Container.md'), (Join-Path $root 'LICENSE'), (Join-Path $root 'NOTICE') -Destination $containerStage
$containerZip = $containerStage + $(if ($SkipSigning) { '-UNSIGNED.zip' } else { '.zip' })
Compress-Archive -Path (Join-Path $containerStage '*') -DestinationPath $containerZip
Write-Host "Container package: $containerZip"
