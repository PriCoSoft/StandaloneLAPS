#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.SYNOPSIS
Installs or upgrades the SLAPS IIS backend (portal + agent API) on Windows Server 2019 or later.

.DESCRIPTION
Only the target directory and the DNS name are required. The installer
  - installs the required IIS / ASP.NET 4.x features,
  - finds the TLS certificate for the DNS name in LocalMachine\My,
  - checks existing HTTPS bindings on port 443 and adds an SNI binding for the DNS name only,
  - creates a dedicated application pool and website (HTTP/2 off for client-certificate renegotiation,
    uploadReadAheadSize raised, SSL required, client certificates accepted on api.aspx only),
  - copies the website, keeps existing data on upgrades and backs up the previous installation,
  - creates the SLAPS CA (35 years) and the recovery certificate (30 years) if missing, trusts the CA,
    imports its CRL and grants the application pool access to both private keys,
  - writes web.config (Entra sign-in, internal networks, URLs, certificate fingerprints, machine key).
Values that cannot be discovered (Entra tenant/client ID, internal networks) are asked for once and
reused on later runs.

.EXAMPLE
.\Install-SlapsServer.ps1 -TargetDirectory D:\Web\SLAPS -HostName slaps.example.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$TargetDirectory,
    [Parameter(Mandatory)][string]$HostName,
    [string]$TenantId,
    [string]$ClientId,
    [string]$PortalAllowedNetworks,
    [string]$CertificateThumbprint,
    [string]$SiteName = 'SLAPS',
    [string]$AppPoolName = 'SLAPS',
    [string]$KeyBackupDirectory
)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Run this installer in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.' }

function Write-Step([string]$Text) { Write-Host ''; Write-Host ('==> ' + $Text) -ForegroundColor Cyan }
function Write-Info([string]$Text) { Write-Host ('    ' + $Text) }
function Get-Sha256([byte[]]$Raw) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash($Raw)).Replace('-', '') } finally { $sha.Dispose() }
}
function Find-MachineCertificate([string]$Sha) {
    if (-not $Sha) { return $null }
    Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.HasPrivateKey -and (Get-Sha256 $_.RawData) -eq $Sha.ToUpperInvariant() } | Select-Object -First 1
}
function Test-CidrList([string]$Value) {
    $entries = @($Value -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($entries.Count -eq 0) { return $false }
    foreach ($entry in $entries) {
        $parts = $entry -split '/'
        $address = $null; $bits = -1
        if ($parts.Count -ne 2 -or -not [System.Net.IPAddress]::TryParse($parts[0], [ref]$address) -or -not [int]::TryParse($parts[1], [ref]$bits)) { return $false }
        if ($bits -lt 0 -or $bits -gt ($address.GetAddressBytes().Length * 8)) { return $false }
    }
    return $true
}
function Test-HostMatch($Certificate, [string]$Name) {
    $names = @($Certificate.DnsNameList | ForEach-Object { $_.Unicode })
    if ($names.Count -eq 0) { $names = @($Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false)) }
    foreach ($candidate in $names) {
        if (-not $candidate) { continue }
        $candidate = $candidate.ToLowerInvariant()
        if ($candidate -eq $Name) { return $true }
        if ($candidate.StartsWith('*.') -and $Name.IndexOf('.') -gt 0 -and $Name.Substring($Name.IndexOf('.') + 1) -eq $candidate.Substring(2)) { return $true }
    }
    return $false
}
function Grant-PrivateKeyRead($Certificate, [string]$Identity) {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($rsa -is [System.Security.Cryptography.RSACng]) {
        $path = Join-Path $env:ProgramData ('Microsoft\Crypto\Keys\' + $rsa.Key.UniqueName)
    } else {
        $path = Join-Path $env:ProgramData ('Microsoft\Crypto\RSA\MachineKeys\' + $rsa.CspKeyContainerInfo.UniqueKeyContainerName)
    }
    if (-not (Test-Path -LiteralPath $path)) { throw "Private key file for $($Certificate.Subject) not found." }
    & icacls.exe $path /grant ($Identity + ':R') | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to grant $Identity read access to the key of $($Certificate.Subject)." }
    return ($rsa -is [System.Security.Cryptography.RSACng])
}
function Test-KeyExportable($Certificate) {
    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
    if ($rsa -is [System.Security.Cryptography.RSACng]) {
        $mask = [System.Security.Cryptography.CngExportPolicies]::AllowExport -bor [System.Security.Cryptography.CngExportPolicies]::AllowPlaintextExport
        return (([int]$rsa.Key.ExportPolicy -band [int]$mask) -ne 0)
    }
    return [bool]$rsa.CspKeyContainerInfo.Exportable
}
function Get-StoredMachineCertificate([string]$Thumbprint) {
    return (Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + $Thumbprint) -ErrorAction SilentlyContinue)
}
# Verifies the PFX backup, deletes the exportable key and re-imports the backup as non-exportable
# into the CNG Software KSP (required for RSA-OAEP-SHA256 on .NET Framework).
function Protect-BackedUpKey($Certificate, [string]$PfxPath, [System.Security.SecureString]$Password) {
    $thumbprint = $Certificate.Thumbprint
    $check = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList ([System.IO.File]::ReadAllBytes($PfxPath)), $Password, ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
    try {
        if ($check.Thumbprint -ne $thumbprint -or -not $check.HasPrivateKey) { throw "The backup $PfxPath could not be verified. The key was left unchanged." }
    } finally { $check.Reset() }

    Remove-Item -LiteralPath ('Cert:\LocalMachine\My\' + $thumbprint) -DeleteKey
    $restoreHint = "Restore it with: certutil -f -csp `"Microsoft Software Key Storage Provider`" -importpfx My `"$PfxPath`" NoExport"
    try {
        Import-PfxCertificate -FilePath $PfxPath -CertStoreLocation 'Cert:\LocalMachine\My' -Password $Password | Out-Null
        $fresh = Get-StoredMachineCertificate $thumbprint
        $isCng = $fresh -and ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($fresh) -is [System.Security.Cryptography.RSACng])
        if (-not $isCng) {
            if ($fresh) { Remove-Item -LiteralPath ('Cert:\LocalMachine\My\' + $thumbprint) -DeleteKey }
            Write-Info 'Re-importing into the Software Key Storage Provider; certutil asks for the backup password once more.'
            & certutil.exe -f -csp 'Microsoft Software Key Storage Provider' -importpfx My $PfxPath NoExport
            if ($LASTEXITCODE -ne 0) { throw 'certutil -importpfx failed.' }
            $fresh = Get-StoredMachineCertificate $thumbprint
        }
    } catch {
        throw "Re-importing $($Certificate.Subject) as non-exportable failed: $($_.Exception.Message) $restoreHint"
    }
    if (-not $fresh -or -not $fresh.HasPrivateKey) { throw "The key of $($Certificate.Subject) is missing after re-import. $restoreHint" }
    if (-not ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($fresh) -is [System.Security.Cryptography.RSACng])) { throw "The key of $($Certificate.Subject) is not a CNG key after re-import. $restoreHint" }
    if (Test-KeyExportable $fresh) { throw "The key of $($Certificate.Subject) is still exportable after re-import." }
    return $fresh
}
function Get-SlapsVersion([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $match = [regex]::Match((Get-Content -LiteralPath $Path -Raw), 'Number\s*=\s*"([0-9.]+)"')
    if ($match.Success) { return $match.Groups[1].Value } else { return $null }
}
function Set-AppSetting([xml]$Document, [string]$Key, [string]$Value) {
    $settings = $Document.configuration.appSettings
    $node = $settings.add | Where-Object { $_.key -eq $Key } | Select-Object -First 1
    if (-not $node) { $node = $Document.CreateElement('add'); $node.SetAttribute('key', $Key); [void]$settings.AppendChild($node) }
    $node.SetAttribute('value', $Value)
}
function Get-AppSetting([xml]$Document, [string]$Key) {
    if (-not $Document) { return '' }
    $node = $Document.configuration.appSettings.add | Where-Object { $_.key -eq $Key } | Select-Object -First 1
    if ($node) { return [string]$node.value } return ''
}
function New-HexKey([int]$Bytes) {
    $buffer = New-Object byte[] $Bytes
    $random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $random.GetBytes($buffer) } finally { $random.Dispose() }
    return [BitConverter]::ToString($buffer).Replace('-', '')
}

# ---- Inputs and source layout -------------------------------------------------------------------
$HostName = $HostName.Trim().ToLowerInvariant()
if ($HostName -notmatch '^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$') { throw "HostName '$HostName' is not a valid DNS name." }
if (-not [System.IO.Path]::IsPathRooted($TargetDirectory) -or $TargetDirectory -notmatch '^[A-Za-z]:\\.+') { throw 'TargetDirectory must be an absolute local path such as D:\Web\SLAPS.' }
$TargetDirectory = [System.IO.Path]::GetFullPath($TargetDirectory).TrimEnd('\')
if ($TargetDirectory.StartsWith($env:windir, [StringComparison]::OrdinalIgnoreCase)) { throw 'Do not install below the Windows directory.' }

if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'website\web.config')) {
    $websiteSource = Join-Path $PSScriptRoot 'website'
    $agentSource = Join-Path $PSScriptRoot 'agent'
    $clientInstaller = Join-Path $PSScriptRoot 'client\Install-SlapsAgent.ps1'
    $linuxSource = Join-Path $PSScriptRoot 'linux'
} else {
    $repository = Split-Path -Parent $PSScriptRoot
    $websiteSource = Join-Path $repository 'web\IisVault'
    $agentSource = Join-Path $repository 'artifacts\Agent-Net472'
    $clientInstaller = Join-Path $PSScriptRoot 'Install-SlapsAgent.ps1'
    $linuxSource = Join-Path $repository 'artifacts\Agent-Linux'
}
foreach ($required in @((Join-Path $websiteSource 'web.config'), (Join-Path $websiteSource 'App_Code\SlapsCertificateAuthority.cs'), (Join-Path $agentSource 'StandaloneLaps.Agent.exe'), (Join-Path $agentSource 'StandaloneLaps.Agent.exe.config'), $clientInstaller)) {
    if (-not (Test-Path -LiteralPath $required)) { throw "Installation source is incomplete: $required is missing. Run the installer from the extracted SLAPS server package." }
}
$poolIdentity = 'IIS AppPool\' + $AppPoolName
$upgrade = Test-Path -LiteralPath (Join-Path $TargetDirectory 'web.config')
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

Write-Host ''
Write-Host 'SLAPS server installation' -ForegroundColor White
Write-Info "Target:    $TargetDirectory $(if ($upgrade) { '(upgrade)' } else { '(new)' })"
Write-Info "Host name: https://$HostName/"
Write-Info "Site/pool: $SiteName / $AppPoolName (an existing site for the target directory is detected below)"

# ---- Prerequisites ------------------------------------------------------------------------------
Write-Step 'Checking prerequisites'
$build = [Environment]::OSVersion.Version.Build
if ($build -lt 17763) { throw 'Windows Server 2019 (build 17763) or later is required.' }
$release = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -ErrorAction SilentlyContinue).Release
if (-not $release -or $release -lt 461808) { throw '.NET Framework 4.7.2 or later is required.' }
if (-not (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue)) { throw 'Install-WindowsFeature is unavailable. Run the installer on Windows Server.' }
$features = Install-WindowsFeature -Name Web-Server, Web-Asp-Net45, Web-Net-Ext45, Web-ISAPI-Ext, Web-ISAPI-Filter, Web-Filtering, Web-Mgmt-Console
if (-not $features.Success) { throw 'Installing the IIS/ASP.NET 4.x features failed.' }
if ($features.RestartNeeded -eq 'Yes') { Write-Warning 'Windows reports that a restart is needed to finish the feature installation.' }
Write-Info 'IIS with ASP.NET 4.x is installed.'
Import-Module WebAdministration

# ---- Existing installation ----------------------------------------------------------------------
# An earlier installation may use another site/pool name (-SiteName/-AppPoolName or renamed in IIS Manager).
# The site that serves TargetDirectory is the SLAPS site; reuse its names unless they were passed explicitly.
$existingSites = @(Get-Website | Where-Object {
    [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($_.physicalPath)).TrimEnd('\') -eq $TargetDirectory
})
if ($existingSites.Count -gt 1) { throw "Several IIS sites use $TargetDirectory ($(($existingSites | ForEach-Object { $_.name }) -join ', ')). Keep one or pass -SiteName." }
if ($existingSites.Count -eq 1) {
    $existingSite = $existingSites[0]
    if ($PSBoundParameters.ContainsKey('SiteName') -and $SiteName -ne $existingSite.name) {
        throw "Site '$($existingSite.name)' already serves $TargetDirectory, but -SiteName '$SiteName' was given. Omit -SiteName to upgrade the existing site."
    }
    $SiteName = $existingSite.name
    if (-not $PSBoundParameters.ContainsKey('AppPoolName')) { $AppPoolName = $existingSite.applicationPool }
    $poolIdentity = 'IIS AppPool\' + $AppPoolName
    Write-Info "Existing SLAPS site detected: '$SiteName' (application pool '$AppPoolName'); it is upgraded in place."
}

# ---- TLS certificate ----------------------------------------------------------------------------
Write-Step "Finding the TLS certificate for $HostName"
$now = Get-Date
if ($CertificateThumbprint) {
    $tls = Get-Item -LiteralPath ('Cert:\LocalMachine\My\' + ($CertificateThumbprint -replace '\s', '')) -ErrorAction SilentlyContinue
    if (-not $tls -or -not $tls.HasPrivateKey) { throw "Certificate $CertificateThumbprint with private key was not found in LocalMachine\My." }
    if (-not (Test-HostMatch $tls $HostName)) { throw "Certificate $CertificateThumbprint does not contain $HostName." }
} else {
    $tls = Get-ChildItem Cert:\LocalMachine\My | Where-Object {
        $_.HasPrivateKey -and $_.NotBefore -le $now -and $_.NotAfter -gt $now.AddDays(7) -and
        (@($_.EnhancedKeyUsageList).Count -eq 0 -or @($_.EnhancedKeyUsageList | Where-Object { $_.ObjectId -eq '1.3.6.1.5.5.7.3.1' }).Count -gt 0) -and
        (Test-HostMatch $_ $HostName)
    } | Sort-Object NotAfter -Descending | Select-Object -First 1
    if (-not $tls) { throw "No valid server certificate with private key for $HostName was found in LocalMachine\My. Import it first or pass -CertificateThumbprint." }
}
Write-Info "Using $($tls.Subject), thumbprint $($tls.Thumbprint), valid until $($tls.NotAfter.ToString('yyyy-MM-dd'))."

# ---- Existing bindings on 443 -------------------------------------------------------------------
Write-Step 'Checking existing HTTPS bindings on port 443'
$bindings = @(Get-WebBinding -Protocol https | ForEach-Object {
    $parts = [regex]::Match($_.bindingInformation, '^(.*):(\d+):(.*)$')
    [pscustomobject]@{ Site = ([regex]::Match($_.ItemXPath, "@name='([^']+)'").Groups[1].Value); Address = $parts.Groups[1].Value; Port = $parts.Groups[2].Value; Host = $parts.Groups[3].Value.ToLowerInvariant(); SslFlags = $_.sslFlags }
})
$conflict = @($bindings | Where-Object { $_.Port -eq '443' -and $_.Host -eq $HostName -and $_.Site -ne $SiteName })
if ($conflict.Count -gt 0) { throw "Site '$($conflict[0].Site)' already uses https://$HostName on port 443. Choose another host name or remove that binding." }
foreach ($binding in @($bindings | Where-Object { $_.Port -eq '443' -and $_.Site -ne $SiteName })) {
    if ($binding.Host) { Write-Info "Site '$($binding.Site)' uses $($binding.Host):443 (separate host name, no conflict)." }
    else { Write-Info "Site '$($binding.Site)' uses $($binding.Address):443 without host name. It stays unchanged; the SNI binding for $HostName takes precedence for this name only." }
}
$ownSslEntry = Get-ChildItem IIS:\SslBindings | Where-Object { $_.Port -eq 443 -and $_.Host -eq $HostName } | Select-Object -First 1
$ownBinding = @($bindings | Where-Object { $_.Port -eq '443' -and $_.Host -eq $HostName -and $_.Site -eq $SiteName }).Count -gt 0
if ($ownSslEntry -and -not $ownBinding) { throw "HTTP.sys already has a certificate binding for ${HostName}:443 that no IIS site uses. Review it (netsh http show sslcert hostnameport=${HostName}:443) before installing." }
if ($bindings.Count -eq 0) { Write-Info 'No other HTTPS bindings exist.' }

# ---- Files --------------------------------------------------------------------------------------
$existingConfig = $null
if ($upgrade) {
    Write-Step 'Backing up the existing installation'
    if ((Test-Path ('IIS:\AppPools\' + $AppPoolName)) -and (Get-WebAppPoolState -Name $AppPoolName).Value -eq 'Started') { Stop-WebAppPool -Name $AppPoolName; Start-Sleep -Seconds 3 }
    $backup = $TargetDirectory + '.backup-' + $stamp
    Copy-Item -LiteralPath $TargetDirectory -Destination $backup -Recurse
    Write-Info "Copied to $backup (contains encrypted vault data; protect or delete it after checking the upgrade)."
    $existingConfig = [xml](Get-Content -LiteralPath (Join-Path $TargetDirectory 'web.config') -Raw)
}

Write-Step 'Copying the website'
$newVersion = Get-SlapsVersion (Join-Path $websiteSource 'App_Code\AppVersion.cs')
$oldVersion = if ($upgrade) { Get-SlapsVersion (Join-Path $TargetDirectory 'App_Code\AppVersion.cs') } else { $null }
if ($upgrade) { Write-Info ('Upgrading SLAPS ' + $(if ($oldVersion) { $oldVersion } else { '(before 1.1.0)' }) + ' -> ' + $newVersion + '.') } else { Write-Info "Installing SLAPS $newVersion." }
New-Item -ItemType Directory -Path $TargetDirectory -Force | Out-Null
$sourceRoot = (Resolve-Path -LiteralPath $websiteSource).Path.TrimEnd('\')
foreach ($file in Get-ChildItem -LiteralPath $sourceRoot -Recurse -File) {
    $relative = $file.FullName.Substring($sourceRoot.Length + 1)
    $destination = Join-Path $TargetDirectory $relative
    if ($relative -eq 'web.config') { continue }
    if ($upgrade -and ($relative -eq 'App_Data\clients.json' -or $relative -like 'App_Data\Vault\*') -and (Test-Path -LiteralPath $destination)) { continue }
    New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force | Out-Null
    Copy-Item -LiteralPath $file.FullName -Destination $destination -Force
}
$agentPackage = Join-Path $TargetDirectory 'App_Data\AgentPackage'
New-Item -ItemType Directory -Path $agentPackage -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $agentSource 'StandaloneLaps.Agent.exe'), (Join-Path $agentSource 'StandaloneLaps.Agent.exe.config'), $clientInstaller -Destination $agentPackage -Force
# Linux agent for "Add client" > Linux (the .deb is stored under a fixed name; packages name it by version).
$linuxPackage = Join-Path $agentPackage 'linux'
$linuxDeb = Get-ChildItem -LiteralPath $linuxSource -Filter 'slaps-agent_*_all.deb' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($linuxDeb) {
    New-Item -ItemType Directory -Path $linuxPackage -Force | Out-Null
    foreach ($name in 'slaps-agent', 'slaps-agent.service', 'agent.conf', 'install.sh') { Copy-Item -LiteralPath (Join-Path $linuxSource $name) -Destination $linuxPackage -Force }
    Copy-Item -LiteralPath $linuxDeb.FullName -Destination (Join-Path $linuxPackage 'slaps-agent.deb') -Force
} else { Write-Warning "Linux agent files not found in $linuxSource; Linux client packages are unavailable." }
New-Item -ItemType Directory -Path (Join-Path $TargetDirectory 'App_Data\Vault') -Force | Out-Null
Get-ChildItem -LiteralPath $TargetDirectory -Recurse -File | Unblock-File
Write-Info 'Website, agent package files and client installer copied.'

# ---- Application pool and site ------------------------------------------------------------------
Write-Step 'Configuring the application pool and website'
if (-not (Test-Path ('IIS:\AppPools\' + $AppPoolName))) { New-WebAppPool -Name $AppPoolName | Out-Null; Write-Info "Created application pool $AppPoolName." }
$poolPath = 'IIS:\AppPools\' + $AppPoolName
Set-ItemProperty $poolPath -Name managedRuntimeVersion -Value 'v4.0'
Set-ItemProperty $poolPath -Name managedPipelineMode -Value 'Integrated'
Set-ItemProperty $poolPath -Name enable32BitAppOnWin64 -Value $false
Set-ItemProperty $poolPath -Name processModel.identityType -Value 'ApplicationPoolIdentity'
Set-ItemProperty $poolPath -Name processModel.maxProcesses -Value 1
Set-ItemProperty $poolPath -Name startMode -Value 'AlwaysRunning'

if (-not (Get-Website -Name $SiteName)) {
    New-Website -Name $SiteName -PhysicalPath $TargetDirectory -ApplicationPool $AppPoolName -HostHeader $HostName -Port 443 -Ssl -SslFlags 1 | Out-Null
    Write-Info "Created website $SiteName."
} else {
    Set-ItemProperty ('IIS:\Sites\' + $SiteName) -Name physicalPath -Value $TargetDirectory
    Set-ItemProperty ('IIS:\Sites\' + $SiteName) -Name applicationPool -Value $AppPoolName
    if (-not (Get-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $HostName)) { New-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $HostName -SslFlags 1 }
    Write-Info "Updated website $SiteName."
}
$flags = 1 + 4                                   # SNI + disable HTTP/2 (client-certificate renegotiation)
if ($build -ge 20348) { $flags += 32 }           # Server 2022+: disable TLS 1.3, which has no renegotiation
$bindingFilter = "system.applicationHost/sites/site[@name='$SiteName']/bindings/binding[@protocol='https' and @bindingInformation='*:443:$HostName']"
$currentFlags = [int](Get-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $HostName).sslFlags
if ($currentFlags -ne $flags) { Set-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter $bindingFilter -Name sslFlags -Value $flags }
$binding = Get-WebBinding -Name $SiteName -Protocol https -Port 443 -HostHeader $HostName
$sslEntry = Get-ChildItem IIS:\SslBindings | Where-Object { $_.Port -eq 443 -and $_.Host -eq $HostName } | Select-Object -First 1
if ($sslEntry -and ($sslEntry.Thumbprint -ne $tls.Thumbprint -or $currentFlags -ne $flags)) { $binding.RemoveSslCertificate(); $sslEntry = $null }
if (-not $sslEntry) { $binding.AddSslCertificate($tls.Thumbprint, 'My') }
Write-Info "HTTPS binding *:443:$HostName (SNI, HTTP/2 off$(if ($build -ge 20348) { ', TLS 1.3 off' })) uses the TLS certificate."

$apphost = 'MACHINE/WEBROOT/APPHOST'
# Client certificates are requested only for the agent API (TLS renegotiation on api.aspx), so browsers
# opening the Entra portal never see a certificate selection dialog. The break-glass Certificate portal
# mode authenticates with client certificates and therefore keeps requesting them on the whole site.
$certificatePortal = (Get-AppSetting $existingConfig 'PortalAuthMode') -eq 'Certificate'
$siteSslFlags = if ($certificatePortal) { 'Ssl,SslNegotiateCert' } else { 'Ssl' }
Set-WebConfigurationProperty -PSPath $apphost -Location $SiteName -Filter 'system.webServer/security/access' -Name sslFlags -Value $siteSslFlags
Set-WebConfigurationProperty -PSPath $apphost -Location ($SiteName + '/api.aspx') -Filter 'system.webServer/security/access' -Name sslFlags -Value 'Ssl,SslNegotiateCert'
Set-WebConfigurationProperty -PSPath $apphost -Location $SiteName -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name enabled -Value $true
Set-WebConfigurationProperty -PSPath $apphost -Location $SiteName -Filter 'system.webServer/security/authentication/anonymousAuthentication' -Name userName -Value ''
Set-WebConfigurationProperty -PSPath $apphost -Location $SiteName -Filter 'system.webServer/serverRuntime' -Name uploadReadAheadSize -Value 131072
if ($certificatePortal) { Write-Info 'SSL required, client certificates accepted on the whole site (Certificate portal mode), upload read-ahead 128 KiB, anonymous identity = pool.' }
else { Write-Info 'SSL required; client certificates are requested only on api.aspx (portal pages show no certificate prompt); upload read-ahead 128 KiB, anonymous identity = pool.' }

Write-Step 'Setting file permissions'
& icacls.exe $TargetDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' ($poolIdentity + ':(OI)(CI)RX') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to set permissions on the website directory.' }
& icacls.exe (Join-Path $TargetDirectory 'App_Data\Vault') /grant ($poolIdentity + ':(OI)(CI)M') | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Unable to set permissions on App_Data\Vault.' }
Write-Info "${poolIdentity}: read on the site, modify on App_Data\Vault only."

# ---- Certificates -------------------------------------------------------------------------------
Write-Step 'Preparing the SLAPS CA and recovery certificate'
$created = @()
$ca = Find-MachineCertificate (Get-AppSetting $existingConfig 'IssuingCaSha256')
if (-not $ca) {
    $ca = New-SelfSignedCertificate -Subject ('CN=SLAPS CA ' + $HostName) -CertStoreLocation 'Cert:\LocalMachine\My' -Type Custom -KeyAlgorithm RSA -KeyLength 4096 `
        -HashAlgorithm SHA256 -Provider 'Microsoft Software Key Storage Provider' -KeyExportPolicy Exportable -KeyUsage CertSign, CRLSign, DigitalSignature `
        -NotAfter (Get-Date).AddYears(35) -TextExtension @('2.5.29.19={critical}{text}ca=true&pathlength=0')
    $created += $ca
    Write-Info "Created SLAPS CA (35 years): $($ca.Thumbprint)."
} else { Write-Info "Using existing SLAPS CA $($ca.Thumbprint)." }
$caSha = Get-Sha256 $ca.RawData

$recoveryList = @((Get-AppSetting $existingConfig 'RecoveryCertificateSha256') -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$recovery = if ($recoveryList.Count -gt 0) { Find-MachineCertificate $recoveryList[0] } else { $null }
if (-not $recovery) {
    $recovery = New-SelfSignedCertificate -Subject ('CN=SLAPS Recovery ' + $HostName) -CertStoreLocation 'Cert:\LocalMachine\My' -Type Custom -KeyAlgorithm RSA -KeyLength 4096 `
        -HashAlgorithm SHA256 -Provider 'Microsoft Software Key Storage Provider' -KeyExportPolicy Exportable -KeyUsage KeyEncipherment `
        -NotAfter (Get-Date).AddYears(30) -TextExtension @('2.5.29.19={text}')
    $created += $recovery
    Write-Info "Created recovery certificate (30 years): $($recovery.Thumbprint)."
} else { Write-Info "Using existing recovery certificate $($recovery.Thumbprint)." }
$recoverySha = Get-Sha256 $recovery.RawData
$recoveryList = @($recoverySha) + @($recoveryList | Where-Object { $_ -ne $recoverySha })

if ($created.Count -gt 0) {
    Write-Step 'Backing up new private keys and locking them (non-exportable)'
    if (-not $KeyBackupDirectory) { $KeyBackupDirectory = Join-Path ([Environment]::GetFolderPath('MyDocuments')) ('SLAPS-KeyBackup-' + $stamp) }
    $backupPassword = Read-Host 'Password for the key backup PFX files (Enter = skip, not recommended)' -AsSecureString
    if ($backupPassword.Length -gt 0) {
        New-Item -ItemType Directory -Path $KeyBackupDirectory -Force | Out-Null
        & icacls.exe $KeyBackupDirectory /inheritance:r /grant:r ('*' + [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value + ':(OI)(CI)F') '*S-1-5-18:(OI)(CI)F' | Out-Null
        foreach ($certificate in $created) {
            $isCa = $certificate.Thumbprint -eq $ca.Thumbprint
            $name = if ($isCa) { 'slaps-ca' } else { 'slaps-recovery' }
            $pfxPath = Join-Path $KeyBackupDirectory ($name + '.pfx')
            Export-PfxCertificate -Cert $certificate -FilePath $pfxPath -Password $backupPassword | Out-Null
            Export-Certificate -Cert $certificate -FilePath (Join-Path $KeyBackupDirectory ($name + '.cer')) | Out-Null
            $locked = Protect-BackedUpKey $certificate $pfxPath $backupPassword
            if ($isCa) { $ca = $locked } else { $recovery = $locked }
        }
        Write-Info "Backup saved to $KeyBackupDirectory. Move these files and the password to an offline safe, then delete the folder."
        Write-Info 'The keys on this server were re-imported as non-exportable.'
    } else {
        Write-Warning 'No key backup was written, so the new keys stay exportable. Without a backup of the recovery key, stored passwords are lost with this server. Export it with certlm.msc, then re-import the PFX without "Mark this key as exportable".'
    }
}
foreach ($certificate in @($ca, $recovery)) {
    if (Test-KeyExportable $certificate) { Write-Warning "The private key of $($certificate.Subject) is exportable. After an offline backup, re-import it as non-exportable (see README, Key protection)." }
}

[void](Grant-PrivateKeyRead $ca $poolIdentity)
if (-not (Grant-PrivateKeyRead $recovery $poolIdentity)) { Write-Warning 'The recovery key is not a CNG key; web decryption (RSA-OAEP-SHA256) may fail.' }
foreach ($missing in @($recoveryList | Select-Object -Skip 1 | Where-Object { -not (Find-MachineCertificate $_) })) { Write-Warning "Historical recovery certificate $missing is not in LocalMachine\My; its versions cannot be revealed on the web." }

$root = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
$root.Open('ReadWrite')
try {
    if (-not ($root.Certificates | Where-Object { $_.Thumbprint -eq $ca.Thumbprint })) {
        $root.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$ca.RawData)))
        Write-Info 'SLAPS CA added to Trusted Root Certification Authorities (this server only).'
    }
} finally { $root.Close() }

if (-not ('StandaloneLapsWeb.SlapsCertificateAuthority' -as [type])) {
    Add-Type -Path (Join-Path $websiteSource 'App_Code\SlapsCertificateAuthority.cs') -ReferencedAssemblies 'System.Core'
}
$crlPath = Join-Path $TargetDirectory 'App_Data\slaps-ca.crl'
$crl = [StandaloneLapsWeb.SlapsCertificateAuthority]::BuildCrl($ca, [long](Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss'), [DateTimeOffset]::UtcNow.AddHours(-1), ([DateTimeOffset]$ca.NotAfter.ToUniversalTime()).AddDays(-1))
[System.IO.File]::WriteAllBytes($crlPath, $crl)
& certutil.exe -f -addstore CA $crlPath | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Importing the SLAPS CA CRL into LocalMachine\CA failed.' }
Write-Info 'CRL (valid until the CA expires) imported into Intermediate Certification Authorities, so agent certificates validate offline.'

# ---- web.config ---------------------------------------------------------------------------------
Write-Step 'Writing web.config'
$config = [xml](Get-Content -LiteralPath (Join-Path $websiteSource 'web.config') -Raw)
if ($existingConfig) {
    foreach ($node in @($config.configuration.appSettings.add)) {
        $old = $existingConfig.configuration.appSettings.add | Where-Object { $_.key -eq $node.key } | Select-Object -First 1
        if ($old) { $node.SetAttribute('value', $old.value) }
    }
    $oldKey = $existingConfig.SelectSingleNode('/configuration/system.web/machineKey')
    if ($oldKey) { [void]$config.configuration.'system.web'.AppendChild($config.ImportNode($oldKey, $true)) }
}
if (-not $TenantId) { $TenantId = Get-AppSetting $existingConfig 'EntraTenantId' }
if (-not $ClientId) { $ClientId = Get-AppSetting $existingConfig 'EntraClientId' }
if (-not $PortalAllowedNetworks) { $PortalAllowedNetworks = Get-AppSetting $existingConfig 'PortalAllowedNetworks' }
$parsed = [guid]::Empty
while (-not [guid]::TryParse($TenantId, [ref]$parsed) -or $parsed -eq [guid]::Empty) { $TenantId = Read-Host 'Microsoft Entra tenant ID (Directory ID, GUID)' }
$TenantId = $parsed.ToString('D')
while (-not [guid]::TryParse($ClientId, [ref]$parsed) -or $parsed -eq [guid]::Empty) { $ClientId = Read-Host 'Entra application (client) ID of the SLAPS app registration (GUID)' }
$ClientId = $parsed.ToString('D')
while (-not (Test-CidrList $PortalAllowedNetworks)) { $PortalAllowedNetworks = Read-Host 'Internal networks allowed to open the portal (CIDR, separated by ;) e.g. 10.10.0.0/16;192.168.20.0/24' }
$PortalAllowedNetworks = (@($PortalAllowedNetworks -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) -join ';')

Set-AppSetting $config 'VaultDataDirectory' '~/App_Data/Vault'
Set-AppSetting $config 'PublicBaseUrl' ('https://' + $HostName + '/')
Set-AppSetting $config 'PortalAuthMode' $(if ((Get-AppSetting $config 'PortalAuthMode') -eq 'Certificate') { 'Certificate' } else { 'Entra' })
Set-AppSetting $config 'EntraTenantId' $TenantId
Set-AppSetting $config 'EntraClientId' $ClientId
Set-AppSetting $config 'PortalAllowedNetworks' $PortalAllowedNetworks
Set-AppSetting $config 'IssuingCaSha256' $caSha
Set-AppSetting $config 'CrlDistributionUrl' ('http://' + $HostName + '/slaps-ca.crl')
Set-AppSetting $config 'EnableWebDecryption' 'true'
Set-AppSetting $config 'RecoveryCertificateSha256' ($recoveryList -join ';')
if (-not $config.SelectSingleNode('/configuration/system.web/machineKey')) {
    $machineKey = $config.CreateElement('machineKey')
    $machineKey.SetAttribute('validation', 'HMACSHA256'); $machineKey.SetAttribute('decryption', 'AES')
    $machineKey.SetAttribute('validationKey', (New-HexKey 64)); $machineKey.SetAttribute('decryptionKey', (New-HexKey 32))
    [void]$config.configuration.'system.web'.AppendChild($machineKey)
    Write-Info 'Generated a machine key for sign-in cookies.'
}
$settingsWriter = New-Object System.Xml.XmlWriterSettings
$settingsWriter.Indent = $true; $settingsWriter.Encoding = New-Object System.Text.UTF8Encoding($false)
$writer = [System.Xml.XmlWriter]::Create((Join-Path $TargetDirectory 'web.config'), $settingsWriter)
try { $config.Save($writer) } finally { $writer.Dispose() }
Write-Info 'Entra sign-in, internal networks, URLs, CA and recovery fingerprints written.'

# ---- Start and smoke test -----------------------------------------------------------------------
Write-Step 'Starting the website'
if ((Get-WebAppPoolState -Name $AppPoolName).Value -ne 'Started') { Start-WebAppPool -Name $AppPoolName } else { Restart-WebAppPool -Name $AppPoolName }
if ((Get-WebsiteState -Name $SiteName).Value -ne 'Started') { Start-Website -Name $SiteName }
Start-Sleep -Seconds 2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
try {
    $status = [int](Invoke-WebRequest -Uri ('https://' + $HostName + '/api.aspx') -UseBasicParsing -MaximumRedirection 0 -TimeoutSec 60).StatusCode
} catch {
    $status = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { $_.Exception.Message }
}
if ($status -eq 403) { Write-Info 'Smoke test: the agent API answers 403 without a client certificate, as expected.' }
else { Write-Warning "Smoke test returned '$status' instead of 403. Check DNS for $HostName on this server, the IIS logs and the Application event log." }

Write-Host ''
Write-Host 'SLAPS server is installed.' -ForegroundColor Green
Write-Info "Portal (internal):  https://$HostName/   allowed from $PortalAllowedNetworks"
Write-Info "Agent API:          https://$HostName/api.aspx   (client certificates; open TCP 443 from the DMZ)"
Write-Info "Entra redirect URI: https://$HostName/signin.aspx   (Web platform, ID tokens enabled)"
Write-Info "App roles:          SLAPS.Admin, SLAPS.Reader   (enterprise app: Assignment required = Yes)"
Write-Info "SLAPS CA SHA-256:   $caSha"
Write-Info "Recovery SHA-256:   $recoverySha"
Write-Info 'Next: sign in as an assigned SLAPS.Admin and use "Add client" to create agent packages.'
