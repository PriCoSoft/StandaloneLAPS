[CmdletBinding()]
param([ValidateRange(1024,65535)][int]$Port = 57843)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$iis = Join-Path $env:ProgramFiles 'IIS Express\iisexpress.exe'
if (-not (Test-Path -LiteralPath $iis)) { throw 'IIS Express was not found.' }
$run = Join-Path $root ('artifacts\preview\' + [guid]::NewGuid().ToString('N').Substring(0,8))
$site = Join-Path $run 'site'
New-Item -ItemType Directory -Path $run -Force | Out-Null
Copy-Item -LiteralPath (Join-Path $root 'web\IisVault') -Destination $site -Recurse
$sourcePath = Join-Path $site 'App_Code\PortalAuth.cs'
$source = [IO.File]::ReadAllText($sourcePath)
$start = $source.IndexOf('        // PREVIEW-AUTH-BEGIN')
$end = $source.IndexOf('        // PREVIEW-AUTH-END', $start)
if ($start -lt 0 -or $end -lt 0) { throw 'Preview isolation patch did not match the expected source.' }
$previewAuth = @'
        public static PortalIdentity Current(HttpRequest request)
        {
            if (!request.IsLocal) return null;
            return new PortalIdentity { Actor = "preview:local", DisplayName = "Local preview - synthetic data", Role = "admin" };
        }
'@
[IO.File]::WriteAllText($sourcePath, $source.Substring(0,$start) + $previewAuth + $source.Substring($end))
$globalPath = Join-Path $site 'Global.asax'
[IO.File]::WriteAllText($globalPath, [IO.File]::ReadAllText($globalPath).Replace('if (!Request.IsSecureConnection)', 'if (!Request.IsLocal)'))
$pagePath = Join-Path $site 'Default.aspx'
[IO.File]::WriteAllText($pagePath, [IO.File]::ReadAllText($pagePath).Replace('<p class="eyebrow">ADMINISTRATOR RECOVERY</p>', '<p class="eyebrow">LOCAL PREVIEW · SYNTHETIC DATA</p>'))
$webConfigPath = Join-Path $site 'web.config'
$webConfig = [xml](Get-Content -LiteralPath $webConfigPath -Raw)
($webConfig.configuration.appSettings.add | Where-Object { $_.key -eq 'VaultDataDirectory' }).value = '~/App_Data/Vault'
($webConfig.configuration.appSettings.add | Where-Object { $_.key -eq 'PortalAuthMode' }).value = 'Preview'
($webConfig.configuration.appSettings.add | Where-Object { $_.key -eq 'PortalAllowedNetworks' }).value = '127.0.0.1/32;::1/128'
# Only the isolated loopback preview uses HTTP. Shipping source keeps HTTPS and secure cookies required.
$webConfig.configuration.'system.web'.httpCookies.requireSSL = 'false'
$webConfig.Save($webConfigPath)
$compiler = Join-Path $env:windir 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$support = Join-Path $run 'PreviewSupport.dll'
$sources = @(Get-ChildItem -LiteralPath (Join-Path $root 'web\IisVault\App_Code') -Filter '*.cs' -File | ForEach-Object { $_.FullName })
$sources += (Join-Path $root 'tests\PreviewData.cs')
& $compiler /nologo /target:library /langversion:5 "/out:$support" /reference:System.Web.dll /reference:System.Web.Extensions.dll /reference:System.Configuration.dll /reference:System.Core.dll /reference:System.Runtime.Serialization.dll /reference:System.IO.Compression.dll $sources
if ($LASTEXITCODE -ne 0) { throw 'Preview data helper compilation failed.' }
& (Join-Path $env:windir 'System32\WindowsPowerShell\v1.0\powershell.exe') -NoProfile -File (Join-Path $PSScriptRoot 'Run-FrameworkTests.ps1') -AssemblyPath $support -FixtureDirectory $run -RunnerType PreviewSeedRunner -DataDirectory (Join-Path $site 'App_Data\Vault')
if ($LASTEXITCODE -ne 0) { throw 'Preview data generation failed.' }
$config = [xml](Get-Content -LiteralPath (Join-Path (Split-Path -Parent $iis) 'AppServer\applicationhost.config') -Raw)
$sites = $config.configuration.'system.applicationHost'.sites
$sites.site.name = 'LapsPreview'
$sites.site.application.virtualDirectory.physicalPath = $site
$sites.site.bindings.binding.bindingInformation = ':' + $Port + ':localhost'
$sites.siteDefaults.logFile.directory = Join-Path $run 'logs'
$sites.siteDefaults.traceFailedRequestsLogging.directory = Join-Path $run 'logs'
$configPath = Join-Path $run 'applicationhost.config'
$config.Save($configPath)
$process = Start-Process -FilePath $iis -ArgumentList @(('/config:"' + $configPath + '"'), '/site:LapsPreview', '/systray:false') -WindowStyle Hidden -RedirectStandardOutput (Join-Path $run 'iis.stdout.log') -RedirectStandardError (Join-Path $run 'iis.stderr.log') -PassThru
$url = 'http://localhost:' + $Port + '/?device=2b0c7224-6121-4181-9dbc-65be629c6069'
$manifest = [pscustomobject]@{ ProcessId = $process.Id; Url = $url; Directory = $run; Config = $configPath; SyntheticDataOnly = $true }
$manifest | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $run 'preview.json') -Encoding UTF8
$manifest
