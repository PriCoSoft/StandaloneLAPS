# Run the managed test library in the actual .NET Framework CLR, independent of PowerShell 7/.NET.
param([Parameter(Mandatory)][string]$AssemblyPath, [Parameter(Mandatory)][string]$FixtureDirectory, [string]$RunnerType = 'TestDomainRunner', [string]$DataDirectory)
$ErrorActionPreference = 'Stop'
[System.Reflection.Assembly]::LoadFrom($AssemblyPath) | Out-Null
$configPath = $AssemblyPath + '.config'
$document = New-Object System.Xml.XmlDocument
$configuration = $document.CreateElement('configuration')
$appSettings = $document.CreateElement('appSettings')
$entry = $document.CreateElement('add')
$entry.SetAttribute('key', 'VaultDataDirectory')
if (-not $DataDirectory) { $DataDirectory = Join-Path $FixtureDirectory 'vault' }
$entry.SetAttribute('value', $DataDirectory)
$appSettings.AppendChild($entry) | Out-Null
# Windows LAPS Entra setup tests (FrameworkWindowsLapsTests): fixed test IDs, no network access (fake transport).
foreach ($pair in @(@('WindowsLapsEntraTenantId', '11111111-2222-3333-4444-555555555555'), @('WindowsLapsEntraClientId', 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'))) {
    $extra = $document.CreateElement('add'); $extra.SetAttribute('key', $pair[0]); $extra.SetAttribute('value', $pair[1]); $appSettings.AppendChild($extra) | Out-Null
}
$configuration.AppendChild($appSettings) | Out-Null
$document.AppendChild($configuration) | Out-Null
$document.Save($configPath)
$setup = New-Object System.AppDomainSetup
$setup.ApplicationBase = Split-Path -Parent $AssemblyPath
$setup.ConfigurationFile = $configPath
$setup.TargetFrameworkName = '.NETFramework,Version=v4.7.2'
$domain = [AppDomain]::CreateDomain('StandaloneLaps-FrameworkTests', $null, $setup)
try {
    $runner = $domain.CreateInstanceFromAndUnwrap($AssemblyPath, $RunnerType)
    $result = $runner.Run($FixtureDirectory)
} finally { [AppDomain]::Unload($domain) }
exit $result
