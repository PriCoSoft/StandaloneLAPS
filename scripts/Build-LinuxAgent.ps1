[CmdletBinding()]
param([string]$OutputDirectory)
# Builds the Linux agent on Windows without Linux tools: artifacts\Agent-Linux\
#   slaps-agent, slaps-agent.service, agent.conf, install.sh (LF line endings, version stamped)
#   slaps-agent_<version>_all.deb (ar archive with control.tar.gz/data.tar.gz, root-owned, Unix modes)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $root 'artifacts\Agent-Linux' }
$source = Join-Path $root 'linux'
$version = [regex]::Match((Get-Content -LiteralPath (Join-Path $root 'web\IisVault\App_Code\AppVersion.cs') -Raw), 'Number\s*=\s*"([0-9.]+)"').Groups[1].Value
if (-not $version) { throw 'Version not found in AppVersion.cs.' }

if (-not ('SlapsDebBuilder' -as [type])) {
    Add-Type -Language CSharp -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

public sealed class SlapsTarEntry
{
    public string Path; public byte[] Content; public int Mode; public bool Directory;
}

public static class SlapsDebBuilder
{
    // POSIX ustar archive, owner root:root, then gzip.
    public static byte[] TarGz(IList<SlapsTarEntry> entries, long mtime)
    {
        using (var tar = new MemoryStream())
        {
            foreach (var entry in entries)
            {
                var content = entry.Directory ? new byte[0] : entry.Content;
                var name = Encoding.ASCII.GetBytes(entry.Path);
                if (name.Length > 99) throw new ArgumentException("Path too long for ustar: " + entry.Path);
                var header = new byte[512];
                Array.Copy(name, header, name.Length);
                Put(header, 100, Octal(entry.Mode, 7));
                Put(header, 108, Octal(0, 7));
                Put(header, 116, Octal(0, 7));
                Put(header, 124, Octal(content.Length, 11));
                Put(header, 136, Octal(mtime, 11));
                for (var i = 148; i < 156; i++) header[i] = 0x20;
                header[156] = (byte)(entry.Directory ? '5' : '0');
                Put(header, 257, "ustar\0");
                Put(header, 263, "00");
                Put(header, 265, "root");
                Put(header, 297, "root");
                long sum = 0;
                foreach (var b in header) sum += b;
                Put(header, 148, Convert.ToString(sum, 8).PadLeft(6, '0') + "\0 ");
                tar.Write(header, 0, 512);
                tar.Write(content, 0, content.Length);
                var padding = (512 - content.Length % 512) % 512;
                tar.Write(new byte[padding], 0, padding);
            }
            tar.Write(new byte[1024], 0, 1024);
            using (var output = new MemoryStream())
            {
                using (var gzip = new GZipStream(output, CompressionLevel.Optimal, true)) { var raw = tar.ToArray(); gzip.Write(raw, 0, raw.Length); }
                return output.ToArray();
            }
        }
    }

    // Debian binary package: "!<arch>" with debian-binary, control.tar.gz, data.tar.gz.
    public static byte[] Deb(byte[] control, byte[] data, long mtime)
    {
        using (var ar = new MemoryStream())
        {
            var magic = Encoding.ASCII.GetBytes("!<arch>\n");
            ar.Write(magic, 0, magic.Length);
            Member(ar, "debian-binary", Encoding.ASCII.GetBytes("2.0\n"), mtime);
            Member(ar, "control.tar.gz", control, mtime);
            Member(ar, "data.tar.gz", data, mtime);
            return ar.ToArray();
        }
    }

    private static void Member(Stream ar, string name, byte[] content, long mtime)
    {
        var header = name.PadRight(16) + mtime.ToString().PadRight(12) + "0".PadRight(6) + "0".PadRight(6) + "100644".PadRight(8) + content.Length.ToString().PadRight(10) + "`\n";
        var bytes = Encoding.ASCII.GetBytes(header);
        if (bytes.Length != 60) throw new InvalidOperationException("Invalid ar header.");
        ar.Write(bytes, 0, bytes.Length);
        ar.Write(content, 0, content.Length);
        if (content.Length % 2 == 1) ar.WriteByte((byte)'\n');
    }

    private static string Octal(long value, int digits) { return Convert.ToString(value, 8).PadLeft(digits, '0') + "\0"; }
    private static void Put(byte[] header, int offset, string value) { var bytes = Encoding.ASCII.GetBytes(value); Array.Copy(bytes, 0, header, offset, bytes.Length); }
}
'@
}

function Get-UnixText([string]$Path) {
    $text = [IO.File]::ReadAllText($Path).Replace("`r`n", "`n").Replace('@VERSION@', $version)
    if ($text.Contains("`r")) { throw "$Path contains carriage returns." }
    $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($text)
    return ,$bytes
}
function New-Entry([string]$Path, [int]$Mode, [byte[]]$Content, [switch]$Directory) {
    $entry = New-Object SlapsTarEntry
    $entry.Path = $Path; $entry.Mode = $Mode; $entry.Content = $Content; $entry.Directory = [bool]$Directory
    return $entry
}

$agent = Get-UnixText (Join-Path $source 'slaps-agent')
$unit = Get-UnixText (Join-Path $source 'slaps-agent.service')
$conf = Get-UnixText (Join-Path $source 'agent.conf')
$installer = Get-UnixText (Join-Path $source 'install.sh')
$mtime = [long]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())

$dataEntries = New-Object 'System.Collections.Generic.List[SlapsTarEntry]'
foreach ($dir in './', './etc/', './etc/slaps/', './lib/', './lib/systemd/', './lib/systemd/system/', './usr/', './usr/sbin/') { $dataEntries.Add((New-Entry $dir 493 $null -Directory)) }
$dataEntries.Add((New-Entry './etc/slaps/agent.conf' 420 $conf))
$dataEntries.Add((New-Entry './lib/systemd/system/slaps-agent.service' 420 $unit))
$dataEntries.Add((New-Entry './usr/sbin/slaps-agent' 493 $agent))

$md5 = [System.Security.Cryptography.MD5]::Create()
$sums = ''
foreach ($e in @($dataEntries | Where-Object { -not $_.Directory -and -not $_.Path.StartsWith('./etc/') })) {
    $sums += ([BitConverter]::ToString($md5.ComputeHash($e.Content)).Replace('-', '').ToLowerInvariant() + '  ' + $e.Path.Substring(2) + "`n")
}
$installedKb = [int][math]::Ceiling((($agent.Length + $unit.Length + $conf.Length) / 1024.0))
$control = [IO.File]::ReadAllText((Join-Path $source 'debian\control')).Replace("`r`n", "`n").Replace('@VERSION@', $version).Replace('@SIZE@', [string]$installedKb)
$utf8 = New-Object System.Text.UTF8Encoding($false)
$controlEntries = New-Object 'System.Collections.Generic.List[SlapsTarEntry]'
$controlEntries.Add((New-Entry './' 493 $null -Directory))
$controlEntries.Add((New-Entry './control' 420 $utf8.GetBytes($control)))
$controlEntries.Add((New-Entry './conffiles' 420 (Get-UnixText (Join-Path $source 'debian\conffiles'))))
$controlEntries.Add((New-Entry './md5sums' 420 $utf8.GetBytes($sums)))
foreach ($script in 'postinst', 'prerm', 'postrm') { $controlEntries.Add((New-Entry ('./' + $script) 493 (Get-UnixText (Join-Path $source ('debian\' + $script))))) }

$deb = [SlapsDebBuilder]::Deb([SlapsDebBuilder]::TarGz($controlEntries, $mtime), [SlapsDebBuilder]::TarGz($dataEntries, $mtime), $mtime)

if (Test-Path -LiteralPath $OutputDirectory) { Remove-Item -LiteralPath $OutputDirectory -Recurse -Force }
New-Item -ItemType Directory -Path $OutputDirectory | Out-Null
[IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'slaps-agent'), $agent)
[IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'slaps-agent.service'), $unit)
[IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'agent.conf'), $conf)
[IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'install.sh'), $installer)
$debName = 'slaps-agent_' + $version + '_all.deb'
[IO.File]::WriteAllBytes((Join-Path $OutputDirectory $debName), $deb)
Write-Host "Linux agent $version -> $OutputDirectory ($debName, $($deb.Length) bytes)"
