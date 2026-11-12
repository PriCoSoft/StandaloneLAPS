using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Hosting;

namespace StandaloneLapsWeb
{
    public sealed class PackageInfo
    {
        public string token { get; set; }
        public string deviceId { get; set; }
        public string displayName { get; set; }
        public string fileName { get; set; }
        public string createdUtc { get; set; }
        public string expiresUtc { get; set; }
        public string createdBy { get; set; }
        public string platform { get; set; }
    }

    public sealed class PackageResult
    {
        public IssuedClient Client;
        public PackageInfo Package;
    }

    // "Add client": issues an agent certificate from the server's SLAPS CA and builds a ZIP that installs
    // the agent with all settings predefined. The PFX password is never stored; it is shown once in the portal.
    public static class ClientPackages
    {
        public static readonly TimeSpan Lifetime = TimeSpan.FromHours(24);
        public static readonly string[] AgentFiles = { "StandaloneLaps.Agent.exe", "StandaloneLaps.Agent.exe.config", "Install-SlapsAgent.ps1" };
        // Linux agent files in App_Data\AgentPackage\linux (copied by the server installer from the package's linux folder).
        public static readonly string[] LinuxAgentFiles = { "slaps-agent", "slaps-agent.service", "agent.conf", "install.sh", "slaps-agent.deb" };
        public const string Windows = "windows", Linux = "linux";
        private static readonly Regex TokenPattern = new Regex("^[0-9a-f]{32}$", RegexOptions.CultureInvariant);

        public static string AgentFilesDirectory
        {
            get { return HostingEnvironment.IsHosted ? HostingEnvironment.MapPath("~/App_Data/AgentPackage") : Vault.Setting("AgentPackageDirectory"); }
        }

        public static string PackagesDirectory { get { return Vault.VaultPath("_packages"); } }

        public static X509Certificate2 FindMachineCertificate(string sha256, bool requirePrivateKey)
        {
            if (string.IsNullOrEmpty(sha256)) return null;
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                return store.Certificates.Cast<X509Certificate2>().FirstOrDefault(c => string.Equals(Vault.Hash(c), sha256, StringComparison.OrdinalIgnoreCase) && (!requirePrivateKey || c.HasPrivateKey));
            }
        }

        // The first RecoveryCertificateSha256 entry is the current recipient for new agents.
        public static byte[] CurrentRecoveryCertificate()
        {
            var current = Vault.List(Vault.Setting("RecoveryCertificateSha256")).FirstOrDefault();
            var certificate = FindMachineCertificate(current, false);
            if (certificate == null) throw new InvalidOperationException("The recovery certificate configured in RecoveryCertificateSha256 is not in the LocalMachine\\My store.");
            return certificate.RawData;
        }

        public static PackageResult Create(string displayName, Guid? existingDevice, string actor)
        {
            return Create(displayName, existingDevice, actor, Windows);
        }

        public static PackageResult Create(string displayName, Guid? existingDevice, string actor, string platform)
        {
            if (platform != Windows && platform != Linux) throw new ArgumentException("Choose Windows or Linux.");
            var agentDirectory = AgentFilesDirectory;
            if (string.IsNullOrEmpty(agentDirectory) || AgentFiles.Any(name => !File.Exists(Path.Combine(agentDirectory, name))))
                throw new InvalidOperationException("The agent package files are missing in App_Data\\AgentPackage. Rerun the server installer.");
            if (platform == Linux && LinuxAgentFiles.Any(name => !File.Exists(Path.Combine(agentDirectory, "linux", name))))
                throw new InvalidOperationException("The Linux agent files are missing in App_Data\\AgentPackage\\linux. Rerun the server installer of version 1.3.0 or later.");
            var ca = FindMachineCertificate(Vault.Setting("IssuingCaSha256"), true);
            if (ca == null) throw new InvalidOperationException("The SLAPS CA configured in IssuingCaSha256 is not available with its private key.");
            var recovery = CurrentRecoveryCertificate();
            var device = existingDevice ?? Guid.NewGuid();
            var issued = SlapsCertificateAuthority.IssueClient(ca, displayName, device, Vault.Setting("CrlDistributionUrl"), DateTimeOffset.UtcNow);
            var zip = platform == Linux ? BuildLinux(issued, PortalAuth.PublicBaseUrl, recovery, Path.Combine(agentDirectory, "linux"))
                : Build(issued, PortalAuth.PublicBaseUrl, recovery, agentDirectory);
            var package = Store(zip, issued, actor, platform);
            try
            {
                Vault.RegisterManagedClient(new Client
                {
                    role = "agent", deviceId = issued.DeviceId, displayName = issued.DisplayName, certificateSha256 = issued.CertificateSha256,
                    createdUtc = DateTimeOffset.UtcNow.ToString("O"), createdBy = actor
                }, existingDevice.HasValue, actor);
            }
            catch { Delete(package.token); throw; }
            return new PackageResult { Client = issued, Package = package };
        }

        private static byte[] SettingsJson(IssuedClient issued, string apiUrl, byte[] recoveryCertificate)
        {
            var settings = new Dictionary<string, object>
            {
                { "deviceId", issued.DeviceId }, { "displayName", issued.DisplayName }, { "apiUrl", apiUrl },
                { "clientCertificateSha256", issued.CertificateSha256 }, { "recoveryCertificateSha256", SlapsCertificateAuthority.Sha256(recoveryCertificate) },
                { "certificateValidUntilUtc", issued.NotAfterUtc.ToString("O") }, { "packageVersion", 1 }
            };
            return Encoding.UTF8.GetBytes(Vault.Json.Serialize(settings));
        }

        // Linux: install.sh installs the .deb (Debian/Ubuntu) or copies the files (other systemd distributions),
        // then enrolls with agent.pfx, recovery.cer and slaps-settings.json.
        public static byte[] BuildLinux(IssuedClient issued, string apiUrl, byte[] recoveryCertificate, string linuxDirectory)
        {
            var folder = FolderName(issued.DisplayName) + "-linux";
            using (var buffer = new MemoryStream())
            {
                using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, true))
                {
                    Add(zip, folder + "/slaps-settings.json", SettingsJson(issued, apiUrl, recoveryCertificate));
                    Add(zip, folder + "/agent.pfx", issued.Pfx);
                    Add(zip, folder + "/recovery.cer", recoveryCertificate);
                    foreach (var name in LinuxAgentFiles.Where(n => n != "slaps-agent.deb"))
                        Add(zip, folder + "/" + name, File.ReadAllBytes(Path.Combine(linuxDirectory, name)));
                    Add(zip, folder + "/slaps-agent_" + AppVersion.Number + "_all.deb", File.ReadAllBytes(Path.Combine(linuxDirectory, "slaps-agent.deb")));
                    Add(zip, folder + "/README.txt", Encoding.UTF8.GetBytes(LinuxReadme(issued, apiUrl)));
                }
                return buffer.ToArray();
            }
        }

        public static byte[] Build(IssuedClient issued, string apiUrl, byte[] recoveryCertificate, string agentDirectory)
        {
            var folder = FolderName(issued.DisplayName);
            using (var buffer = new MemoryStream())
            {
                using (var zip = new ZipArchive(buffer, ZipArchiveMode.Create, true))
                {
                    Add(zip, folder + "/slaps-settings.json", SettingsJson(issued, apiUrl, recoveryCertificate));
                    Add(zip, folder + "/agent.pfx", issued.Pfx);
                    Add(zip, folder + "/recovery.cer", recoveryCertificate);
                    Add(zip, folder + "/bin/StandaloneLaps.Agent.exe", File.ReadAllBytes(Path.Combine(agentDirectory, "StandaloneLaps.Agent.exe")));
                    Add(zip, folder + "/bin/StandaloneLaps.Agent.exe.config", File.ReadAllBytes(Path.Combine(agentDirectory, "StandaloneLaps.Agent.exe.config")));
                    Add(zip, folder + "/Install-SlapsAgent.ps1", File.ReadAllBytes(Path.Combine(agentDirectory, "Install-SlapsAgent.ps1")));
                    Add(zip, folder + "/Install.cmd", Encoding.ASCII.GetBytes(InstallCommand));
                    Add(zip, folder + "/README.txt", Encoding.UTF8.GetBytes(Readme(issued, apiUrl)));
                }
                return buffer.ToArray();
            }
        }

        public static string FolderName(string displayName) { return "SLAPS-Agent-" + displayName.Replace(' ', '-'); }

        public static PackageInfo Store(byte[] zip, IssuedClient issued, string actor)
        {
            return Store(zip, issued, actor, Windows);
        }

        public static PackageInfo Store(byte[] zip, IssuedClient issued, string actor, string platform)
        {
            Cleanup();
            var bytes = new byte[16];
            using (var random = RandomNumberGenerator.Create()) random.GetBytes(bytes);
            var now = DateTimeOffset.UtcNow;
            var info = new PackageInfo
            {
                token = BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant(), deviceId = issued.DeviceId, displayName = issued.DisplayName,
                fileName = FolderName(issued.DisplayName) + (platform == Linux ? "-linux" : "") + ".zip", createdUtc = now.ToString("O"),
                expiresUtc = now.Add(Lifetime).ToString("O"), createdBy = actor, platform = platform
            };
            Directory.CreateDirectory(PackagesDirectory);
            File.WriteAllBytes(Path.Combine(PackagesDirectory, info.token + ".zip"), zip);
            File.WriteAllText(Path.Combine(PackagesDirectory, info.token + ".json"), Vault.Json.Serialize(info));
            return info;
        }

        public static PackageInfo Find(string token)
        {
            if (token == null || !TokenPattern.IsMatch(token)) return null;
            var metadata = Path.Combine(PackagesDirectory, token + ".json");
            if (!File.Exists(metadata) || !File.Exists(ZipPath(token))) return null;
            var info = Vault.Json.Deserialize<PackageInfo>(File.ReadAllText(metadata));
            if (info == null || info.token != token || Vault.Timestamp(info.expiresUtc) <= DateTimeOffset.UtcNow) return null;
            return info;
        }

        public static string ZipPath(string token)
        {
            if (token == null || !TokenPattern.IsMatch(token)) throw new ArgumentException("Invalid package token.");
            return Path.Combine(PackagesDirectory, token + ".zip");
        }

        public static void Delete(string token)
        {
            if (token == null || !TokenPattern.IsMatch(token)) return;
            foreach (var extension in new[] { ".zip", ".json" })
            {
                var path = Path.Combine(PackagesDirectory, token + extension);
                if (File.Exists(path)) File.Delete(path);
            }
        }

        public static void Cleanup()
        {
            if (!Directory.Exists(PackagesDirectory)) return;
            foreach (var metadata in Directory.EnumerateFiles(PackagesDirectory, "*.json").ToArray())
            {
                var token = Path.GetFileNameWithoutExtension(metadata);
                PackageInfo info = null;
                try { info = Vault.Json.Deserialize<PackageInfo>(File.ReadAllText(metadata)); } catch (ArgumentException) { } catch (InvalidOperationException) { }
                if (info == null || Vault.Timestamp(info.expiresUtc) <= DateTimeOffset.UtcNow) Delete(token);
            }
        }

        private static void Add(ZipArchive zip, string name, byte[] content)
        {
            var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
            using (var stream = entry.Open()) stream.Write(content, 0, content.Length);
        }

        private const string InstallCommand =
            "@echo off\r\n" +
            "rem Installs or upgrades the SLAPS agent with the predefined settings. Run as administrator.\r\n" +
            "rem Optional parameters are passed to Install-SlapsAgent.ps1, for example: Install.cmd -NoStart\r\n" +
            "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%~dp0Install-SlapsAgent.ps1\" %*\r\n" +
            "if \"%~1\"==\"\" pause\r\n";

        private static string LinuxReadme(IssuedClient issued, string apiUrl)
        {
            return "SLAPS Linux agent package for " + issued.DisplayName + "\n\n" +
                "Device ID:            " + issued.DeviceId + "\n" +
                "API URL:              " + apiUrl + "\n" +
                "Client certificate:   " + issued.CertificateSha256 + " (valid until " + issued.NotAfterUtc.ToString("yyyy-MM-dd") + " UTC)\n\n" +
                "Requirements: systemd, python3 (3.6+), openssl, chpasswd. Debian/Ubuntu use the included .deb;\n" +
                "other distributions (RHEL, SUSE, ...) get the same files installed directly.\n\n" +
                "Install:\n" +
                "  1. Copy the ZIP to the server and extract it, e.g.: python3 -m zipfile -e <package>.zip .\n" +
                "  2. cd into the folder and run: sudo sh install.sh\n" +
                "  3. Enter the PFX password that the SLAPS portal displayed once when the package was created.\n" +
                "  4. Delete the folder and the ZIP afterwards: agent.pfx contains the agent's private key.\n\n" +
                "Options: sudo sh install.sh [--api-url <url>] [--no-start] [--skip-connectivity-test]\n" +
                "Remove:  sudo sh install.sh --uninstall [--purge]\n\n" +
                "Password rules: /etc/slaps/agent.conf (Account=root, PasswordLength=14, PasswordComplexity=4, PasswordAgeDays=30).\n" +
                "Commands: slaps-agent validate-config | test-connection | rotate-now; log: journalctl -u slaps-agent\n" +
                "The server's TLS certificate must be trusted (system trust store or CaFile in agent.conf).\n";
        }

        private static string Readme(IssuedClient issued, string apiUrl)
        {
            return "SLAPS agent package for " + issued.DisplayName + "\r\n\r\n" +
                "Device ID:            " + issued.DeviceId + "\r\n" +
                "API URL:              " + apiUrl + "\r\n" +
                "Client certificate:   " + issued.CertificateSha256 + " (valid until " + issued.NotAfterUtc.ToString("yyyy-MM-dd") + " UTC)\r\n\r\n" +
                "Install:\r\n" +
                "  1. Copy this folder to the server and right-click Install.cmd > Run as administrator.\r\n" +
                "  2. Enter the PFX password that the SLAPS portal displayed once when the package was created.\r\n" +
                "  3. Delete this folder afterwards: agent.pfx contains the agent's private key.\r\n\r\n" +
                "Options (PowerShell): .\\Install-SlapsAgent.ps1 [-ApiUrl <url>] [-InstallDirectory <path>] [-NoStart] [-SkipConnectivityTest]\r\n" +
                "Remove:              .\\Install-SlapsAgent.ps1 -Uninstall\r\n\r\n" +
                "Password rules are controlled by local policy: gpedit.msc > Computer Configuration > Administrative Templates > System > LAPS.\r\n" +
                "BackupDirectory must stay Disabled; the agent backs up to the SLAPS server instead.\r\n";
        }
    }
}
