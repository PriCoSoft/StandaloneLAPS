using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using StandaloneLapsWeb;

namespace StandaloneLaps.Server;

public sealed class PackageResult
{
    public IssuedClient Client;
    public PackageInfo Package;
}

// "Add client": issues an agent certificate and builds the same ZIP layout as the IIS backend, so the unchanged
// Windows installer (Install-SlapsAgent.ps1) and Linux install.sh work against the container.
public sealed class ClientPackages
{
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(24);
    public static readonly string[] AgentFiles = { "StandaloneLaps.Agent.exe", "StandaloneLaps.Agent.exe.config", "Install-SlapsAgent.ps1" };
    public static readonly string[] LinuxAgentFiles = { "slaps-agent", "slaps-agent.service", "agent.conf", "install.sh", "slaps-agent.deb" };
    public const string Windows = "windows", Linux = "linux";
    private readonly VaultStore store;
    private readonly KeyVault keys;
    private readonly ServerOptions options;

    public ClientPackages(VaultStore store, KeyVault keys, ServerOptions options)
    {
        this.store = store;
        this.keys = keys;
        this.options = options;
    }

    public string AgentDirectory => options.AgentPackageDirectory;

    public string MissingFiles(string platform)
    {
        var missing = AgentFiles.Where(name => !File.Exists(Path.Combine(AgentDirectory, name))).ToList();
        if (platform == Linux) missing.AddRange(LinuxAgentFiles.Where(name => !File.Exists(Path.Combine(AgentDirectory, "linux", name))).Select(name => "linux/" + name));
        return missing.Count == 0 ? null : string.Join(", ", missing);
    }

    public string AgentVersion
    {
        get
        {
            var agent = Path.Combine(AgentDirectory, "StandaloneLaps.Agent.exe");
            if (!File.Exists(agent)) return "Agent files missing in " + AgentDirectory;
            var version = System.Diagnostics.FileVersionInfo.GetVersionInfo(agent).ProductVersion;
            return string.IsNullOrEmpty(version) ? "present (version unknown)" : version;
        }
    }

    public PackageResult Create(string displayName, Guid? existingDevice, string actor, string platform)
    {
        if (platform != Windows && platform != Linux) throw new ArgumentException("Choose Windows or Linux.");
        var missing = MissingFiles(platform);
        if (missing != null) throw new InvalidOperationException("Agent package files are missing in " + AgentDirectory + ": " + missing + ". Use the container image from the release package or mount the files there.");
        if (options.AgentApiUrl == null) throw new InvalidOperationException("Slaps:AgentApiUrl is not configured.");
        var device = existingDevice ?? Guid.NewGuid();
        var issued = keys.IssueClient(displayName, device, DateTimeOffset.UtcNow);
        var zip = platform == Linux ? BuildLinux(issued, options.AgentApiUrl, keys.Recovery.RawData, Path.Combine(AgentDirectory, "linux"))
            : Build(issued, options.AgentApiUrl, keys.Recovery.RawData, AgentDirectory);
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var now = DateTimeOffset.UtcNow;
        var info = new PackageInfo
        {
            Token = token, DeviceId = issued.DeviceId, DisplayName = issued.DisplayName, Platform = platform, CreatedBy = actor,
            FileName = FolderName(issued.DisplayName) + (platform == Linux ? "-linux" : "") + ".zip",
            CreatedUtc = now.ToString("O"), ExpiresUtc = now.Add(Lifetime).ToString("O")
        };
        store.StorePackage(info, zip);
        try
        {
            store.RegisterClient(new AgentClient
            {
                DeviceId = issued.DeviceId, DisplayName = issued.DisplayName, CertificateSha256 = issued.CertificateSha256, Platform = platform, CreatedUtc = Wire.Now(), CreatedBy = actor
            }, existingDevice.HasValue, actor);
        }
        catch { store.DeletePackage(token); throw; }
        return new PackageResult { Client = issued, Package = info };
    }

    private static byte[] SettingsJson(IssuedClient issued, string apiUrl, byte[] recoveryCertificate)
    {
        var settings = new Dictionary<string, object>
        {
            ["deviceId"] = issued.DeviceId, ["displayName"] = issued.DisplayName, ["apiUrl"] = apiUrl,
            ["clientCertificateSha256"] = issued.CertificateSha256, ["recoveryCertificateSha256"] = Wire.Sha256(recoveryCertificate),
            ["certificateValidUntilUtc"] = issued.NotAfterUtc.ToString("O"), ["packageVersion"] = 1
        };
        return JsonSerializer.SerializeToUtf8Bytes(settings);
    }

    public static byte[] BuildLinux(IssuedClient issued, string apiUrl, byte[] recoveryCertificate, string linuxDirectory)
    {
        var folder = FolderName(issued.DisplayName) + "-linux";
        using var buffer = new MemoryStream();
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

    public static byte[] Build(IssuedClient issued, string apiUrl, byte[] recoveryCertificate, string agentDirectory)
    {
        var folder = FolderName(issued.DisplayName);
        using var buffer = new MemoryStream();
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

    public static string FolderName(string displayName) => "SLAPS-Agent-" + displayName.Replace(' ', '-');

    private static void Add(ZipArchive zip, string name, byte[] content)
    {
        var entry = zip.CreateEntry(name, CompressionLevel.Optimal);
        using var stream = entry.Open();
        stream.Write(content, 0, content.Length);
    }

    private const string InstallCommand =
        "@echo off\r\n" +
        "rem Installs or upgrades the SLAPS agent with the predefined settings. Run as administrator.\r\n" +
        "rem Optional parameters are passed to Install-SlapsAgent.ps1, for example: Install.cmd -NoStart\r\n" +
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%~dp0Install-SlapsAgent.ps1\" %*\r\n" +
        "if \"%~1\"==\"\" pause\r\n";

    private static string LinuxReadme(IssuedClient issued, string apiUrl) =>
        "SLAPS Linux agent package for " + issued.DisplayName + "\n\n" +
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

    private static string Readme(IssuedClient issued, string apiUrl) =>
        "SLAPS agent package for " + issued.DisplayName + "\r\n\r\n" +
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
        "BackupDirectory must stay Disabled; the agent backs up to the SLAPS server instead.\r\n" +
        "The server's TLS certificate must be trusted by this server (LocalMachine certificate store).\r\n";
}
