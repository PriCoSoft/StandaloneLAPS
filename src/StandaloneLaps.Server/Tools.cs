using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace StandaloneLaps.Server;

// Maintenance commands, run inside the container: docker compose exec slaps dotnet StandaloneLaps.Server.dll <command>
public static class Tools
{
    private static ServerOptions Options()
    {
        var configuration = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("appsettings.json", optional: true).AddEnvironmentVariables().Build();
        var options = ServerOptions.Load(configuration);
        if (string.IsNullOrEmpty(options.MasterKey) || options.MasterKey.Length < 32) throw new InvalidOperationException("SLAPS_MASTER_KEY (or SLAPS_MASTER_KEY_FILE) is required.");
        return options;
    }

    private static string Password(string variable)
    {
        var value = Environment.GetEnvironmentVariable(variable);
        var file = Environment.GetEnvironmentVariable(variable + "_FILE");
        if (string.IsNullOrEmpty(value) && !string.IsNullOrEmpty(file)) value = File.ReadAllText(file).Trim();
        if (string.IsNullOrEmpty(value) && !Console.IsInputRedirected)
        {
            Console.Write("PFX password: ");
            var chars = new List<char>();
            ConsoleKeyInfo key;
            while ((key = Console.ReadKey(true)).Key != ConsoleKey.Enter)
                if (key.Key == ConsoleKey.Backspace) { if (chars.Count > 0) chars.RemoveAt(chars.Count - 1); } else chars.Add(key.KeyChar);
            Console.WriteLine();
            value = new string(chars.ToArray());
        }
        if (string.IsNullOrEmpty(value)) throw new InvalidOperationException("Set " + variable + " (or " + variable + "_FILE) or run the command interactively (docker compose exec -it).");
        return value;
    }

    private static string Argument(string[] args, string name)
    {
        var index = Array.IndexOf(args, name);
        return index >= 0 && index + 1 < args.Length ? args[index + 1] : null;
    }

    public static async Task<int> Health(string[] args)
    {
        var port = Environment.GetEnvironmentVariable("Slaps__PortalPort") ?? "8443";
        using var handler = new HttpClientHandler { ServerCertificateCustomValidationCallback = (_, _, _, _) => true };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        try { return (await client.GetStringAsync("https://127.0.0.1:" + port + "/healthz")) == "ok" ? 0 : 1; }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) { Console.Error.WriteLine(ex.Message); return 1; }
    }

    // Writes the CA or recovery certificate with its private key as PFX (AES-256), e.g. for offline recovery with
    // the agent's "recover" command or Get-PasswordHistory.ps1. The password comes from SLAPS_EXPORT_PASSWORD or a prompt.
    public static int ExportKey(string[] args, string name)
    {
        if (args.Length < 1) throw new InvalidOperationException("Usage: export-" + (name == KeyVault.CaKey ? "ca" : "recovery") + "-key <file.pfx>");
        var options = Options();
        var store = new VaultStore(options);
        store.Initialize();
        using var keys = new KeyVault(store, options);
        keys.Initialize(loadTls: false);
        var password = Password("SLAPS_EXPORT_PASSWORD");
        if (password.Length < 16) throw new InvalidOperationException("Use an export password with at least 16 characters.");
        var certificate = name == KeyVault.CaKey ? keys.Ca : keys.Recovery;
        File.WriteAllBytes(args[0], certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, password));
        store.Audit("cli:" + Environment.UserName, "key-exported-" + name, Guid.Empty, Guid.Empty);
        Console.WriteLine("Exported " + certificate.Subject + " (SHA-256 " + Wire.Sha256(certificate.RawData) + ") to " + args[0] + ". Store it offline and delete this copy from the volume.");
        return 0;
    }

    // Migration from the IIS backend: imports the key backup PFX files created by Install-SlapsServer.ps1.
    // Must run before the first start (empty key table), so existing agent certificates and envelopes stay valid.
    public static int ImportKeys(string[] args)
    {
        var caPath = Argument(args, "--ca");
        var recoveryPath = Argument(args, "--recovery");
        if (caPath == null || recoveryPath == null) throw new InvalidOperationException("Usage: import-keys --ca <ca.pfx> --recovery <recovery.pfx> [--previous-recovery <older.pfx>] (password: SLAPS_IMPORT_PASSWORD or prompt)");
        var options = Options();
        var store = new VaultStore(options);
        store.Initialize();
        if (store.Key(KeyVault.CaKey) != null || store.Key(KeyVault.RecoveryKey) != null)
            throw new InvalidOperationException("This database already has keys. Import keys into a new, empty database before the first start.");
        var password = Password("SLAPS_IMPORT_PASSWORD");
        var flags = X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable;
        using var vault = new KeyVault(store, options);
        void Import(string path, string name, bool requireCa)
        {
            using var certificate = X509CertificateLoader.LoadPkcs12FromFile(path, password, flags);
            if (!certificate.HasPrivateKey) throw new InvalidOperationException(path + " contains no private key.");
            using (var rsa = certificate.GetRSAPrivateKey())
                if (rsa == null || rsa.KeySize < 3072) throw new InvalidOperationException(path + " must contain an RSA key with at least 3072 bits.");
            if (requireCa) KeyVault.ValidateIssuer(certificate);
            var key = vault.Protect(name == "previous" ? KeyVault.RecoveryKey + ":" + Wire.Sha256(certificate.RawData) : name, certificate);
            if (!store.AddKey(key, "cli:import")) throw new InvalidOperationException("Key " + key.Name + " already exists.");
            Console.WriteLine("Imported " + certificate.Subject + " as " + key.Name + " (SHA-256 " + key.Sha256 + ")");
        }
        Import(caPath, KeyVault.CaKey, true);
        Import(recoveryPath, KeyVault.RecoveryKey, false);
        for (var i = 0; i < args.Length - 1; i++)
            if (args[i] == "--previous-recovery") Import(args[i + 1], "previous", false);
        return 0;
    }

    private sealed class IisClient { public string certificateSha256 { get; set; } public string role { get; set; } public string deviceId { get; set; } public string displayName { get; set; } public string createdUtc { get; set; } public string createdBy { get; set; } }
    private sealed class IisRecord { public Envelope envelope { get; set; } public string receivedUtc { get; set; } }
    private sealed class IisDeleted { public string deviceId { get; set; } public string archiveId { get; set; } public string deletedUtc { get; set; } public string actor { get; set; } }
    private sealed class IisSettings { public int historyLimit { get; set; } }

    // Migration from the IIS backend: imports agents (Vault\_clients and agent entries of clients.json), encrypted
    // password versions, applied reports, deleted devices and the history limit from a copy of App_Data.
    public static int ImportIisVault(string[] args)
    {
        if (args.Length < 1 || !Directory.Exists(args[0])) throw new InvalidOperationException("Usage: import-iis-vault <copy of the IIS App_Data directory>");
        var appData = args[0];
        var vault = Directory.Exists(Path.Combine(appData, "Vault")) ? Path.Combine(appData, "Vault") : appData;
        var options = Options();
        var store = new VaultStore(options);
        store.Initialize();
        var json = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var clients = new List<IisClient>();
        var staticClients = Path.Combine(appData, "clients.json");
        if (File.Exists(staticClients)) clients.AddRange(JsonSerializer.Deserialize<IisClient[]>(File.ReadAllText(staticClients), json) ?? Array.Empty<IisClient>());
        var managed = Path.Combine(vault, "_clients");
        if (Directory.Exists(managed)) clients.AddRange(Directory.EnumerateFiles(managed, "*.json").Select(f => JsonSerializer.Deserialize<IisClient>(File.ReadAllText(f), json)));
        var deleted = new Dictionary<string, IisDeleted>(StringComparer.OrdinalIgnoreCase);
        var deletedRoot = Path.Combine(vault, "_deleted");
        if (Directory.Exists(deletedRoot))
            foreach (var marker in Directory.EnumerateFiles(deletedRoot, "*.json").Select(f => JsonSerializer.Deserialize<IisDeleted>(File.ReadAllText(f), json)).Where(m => m?.deviceId != null))
                deleted[marker.deviceId] = marker;
        int devices = 0, records = 0;
        foreach (var client in clients.Where(c => c != null && c.role == "agent" && Guid.TryParseExact(c.deviceId, "D", out _) && Wire.IsHex64(c.certificateSha256))
                     .GroupBy(c => c.deviceId, StringComparer.OrdinalIgnoreCase).Select(g => g.Last()))
        {
            var device = Guid.Parse(client.deviceId);
            deleted.TryGetValue(client.deviceId, out var marker);
            var name = KeyVault.ValidName(client.displayName ?? "") ? client.displayName : "Device-" + device.ToString("N")[..8];
            store.ImportClient(new AgentClient
            {
                DeviceId = device.ToString("D"), DisplayName = name, CertificateSha256 = client.certificateSha256, Platform = "windows",
                CreatedUtc = client.createdUtc, CreatedBy = client.createdBy ?? "import", DeletedUtc = marker?.deletedUtc, DeletedBy = marker?.actor
            }, "cli:import-iis-vault");
            devices++;
            var folders = new List<string> { Path.Combine(vault, device.ToString("D")) };
            if (marker != null && Guid.TryParseExact(marker.archiveId, "N", out var archive)) folders.Add(Path.Combine(deletedRoot, device.ToString("D"), archive.ToString("N")));
            foreach (var folder in folders.Where(Directory.Exists))
                foreach (var file in Directory.EnumerateFiles(folder, "*.record.json"))
                {
                    var record = JsonSerializer.Deserialize<IisRecord>(File.ReadAllText(file), json);
                    var rotation = Guid.Parse(Path.GetFileName(file)[..36]);
                    if (record == null || !Wire.Valid(record.envelope, device, rotation)) { Console.Error.WriteLine("Skipped invalid record " + file); continue; }
                    var appliedFile = Path.Combine(folder, rotation.ToString("D") + ".applied.json");
                    var applied = File.Exists(appliedFile) ? JsonSerializer.Deserialize<string>(File.ReadAllText(appliedFile)) : null;
                    store.ImportRecord(device, record.envelope, record.receivedUtc, applied);
                    records++;
                }
        }
        var settingsFile = Path.Combine(vault, "settings.json");
        if (File.Exists(settingsFile))
        {
            var settings = JsonSerializer.Deserialize<IisSettings>(File.ReadAllText(settingsFile), json);
            if (settings != null && settings.historyLimit >= ServerOptions.MinHistoryLimit && settings.historyLimit <= ServerOptions.MaxHistoryLimit) store.ImportHistoryLimit(settings.historyLimit, "cli:import-iis-vault");
        }
        Console.WriteLine($"Imported {devices} devices and {records} password versions. Existing agents keep working if their certificates were issued by the imported SLAPS CA (import-keys) and their apiUrl points to the agent port.");
        return 0;
    }
}
