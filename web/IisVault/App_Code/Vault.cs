using System;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using System.Web.Hosting;
using System.Web.Script.Serialization;

namespace StandaloneLapsWeb
{
    public sealed class StoredRecord
    {
        public Envelope envelope { get; set; }
        public string receivedUtc { get; set; }
    }
    public sealed class HistoryEntry
    {
        public Guid rotationId { get; set; }
        public string createdUtc { get; set; }
        public string receivedUtc { get; set; }
        public string appliedReportedUtc { get; set; }
    }
    public sealed class Client
    {
        public string certificateSha256 { get; set; }
        public string role { get; set; }
        public string deviceId { get; set; }
        public string displayName { get; set; }
        public string createdUtc { get; set; }
        public string createdBy { get; set; }
    }
    public sealed class DeletedDevice
    {
        public string deviceId { get; set; }
        public string archiveId { get; set; }
        public string deletedUtc { get; set; }
        public string actor { get; set; }
    }
    public sealed class DeviceSummary
    {
        public string DeviceId, Name, LastBackupUtc, LastAppliedUtc, CertificateSha256;
        public int Versions;
        public bool Deleted, Unconfirmed, Managed;
    }
    // Portal-editable settings, stored in the writable vault (App_Data\Vault\settings.json).
    public sealed class PortalSettings
    {
        public int historyLimit { get; set; }
        public string updatedUtc { get; set; }
        public string updatedBy { get; set; }
    }
    public static class Vault
    {
        public const int DefaultHistoryLimit = 20, MinHistoryLimit = 2, MaxHistoryLimit = 100;
        private static readonly object Gate = new object();
        private static PortalSettings cachedSettings;
        private static DateTime cachedSettingsStamp;

        public static string SettingsPath { get { return VaultPath("settings.json"); } }
        public static PortalSettings Settings()
        {
            lock (Gate)
            {
                var path = SettingsPath;
                if (!File.Exists(path)) return new PortalSettings { historyLimit = DefaultHistoryLimit };
                var stamp = File.GetLastWriteTimeUtc(path);
                if (cachedSettings == null || stamp != cachedSettingsStamp)
                {
                    var settings = Json.Deserialize<PortalSettings>(File.ReadAllText(path));
                    // Fail closed: a damaged file must not silently fall back to a smaller limit and trim history.
                    if (settings == null || settings.historyLimit < MinHistoryLimit || settings.historyLimit > MaxHistoryLimit)
                        throw new InvalidDataException("App_Data\\Vault\\settings.json is invalid. Fix or delete it (default: " + DefaultHistoryLimit + " versions).");
                    cachedSettings = settings; cachedSettingsStamp = stamp;
                }
                return cachedSettings;
            }
        }
        // Number of password versions retained per device (newest first, plus the latest known-applied version).
        public static int HistoryLimit { get { return Settings().historyLimit; } }

        // Changes the retention limit and applies it to all active devices. Lowering it permanently deletes older versions.
        public static void SetHistoryLimit(int limit, string actor)
        {
            if (limit < MinHistoryLimit || limit > MaxHistoryLimit)
                throw new ArgumentOutOfRangeException("limit", "The history limit must be between " + MinHistoryLimit + " and " + MaxHistoryLimit + ".");
            lock (Gate)
            {
                var previous = HistoryLimit;
                if (previous == limit) return;
                Audit(actor, "settings-history-limit-" + previous + "-to-" + limit, Guid.Empty, Guid.Empty);
                WriteReplace(SettingsPath, Json.Serialize(new PortalSettings { historyLimit = limit, updatedUtc = DateTimeOffset.UtcNow.ToString("O"), updatedBy = actor }));
                cachedSettings = null;
                if (limit < previous) EnforceRetention();
            }
        }
        private sealed class Rate { public DateTime Window; public int Count; }
        private static readonly Dictionary<string, Rate> Rates = new Dictionary<string, Rate>();
        public static JavaScriptSerializer Json { get { return new JavaScriptSerializer { MaxJsonLength = 65536, RecursionLimit = 16 }; } }
        public static string Setting(string name) { return ConfigurationManager.AppSettings[name] ?? ""; }
        public static string Hash(X509Certificate2 certificate)
        { using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(certificate.RawData)).Replace("-", ""); }
        public static string[] List(string value) { return value.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries).Select(s => s.Trim()).ToArray(); }

        public static string DataRoot
        {
            get
            {
                var configured = Setting("VaultDataDirectory");
                if (string.IsNullOrWhiteSpace(configured)) configured = "~/App_Data/Vault";
                var root = HostingEnvironment.IsHosted ? HostingEnvironment.MapPath(configured) : configured;
                if (!Path.IsPathRooted(root) || root.StartsWith(@"\\", StringComparison.Ordinal))
                    throw new ConfigurationErrorsException("Configure a local App_Data vault directory.");
                var full = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                if (HostingEnvironment.IsHosted)
                {
                    var appData = Path.GetFullPath(HostingEnvironment.MapPath("~/App_Data")).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
                    if (!full.StartsWith(appData, StringComparison.OrdinalIgnoreCase) || full == appData)
                        throw new ConfigurationErrorsException("Vault storage must be a dedicated subdirectory of App_Data.");
                }
                Directory.CreateDirectory(full);
                return full;
            }
        }

        // Static, administrator-maintained entries (read-only for the application pool).
        public static string StaticClientsPath
        {
            get { return HostingEnvironment.IsHosted ? HostingEnvironment.MapPath("~/App_Data/clients.json") : Path.Combine(Path.GetDirectoryName(DataRoot.TrimEnd(Path.DirectorySeparatorChar)), "clients.json"); }
        }
        // Agents added through the portal ("Add client"); stored in the writable vault.
        public static string ManagedClientsDirectory { get { return VaultPath("_clients"); } }

        public static Client[] Clients()
        {
            var clients = new List<Client>();
            var path = StaticClientsPath;
            if (File.Exists(path)) clients.AddRange(Json.Deserialize<Client[]>(File.ReadAllText(path)) ?? new Client[0]);
            var managed = ManagedClientsDirectory;
            if (Directory.Exists(managed))
                foreach (var file in Directory.EnumerateFiles(managed, "*.json"))
                {
                    var client = Json.Deserialize<Client>(File.ReadAllText(file));
                    if (client != null && client.role == "agent" && IsGuid(client.deviceId) && string.Equals(Path.GetFileNameWithoutExtension(file), client.deviceId, StringComparison.OrdinalIgnoreCase))
                        clients.Add(client);
                }
            return clients.ToArray();
        }
        public static bool IsManagedClient(Guid device) { return File.Exists(Path.Combine(ManagedClientsDirectory, device.ToString("D") + ".json")); }

        // Registers a new portal-managed agent, or replaces the certificate pin of an existing one (rekey).
        // Replacing the pin immediately revokes the previous agent certificate for this application.
        public static void RegisterManagedClient(Client client, bool replace, string actor)
        {
            Guid device;
            if (client == null || client.role != "agent" || !Guid.TryParseExact(client.deviceId, "D", out device) || device == Guid.Empty ||
                client.certificateSha256 == null || client.certificateSha256.Length != 64 || !client.certificateSha256.All(Uri.IsHexDigit))
                throw new ArgumentException("Invalid agent registration.");
            lock (Gate)
            {
                var path = Path.Combine(ManagedClientsDirectory, device.ToString("D") + ".json");
                var existing = Clients();
                if (replace)
                {
                    if (!File.Exists(path)) throw new InvalidOperationException("Only devices added through the portal can receive a new certificate here.");
                    if (IsDeleted(device)) throw new InvalidOperationException("Restore the device before issuing a new certificate.");
                }
                else
                {
                    if (existing.Any(c => string.Equals(c.deviceId, client.deviceId, StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("The device ID is already registered.");
                    if (existing.Any(c => c.role == "agent" && IsGuid(c.deviceId) && !IsDeleted(Guid.Parse(c.deviceId)) && string.Equals(c.displayName, client.displayName, StringComparison.OrdinalIgnoreCase)))
                        throw new ArgumentException("An active device with this name already exists.");
                }
                if (existing.Any(c => string.Equals(c.certificateSha256, client.certificateSha256, StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("The certificate is already registered.");
                Directory.CreateDirectory(ManagedClientsDirectory);
                Audit(actor, replace ? "client-certificate-replaced" : "client-added", device, Guid.Empty);
                WriteReplace(UnderRoot(path), Json.Serialize(client));
            }
        }
        public static Client CertificateClient(HttpRequest request)
        {
            if (!request.IsSecureConnection || !request.ClientCertificate.IsPresent || !request.ClientCertificate.IsValid) return null;
            using (var certificate = new X509Certificate2(request.ClientCertificate.Certificate))
                return MatchCertificate(certificate, Clients());
        }
        public static Client MatchCertificate(X509Certificate2 certificate, IEnumerable<Client> clients)
        {
            var now = DateTime.UtcNow;
            if (now < certificate.NotBefore.ToUniversalTime() || now >= certificate.NotAfter.ToUniversalTime()) return null;
            var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (eku == null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == "1.3.6.1.5.5.7.3.2")) return null;
            var hash = Hash(certificate);
            return clients.SingleOrDefault(c => string.Equals(c.certificateSha256, hash, StringComparison.OrdinalIgnoreCase) &&
                (c.role == "reader" || c.role == "admin" || (c.role == "agent" && IsGuid(c.deviceId))));
        }
        public static bool CanAccess(Client client, Guid device, bool write)
        {
            if (client == null || IsDeleted(device)) return false;
            return write ? client.role == "agent" && string.Equals(client.deviceId, device.ToString("D"), StringComparison.OrdinalIgnoreCase)
                : client.role == "reader" || client.role == "admin" || (client.role == "agent" && string.Equals(client.deviceId, device.ToString("D"), StringComparison.OrdinalIgnoreCase));
        }
        public static bool CanManageClient(Client client) { return client != null && client.role == "admin"; }
        public static bool IsGuid(string value) { Guid id; return Guid.TryParseExact(value, "D", out id) && id != Guid.Empty; }
        public static DateTimeOffset Timestamp(string value) { return DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.None); }
        public static bool PermitApiRequest(string fingerprint)
        {
            lock (Gate)
            {
                Rate rate;
                var now = DateTime.UtcNow;
                if (!Rates.TryGetValue(fingerprint, out rate) || now - rate.Window >= TimeSpan.FromMinutes(1))
                { rate = new Rate { Window = now }; Rates[fingerprint] = rate; }
                return ++rate.Count <= 60;
            }
        }
        public static bool Valid(Envelope envelope, Guid device, Guid rotation)
        {
            try
            {
                return envelope != null && envelope.version == 1 && envelope.deviceId == device.ToString("D") && envelope.rotationId == rotation &&
                    rotation != Guid.Empty && envelope.recipientSha256 != null && envelope.recipientSha256.Length == 64 &&
                    envelope.recipientSha256.All(Uri.IsHexDigit) && Timestamp(envelope.createdUtc) != default(DateTimeOffset) &&
                    Convert.FromBase64String(envelope.wrappedKey).Length >= 384 && Convert.FromBase64String(envelope.wrappedKey).Length <= 1024 &&
                    Convert.FromBase64String(envelope.nonce).Length == 12 && Convert.FromBase64String(envelope.tag).Length == 16 &&
                    Convert.FromBase64String(envelope.ciphertext).Length > 0 && Convert.FromBase64String(envelope.ciphertext).Length <= 16384;
            }
            catch (ArgumentException) { return false; }
            catch (FormatException) { return false; }
        }

        private static string UnderRoot(string path)
        {
            var full = Path.GetFullPath(path);
            var root = DataRoot;
            if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidDataException("Path is outside the vault.");
            var current = full;
            while (!string.IsNullOrEmpty(current) && current.Length >= root.TrimEnd(Path.DirectorySeparatorChar).Length)
            {
                if (Directory.Exists(current) && RedirectsPath(current)) throw new InvalidDataException("Linked vault directories are unsupported.");
                current = Path.GetDirectoryName(current);
            }
            return full;
        }
        private static bool RedirectsPath(string path)
        {
            if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0) return false;
            // Cloud placeholders (including OneDrive) are reparse points without redirecting names.
            // Reject junctions/symlinks, while allowing those nonredirecting storage tags.
            using (var handle = OpenPath(path, 0, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero))
            {
                if (handle.IsInvalid) throw new IOException("Cannot inspect vault directory.");
                var data = new byte[16384]; uint written;
                if (!ReadReparse(handle, 0x000900A8, IntPtr.Zero, 0, data, data.Length, out written, IntPtr.Zero) || written < 4)
                    throw new IOException("Cannot inspect vault reparse data.");
                return (BitConverter.ToUInt32(data, 0) & 0x20000000) != 0;
            }
        }
        [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle OpenPath(string name, uint access, uint sharing, IntPtr security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
        private static extern bool ReadReparse(SafeFileHandle handle, uint operation, IntPtr input, int inputLength, byte[] output, int outputLength, out uint written, IntPtr overlap);
        public static string VaultPath(string relative)
        {
            if (string.IsNullOrEmpty(relative) || Path.IsPathRooted(relative) || relative.Contains("..")) throw new ArgumentException("Invalid vault path.");
            return UnderRoot(Path.Combine(DataRoot, relative));
        }
        private static string DirectoryFor(Guid device) { return UnderRoot(Path.Combine(DataRoot, device.ToString("D"))); }
        private static string DeletedRoot { get { return UnderRoot(Path.Combine(DataRoot, "_deleted")); } }
        private static string DeletedPath(Guid device) { return Path.Combine(DeletedRoot, device.ToString("D") + ".json"); }
        public static bool IsDeleted(Guid device) { return File.Exists(DeletedPath(device)); }
        private static string RecordPath(Guid device, Guid rotation) { return Path.Combine(DirectoryFor(device), rotation.ToString("D") + ".record.json"); }
        private static string AppliedPath(Guid device, Guid rotation) { return Path.Combine(DirectoryFor(device), rotation.ToString("D") + ".applied.json"); }
        public static StoredRecord Get(Guid device, Guid rotation)
        {
            lock (Gate)
            {
                if (IsDeleted(device)) return null;
                var path = RecordPath(device, rotation);
                return File.Exists(path) ? Json.Deserialize<StoredRecord>(File.ReadAllText(path)) : null;
            }
        }
        public static bool Put(Guid device, Guid rotation, Envelope envelope)
        {
            lock (Gate)
            {
                if (IsDeleted(device)) throw new HttpException(403, "Device is deleted.");
                var stored = Get(device, rotation);
                if (stored != null) { PruneLocked(device); return Json.Serialize(stored.envelope) == Json.Serialize(envelope); }
                Directory.CreateDirectory(DirectoryFor(device));
                WriteNew(RecordPath(device, rotation), Json.Serialize(new StoredRecord { envelope = envelope, receivedUtc = DateTimeOffset.UtcNow.ToString("O") }));
                PruneLocked(device);
                return Json.Serialize(Get(device, rotation).envelope) == Json.Serialize(envelope);
            }
        }
        public static bool Applied(Guid device, Guid rotation)
        {
            lock (Gate)
            {
                if (Get(device, rotation) == null) return false;
                var path = AppliedPath(device, rotation);
                if (!File.Exists(path)) WriteNew(path, Json.Serialize(DateTimeOffset.UtcNow.ToString("O")));
                return true;
            }
        }
        public static HistoryEntry[] History(Guid device, int skip, int take)
        {
            lock (Gate)
            {
            if (IsDeleted(device)) return new HistoryEntry[0];
            var limit = HistoryLimit;
            return Records(device).Take(limit).Skip(Math.Max(0, skip)).Take(Math.Min(limit, Math.Max(0, take)))
                .Select(record => new HistoryEntry { rotationId = record.envelope.rotationId, createdUtc = record.envelope.createdUtc, receivedUtc = record.receivedUtc,
                    appliedReportedUtc = File.Exists(AppliedPath(device, record.envelope.rotationId)) ? Json.Deserialize<string>(File.ReadAllText(AppliedPath(device, record.envelope.rotationId))) : null }).ToArray();
            }
        }
        private static StoredRecord[] Records(Guid device)
        {
            var directory = DirectoryFor(device);
            return !Directory.Exists(directory) ? new StoredRecord[0] : Directory.EnumerateFiles(directory, "*.record.json")
                .Select(path => ReadRecord(path, device))
                .OrderByDescending(record => Timestamp(record.receivedUtc)).ThenBy(record => record.envelope.rotationId).ToArray();
        }
        private static StoredRecord ReadRecord(string path, Guid device)
        {
            var name = Path.GetFileName(path); Guid rotation;
            if (name.Length != 48 || !Guid.TryParseExact(name.Substring(0, 36), "D", out rotation)) throw new InvalidDataException("Invalid record filename.");
            var record = Json.Deserialize<StoredRecord>(File.ReadAllText(path));
            if (record == null || !Valid(record.envelope, device, rotation)) throw new InvalidDataException("Invalid stored record.");
            Timestamp(record.receivedUtc);
            return record;
        }
        private static void PruneLocked(Guid device)
        {
            var records = Records(device);
            var limit = HistoryLimit;
            if (records.Length <= limit) return;
            var keep = records.Take(limit).ToList();
            // Repeated failed resets must not evict the most recent known-applied recovery password.
            var confirmed = records.FirstOrDefault(record => File.Exists(AppliedPath(device, record.envelope.rotationId)));
            if (confirmed != null && !keep.Contains(confirmed)) { keep.RemoveAt(keep.Count - 1); keep.Add(confirmed); }
            Audit("system:retention", "trim-history-to-" + limit, device, Guid.Empty);
            foreach (var record in records.Except(keep))
            {
                File.Delete(UnderRoot(RecordPath(device, record.envelope.rotationId)));
                var applied = AppliedPath(device, record.envelope.rotationId);
                if (File.Exists(applied)) File.Delete(UnderRoot(applied));
            }
        }
        public static void EnforceRetention()
        {
            lock (Gate)
                foreach (var path in Directory.EnumerateDirectories(DataRoot))
                { Guid device; if (Guid.TryParseExact(Path.GetFileName(path), "D", out device) && !IsDeleted(device)) PruneLocked(device); }
        }
        public static bool ArchiveDevice(Guid device, string actor)
        {
            lock (Gate)
            {
                if (device == Guid.Empty) throw new ArgumentException("Device required.");
                if (IsDeleted(device)) return false;
                PruneLocked(device);
                var archiveId = Guid.NewGuid().ToString("N");
                var source = DirectoryFor(device);
                var target = UnderRoot(Path.Combine(DeletedRoot, device.ToString("D"), archiveId));
                Audit(actor, "device-delete", device, Guid.Empty);
                Directory.CreateDirectory(DeletedRoot);
                WriteNew(DeletedPath(device), Json.Serialize(new DeletedDevice { deviceId = device.ToString("D"), archiveId = archiveId, actor = actor, deletedUtc = DateTimeOffset.UtcNow.ToString("O") }));
                if (Directory.Exists(source)) { Directory.CreateDirectory(Path.GetDirectoryName(target)); Directory.Move(UnderRoot(source), UnderRoot(target)); }
                return true;
            }
        }
        public static bool RestoreDevice(Guid device, string actor)
        {
            lock (Gate)
            {
                if (!IsDeleted(device)) return false;
                var marker = Json.Deserialize<DeletedDevice>(File.ReadAllText(DeletedPath(device)));
                Guid archiveId;
                if (marker.deviceId != device.ToString("D") || !Guid.TryParseExact(marker.archiveId, "N", out archiveId)) throw new InvalidDataException("Invalid deletion record.");
                var source = UnderRoot(Path.Combine(DeletedRoot, device.ToString("D"), archiveId.ToString("N")));
                var target = DirectoryFor(device);
                if (Directory.Exists(source) && Directory.Exists(target)) throw new IOException("Both active and archived data exist; manual coordination required.");
                Audit(actor, "device-restore", device, Guid.Empty);
                if (Directory.Exists(source)) Directory.Move(UnderRoot(source), UnderRoot(target));
                PruneLocked(device);
                File.Delete(UnderRoot(DeletedPath(device)));
                return true;
            }
        }
        public static DeviceSummary[] Devices(bool deleted, string query)
        {
            var clients = Clients().Where(client => client.role == "agent" && IsGuid(client.deviceId)).GroupBy(client => client.deviceId, StringComparer.OrdinalIgnoreCase).Select(group => group.First());
            return FilterDevices(clients.Select(client => Summary(client)), deleted, query);
        }
        public static DeviceSummary[] FilterDevices(IEnumerable<DeviceSummary> devices, bool deleted, string query)
        {
            query = (query ?? "").Trim();
            return devices.Where(device => device.Deleted == deleted && (query.Length == 0 || device.Name.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0 || device.DeviceId.IndexOf(query, StringComparison.OrdinalIgnoreCase) >= 0))
                .OrderBy(device => device.Name, StringComparer.OrdinalIgnoreCase).ToArray();
        }
        private static DeviceSummary Summary(Client client)
        {
            var id = Guid.Parse(client.deviceId); var history = History(id, 0, HistoryLimit);
            var applied = history.FirstOrDefault(entry => entry.appliedReportedUtc != null);
            return new DeviceSummary { DeviceId = id.ToString("D"), Name = string.IsNullOrWhiteSpace(client.displayName) ? id.ToString("D") : client.displayName,
                CertificateSha256 = client.certificateSha256, Deleted = IsDeleted(id), Versions = history.Length, Managed = IsManagedClient(id),
                LastBackupUtc = history.Length == 0 ? null : history[0].receivedUtc, LastAppliedUtc = applied == null ? null : applied.appliedReportedUtc,
                Unconfirmed = history.Length > 0 && history[0].appliedReportedUtc == null };
        }
        private static void WriteNew(string path, string content)
        {
            var temporary = Path.Combine(Path.GetDirectoryName(path), Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                var bytes = Encoding.UTF8.GetBytes(content);
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
                File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        private static void WriteReplace(string path, string content)
        {
            var temporary = Path.Combine(Path.GetDirectoryName(path), Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                var bytes = Encoding.UTF8.GetBytes(content);
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
                if (File.Exists(path)) File.Replace(temporary, path, null); else File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
        public static void Audit(string actor, string action, Guid device, Guid rotation)
        {
            var line = Json.Serialize(new { utc = DateTimeOffset.UtcNow.ToString("O"), actor = actor, action = action, deviceId = device, rotationId = rotation }) + Environment.NewLine;
            lock (Gate)
            {
                var bytes = Encoding.UTF8.GetBytes(line);
                using (var stream = new FileStream(Path.Combine(DataRoot, "audit.jsonl"), FileMode.Append, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough))
                { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
            }
        }
        public static Payload Reveal(Envelope envelope)
        {
            if (!string.Equals(Setting("EnableWebDecryption"), "true", StringComparison.OrdinalIgnoreCase)) throw new HttpException(403, "Web decryption is disabled.");
            if (!List(Setting("RecoveryCertificateSha256")).Any(hash => string.Equals(hash, envelope.recipientSha256, StringComparison.OrdinalIgnoreCase)))
                throw new CryptographicException("Recovery certificate is not allowed for web decryption.");
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                using (var certificate = store.Certificates.Cast<X509Certificate2>().Single(c => c.HasPrivateKey && Hash(c) == envelope.recipientSha256))
                    return EnvelopeCrypto.Decrypt(envelope, certificate);
            }
        }
    }
}
