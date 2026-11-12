using System;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StandaloneLapsWeb;

public static class FrameworkTests
{
    private static int passed;
    private static void Check(bool condition, string label)
    { if (!condition) throw new Exception("FAILED: " + label); passed++; Console.WriteLine("PASS Framework " + label); }
    private static void Fails(Action action, string label)
    { try { action(); } catch { Check(true, label); return; } throw new Exception("FAILED: " + label); }
    public static int Main(string[] args)
    {
        try { Run(args[0]); Console.WriteLine(passed + " .NET Framework checks passed."); return 0; }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }
    private static void Run(string directory)
    {
        var root = Path.Combine(directory, "vault"); Directory.CreateDirectory(root);
        using (var recoveryKey = new RSACng(3072))
        {
            var request = new CertificateRequest("CN=Framework-Test-Recovery", recoveryKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
            using (var recovery = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1)))
            {
                var testPayload = new Payload { version = 1, deviceId = Guid.NewGuid().ToString("D"), rotationId = Guid.NewGuid(), createdUtc = DateTimeOffset.UtcNow.ToString("O"),
                    computerName = "TEST", accountName = "Administrator", accountSid = "S-1-5-21-1-2-3-500", password = StandaloneLaps.FrameworkAgent.RotationEngine.GeneratePassword(32, 4) };
                File.WriteAllText(Path.Combine(directory, "envelope.json"), Vault.Json.Serialize(EnvelopeCrypto.Encrypt(testPayload, recovery)));
                File.WriteAllBytes(Path.Combine(directory, "recovery.pfx"), recovery.Export(X509ContentType.Pfx));
            }
        }
        var envelope = Vault.Json.Deserialize<Envelope>(File.ReadAllText(Path.Combine(directory, "envelope.json")));
        using (var certificate = new X509Certificate2(File.ReadAllBytes(Path.Combine(directory, "recovery.pfx")), "", X509KeyStorageFlags.EphemeralKeySet))
        {
            var payload = EnvelopeCrypto.Decrypt(envelope, certificate);
            Check(payload.password.Length == 32 && payload.computerName == "TEST", "Framework AES-GCM encrypt/decrypt round trip using Windows BCrypt");
            passed += FrameworkAgentTests.Run(certificate, directory);
            var device = Guid.Parse(envelope.deviceId); var rotation = envelope.rotationId;
            Check(Vault.Valid(envelope, device, rotation), "agent JSON maps to Web Forms DTO");
            Check(!Vault.Valid(envelope, Guid.NewGuid(), rotation), "device mismatch rejected");
            var originalTag = envelope.tag;
            var tag = Convert.FromBase64String(originalTag); tag[0] ^= 1; envelope.tag = Convert.ToBase64String(tag);
            Fails(() => EnvelopeCrypto.Decrypt(envelope, certificate), "GCM rejects modified authentication tag");
            envelope.tag = originalTag;
            var originalDevice = envelope.deviceId; envelope.deviceId = Guid.NewGuid().ToString("D");
            Fails(() => EnvelopeCrypto.Decrypt(envelope, certificate), "GCM binds device metadata");
            envelope.deviceId = originalDevice;
            Check(Vault.Put(device, rotation, envelope), "persist encrypted record");
            Check(Vault.Put(device, rotation, envelope), "identical upload is idempotent");
            var originalCiphertext = envelope.ciphertext; envelope.ciphertext = "changed";
            Check(!Vault.Put(device, rotation, envelope), "existing generation cannot be overwritten");
            envelope.ciphertext = originalCiphertext;
            Check(Vault.Json.Serialize(Vault.Get(device, rotation).envelope) == Vault.Json.Serialize(envelope), "read-back preserves exact envelope");
            Check(Vault.History(device, 0, 100).Single().appliedReportedUtc == null, "new generation is unconfirmed");
            Check(Vault.Applied(device, rotation), "record applied status");
            var applied = Vault.History(device, 0, 100).Single().appliedReportedUtc;
            Check(applied != null && Vault.Applied(device, rotation) && Vault.History(device, 0, 100).Single().appliedReportedUtc == applied, "applied retry is idempotent");
            Check(Vault.History(device, 1, 100).Length == 0, "history supports paging");
            Check(!Vault.Applied(device, Guid.NewGuid()), "unknown generation cannot be marked applied");
            Vault.Audit("test-reader", "password-reveal-attempt", device, rotation);
            Check(!File.ReadAllText(Path.Combine(root, "audit.jsonl")).Contains(payload.password), "audit contains no password");
            Check(!File.ReadAllText(Directory.GetFiles(Path.Combine(root, device.ToString("D")), "*.record.json").Single()).Contains(payload.password), "record contains no password");
            Fails(() => Vault.Reveal(envelope), "web decryption disabled by default");
            var agent = new Client { role = "agent", deviceId = device.ToString("D") };
            var reader = new Client { role = "reader" };
            Check(Vault.CanAccess(agent, device, true) && Vault.CanAccess(agent, device, false), "agent accesses assigned device");
            Check(!Vault.CanAccess(agent, Guid.NewGuid(), true) && !Vault.CanAccess(agent, Guid.NewGuid(), false), "agent denied other devices");
            Check(Vault.CanAccess(reader, device, false) && !Vault.CanAccess(reader, device, true), "reader cannot write");
            Check(!Vault.CanAccess(null, device, false), "anonymous read denied");
            Check(Vault.MatchCertificate(certificate, new[] { new Client { role = "reader", certificateSha256 = Vault.Hash(certificate) } }) == null,
                "recovery-only certificate cannot authenticate");
            Check(!Vault.CanManageClient(reader) && !Vault.CanManageClient(agent) && !Vault.CanManageClient(null), "reader/agent/anonymous cannot manage devices");
            var admin = new Client { role = "admin" };
            Check(Vault.CanManageClient(admin) && Vault.CanAccess(admin, device, false) && !Vault.CanAccess(admin, device, true), "administrator manages devices without agent upload rights");
            var candidates = new System.Collections.Generic.List<Guid>();
            for (var i = 0; i < 25; i++)
            {
                payload.rotationId = Guid.NewGuid(); payload.createdUtc = DateTimeOffset.UtcNow.ToString("O");
                var candidate = EnvelopeCrypto.Encrypt(payload, certificate); candidates.Add(candidate.rotationId);
                Vault.Put(device, candidate.rotationId, candidate);
            }
            Check(Vault.History(device, 0, 500).Length == 20 && Directory.GetFiles(Path.Combine(root, device.ToString("D")), "*.record.json").Length == 20, "history and stored records limited to 20");
            Check(Vault.Get(device, rotation) != null, "failed attempts retain latest known-applied recovery version");
            Check(Vault.Get(device, candidates[0]) == null && Vault.Get(device, candidates.Last()) != null, "oldest unconfirmed candidates pruned, newest retained");
            Check(Vault.Applied(device, candidates.Last()), "newest applied version acknowledged");
            payload.rotationId = Guid.NewGuid();
            Vault.Put(device, payload.rotationId, EnvelopeCrypto.Encrypt(payload, certificate));
            Check(Vault.Get(device, rotation) == null && !File.Exists(Path.Combine(root, device.ToString("D"), rotation.ToString("D") + ".applied.json")), "superseded applied record and marker pruned together");
            for (var i = 0; i < 3; i++)
            {
                payload.rotationId = Guid.NewGuid(); var candidate = EnvelopeCrypto.Encrypt(payload, certificate);
                File.WriteAllText(Path.Combine(root, device.ToString("D"), candidate.rotationId.ToString("D") + ".record.json"), Vault.Json.Serialize(new StoredRecord { envelope = candidate, receivedUtc = DateTimeOffset.UtcNow.ToString("O") }));
            }
            Vault.EnforceRetention();
            Check(Directory.GetFiles(Path.Combine(root, device.ToString("D")), "*.record.json").Length == 20, "startup maintenance trims existing over-limit history");
            var retained = Vault.History(device, 0, 20).Select(entry => entry.rotationId).ToArray();
            Check(Vault.ArchiveDevice(device, "test-admin") && Vault.IsDeleted(device), "device deletion creates a persistent tombstone");
            Check(!Directory.Exists(Path.Combine(root, device.ToString("D"))) && Directory.EnumerateFiles(Path.Combine(root, "_deleted"), "*.record.json", SearchOption.AllDirectories).Count() == 20, "deleted encrypted history moved to recoverable archive");
            Check(!Vault.CanAccess(agent, device, true) && !Vault.CanAccess(reader, device, false) && Vault.Get(device, retained[0]) == null && Vault.History(device, 0, 20).Length == 0, "deleted device blocked from API/read access");
            Fails(() => Vault.Put(device, envelope.rotationId, envelope), "deleted agent cannot recreate device through upload");
            Check(!Vault.ArchiveDevice(device, "test-admin"), "repeat deletion is idempotent");
            Check(Vault.RestoreDevice(device, "test-admin") && !Vault.IsDeleted(device), "administrator restores device");
            Check(Vault.History(device, 0, 20).Select(entry => entry.rotationId).SequenceEqual(retained) && Vault.CanAccess(agent, device, true), "restore preserves history and reenables configured agent");
            Check(!Vault.RestoreDevice(device, "test-admin"), "repeat restore is idempotent");
            // Configurable history limit (App_Data\Vault\settings.json)
            Check(Vault.HistoryLimit == Vault.DefaultHistoryLimit && !File.Exists(Path.Combine(root, "settings.json")), "history limit defaults to 20 without settings file");
            Fails(() => Vault.SetHistoryLimit(1, "test-admin"), "history limit below minimum rejected");
            Fails(() => Vault.SetHistoryLimit(101, "test-admin"), "history limit above maximum rejected");
            Vault.SetHistoryLimit(30, "test-admin");
            Check(Vault.HistoryLimit == 30 && Vault.Settings().updatedBy == "test-admin" && Vault.History(device, 0, 100).Length == 20, "raising the limit keeps existing versions");
            for (var i = 0; i < 5; i++)
            {
                payload.rotationId = Guid.NewGuid(); var candidate = EnvelopeCrypto.Encrypt(payload, certificate);
                Vault.Put(device, candidate.rotationId, candidate);
            }
            Check(Vault.History(device, 0, 100).Length == 25, "raised limit retains more versions");
            var newest = Vault.History(device, 0, 100).Select(entry => entry.rotationId).Take(5).ToArray();
            Vault.Applied(device, newest[0]); // latest known-applied version is among the newest, so exactly the newest 5 remain
            Vault.SetHistoryLimit(5, "test-admin");
            Check(Directory.GetFiles(Path.Combine(root, device.ToString("D")), "*.record.json").Length == 5 &&
                Vault.History(device, 0, 100).Select(entry => entry.rotationId).SequenceEqual(newest), "lowering the limit trims all devices to the newest versions");
            Check(File.ReadAllText(Path.Combine(root, "audit.jsonl")).Contains("settings-history-limit-30-to-5"), "history limit change audited");
            File.WriteAllText(Path.Combine(root, "settings.json"), "{\"historyLimit\":0}");
            File.SetLastWriteTimeUtc(Path.Combine(root, "settings.json"), DateTime.UtcNow.AddMinutes(1));
            Fails(() => { var unused = Vault.HistoryLimit; }, "invalid settings file fails closed instead of trimming");
            File.Delete(Path.Combine(root, "settings.json"));
            Check(Vault.HistoryLimit == Vault.DefaultHistoryLimit, "deleting settings file restores default");
            var summaries = new[] { new DeviceSummary { DeviceId = device.ToString("D"), Name = "DMZ-WEB-01" }, new DeviceSummary { DeviceId = Guid.NewGuid().ToString("D"), Name = "DMZ-APP-02", Deleted = true } };
            Check(Vault.FilterDevices(summaries, false, "web").Length == 1 && Vault.FilterDevices(summaries, false, device.ToString("D").Substring(0, 8)).Length == 1, "device search matches case-insensitive name or ID");
            Check(Vault.FilterDevices(summaries, true, "APP").Length == 1 && Vault.FilterDevices(summaries, false, "missing").Length == 0, "search separates deleted devices and handles no results");
        }
        using (var rsa = new RSACng(3072))
        {
            var request = new CertificateRequest("CN=Framework-Client", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.2") }, true));
            using (var client = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1)))
            {
                var allowed = new Client { role = "reader", certificateSha256 = Vault.Hash(client) };
                Check(Vault.MatchCertificate(client, new[] { allowed }) == allowed, "pinned ClientAuth certificate accepted");
                Check(Vault.MatchCertificate(client, new Client[0]) == null, "unknown client certificate rejected");
            }
            using (var expired = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-2), DateTimeOffset.UtcNow.AddHours(-1)))
                Check(Vault.MatchCertificate(expired, new[] { new Client { role = "reader", certificateSha256 = Vault.Hash(expired) } }) == null, "expired client rejected");
        }
        passed += FrameworkPortalTests.Run(directory);
        var key = Guid.NewGuid().ToString("D");
        for (var i = 0; i < 60; i++) if (!Vault.PermitApiRequest(key)) throw new Exception("Rate limit rejected too early.");
        Check(!Vault.PermitApiRequest(key), "API rate limit rejects request 61");
    }
}

public sealed class TestDomainRunner : MarshalByRefObject
{
    public int Run(string directory) { return FrameworkTests.Main(new[] { directory }); }
}
