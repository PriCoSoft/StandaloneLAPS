using System.Globalization;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

[assembly: AssemblyVersion(StandaloneLapsWeb.AppVersion.Assembly)]
[assembly: AssemblyFileVersion(StandaloneLapsWeb.AppVersion.Assembly)]
[assembly: AssemblyInformationalVersion(StandaloneLapsWeb.AppVersion.Number)]

namespace StandaloneLaps.Server;

// Wire format v1, identical to web/IisVault/App_Code/EnvelopeModels.cs and the Windows/Linux agents.
public sealed class Envelope
{
    public int version { get; set; }
    public string deviceId { get; set; }
    public Guid rotationId { get; set; }
    public string createdUtc { get; set; }
    public string recipientSha256 { get; set; }
    public string wrappedKey { get; set; }
    public string nonce { get; set; }
    public string tag { get; set; }
    public string ciphertext { get; set; }
}

public sealed class Payload
{
    public int version { get; set; }
    public string deviceId { get; set; }
    public Guid rotationId { get; set; }
    public string createdUtc { get; set; }
    public string computerName { get; set; }
    public string accountName { get; set; }
    public string accountSid { get; set; }
    public string password { get; set; }
}

public sealed class HistoryEntry
{
    public Guid rotationId { get; set; }
    public string createdUtc { get; set; }
    public string receivedUtc { get; set; }
    public string appliedReportedUtc { get; set; }
}

public static class Wire
{
    public static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = null, MaxDepth = 16 };

    public static DateTimeOffset Timestamp(string value) => DateTimeOffset.Parse(value, CultureInfo.InvariantCulture, DateTimeStyles.None);

    public static string Now() => DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture);

    public static string Sha256(byte[] raw) => Convert.ToHexString(SHA256.HashData(raw));

    public static bool IsHex64(string value) => value != null && value.Length == 64 && value.All(Uri.IsHexDigit);

    // Same checks as Vault.Valid in the IIS backend.
    public static bool Valid(Envelope envelope, Guid device, Guid rotation)
    {
        try
        {
            return envelope != null && envelope.version == 1 && envelope.deviceId == device.ToString("D") && envelope.rotationId == rotation &&
                rotation != Guid.Empty && IsHex64(envelope.recipientSha256) && Timestamp(envelope.createdUtc) != default &&
                Length(envelope.wrappedKey) is >= 384 and <= 1024 && Length(envelope.nonce) == 12 && Length(envelope.tag) == 16 &&
                Length(envelope.ciphertext) is > 0 and <= 16384;
        }
        catch (ArgumentException) { return false; }
        catch (FormatException) { return false; }
    }

    private static int Length(string base64) => Convert.FromBase64String(base64 ?? throw new FormatException()).Length;

    public static bool SameEnvelope(Envelope a, Envelope b) =>
        a.version == b.version && a.deviceId == b.deviceId && a.rotationId == b.rotationId && a.createdUtc == b.createdUtc &&
        a.recipientSha256 == b.recipientSha256 && a.wrappedKey == b.wrappedKey && a.nonce == b.nonce && a.tag == b.tag && a.ciphertext == b.ciphertext;

    private static byte[] AssociatedData(Envelope envelope) => Encoding.UTF8.GetBytes(string.Format(CultureInfo.InvariantCulture,
        "StandaloneLaps/v1|{0}|{1:D}|{2:O}|{3}|{4}", envelope.deviceId, envelope.rotationId, Timestamp(envelope.createdUtc), envelope.recipientSha256, envelope.wrappedKey));

    // AES-256-GCM key wrapped with RSA-OAEP-SHA256 for the recovery certificate (same as EnvelopeCrypto.Decrypt).
    public static Payload Decrypt(Envelope envelope, X509Certificate2 recovery)
    {
        if (envelope == null || envelope.version != 1 || !string.Equals(Sha256(recovery.RawData), envelope.recipientSha256, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("Unsupported envelope or incorrect recovery certificate.");
        using var rsa = recovery.GetRSAPrivateKey() ?? throw new CryptographicException("RSA private key required.");
        var key = rsa.Decrypt(Convert.FromBase64String(envelope.wrappedKey), RSAEncryptionPadding.OaepSHA256);
        var ciphertext = Convert.FromBase64String(envelope.ciphertext);
        var plaintext = new byte[ciphertext.Length];
        try
        {
            if (key.Length != 32) throw new CryptographicException("Invalid content key.");
            using (var aes = new AesGcm(key, 16))
                aes.Decrypt(Convert.FromBase64String(envelope.nonce), ciphertext, Convert.FromBase64String(envelope.tag), plaintext, AssociatedData(envelope));
            var payload = JsonSerializer.Deserialize<Payload>(plaintext, Json);
            if (payload == null || payload.version != 1 || payload.deviceId != envelope.deviceId || payload.rotationId != envelope.rotationId ||
                Timestamp(payload.createdUtc) != Timestamp(envelope.createdUtc)) throw new CryptographicException("Payload metadata mismatch.");
            return payload;
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(plaintext); }
    }

    // Used by tests and tools; mirrors the agent's EnvelopeCrypto.Encrypt.
    public static Envelope Encrypt(Payload payload, X509Certificate2 recovery)
    {
        var key = RandomNumberGenerator.GetBytes(32);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(payload, Json);
        try
        {
            using var rsa = recovery.GetRSAPublicKey();
            if (rsa == null || rsa.KeySize < 3072) throw new CryptographicException("RSA 3072 or stronger required.");
            var envelope = new Envelope
            {
                version = 1, deviceId = payload.deviceId, rotationId = payload.rotationId, createdUtc = payload.createdUtc, recipientSha256 = Sha256(recovery.RawData),
                wrappedKey = Convert.ToBase64String(rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256)), nonce = Convert.ToBase64String(nonce)
            };
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];
            using (var aes = new AesGcm(key, 16)) aes.Encrypt(nonce, plaintext, ciphertext, tag, AssociatedData(envelope));
            envelope.ciphertext = Convert.ToBase64String(ciphertext);
            envelope.tag = Convert.ToBase64String(tag);
            return envelope;
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(plaintext); }
    }
}
