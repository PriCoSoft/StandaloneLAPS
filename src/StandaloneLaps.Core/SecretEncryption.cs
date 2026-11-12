using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace StandaloneLaps;

// Wire format v1: RSA-OAEP-SHA256 wraps an AES-256-GCM key. Metadata is bound as AAD.
public static class SecretEncryption
{
    public static string Fingerprint(X509Certificate2 certificate) =>
        certificate.GetCertHashString(HashAlgorithmName.SHA256);

    public static void ValidateRecipient(X509Certificate2 certificate, string expectedSha256)
    {
        if (!string.Equals(Fingerprint(certificate), expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("Recovery certificate fingerprint mismatch.");
        var now = DateTime.UtcNow;
        if (now < certificate.NotBefore.ToUniversalTime() || now >= certificate.NotAfter.ToUniversalTime())
            throw new CryptographicException("Recovery certificate is outside its validity period.");
        using var rsa = certificate.GetRSAPublicKey();
        if (rsa is null || rsa.KeySize < 3072) throw new CryptographicException("RSA 3072 or stronger is required.");
        var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
        if (usage is not null && !usage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment))
            throw new CryptographicException("Recovery certificate must allow key encipherment.");
    }

    public static Envelope Encrypt(SecretPayload payload, X509Certificate2 recipient)
    {
        using var rsa = recipient.GetRSAPublicKey() ?? throw new CryptographicException("RSA certificate required.");
        var key = RandomNumberGenerator.GetBytes(32);
        var plaintext = JsonSerializer.SerializeToUtf8Bytes(payload);
        try
        {
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var ciphertext = new byte[plaintext.Length];
            var envelope = new Envelope(1, payload.DeviceId, payload.RotationId, payload.CreatedUtc,
                Fingerprint(recipient), Convert.ToBase64String(rsa.Encrypt(key, RSAEncryptionPadding.OaepSHA256)),
                Convert.ToBase64String(nonce), "", "");
            using var aes = new AesGcm(key, 16);
            aes.Encrypt(nonce, plaintext, ciphertext, tag, AssociatedData(envelope));
            return envelope with { Tag = Convert.ToBase64String(tag), Ciphertext = Convert.ToBase64String(ciphertext) };
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(plaintext); }
    }

    public static SecretPayload Decrypt(Envelope envelope, X509Certificate2 recipient)
    {
        if (envelope.Version != 1 || Fingerprint(recipient) != envelope.RecipientSha256)
            throw new CryptographicException("Unsupported envelope or incorrect recovery certificate.");
        using var rsa = recipient.GetRSAPrivateKey() ?? throw new CryptographicException("Private key required.");
        var key = rsa.Decrypt(Convert.FromBase64String(envelope.WrappedKey), RSAEncryptionPadding.OaepSHA256);
        var plaintext = new byte[Convert.FromBase64String(envelope.Ciphertext).Length];
        try
        {
            using var aes = new AesGcm(key, 16);
            aes.Decrypt(Convert.FromBase64String(envelope.Nonce), Convert.FromBase64String(envelope.Ciphertext),
                Convert.FromBase64String(envelope.Tag), plaintext, AssociatedData(envelope));
            var payload = JsonSerializer.Deserialize<SecretPayload>(plaintext) ?? throw new CryptographicException("Empty payload.");
            if (payload.Version != 1 || payload.DeviceId != envelope.DeviceId || payload.RotationId != envelope.RotationId ||
                payload.CreatedUtc != envelope.CreatedUtc) throw new CryptographicException("Payload metadata mismatch.");
            return payload;
        }
        finally { CryptographicOperations.ZeroMemory(key); CryptographicOperations.ZeroMemory(plaintext); }
    }

    private static byte[] AssociatedData(Envelope envelope) => Encoding.UTF8.GetBytes(
        $"StandaloneLaps/v1|{envelope.DeviceId}|{envelope.RotationId:D}|{envelope.CreatedUtc:O}|{envelope.RecipientSha256}|{envelope.WrappedKey}");
}
