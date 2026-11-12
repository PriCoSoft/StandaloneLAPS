using System.Security.Cryptography.X509Certificates;

namespace StandaloneLaps.Api;

public sealed class VaultOptions
{
    public int Port { get; set; } = 8443;
    public string ServerCertificateSha256 { get; set; } = "";
    public string DataDirectory { get; set; } = "";
    public List<VaultClient> Clients { get; set; } = [];

    public void Validate()
    {
        static bool Hash(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);
        if (Port is < 1 or > 65535 || !Hash(ServerCertificateSha256) || !Path.IsPathFullyQualified(DataDirectory) ||
            DataDirectory.StartsWith(@"\\", StringComparison.Ordinal) || !Directory.Exists(DataDirectory))
            throw new InvalidOperationException("Configure the HTTPS certificate, port and an existing local vault directory.");
        if (Clients.Count == 0 || Clients.Select(c => c.CertificateSha256.ToUpperInvariant()).Distinct().Count() != Clients.Count)
            throw new InvalidOperationException("Configure unique authorized client certificates.");
        foreach (var client in Clients)
        {
            if (!Hash(client.CertificateSha256) || client.Role is not ("agent" or "reader") ||
                (client.Role == "agent" && !Guid.TryParseExact(client.DeviceId, "D", out _)))
                throw new InvalidOperationException("Invalid authorized client configuration.");
            client.CertificateSha256 = client.CertificateSha256.ToUpperInvariant();
            client.DeviceId = client.DeviceId?.ToLowerInvariant();
        }
    }

    public VaultClient? Authorize(X509Certificate2? certificate)
    {
        if (certificate is null) return null;
        var now = DateTime.UtcNow;
        if (now < certificate.NotBefore.ToUniversalTime() || now >= certificate.NotAfter.ToUniversalTime()) return null;
        var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku is null || !eku.EnhancedKeyUsages.Cast<System.Security.Cryptography.Oid>().Any(o => o.Value == "1.3.6.1.5.5.7.3.2")) return null;
        return Clients.SingleOrDefault(c => c.CertificateSha256 == SecretEncryption.Fingerprint(certificate));
    }
}

public sealed class VaultClient
{
    public string CertificateSha256 { get; set; } = "";
    public string Role { get; set; } = "";
    public string? DeviceId { get; set; }
}
