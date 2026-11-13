using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace StandaloneLaps.Server;

public sealed class IssuedClient
{
    public string DeviceId, DisplayName, CertificateSha256, PfxPassword;
    public byte[] Pfx, CertificateRaw;
    public DateTime NotAfterUtc;
}

public sealed class CertificateInfo
{
    public string Role, Purpose, Sha256, Subject, Issuer, Thumbprint, SerialNumber, KeyDescription, KeyStatus, FileName;
    public DateTime NotBeforeUtc, NotAfterUtc;
    public bool Expired;
    public byte[] Raw;
}

// SLAPS CA (issues agent client certificates), recovery certificate (agents encrypt to it) and the TLS certificate.
// Private keys are stored in the database as PKCS#12 (PBES2/AES-256) encrypted with the master key, so a copy of
// the database or volume alone cannot decrypt passwords or issue certificates.
public sealed class KeyVault : IDisposable
{
    public const string CaKey = "ca", RecoveryKey = "recovery", TlsKey = "tls";
    public const string ClientAuthOid = "1.3.6.1.5.5.7.3.2", ServerAuthOid = "1.3.6.1.5.5.7.3.1";
    public const int ClientYears = 30;
    private const string PasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    private static readonly X509KeyStorageFlags KeyFlags = X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable;
    private readonly VaultStore store;
    private readonly ServerOptions options;
    private readonly List<X509Certificate2> recovery = new();

    public X509Certificate2 Ca { get; private set; }
    public X509Certificate2 Recovery => recovery[0];
    public IReadOnlyList<X509Certificate2> RecoveryCertificates => recovery;
    public X509Certificate2 Tls { get; private set; }
    public X509Certificate2Collection TlsChain { get; } = new();
    public string TlsSource { get; private set; }

    public KeyVault(VaultStore store, ServerOptions options)
    {
        this.store = store;
        this.options = options;
    }

    // ---- Startup ----------------------------------------------------------------------------------

    public void Initialize(bool loadTls = true)
    {
        Ca = LoadOrCreate(CaKey, CreateCa);
        ValidateIssuer(Ca);
        var current = LoadOrCreate(RecoveryKey, CreateRecovery);
        recovery.Add(current);
        // Earlier recovery keys stay available to decrypt older versions ("recovery:<sha256>").
        foreach (var previous in store.Keys(RecoveryKey + ":")) recovery.Add(Load(previous));
        if (loadTls) LoadTls();
    }

    private X509Certificate2 LoadOrCreate(string name, Func<X509Certificate2> create)
    {
        var existing = store.Key(name);
        if (existing != null) return Load(existing);
        using (var created = create()) store.AddKey(Protect(name, created), "system:startup");
        return Load(store.Key(name));
    }

    private X509Certificate2 Load(StoredKey key)
    {
        try
        {
            var certificate = X509CertificateLoader.LoadPkcs12(key.Pkcs12, options.MasterKey, KeyFlags);
            if (!string.Equals(Wire.Sha256(certificate.RawData), key.Sha256, StringComparison.OrdinalIgnoreCase)) throw new CryptographicException("Fingerprint mismatch.");
            return certificate;
        }
        catch (CryptographicException ex)
        {
            throw new InvalidOperationException("The key '" + key.Name + "' cannot be decrypted. SLAPS_MASTER_KEY does not match the key used when the database was created.", ex);
        }
    }

    public StoredKey Protect(string name, X509Certificate2 certificate) => new()
    {
        Name = name, Sha256 = Wire.Sha256(certificate.RawData), CreatedUtc = Wire.Now(),
        Pkcs12 = certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, options.MasterKey)
    };

    private X509Certificate2 CreateCa()
    {
        using var key = RSA.Create(4096);
        var request = new CertificateRequest("CN=SLAPS CA " + options.HostName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddHours(-1), now.AddYears(35));
    }

    private X509Certificate2 CreateRecovery()
    {
        using var key = RSA.Create(4096);
        var request = new CertificateRequest("CN=SLAPS Recovery " + options.HostName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddHours(-1), now.AddYears(30));
    }

    // ---- TLS ---------------------------------------------------------------------------------------

    private static X509KeyStorageFlags TlsFlags => OperatingSystem.IsWindows() ? X509KeyStorageFlags.UserKeySet : X509KeyStorageFlags.EphemeralKeySet;

    private void LoadTls()
    {
        if (options.TlsCertificatePath != null)
        {
            using var pem = X509Certificate2.CreateFromPemFile(options.TlsCertificatePath, options.TlsKeyPath ?? throw new InvalidOperationException("Slaps:TlsKeyPath is required with TlsCertificatePath."));
            // Re-import so Windows SslStream gets a usable key; on Linux the key stays in memory.
            Tls = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null, TlsFlags);
            // Intermediate certificates after the first one in the PEM file are sent in the handshake.
            var all = new X509Certificate2Collection();
            all.ImportFromPemFile(options.TlsCertificatePath);
            foreach (var extra in all.Cast<X509Certificate2>().Where(c => c.Thumbprint != Tls.Thumbprint)) TlsChain.Add(extra);
            TlsSource = "PEM files (" + options.TlsCertificatePath + ")";
        }
        else if (options.TlsPfxPath != null)
        {
            Tls = X509CertificateLoader.LoadPkcs12FromFile(options.TlsPfxPath, options.TlsPfxPassword, TlsFlags);
            TlsSource = "PFX file (" + options.TlsPfxPath + ")";
        }
        else
        {
            var names = DnsNames();
            var stored = store.Key(TlsKey);
            X509Certificate2 current = stored == null ? null : Load(stored);
            if (current == null || current.NotAfter.ToUniversalTime() < DateTime.UtcNow.AddDays(60) || !names.All(name => current.MatchesHostname(name)))
            {
                current?.Dispose();
                using var created = CreateSelfSignedTls(names);
                store.ReplaceKey(Protect(TlsKey, created), "system:startup");
                current = Load(store.Key(TlsKey));
            }
            using (current) Tls = X509CertificateLoader.LoadPkcs12(current.Export(X509ContentType.Pkcs12), null, TlsFlags);
            TlsSource = "Generated self-signed certificate (agents must trust it; download it on the Settings page)";
        }
        if (!Tls.HasPrivateKey) throw new InvalidOperationException("The TLS certificate has no private key.");
    }

    public string[] DnsNames()
    {
        var names = new List<string>();
        foreach (var url in new[] { options.PublicUrl, options.AgentApiUrl })
            if (url != null && Uri.TryCreate(url, UriKind.Absolute, out var uri)) names.Add(uri.Host);
        names.AddRange(options.TlsDnsNames);
        if (names.Count == 0) names.Add("localhost");
        return names.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    // A self-signed end-entity certificate (not a CA): trusting it on a DMZ server trusts exactly this server.
    private static X509Certificate2 CreateSelfSignedTls(string[] names)
    {
        using var key = RSA.Create(3072);
        var request = new CertificateRequest("CN=" + names[0], key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in names)
            if (System.Net.IPAddress.TryParse(name, out var address)) san.AddIpAddress(address); else san.AddDnsName(name);
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ServerAuthOid) }, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddHours(-1), now.AddDays(825));
    }

    // ---- Agent certificates -----------------------------------------------------------------------

    public static void ValidateIssuer(X509Certificate2 ca)
    {
        if (ca == null || !ca.HasPrivateKey) throw new CryptographicException("The SLAPS CA certificate with its private key is unavailable.");
        var constraints = ca.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
        if (constraints == null || !constraints.CertificateAuthority) throw new CryptographicException("The SLAPS CA is not a CA certificate.");
        var now = DateTime.UtcNow;
        if (now < ca.NotBefore.ToUniversalTime() || now >= ca.NotAfter.ToUniversalTime()) throw new CryptographicException("The SLAPS CA certificate is not currently valid.");
    }

    public static bool ValidName(string name) => !string.IsNullOrWhiteSpace(name) && name.Length <= 64 && name.Trim() == name &&
        name.All(c => c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_' or '.' or ' ');

    // Same certificate profile as SlapsCertificateAuthority.IssueClient in the IIS backend (without CRL distribution point:
    // the container validates agent chains itself; revocation is done by replacing or deleting the pin).
    public IssuedClient IssueClient(string displayName, Guid deviceId, DateTimeOffset now)
    {
        ValidateIssuer(Ca);
        if (!ValidName(displayName)) throw new ArgumentException("Use 1-64 letters, digits, spaces, dots, dashes or underscores for the device name.");
        if (deviceId == Guid.Empty) throw new ArgumentException("A device ID is required.");
        var notBefore = now.AddHours(-1);
        var caStart = new DateTimeOffset(Ca.NotBefore.ToUniversalTime());
        if (notBefore < caStart) notBefore = caStart;
        var notAfter = now.AddYears(ClientYears);
        var caEnd = new DateTimeOffset(Ca.NotAfter.ToUniversalTime()).AddDays(-1);
        if (notAfter > caEnd) notAfter = caEnd;
        if (notAfter <= now.AddDays(30)) throw new CryptographicException("The SLAPS CA certificate expires too soon to issue client certificates.");
        using var key = RSA.Create(3072);
        var request = new CertificateRequest(new X500DistinguishedName("CN=SLAPS Agent " + displayName + ", OU=" + deviceId.ToString("D")), key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ClientAuthOid) }, false));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        request.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Ca, true, false));
        var serial = RandomNumberGenerator.GetBytes(16);
        serial[0] = (byte)((serial[0] & 0x7F) | 0x01);
        using var issued = request.Create(Ca, notBefore, notAfter, serial);
        using var withKey = issued.CopyWithPrivateKey(key);
        var password = NewPassword(24);
        return new IssuedClient
        {
            DeviceId = deviceId.ToString("D"), DisplayName = displayName, CertificateSha256 = Wire.Sha256(issued.RawData), CertificateRaw = issued.RawData, PfxPassword = password,
            // 3DES/SHA-1 PKCS#12: imports on Windows Server 2016+ and with OpenSSL 3 without -legacy (same as the IIS backend).
            Pfx = withKey.ExportPkcs12(Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, password), NotAfterUtc = issued.NotAfter.ToUniversalTime()
        };
    }

    // TLS handshake check on the agent port: valid client-authentication certificate issued by this SLAPS CA.
    // The pin (SHA-256 in slaps_clients) is enforced per request by the agent API.
    public bool IsAgentCertificate(X509Certificate2 certificate)
    {
        if (certificate == null) return false;
        var now = DateTime.UtcNow;
        if (now < certificate.NotBefore.ToUniversalTime() || now >= certificate.NotAfter.ToUniversalTime()) return false;
        var eku = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
        if (eku == null || !eku.EnhancedKeyUsages.Cast<Oid>().Any(oid => oid.Value == ClientAuthOid)) return false;
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(Ca);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
        return chain.Build(certificate) && chain.ChainElements.Count == 2 && Wire.Sha256(chain.ChainElements[1].Certificate.RawData) == Wire.Sha256(Ca.RawData);
    }

    public static string NewPassword(int length)
    {
        var result = new StringBuilder(length);
        while (result.Length < length) result.Append(PasswordAlphabet[RandomNumberGenerator.GetInt32(PasswordAlphabet.Length)]);
        return result.ToString();
    }

    public Payload Reveal(Envelope envelope)
    {
        var certificate = recovery.FirstOrDefault(c => string.Equals(Wire.Sha256(c.RawData), envelope.recipientSha256, StringComparison.OrdinalIgnoreCase))
            ?? throw new CryptographicException("The recovery key for this version is not stored on this server.");
        return Wire.Decrypt(envelope, certificate);
    }

    // ---- Portal display ----------------------------------------------------------------------------

    public CertificateInfo[] Describe()
    {
        var result = new List<CertificateInfo> { Info(Ca, "SLAPS CA", "Issues the agent client certificates; the agent port accepts only certificates from this CA.", "SLAPS-CA") };
        for (var i = 0; i < recovery.Count; i++)
            result.Add(Info(recovery[i], i == 0 ? "Recovery certificate" : "Previous recovery certificate",
                i == 0 ? "Encrypts new password versions (public key in every client package); its private key decrypts them." : "Kept to decrypt older password versions.",
                "SLAPS-Recovery-" + Wire.Sha256(recovery[i].RawData)[..8]));
        if (Tls != null) result.Add(Info(Tls, "TLS certificate", TlsSource, "SLAPS-TLS"));
        return result.ToArray();
    }

    private static CertificateInfo Info(X509Certificate2 certificate, string role, string purpose, string fileName)
    {
        using var publicKey = certificate.GetRSAPublicKey();
        return new CertificateInfo
        {
            Role = role, Purpose = purpose, Sha256 = Wire.Sha256(certificate.RawData), Subject = certificate.Subject, Issuer = certificate.Issuer, Thumbprint = certificate.Thumbprint,
            SerialNumber = certificate.SerialNumber, NotBeforeUtc = certificate.NotBefore.ToUniversalTime(), NotAfterUtc = certificate.NotAfter.ToUniversalTime(),
            Expired = DateTime.UtcNow >= certificate.NotAfter.ToUniversalTime(), KeyDescription = publicKey == null ? certificate.PublicKey.Oid.FriendlyName : "RSA " + publicKey.KeySize + " bit",
            KeyStatus = certificate.HasPrivateKey ? "Private key encrypted with the master key in the database" : "No private key", FileName = fileName, Raw = certificate.RawData
        };
    }

    public static string Pem(byte[] raw) => PemEncoding.WriteString("CERTIFICATE", raw) + "\n";

    public void Dispose()
    {
        Ca?.Dispose();
        foreach (var certificate in recovery) certificate.Dispose();
        Tls?.Dispose();
    }
}
