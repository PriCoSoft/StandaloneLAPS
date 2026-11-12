using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;
using StandaloneLapsWeb;

// Entra ID token validation, internal-network restriction, SLAPS CA issuing/CRL, portal-managed clients
// and client packages. Ephemeral keys only; no certificate store, registry or IIS change.
public static class FrameworkPortalTests
{
    private static int passed;
    private static void Check(bool condition, string label)
    { if (!condition) throw new Exception("FAILED: " + label); passed++; Console.WriteLine("PASS Portal " + label); }
    private static void Fails<T>(Action action, string label) where T : Exception
    { try { action(); } catch (T) { Check(true, label); return; } throw new Exception("FAILED: " + label); }

    public static int Run(string directory)
    {
        passed = 0;
        Networks();
        Tokens();
        CertificateAuthorityAndPackages(directory);
        return passed;
    }

    private static void Networks()
    {
        var internalNets = new[] { "10.10.0.0/16", "192.168.20.0/24", "fd00::/8" };
        Check(PortalAuth.NetworkAllowed("10.10.200.7", internalNets) && PortalAuth.NetworkAllowed("192.168.20.255", internalNets), "IPv4 addresses inside configured internal networks allowed");
        Check(!PortalAuth.NetworkAllowed("10.11.0.1", internalNets) && !PortalAuth.NetworkAllowed("192.168.21.1", internalNets), "addresses outside internal networks (e.g. DMZ) denied");
        Check(PortalAuth.NetworkAllowed("::ffff:10.10.1.1", internalNets), "IPv4-mapped IPv6 address matched against IPv4 network");
        Check(PortalAuth.NetworkAllowed("fd12::1", internalNets) && !PortalAuth.NetworkAllowed("fe80::1", internalNets), "IPv6 prefix matching");
        Check(!PortalAuth.NetworkAllowed("10.10.1.1", new string[0]) && !PortalAuth.NetworkAllowed("garbage", internalNets), "empty network list or invalid address denies portal access");
        Check(PortalAuth.NetworkAllowed("172.16.5.4", new[] { "172.16.5.4/32" }) && PortalAuth.NetworkAllowed("8.8.8.8", new[] { "0.0.0.0/0" }), "host and all-address prefixes");
        Check(!PortalAuth.ValidNetwork("10.0.0.0") && !PortalAuth.ValidNetwork("10.0.0.0/33") && !PortalAuth.ValidNetwork("x/8") && PortalAuth.ValidNetwork("10.0.0.0/8"), "invalid CIDR syntax rejected");
    }

    private const string Tenant = "11111111-2222-3333-4444-555555555555";
    private const string App = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private const string Nonce = "nonce-value-123";

    private static void Tokens()
    {
        using (var key = new RSACng(2048))
        using (var other = new RSACng(2048))
        {
            var parameters = key.ExportParameters(false);
            var jwks = new JavaScriptSerializer().Serialize(new Dictionary<string, object> { { "keys", new object[] {
                new Dictionary<string, object> { { "kty", "RSA" }, { "use", "sig" }, { "kid", "k1" }, { "n", EntraTokenValidator.Base64UrlEncode(parameters.Modulus) }, { "e", EntraTokenValidator.Base64UrlEncode(parameters.Exponent) } } } } });
            var now = DateTime.UtcNow;
            var admin = EntraTokenValidator.Validate(Token(key, "k1", Claims(now, new[] { PortalAuth.AdminRole }), "RS256"), jwks, Tenant, App, Nonce, now);
            Check(admin.IsAdmin && admin.Actor == "entra:99999999-8888-7777-6666-555555555555" && admin.DisplayName == "Test Admin", "valid Entra ID token with SLAPS.Admin role accepted");
            var reader = EntraTokenValidator.Validate(Token(key, "k1", Claims(now, new[] { "Other", PortalAuth.ReaderRole }), "RS256"), jwks, Tenant, App, Nonce, now);
            Check(reader.Role == "reader" && !reader.IsAdmin, "SLAPS.Reader role maps to read-only access");
            Fails<TokenValidationException>(() => EntraTokenValidator.Validate(Token(key, "k1", Claims(now, new string[0]), "RS256"), jwks, Tenant, App, Nonce, now), "assigned user without SLAPS role denied");
            Fails<TokenValidationException>(() => EntraTokenValidator.Validate(Token(other, "k1", Claims(now, new[] { PortalAuth.AdminRole }), "RS256"), jwks, Tenant, App, Nonce, now), "token signed with a foreign key rejected");
            Fails<SigningKeyNotFoundException>(() => EntraTokenValidator.Validate(Token(key, "k2", Claims(now, new[] { PortalAuth.AdminRole }), "RS256"), jwks, Tenant, App, Nonce, now), "unknown key ID triggers signing-key refresh path");
            Fails<TokenValidationException>(() => EntraTokenValidator.Validate(Token(key, "k1", Claims(now, new[] { PortalAuth.AdminRole }), "none"), jwks, Tenant, App, Nonce, now), "alg=none rejected");
            Fails<TokenValidationException>(() => EntraTokenValidator.Validate(Token(key, "k1", Claims(now, new[] { PortalAuth.AdminRole }), "RS256"), jwks, Tenant, Guid.NewGuid().ToString(), Nonce, now), "token for another application rejected");
            Fails<TokenValidationException>(() => EntraTokenValidator.Validate(Token(key, "k1", Claims(now, new[] { PortalAuth.AdminRole }), "RS256"), jwks, Guid.NewGuid().ToString(), App, Nonce, now), "token from another tenant/issuer rejected");
            Fails<TokenValidationException>(() => EntraTokenValidator.Validate(Token(key, "k1", Claims(now, new[] { PortalAuth.AdminRole }), "RS256"), jwks, Tenant, App, "other-nonce", now), "nonce mismatch (replay/CSRF) rejected");
            Fails<TokenValidationException>(() => EntraTokenValidator.Validate(Token(key, "k1", Claims(now.AddHours(-3), new[] { PortalAuth.AdminRole }), "RS256"), jwks, Tenant, App, Nonce, now), "expired token rejected");
            var parts = Token(key, "k1", Claims(now, new[] { PortalAuth.ReaderRole }), "RS256").Split('.');
            var elevated = EntraTokenValidator.Base64UrlEncode(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(EntraTokenValidator.Base64UrlDecode(parts[1])).Replace(PortalAuth.ReaderRole, PortalAuth.AdminRole)));
            Fails<TokenValidationException>(() => EntraTokenValidator.Validate(parts[0] + "." + elevated + "." + parts[2], jwks, Tenant, App, Nonce, now), "modified role claim breaks signature");
            Fails<TokenValidationException>(() => EntraTokenValidator.Validate("abc", jwks, Tenant, App, Nonce, now), "malformed token rejected");
        }
        Check(PortalAuth.SafeReturnUrl("Default.aspx?device=2b0c7224-6121-4181-9dbc-65be629c6069&tab=history") != "Default.aspx" &&
            PortalAuth.SafeReturnUrl("https://evil.example/") == "Default.aspx" && PortalAuth.SafeReturnUrl("//evil") == "Default.aspx", "sign-in return URL limited to local portal pages");
        Check(PortalAuth.FixedTimeEquals("abc", "abc") && !PortalAuth.FixedTimeEquals("abc", "abd") && !PortalAuth.FixedTimeEquals(null, "a"), "state comparison");
    }

    private static Dictionary<string, object> Claims(DateTime issued, string[] roles)
    {
        var epoch = (long)(issued - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
        var claims = new Dictionary<string, object>
        {
            { "iss", "https://login.microsoftonline.com/" + Tenant + "/v2.0" }, { "aud", App }, { "tid", Tenant }, { "oid", "99999999-8888-7777-6666-555555555555" },
            { "nonce", Nonce }, { "iat", epoch }, { "nbf", epoch }, { "exp", epoch + 3600 }, { "name", "Test Admin" }
        };
        if (roles.Length > 0) claims["roles"] = roles;
        return claims;
    }

    private static string Token(RSA key, string keyId, Dictionary<string, object> claims, string algorithm)
    {
        var serializer = new JavaScriptSerializer();
        var header = EntraTokenValidator.Base64UrlEncode(Encoding.UTF8.GetBytes(serializer.Serialize(new Dictionary<string, object> { { "alg", algorithm }, { "kid", keyId }, { "typ", "JWT" } })));
        var payload = EntraTokenValidator.Base64UrlEncode(Encoding.UTF8.GetBytes(serializer.Serialize(claims)));
        var signature = key.SignData(Encoding.ASCII.GetBytes(header + "." + payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return header + "." + payload + "." + EntraTokenValidator.Base64UrlEncode(signature);
    }

    private static void CertificateAuthorityAndPackages(string directory)
    {
        using (var caKey = new RSACng(3072))
        {
            var request = new CertificateRequest("CN=SLAPS CA test", caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
            using (var ca = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(35)))
            {
                var device = Guid.NewGuid();
                var issued = SlapsCertificateAuthority.IssueClient(ca, "DMZ-WEB-01", device, "http://slaps.example.com/slaps-ca.crl", DateTimeOffset.UtcNow);
                using (var client = new X509Certificate2(issued.Pfx, issued.PfxPassword, X509KeyStorageFlags.EphemeralKeySet))
                {
                    Check(client.HasPrivateKey && issued.CertificateSha256 == Vault.Hash(client) && issued.PfxPassword.Length == 24, "agent PFX contains the issued certificate and private key");
                    Fails<CryptographicException>(() => new X509Certificate2(issued.Pfx, "wrong-password", X509KeyStorageFlags.EphemeralKeySet), "agent PFX requires the one-time password");
                    Check(client.Issuer == ca.Subject && client.Subject.Contains("SLAPS Agent DMZ-WEB-01") && client.Subject.Contains(device.ToString("D")), "agent certificate issued by the SLAPS CA with device name/ID");
                    Check(client.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddYears(29) && client.NotAfter.ToUniversalTime() < DateTime.UtcNow.AddYears(31), "agent certificate valid for 30 years");
                    var constraints = client.Extensions.OfType<X509BasicConstraintsExtension>().Single();
                    var eku = client.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single();
                    Check(!constraints.CertificateAuthority && eku.EnhancedKeyUsages.Cast<Oid>().Single().Value == SlapsCertificateAuthority.ClientAuthOid, "agent certificate is an end entity limited to Client Authentication");
                    var authority = client.Extensions.Cast<X509Extension>().Single(x => x.Oid.Value == "2.5.29.35").Format(false).Replace(" ", "");
                    Check(authority.IndexOf(ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single().SubjectKeyIdentifier, StringComparison.OrdinalIgnoreCase) >= 0, "authority key identifier references the CA key");
                    Check(client.Extensions.Cast<X509Extension>().Single(x => x.Oid.Value == "2.5.29.31").Format(false).Contains("http://slaps.example.com/slaps-ca.crl"), "CRL distribution point encoded");
                    using (var chain = new X509Chain())
                    {
                        chain.ChainPolicy.ExtraStore.Add(ca);
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                        Check(chain.Build(client) && chain.ChainElements.Count == 2 && chain.ChainElements[1].Certificate.Thumbprint == ca.Thumbprint, "agent certificate chains to the SLAPS CA");
                    }
                    var pinned = new Client { role = "agent", deviceId = device.ToString("D"), certificateSha256 = issued.CertificateSha256 };
                    Check(Vault.MatchCertificate(client, new[] { pinned }) == pinned, "issued agent certificate authenticates once pinned");
                }
                Fails<ArgumentException>(() => SlapsCertificateAuthority.IssueClient(ca, "bad,name=x", Guid.NewGuid(), null, DateTimeOffset.UtcNow), "device names with DN syntax rejected");
                using (var plain = new X509Certificate2(issued.CertificateRaw))
                    Fails<CryptographicException>(() => SlapsCertificateAuthority.IssueClient(plain, "X", Guid.NewGuid(), null, DateTimeOffset.UtcNow), "issuing without CA private key/CA flag rejected");

                var crl = SlapsCertificateAuthority.BuildCrl(ca, 20261111120000L, DateTimeOffset.UtcNow.AddHours(-1), new DateTimeOffset(ca.NotAfter.ToUniversalTime()).AddDays(-1));
                Check(VerifyCrl(crl, ca), "CRL (UTCTime/GeneralizedTime, AKI, CRL number) parses and is signed by the SLAPS CA");
                File.WriteAllBytes(Path.Combine(directory, "slaps-ca.crl"), crl);

                // Portal-managed clients and packages.
                var registration = new Client { role = "agent", deviceId = device.ToString("D"), displayName = "DMZ-WEB-01", certificateSha256 = issued.CertificateSha256, createdBy = "test-admin" };
                Vault.RegisterManagedClient(registration, false, "test-admin");
                Check(Vault.Clients().Any(c => c.deviceId == device.ToString("D") && c.certificateSha256 == issued.CertificateSha256) && Vault.IsManagedClient(device), "portal-added client is registered and pinned");
                Check(Vault.Devices(false, "WEB-01").Single().Managed, "portal-added client appears in the device list");
                Fails<ArgumentException>(() => Vault.RegisterManagedClient(new Client { role = "agent", deviceId = Guid.NewGuid().ToString("D"), displayName = "dmz-web-01", certificateSha256 = new string('A', 64) }, false, "test-admin"), "duplicate active device name rejected");
                Fails<InvalidOperationException>(() => Vault.RegisterManagedClient(new Client { role = "agent", deviceId = Guid.NewGuid().ToString("D"), displayName = "Other", certificateSha256 = issued.CertificateSha256 }, false, "test-admin"), "certificate cannot be pinned twice");
                var rekeyed = SlapsCertificateAuthority.IssueClient(ca, "DMZ-WEB-01", device, null, DateTimeOffset.UtcNow);
                Vault.RegisterManagedClient(new Client { role = "agent", deviceId = device.ToString("D"), displayName = "DMZ-WEB-01", certificateSha256 = rekeyed.CertificateSha256 }, true, "test-admin");
                using (var oldCertificate = new X509Certificate2(issued.CertificateRaw))
                    Check(Vault.Clients().Count(c => c.deviceId == device.ToString("D")) == 1 && Vault.MatchCertificate(oldCertificate, Vault.Clients()) == null, "new certificate package replaces and revokes the previous pin");
                Fails<InvalidOperationException>(() => Vault.RegisterManagedClient(new Client { role = "agent", deviceId = Guid.NewGuid().ToString("D"), displayName = "X", certificateSha256 = new string('B', 64) }, true, "test-admin"), "rekey limited to portal-managed devices");

                var agentDirectory = Path.Combine(directory, "agent-package");
                Directory.CreateDirectory(agentDirectory);
                foreach (var name in ClientPackages.AgentFiles) File.WriteAllText(Path.Combine(agentDirectory, name), "test " + name);
                var zip = ClientPackages.Build(rekeyed, "https://slaps.example.com/", ca.RawData, agentDirectory);
                using (var archive = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read))
                {
                    var names = archive.Entries.Select(entry => entry.FullName).ToArray();
                    var expected = new[] { "slaps-settings.json", "agent.pfx", "recovery.cer", "bin/StandaloneLaps.Agent.exe", "bin/StandaloneLaps.Agent.exe.config", "Install-SlapsAgent.ps1", "Install.cmd", "README.txt" };
                    Check(expected.All(name => names.Contains("SLAPS-Agent-DMZ-WEB-01/" + name)), "client package contains installer, agent, PFX, recovery certificate and settings");
                    string settingsJson;
                    using (var reader = new StreamReader(archive.GetEntry("SLAPS-Agent-DMZ-WEB-01/slaps-settings.json").Open())) settingsJson = reader.ReadToEnd();
                    var settings = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(settingsJson);
                    Check((string)settings["deviceId"] == device.ToString("D") && (string)settings["apiUrl"] == "https://slaps.example.com/" &&
                        (string)settings["clientCertificateSha256"] == rekeyed.CertificateSha256 && (string)settings["recoveryCertificateSha256"] == Vault.Hash(ca), "package settings are predefined for this device");
                }
                Check(Encoding.UTF8.GetString(zip).IndexOf(rekeyed.PfxPassword, StringComparison.Ordinal) < 0, "package does not contain the PFX password");

                var linuxDirectory = Path.Combine(agentDirectory, "linux");
                Directory.CreateDirectory(linuxDirectory);
                foreach (var name in ClientPackages.LinuxAgentFiles) File.WriteAllText(Path.Combine(linuxDirectory, name), "test " + name);
                var linuxZip = ClientPackages.BuildLinux(rekeyed, "https://slaps.example.com/", ca.RawData, linuxDirectory);
                using (var archive = new ZipArchive(new MemoryStream(linuxZip), ZipArchiveMode.Read))
                {
                    var names = archive.Entries.Select(entry => entry.FullName).ToArray();
                    var expected = new[] { "slaps-settings.json", "agent.pfx", "recovery.cer", "install.sh", "slaps-agent", "slaps-agent.service", "agent.conf",
                        "slaps-agent_" + AppVersion.Number + "_all.deb", "README.txt" };
                    Check(expected.All(name => names.Contains("SLAPS-Agent-DMZ-WEB-01-linux/" + name)) && !names.Any(name => name.EndsWith(".exe") || name.EndsWith(".cmd")),
                        "Linux client package contains install.sh, agent, .deb, PFX, recovery certificate and settings");
                }
                Check(ClientPackages.Store(linuxZip, rekeyed, "test-admin", ClientPackages.Linux).fileName == "SLAPS-Agent-DMZ-WEB-01-linux.zip", "Linux package file name");
                var stored = ClientPackages.Store(zip, rekeyed, "test-admin");
                Check(ClientPackages.Find(stored.token) != null && File.ReadAllBytes(ClientPackages.ZipPath(stored.token)).SequenceEqual(zip), "package stored for time-limited download");
                Check(ClientPackages.Find("../../web") == null && ClientPackages.Find(new string('0', 32)) == null, "package token validated");
                var metadata = Path.Combine(ClientPackages.PackagesDirectory, stored.token + ".json");
                var expired = new JavaScriptSerializer().Deserialize<PackageInfo>(File.ReadAllText(metadata));
                expired.expiresUtc = DateTimeOffset.UtcNow.AddMinutes(-1).ToString("O");
                File.WriteAllText(metadata, new JavaScriptSerializer().Serialize(expired));
                ClientPackages.Cleanup();
                Check(ClientPackages.Find(stored.token) == null && !File.Exists(ClientPackages.ZipPath(stored.token)), "expired packages are deleted");
                Check(SlapsCertificateAuthority.NewPassword(64).All(c => char.IsLetterOrDigit(c) && "O0Il1".IndexOf(c) < 0), "PFX passwords avoid ambiguous characters");
            }
        }
    }

    private static bool VerifyCrl(byte[] crl, X509Certificate2 issuer)
    {
        var context = CertCreateCRLContext(1, crl, crl.Length);
        if (context == IntPtr.Zero) return false;
        try { return CryptVerifyCertificateSignatureEx(IntPtr.Zero, 1, 3, context, 2, issuer.Handle, 0, IntPtr.Zero); }
        finally { CertFreeCRLContext(context); }
    }
    [DllImport("crypt32.dll", SetLastError = true)] private static extern IntPtr CertCreateCRLContext(int encoding, byte[] data, int length);
    [DllImport("crypt32.dll")] private static extern bool CertFreeCRLContext(IntPtr context);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern bool CryptVerifyCertificateSignatureEx(IntPtr provider, int encoding, int subjectType, IntPtr subject, int issuerType, IntPtr issuer, int flags, IntPtr extra);
}
