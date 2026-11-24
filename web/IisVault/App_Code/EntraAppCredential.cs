using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web.Security;

namespace StandaloneLapsWeb
{
    // State of the certificate that the setup wizard created for the Microsoft Graph (Entra) lookup.
    // Stored in App_Data\Vault\entra-app-credential.json; the PFX is protected with the site's machineKey.
    public sealed class EntraCredentialState
    {
        public string objectId { get; set; }
        public string current { get; set; }
        public string currentThumbprint { get; set; }
        public string currentNotAfter { get; set; }
        public string currentKeyId { get; set; }
        public string currentCreatedUtc { get; set; }
        public string pending { get; set; }
        public string pendingThumbprint { get; set; }
        public string pendingNotAfter { get; set; }
        public string pendingKeyId { get; set; }
        public string pendingCreatedUtc { get; set; }
        public string lastAttemptUtc { get; set; }
        public string lastRenewalUtc { get; set; }
        public string lastRenewalError { get; set; }
        public string consentUtc { get; set; }
        public string consentBy { get; set; }
        public string consentResult { get; set; }
    }

    public static class EntraAppCredential
    {
        public const int ValidityDays = 365, RenewBeforeDays = 30;
        public const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
        private const string Purpose = "StandaloneLaps.EntraGraphCertificate.v1";
        private static readonly object Gate = new object();

        // Replaceable for tests (MachineKey needs the hosted ASP.NET runtime).
        public static Func<byte[], byte[]> Protector = data => MachineKey.Protect(data, Purpose);
        public static Func<byte[], byte[]> Unprotector = data => MachineKey.Unprotect(data, Purpose);
        public static Func<string> PathProvider = () => Vault.VaultPath("entra-app-credential.json");

        public static EntraCredentialState Load()
        {
            lock (Gate)
            {
                var path = PathProvider();
                if (!File.Exists(path)) return new EntraCredentialState();
                return Vault.Json.Deserialize<EntraCredentialState>(File.ReadAllText(path)) ?? new EntraCredentialState();
            }
        }

        public static void Save(EntraCredentialState state)
        {
            lock (Gate)
            {
                var path = PathProvider();
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                Vault.WriteReplace(path, Vault.Json.Serialize(state));
            }
        }

        public static bool Configured { get { return !string.IsNullOrEmpty(Load().current); } }

        // RSA 2048 / SHA-256 self-signed client-authentication certificate. Only its public part goes to Entra ID.
        public static byte[] NewCertificate(DateTime utcNow, out X509Certificate2 certificate)
        {
            // First choice: ephemeral CNG key (nothing touches the disk). Fallback for application pool identities where
            // that fails: a temporary CSP key in the machine key store, deleted again right after the PFX export.
            try
            {
                using (var rsa = new RSACng(2048)) return Build(rsa, utcNow, out certificate);
            }
            catch (CryptographicException)
            {
                var parameters = new CspParameters(24, null, "SLAPS-Graph-" + Guid.NewGuid().ToString("N")) { Flags = CspProviderFlags.UseMachineKeyStore };
                using (var rsa = new RSACryptoServiceProvider(2048, parameters))
                {
                    try { return Build(rsa, utcNow, out certificate); }
                    finally { rsa.PersistKeyInCsp = false; rsa.Clear(); }
                }
            }
        }

        private static byte[] Build(RSA rsa, DateTime utcNow, out X509Certificate2 certificate)
        {
            var request = new CertificateRequest("CN=SLAPS Graph access " + Environment.MachineName.ToLowerInvariant(), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ClientAuthOid) }, false));
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            using (var created = request.CreateSelfSigned(new DateTimeOffset(utcNow.AddMinutes(-10)), new DateTimeOffset(utcNow.AddDays(ValidityDays))))
            {
                var pfx = created.Export(X509ContentType.Pkcs12);
                certificate = Open(pfx);
                return pfx;
            }
        }

        // Ephemeral key set: no key file in a user profile (application pool identities often have none).
        public static X509Certificate2 Open(byte[] pfx) { return new X509Certificate2(pfx, (string)null, X509KeyStorageFlags.EphemeralKeySet); }

        public static string Protect(byte[] pfx) { return Convert.ToBase64String(Protector(pfx)); }

        public static X509Certificate2 OpenProtected(string value)
        {
            if (string.IsNullOrEmpty(value)) return null;
            try { return Open(Unprotector(Convert.FromBase64String(value))); }
            catch (CryptographicException) { throw new WindowsLapsException("The stored Graph certificate cannot be opened (was the machineKey in web.config changed?). Create a new certificate in the setup."); }
        }

        public static X509Certificate2 Current() { return OpenProtected(Load().current); }

        public static string Stamp(DateTime value) { return value.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture); }

        public static DateTime? Parse(string value)
        {
            DateTime parsed;
            return DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out parsed) ? parsed : (DateTime?)null;
        }

        // Wizard step 1: a new certificate replaces the current one (its public part must then be uploaded to Entra).
        public static EntraCredentialState Create(string actor)
        {
            X509Certificate2 certificate;
            var pfx = NewCertificate(DateTime.UtcNow, out certificate);
            using (certificate)
            {
                var state = Load();
                state.current = Protect(pfx);
                state.currentThumbprint = certificate.Thumbprint;
                state.currentNotAfter = Stamp(certificate.NotAfter);
                state.currentKeyId = null;
                state.currentCreatedUtc = Stamp(DateTime.UtcNow);
                state.pending = state.pendingThumbprint = state.pendingNotAfter = state.pendingKeyId = state.pendingCreatedUtc = null;
                state.lastRenewalError = null;
                Save(state);
                Vault.AuditTarget(actor, "entra-graph-certificate-created", certificate.Thumbprint);
                return state;
            }
        }

        public static bool NeedsRenewal(EntraCredentialState state, DateTime utcNow)
        {
            var notAfter = Parse(state.currentNotAfter);
            return !string.IsNullOrEmpty(state.current) && notAfter.HasValue && notAfter.Value - utcNow < TimeSpan.FromDays(RenewBeforeDays);
        }

        public static byte[] PublicCertificate()
        {
            using (var certificate = Current()) return certificate == null ? null : certificate.RawData;
        }
    }
}
