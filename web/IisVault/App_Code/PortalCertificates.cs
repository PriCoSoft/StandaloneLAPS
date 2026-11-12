using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace StandaloneLapsWeb
{
    public sealed class CertificateInfo
    {
        public string Role, Purpose, Sha256, Subject, Issuer, Thumbprint, SerialNumber, KeyDescription, KeyStatus, FileName;
        public DateTime NotBeforeUtc, NotAfterUtc;
        public bool Installed, Current, Expired;
    }

    // Read-only view of the SLAPS CA and recovery certificates configured in web.config (public data only).
    public static class PortalCertificates
    {
        public static CertificateInfo[] All()
        {
            var result = new List<CertificateInfo>();
            var ca = Vault.Setting("IssuingCaSha256").Trim();
            if (ca.Length > 0) result.Add(Describe(ca, "SLAPS CA", "Issues the agent client certificates; trusted by IIS for client authentication.", true, "SLAPS-CA.cer"));
            var recovery = Vault.List(Vault.Setting("RecoveryCertificateSha256"));
            for (var i = 0; i < recovery.Length; i++)
                result.Add(Describe(recovery[i], i == 0 ? "Recovery certificate" : "Previous recovery certificate",
                    i == 0 ? "Encrypts new password versions (public key in every client package); its private key decrypts them."
                           : "Kept to decrypt older password versions.",
                    i == 0, "SLAPS-Recovery-" + recovery[i].Substring(0, Math.Min(8, recovery[i].Length)) + ".cer"));
            return result.ToArray();
        }

        // Returns the public certificate only if it is one of the configured SLAPS certificates.
        public static X509Certificate2 FindConfigured(string sha256, out string fileName)
        {
            fileName = null;
            if (sha256 == null || sha256.Length != 64 || !sha256.All(Uri.IsHexDigit)) return null;
            var match = All().FirstOrDefault(info => info.Installed && string.Equals(info.Sha256, sha256, StringComparison.OrdinalIgnoreCase));
            if (match == null) return null;
            fileName = match.FileName;
            var certificate = ClientPackages.FindMachineCertificate(match.Sha256, false);
            return certificate == null ? null : new X509Certificate2(certificate.RawData);
        }

        public static string Pem(byte[] raw)
        {
            return "-----BEGIN CERTIFICATE-----\r\n" + Convert.ToBase64String(raw, Base64FormattingOptions.InsertLineBreaks) + "\r\n-----END CERTIFICATE-----\r\n";
        }

        private static CertificateInfo Describe(string sha256, string role, string purpose, bool current, string fileName)
        {
            var info = new CertificateInfo { Role = role, Purpose = purpose, Sha256 = sha256.ToUpperInvariant(), Current = current, FileName = fileName };
            var certificate = ClientPackages.FindMachineCertificate(sha256, false);
            if (certificate == null) { info.KeyStatus = "Not installed in LocalMachine\\My on this server"; return info; }
            info.Installed = true;
            info.Subject = certificate.Subject;
            info.Issuer = certificate.Issuer;
            info.Thumbprint = certificate.Thumbprint;
            info.SerialNumber = certificate.SerialNumber;
            info.NotBeforeUtc = certificate.NotBefore.ToUniversalTime();
            info.NotAfterUtc = certificate.NotAfter.ToUniversalTime();
            info.Expired = DateTime.UtcNow >= info.NotAfterUtc;
            using (var publicKey = certificate.GetRSAPublicKey())
                info.KeyDescription = publicKey == null ? certificate.PublicKey.Oid.FriendlyName : "RSA " + publicKey.KeySize + " bit";
            info.KeyStatus = KeyStatus(certificate);
            return info;
        }

        private static string KeyStatus(X509Certificate2 certificate)
        {
            if (!certificate.HasPrivateKey) return "No private key on this server";
            try
            {
                using (var key = certificate.GetRSAPrivateKey())
                {
                    if (key == null) return "Private key present, unsupported algorithm";
                    var cng = key as RSACng;
                    if (cng == null) return "Private key accessible (CSP, not CNG)";
                    var exportable = (cng.Key.ExportPolicy & (CngExportPolicies.AllowExport | CngExportPolicies.AllowPlaintextExport)) != 0;
                    return exportable ? "Private key accessible, exportable" : "Private key accessible, non-exportable";
                }
            }
            catch (CryptographicException) { return "Private key present, not accessible by the application pool"; }
        }
    }
}
