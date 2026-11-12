using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace StandaloneLapsWeb
{
    public sealed class IssuedClient
    {
        public string DeviceId, DisplayName, CertificateSha256, PfxPassword;
        public byte[] Pfx, CertificateRaw;
        public DateTime NotAfterUtc;
    }

    // Small issuing CA for agent client certificates. It uses the .NET Framework 4.7.2 CertificateRequest API
    // and adds the few DER structures the framework cannot build itself (AKI/CDP extensions and the CRL).
    // This file has no System.Web dependency so the server installer can compile it with Add-Type.
    public static class SlapsCertificateAuthority
    {
        public const string ClientAuthOid = "1.3.6.1.5.5.7.3.2";
        public const int ClientYears = 30;
        private const string PasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
        private static readonly byte[] Sha256WithRsa = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00 };
        private static readonly byte[] AuthorityKeyIdentifierOid = { 0x06, 0x03, 0x55, 0x1D, 0x23 };
        private static readonly byte[] CrlNumberOid = { 0x06, 0x03, 0x55, 0x1D, 0x14 };

        public static bool ValidName(string name)
        {
            return !string.IsNullOrWhiteSpace(name) && name.Length <= 64 && name.Trim() == name &&
                name.All(c => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == ' ');
        }

        public static string Sha256(byte[] raw)
        {
            using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(raw)).Replace("-", "");
        }

        public static void ValidateIssuer(X509Certificate2 ca)
        {
            if (ca == null || !ca.HasPrivateKey) throw new CryptographicException("The SLAPS CA certificate with its private key is unavailable.");
            var constraints = ca.Extensions.OfType<X509BasicConstraintsExtension>().FirstOrDefault();
            if (constraints == null || !constraints.CertificateAuthority) throw new CryptographicException("The configured issuing certificate is not a CA certificate.");
            var usage = ca.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (usage != null && (usage.KeyUsages & (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign)) != (X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign))
                throw new CryptographicException("The SLAPS CA certificate must allow certificate and CRL signing.");
            var now = DateTime.UtcNow;
            if (now < ca.NotBefore.ToUniversalTime() || now >= ca.NotAfter.ToUniversalTime()) throw new CryptographicException("The SLAPS CA certificate is not currently valid.");
        }

        public static IssuedClient IssueClient(X509Certificate2 ca, string displayName, Guid deviceId, string crlUrl, DateTimeOffset now)
        {
            ValidateIssuer(ca);
            if (!ValidName(displayName)) throw new ArgumentException("Use 1-64 letters, digits, spaces, dots, dashes or underscores for the device name.");
            if (deviceId == Guid.Empty) throw new ArgumentException("A device ID is required.");
            var notBefore = now.AddHours(-1);
            var caStart = new DateTimeOffset(ca.NotBefore.ToUniversalTime());
            if (notBefore < caStart) notBefore = caStart;
            var notAfter = now.AddYears(ClientYears);
            var caEnd = new DateTimeOffset(ca.NotAfter.ToUniversalTime()).AddDays(-1);
            if (notAfter > caEnd) notAfter = caEnd;
            if (notAfter <= now.AddDays(30)) throw new CryptographicException("The SLAPS CA certificate expires too soon to issue client certificates.");
            using (var key = new RSACng(3072))
            {
                var subject = new X500DistinguishedName("CN=SLAPS Agent " + displayName + ", OU=" + deviceId.ToString("D"));
                var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ClientAuthOid) }, false));
                request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
                var authority = AuthorityKeyIdentifier(ca);
                if (authority != null) request.CertificateExtensions.Add(authority);
                if (!string.IsNullOrEmpty(crlUrl)) request.CertificateExtensions.Add(CrlDistributionPoint(crlUrl));
                var serial = new byte[16];
                using (var random = RandomNumberGenerator.Create()) random.GetBytes(serial);
                serial[0] = (byte)((serial[0] & 0x7F) | 0x01);
                using (var issued = request.Create(ca, notBefore, notAfter, serial))
                using (var withKey = issued.CopyWithPrivateKey(key))
                {
                    var password = NewPassword(24);
                    return new IssuedClient
                    {
                        DeviceId = deviceId.ToString("D"), DisplayName = displayName, CertificateSha256 = Sha256(issued.RawData), CertificateRaw = issued.RawData,
                        PfxPassword = password, Pfx = withKey.Export(X509ContentType.Pfx, password), NotAfterUtc = issued.NotAfter.ToUniversalTime()
                    };
                }
            }
        }

        // An empty CRL valid until shortly before the CA expires. It is imported into the IIS host's
        // intermediate CA store, so revocation checks of agent certificates succeed without network access.
        // Day-to-day revocation is done by removing the certificate pin in the SLAPS portal.
        public static byte[] BuildCrl(X509Certificate2 ca, long crlNumber, DateTimeOffset thisUpdate, DateTimeOffset nextUpdate)
        {
            ValidateIssuer(ca);
            if (crlNumber < 1 || nextUpdate <= thisUpdate) throw new ArgumentException("Invalid CRL number or validity.");
            var extensions = new List<byte[]>();
            var authority = AuthorityKeyIdentifier(ca);
            if (authority != null) extensions.Add(Der(0x30, Concat(AuthorityKeyIdentifierOid, Der(0x04, authority.RawData))));
            extensions.Add(Der(0x30, Concat(CrlNumberOid, Der(0x04, Integer(crlNumber)))));
            var tbs = Der(0x30, Concat(Integer(1), Sha256WithRsa, ca.SubjectName.RawData, Time(thisUpdate), Time(nextUpdate), Der(0xA0, Der(0x30, Concat(extensions.ToArray())))));
            byte[] signature;
            using (var rsa = ca.GetRSAPrivateKey())
            {
                if (rsa == null) throw new CryptographicException("The SLAPS CA private key is not an RSA key.");
                signature = rsa.SignData(tbs, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            }
            return Der(0x30, Concat(tbs, Sha256WithRsa, Der(0x03, Concat(new byte[] { 0 }, signature))));
        }

        public static X509Extension AuthorityKeyIdentifier(X509Certificate2 ca)
        {
            var subjectKey = ca.Extensions.OfType<X509SubjectKeyIdentifierExtension>().FirstOrDefault();
            if (subjectKey == null || string.IsNullOrEmpty(subjectKey.SubjectKeyIdentifier)) return null;
            return new X509Extension(new Oid("2.5.29.35"), Der(0x30, Der(0x80, Hex(subjectKey.SubjectKeyIdentifier))), false);
        }

        public static X509Extension CrlDistributionPoint(string url)
        {
            Uri uri;
            if (!Uri.TryCreate(url, UriKind.Absolute, out uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
                throw new ArgumentException("The CRL distribution URL must be an absolute HTTP(S) URL.");
            var name = Der(0x86, Encoding.ASCII.GetBytes(uri.AbsoluteUri));
            return new X509Extension(new Oid("2.5.29.31"), Der(0x30, Der(0x30, Der(0xA0, Der(0xA0, name)))), false);
        }

        public static string NewPassword(int length)
        {
            var result = new StringBuilder(length);
            var buffer = new byte[1];
            using (var random = RandomNumberGenerator.Create())
                while (result.Length < length)
                {
                    random.GetBytes(buffer);
                    if (buffer[0] >= PasswordAlphabet.Length * 4) continue;
                    result.Append(PasswordAlphabet[buffer[0] % PasswordAlphabet.Length]);
                }
            return result.ToString();
        }

        private static byte[] Time(DateTimeOffset value)
        {
            var utc = value.UtcDateTime;
            return utc.Year >= 2050
                ? Der(0x18, Encoding.ASCII.GetBytes(utc.ToString("yyyyMMddHHmmss", CultureInfo.InvariantCulture) + "Z"))
                : Der(0x17, Encoding.ASCII.GetBytes(utc.ToString("yyMMddHHmmss", CultureInfo.InvariantCulture) + "Z"));
        }

        private static byte[] Integer(long value)
        {
            var bytes = new List<byte>();
            do { bytes.Insert(0, (byte)(value & 0xFF)); value >>= 8; } while (value > 0);
            if ((bytes[0] & 0x80) != 0) bytes.Insert(0, 0);
            return Der(0x02, bytes.ToArray());
        }

        private static byte[] Der(byte tag, byte[] content)
        {
            var length = new List<byte>();
            if (content.Length < 0x80) length.Add((byte)content.Length);
            else
            {
                var value = content.Length;
                while (value > 0) { length.Insert(0, (byte)(value & 0xFF)); value >>= 8; }
                length.Insert(0, (byte)(0x80 | length.Count));
            }
            return Concat(new[] { tag }, length.ToArray(), content);
        }

        private static byte[] Concat(params byte[][] parts)
        {
            var result = new byte[parts.Sum(part => part.Length)];
            var offset = 0;
            foreach (var part in parts) { Buffer.BlockCopy(part, 0, result, offset, part.Length); offset += part.Length; }
            return result;
        }

        private static byte[] Hex(string value)
        {
            if (value.Length % 2 != 0) throw new FormatException("Invalid key identifier.");
            var result = new byte[value.Length / 2];
            for (var i = 0; i < result.Length; i++) result[i] = byte.Parse(value.Substring(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            return result;
        }
    }
}
