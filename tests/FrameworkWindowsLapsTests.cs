using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;
using StandaloneLapsWeb;

// Windows LAPS lookup: attribute formats, real DPAPI-NG round trip (LOCAL=user descriptor instead of a domain SID,
// same NCryptUnprotectSecret path), attribute-to-credential mapping, Graph parsing and the Entra client assertion.
// No directory, network or Graph access.
public static class FrameworkWindowsLapsTests
{
    private static int passed;
    private static void Check(bool condition, string label)
    { if (!condition) throw new Exception("FAILED: " + label); passed++; Console.WriteLine("PASS WindowsLaps " + label); }

    public static int Run()
    {
        passed = 0;
        Formats();
        Decryption();
        Graph();
        Assertion();
        Labels();
        EntraSetup();
        return passed;
    }

    public static byte[] EncryptedAttribute(byte[] blob, DateTime updatedUtc)
    {
        var fileTime = updatedUtc.ToFileTimeUtc();
        var value = new byte[16 + blob.Length];
        BitConverter.GetBytes((uint)(fileTime >> 32)).CopyTo(value, 0);
        BitConverter.GetBytes((uint)(fileTime & 0xFFFFFFFF)).CopyTo(value, 4);
        BitConverter.GetBytes((uint)blob.Length).CopyTo(value, 8);
        BitConverter.GetBytes(0u).CopyTo(value, 12);
        blob.CopyTo(value, 16);
        return value;
    }

    private static string Payload(string account, DateTime time, string password)
    {
        return "{\"n\":\"" + account + "\",\"t\":\"" + time.ToFileTimeUtc().ToString("x") + "\",\"p\":\"" + password + "\"}";
    }

    private static void Formats()
    {
        Check(WindowsLapsFormat.ValidQuery("SRV-APP01") && WindowsLapsFormat.ValidQuery("srv01.corp.example") && WindowsLapsFormat.ValidQuery("SRV*") && WindowsLapsFormat.ValidQuery("b465e4e8-e4e8-b465-e8e4-65b4e8e465b4"), "valid computer queries accepted");
        Check(!WindowsLapsFormat.ValidQuery("*") && !WindowsLapsFormat.ValidQuery("a*") && !WindowsLapsFormat.ValidQuery("S*V") && !WindowsLapsFormat.ValidQuery("x)(objectClass=*") && !WindowsLapsFormat.ValidQuery("") && !WindowsLapsFormat.ValidQuery(new string('a', 129)), "wildcard-only, inner wildcard, LDAP injection and empty queries rejected");
        Check(WindowsLapsFormat.ComputerFilter("SRV*", true, true) == "(&(objectCategory=computer)(|(name=SRV*)(dNSHostName=SRV*))(|(ms-Mcs-AdmPwd=*)(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)(msLAPS-EncryptedDSRMPassword=*)))" && WindowsLapsFormat.ComputerFilter("A1", false, true).EndsWith("(|(msLAPS-Password=*)(msLAPS-EncryptedPassword=*)(msLAPS-EncryptedDSRMPassword=*)))") && WindowsLapsFormat.ComputerFilter("A1", true, false).EndsWith("(|(ms-Mcs-AdmPwd=*)))") && WindowsLapsFormat.LdapEscape("a*(b)\\") == "a\\2a\\28b\\29\\5c", "LDAP filter lists only computers with a stored password; RFC 4515 escaping");
        Check(WindowsLapsFormat.ODataLiteral("o'brien") == "'o''brien'", "OData string literal escaping");
        var when = new DateTime(2026, 11, 24, 10, 30, 0, DateTimeKind.Utc);
        Check(WindowsLapsFormat.FileTime(when.ToFileTimeUtc().ToString()) == when && WindowsLapsFormat.FileTime("0") == null && WindowsLapsFormat.FileTime("9223372036854775807") == null, "AD FILETIME values incl. 0 and never");
        var parsed = WindowsLapsFormat.ParsePayload(Payload("Administrator", when, "Pa\\\"ss\\u00e9"), "ad", "current");
        Check(parsed.Account == "Administrator" && parsed.Password == "Pa\"ssé" && parsed.UpdatedUtc == when, "msLAPS payload JSON with escapes parsed");
        var threw = false;
        try { WindowsLapsFormat.ParsePayload("{\"n\":\"x\"}", "ad", "current"); } catch (FormatException) { threw = true; }
        Check(threw, "payload without password rejected");
        threw = false;
        try { WindowsLapsFormat.ParseFlatJson("{\"p\":\"x\"} trailing"); } catch (FormatException) { threw = true; }
        Check(threw, "trailing data after JSON rejected");
        threw = false;
        try { WindowsLapsFormat.ParseEncrypted(EncryptedAttribute(new byte[8], when).Take(20).ToArray()); } catch (FormatException) { threw = true; }
        Check(threw, "encrypted attribute with wrong size rejected");
        Check(WindowsLapsFormat.GraphPassword(Convert.ToBase64String(Encoding.UTF8.GetBytes("Pw-ä1"))) == "Pw-ä1" && WindowsLapsFormat.GraphPassword("UQBRAEAAZAA4AGYAOABnAFkA") == "QQ@d8f8gY", "Graph passwordBase64 as UTF-8 and UTF-16LE");
    }

    private static void Decryption()
    {
        var when = new DateTime(2026, 11, 20, 8, 0, 0, DateTimeKind.Utc);
        var older = when.AddDays(-30);
        Func<string, byte[]> protect = text => NativeDpapiNg.Protect("LOCAL=user", Encoding.Unicode.GetBytes(text + "\0"));
        var current = protect(Payload("LapsAdmin", when, "Current-Pw-1"));
        Check(WindowsLapsFormat.DecryptedText(NativeDpapiNg.Unprotect(current)) == Payload("LapsAdmin", when, "Current-Pw-1"), "NCryptProtectSecret/NCryptUnprotectSecret round trip");
        var threw = false;
        try { var broken = (byte[])current.Clone(); broken[broken.Length - 5] ^= 0xFF; NativeDpapiNg.Unprotect(broken); } catch (CryptographicException) { threw = true; }
        Check(threw, "tampered DPAPI-NG blob rejected");

        var attributes = new Dictionary<string, object[]>(StringComparer.OrdinalIgnoreCase)
        {
            { "name", new object[] { "SRV-APP01" } },
            { WindowsLapsFormat.EncryptedPassword, new object[] { EncryptedAttribute(current, when) } },
            { WindowsLapsFormat.EncryptedHistory, new object[] { EncryptedAttribute(protect(Payload("LapsAdmin", older, "Old-Pw-0")), older), EncryptedAttribute(new byte[] { 1, 2, 3 }, older.AddDays(-30)) } },
            { WindowsLapsFormat.Expiration, new object[] { when.AddDays(30).ToFileTimeUtc().ToString() } },
            { WindowsLapsFormat.LegacyPassword, new object[] { "Legacy-Pw" } },
            { WindowsLapsFormat.LegacyExpiration, new object[] { when.AddDays(10).ToFileTimeUtc().ToString() } }
        };
        Func<IList<byte[]>, IList<DecryptOutcome>> decrypt = blobs => blobs.Select(b =>
        {
            try { return new DecryptOutcome { Data = NativeDpapiNg.Unprotect(b) }; }
            catch (CryptographicException ex) { return new DecryptOutcome { Error = ex.Message }; }
        }).ToList();
        var all = new ActiveDirectoryLapsOptions { Legacy = true, Modern = true, Decrypt = true, History = true };
        var result = ActiveDirectoryLapsReader.Read(attributes, all, decrypt);
        var first = result.Credentials[0];
        Check(first.Source == "ad" && first.Kind == "current" && first.Encrypted && first.Account == "LapsAdmin" && first.Password == "Current-Pw-1" && first.ExpiresUtc == when.AddDays(30), "encrypted current password decrypted and listed first with expiry");
        Check(result.Credentials[1].Source == "ad-legacy" && result.Credentials[1].Password == "Legacy-Pw" && result.Credentials[1].ExpiresUtc == when.AddDays(10), "legacy ms-Mcs-AdmPwd listed after Windows LAPS");
        var history = result.Credentials.Where(c => c.Kind == "history").ToList();
        Check(history.Count == 2 && history[0].Password == "Old-Pw-0" && history[1].Error != null && history[1].Password == null, "history decrypted newest first; undecryptable entry reported, not hidden");

        var none = ActiveDirectoryLapsReader.Read(attributes, new ActiveDirectoryLapsOptions { Legacy = false, Modern = true, Decrypt = false, History = true }, b => { throw new InvalidOperationException("must not decrypt"); });
        Check(none.Credentials.Count == 0 && none.Errors.Any(e => e.Contains("decryption is disabled")), "WindowsLapsAdDecrypt=false: no decryption attempt, clear message");
        var legacyOnly = ActiveDirectoryLapsReader.Read(attributes, new ActiveDirectoryLapsOptions { Legacy = true, Modern = false, Decrypt = true, History = true }, decrypt);
        Check(legacyOnly.Credentials.Count == 1 && legacyOnly.Credentials[0].Source == "ad-legacy", "WindowsLapsAdModern=false shows only legacy LAPS");
        var plain = ActiveDirectoryLapsReader.Read(new Dictionary<string, object[]> { { WindowsLapsFormat.Password, new object[] { Payload("Administrator", when, "Plain-Pw") } } }, all, decrypt);
        Check(plain.Credentials.Count == 1 && !plain.Credentials[0].Encrypted && plain.Credentials[0].Password == "Plain-Pw", "unencrypted msLAPS-Password parsed");
        var failing = ActiveDirectoryLapsReader.Read(attributes, new ActiveDirectoryLapsOptions { Modern = true, Decrypt = true }, b => { throw new InvalidOperationException("helper missing"); });
        Check(failing.Errors.Any(e => e.Contains("helper missing")), "decryptor failure surfaces as error message");
    }

    private static void Graph()
    {
        var list = "{\"value\":[{\"id\":\"b465e4e8-e4e8-b465-e8e4-65b4e8e465b4\",\"deviceName\":\"LAPS_TEST\",\"lastBackupDateTime\":\"2023-04-21T13:45:30.0000000Z\",\"refreshDateTime\":\"2023-05-20T13:45:30Z\"}]}";
        var devices = EntraLaps.ParseDevices(list);
        Check(devices.Count == 1 && devices[0].Source == "entra" && devices[0].Name == "LAPS_TEST" && devices[0].LastBackupUtc == new DateTime(2023, 4, 21, 13, 45, 30, DateTimeKind.Utc), "Graph device list parsed");
        var single = "{\"id\":\"b465e4e8-e4e8-b465-e8e4-65b4e8e465b4\",\"deviceName\":\"LAPS_TEST\",\"refreshDateTime\":\"2023-05-20T13:45:30Z\",\"credentials\":[" +
            "{\"accountName\":\"Administrator\",\"backupDateTime\":\"2023-02-23T13:45:30Z\",\"passwordBase64\":\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes("Oldest")) + "\"}," +
            "{\"accountName\":\"LocalAdmin\",\"backupDateTime\":\"2023-04-21T13:45:30Z\",\"passwordBase64\":\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes("Newest")) + "\"}," +
            "{\"accountName\":\"LocalAdmin\",\"backupDateTime\":\"2023-03-22T13:45:30Z\",\"passwordBase64\":\"not base64!\"}]}";
        var result = EntraLaps.ParseCredentials(single, true);
        Check(result.Credentials.Count == 3 && result.Credentials[0].Kind == "current" && result.Credentials[0].Password == "Newest" && result.Credentials[0].ExpiresUtc == new DateTime(2023, 5, 20, 13, 45, 30, DateTimeKind.Utc), "Graph credentials: newest is current with next rotation");
        Check(result.Credentials[1].Error != null && result.Credentials[2].Password == "Oldest", "invalid base64 reported per entry");
        Check(EntraLaps.ParseCredentials(single, false).Credentials.Count == 1, "WindowsLapsEntraHistory=false keeps only the current password");
        Check(EntraLaps.ParseCredentials("{\"value\":{\"id\":\"b465e4e8-e4e8-b465-e8e4-65b4e8e465b4\",\"credentials\":[]}}", true).Errors.Count == 1, "documented {value:{...}} wrapper accepted; empty credentials explained");
        Check(EntraLaps.ErrorText("{\"error\":{\"code\":\"Authorization_RequestDenied\",\"message\":\"Insufficient privileges\"}}") == "Insufficient privileges", "Graph error message extracted");
    }

    private static void Labels()
    {
        Check(WindowsLapsFormat.Title(new WindowsLapsCredential { Source = "ad", Kind = "current" }) == "Windows LAPS · current password" &&
              WindowsLapsFormat.Title(new WindowsLapsCredential { Source = "ad-legacy", Kind = "current" }) == "Legacy LAPS · current password" &&
              WindowsLapsFormat.Title(new WindowsLapsCredential { Source = "entra", Kind = "history" }) == "Entra ID · previous password", "card titles name the LAPS flavour (mixed operation shows both clearly)");
    }

    private static Dictionary<string, object> JwtPart(string jwt, int index)
    {
        return new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(EntraTokenValidator.Base64UrlDecode(jwt.Split('.')[index])));
    }

    // Entra setup: certificate created and stored protected, used for tokens, renewed via addKey with proof of
    // possession, previous key removed. Microsoft Graph and the token endpoint are simulated (EntraLaps.Transport).
    private static void EntraSetup()
    {
        var directory = Path.Combine(Path.GetTempPath(), "slaps-entra-" + Guid.NewGuid().ToString("N").Substring(0, 8));
        Directory.CreateDirectory(directory);
        var objectId = "99999999-0000-1111-2222-333333333333";
        var addedKeys = new List<string>();
        var removedKeys = new List<string>();
        var acceptedThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string lastProofIssuer = null;
        var proofValid = true;
        try
        {
            EntraAppCredential.Protector = data => data.Select(b => (byte)(b ^ 0x5A)).ToArray();
            EntraAppCredential.Unprotector = data => data.Select(b => (byte)(b ^ 0x5A)).ToArray();
            EntraAppCredential.PathProvider = () => Path.Combine(directory, "entra-app-credential.json");
            EntraLaps.ResetToken();
            Check(!EntraAppCredential.Configured && EntraLaps.CredentialSource == "Not configured", "no Graph credential before the setup");

            var state = EntraAppCredential.Create("test:admin");
            var stored = File.ReadAllText(EntraAppCredential.PathProvider());
            using (var current = EntraAppCredential.Current())
                Check(current.HasPrivateKey && current.Thumbprint == state.currentThumbprint && (current.NotAfter.ToUniversalTime() - DateTime.UtcNow).TotalDays > 360 &&
                      current.Extensions.OfType<X509EnhancedKeyUsageExtension>().Single().EnhancedKeyUsages[0].Value == EntraAppCredential.ClientAuthOid, "setup creates a one-year client-authentication certificate with private key");
            Check(!stored.Contains("MII") && EntraAppCredential.PublicCertificate().Length > 300, "PFX is stored only in protected form; the public .cer is available for upload");
            Check(EntraLaps.CredentialSource.Contains("created by the setup"), "setup certificate becomes the Graph credential");
            acceptedThumbprints.Add(state.currentThumbprint);

            EntraLaps.Transport = (url, method, body, bearer) =>
            {
                if (url.Contains("/oauth2/v2.0/token"))
                {
                    var assertion = Uri.UnescapeDataString(body.Split('&').First(p => p.StartsWith("client_assertion=")).Substring(17));
                    var thumbprint = BitConverter.ToString(EntraTokenValidator.Base64UrlDecode((string)JwtPart(assertion, 0)["x5t"])).Replace("-", "");
                    if (!acceptedThumbprints.Contains(thumbprint)) throw new WindowsLapsException("AADSTS700027: key not found");
                    return "{\"access_token\":\"tok-" + thumbprint + "\",\"expires_in\":3600}";
                }
                if (url.EndsWith("/applications/" + objectId + "/addKey"))
                {
                    var request = new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(body);
                    var proof = JwtPart((string)request["proof"], 1);
                    lastProofIssuer = (string)proof["iss"];
                    proofValid = (string)proof["aud"] == "00000002-0000-0000-c000-000000000000" && Convert.ToInt64(proof["exp"]) - Convert.ToInt64(proof["nbf"]) == 600 && bearer.StartsWith("tok-");
                    var key = (Dictionary<string, object>)request["keyCredential"];
                    using (var added = new X509Certificate2(Convert.FromBase64String((string)key["key"])))
                    {
                        if ((string)key["type"] != "AsymmetricX509Cert" || (string)key["usage"] != "Verify" || added.HasPrivateKey) throw new WindowsLapsException("bad key");
                        acceptedThumbprints.Add(added.Thumbprint);
                    }
                    var keyId = Guid.NewGuid().ToString("D");
                    addedKeys.Add(keyId);
                    return "{\"keyId\":\"" + keyId + "\",\"type\":\"AsymmetricX509Cert\"}";
                }
                if (url.EndsWith("/applications/" + objectId + "/removeKey"))
                {
                    removedKeys.Add((string)new JavaScriptSerializer().Deserialize<Dictionary<string, object>>(body)["keyId"]);
                    return "";
                }
                if (url.Contains("/directory/deviceLocalCredentials?$top=1")) return "{\"value\":[{\"id\":\"b465e4e8-e4e8-b465-e8e4-65b4e8e465b4\",\"deviceName\":\"X\"}]}";
                throw new WindowsLapsException("unexpected " + method + " " + url);
            };
            Check(EntraLaps.Test().Contains("works"), "connection test acquires a token with the setup certificate and reads Graph");

            var threw = false;
            try { EntraLaps.Renew("test:admin"); } catch (WindowsLapsException ex) { threw = ex.Message.Contains("Object ID"); }
            Check(threw && EntraAppCredential.Load().lastRenewalError.Contains("Object ID"), "renewal without Object ID is refused and the reason is kept for the Settings page");

            state = EntraAppCredential.Load();
            state.objectId = objectId;
            state.currentNotAfter = EntraAppCredential.Stamp(DateTime.UtcNow.AddDays(10));
            EntraAppCredential.Save(state);
            Check(EntraAppCredential.NeedsRenewal(EntraAppCredential.Load(), DateTime.UtcNow), "renewal is due 30 days before expiry");
            var firstThumbprint = state.currentThumbprint;
            var message = EntraLaps.Renew("test:admin");
            state = EntraAppCredential.Load();
            Check(message.StartsWith("Renewed") && state.currentThumbprint != firstThumbprint && state.currentKeyId == addedKeys[0] && state.pending == null && state.lastRenewalError == null, "renewal adds a new key (addKey) and switches to it");
            Check(proofValid && lastProofIssuer == objectId, "addKey proof of possession: audience 00000002-..., issuer = application object ID, 10 minutes");
            Check(removedKeys.Count == 0 && message.Contains("stays in the app registration"), "manually uploaded first certificate (unknown key ID) is left to expire");

            // Entra has not replicated the new key yet: it stays pending, the current certificate stays active.
            var secondThumbprint = state.currentThumbprint;
            var replicate = acceptedThumbprints;
            acceptedThumbprints = new HashSet<string>(replicate, StringComparer.OrdinalIgnoreCase);
            EntraLaps.Transport = WrapRejectingNew(EntraLaps.Transport, () => acceptedThumbprints, secondThumbprint);
            message = EntraLaps.Renew("test:admin");
            state = EntraAppCredential.Load();
            Check(message.Contains("becomes active as soon as") && state.pending != null && state.currentThumbprint == secondThumbprint, "new key not yet accepted: kept pending, current certificate stays in use");
            rejectNew = false;
            message = EntraLaps.Renew("test:admin");
            state = EntraAppCredential.Load();
            Check(message.StartsWith("Renewed") && state.pending == null && state.currentThumbprint != secondThumbprint && addedKeys.Count == 2, "pending key is activated later without adding another key");
            Check(removedKeys.Count == 1 && removedKeys[0] == addedKeys[0] && message.Contains("was removed"), "previous key with known key ID is removed (removeKey)");
        }
        finally
        {
            EntraLaps.Transport = null;
            EntraLaps.ResetToken();
            EntraAppCredential.PathProvider = () => Vault.VaultPath("entra-app-credential.json");
            try { Directory.Delete(directory, true); } catch (IOException) { }
        }
    }

    private static bool rejectNew;

    // Simulates replication delay: tokens for certificates other than the given one fail while rejectNew is set.
    private static Func<string, string, string, string, string> WrapRejectingNew(Func<string, string, string, string, string> inner, Func<HashSet<string>> accepted, string onlyThumbprint)
    {
        rejectNew = true;
        return (url, method, body, bearer) =>
        {
            if (rejectNew && url.Contains("/oauth2/v2.0/token"))
            {
                var assertion = Uri.UnescapeDataString(body.Split('&').First(p => p.StartsWith("client_assertion=")).Substring(17));
                var thumbprint = BitConverter.ToString(EntraTokenValidator.Base64UrlDecode((string)JwtPart(assertion, 0)["x5t"])).Replace("-", "");
                if (!string.Equals(thumbprint, onlyThumbprint, StringComparison.OrdinalIgnoreCase)) throw new WindowsLapsException("AADSTS700027: key not found (replication)");
            }
            return inner(url, method, body, bearer);
        };
    }

    private static void Assertion()
    {
        using (var rsa = new RSACng(2048))
        {
            var request = new CertificateRequest("CN=SLAPS Graph test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using (var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1)))
            {
                var now = DateTime.UtcNow;
                var jwt = EntraLaps.ClientAssertion(certificate, "11111111-2222-3333-4444-555555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", now);
                var parts = jwt.Split('.');
                var serializer = new JavaScriptSerializer();
                var header = serializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(EntraTokenValidator.Base64UrlDecode(parts[0])));
                var claims = serializer.Deserialize<Dictionary<string, object>>(Encoding.UTF8.GetString(EntraTokenValidator.Base64UrlDecode(parts[1])));
                var valid = rsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), EntraTokenValidator.Base64UrlDecode(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Check(valid && (string)header["alg"] == "RS256" && (string)header["x5t"] == EntraTokenValidator.Base64UrlEncode(certificate.GetCertHash()), "client assertion signed RS256 with x5t thumbprint");
                Check((string)claims["aud"] == "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token" && (string)claims["iss"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" && (string)claims["sub"] == (string)claims["iss"] && Convert.ToInt64(claims["exp"]) > Convert.ToInt64(claims["iat"]), "client assertion audience, issuer, subject and lifetime");
            }
        }
    }
}
