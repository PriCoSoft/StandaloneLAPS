using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace StandaloneLapsWeb
{
    // Read-only view of passwords that Windows LAPS / legacy Microsoft LAPS stored in Active Directory or
    // Microsoft Entra ID. Shared by the IIS portal (C# 5, .NET Framework) and the container server (.NET 10):
    // no System.Web, no JSON library, only format parsing and the native DPAPI-NG call.
    public sealed class WindowsLapsCredential
    {
        public string Source { get; set; }        // "ad-legacy", "ad", "entra"
        public string Kind { get; set; }          // "current", "history", "dsrm", "dsrm-history"
        public string Account { get; set; }
        public string Password { get; set; }
        public DateTime? UpdatedUtc { get; set; }
        public DateTime? ExpiresUtc { get; set; }
        public bool Encrypted { get; set; }
        public string Error { get; set; }
        public bool IsCurrent { get { return Kind == "current"; } }
        public bool IsHistory { get { return Kind == "history" || Kind == "dsrm-history"; } }
    }

    public sealed class WindowsLapsComputer
    {
        public string Source { get; set; }        // "ad" or "entra"
        public string Id { get; set; }            // AD objectGUID or Entra device ID
        public string DistinguishedName { get; set; }
        public string Name { get; set; }
        public string DnsName { get; set; }
        public string OperatingSystem { get; set; }
        public string Description { get; set; }
        public DateTime? LegacyExpiresUtc { get; set; }
        public DateTime? ExpiresUtc { get; set; }
        public DateTime? LastBackupUtc { get; set; }
        public bool HasLegacyExpiry { get { return LegacyExpiresUtc.HasValue; } }
    }

    public sealed class WindowsLapsResult
    {
        public WindowsLapsResult() { Credentials = new List<WindowsLapsCredential>(); Errors = new List<string>(); }
        public List<WindowsLapsCredential> Credentials { get; private set; }
        public List<string> Errors { get; private set; }
    }

    public sealed class EncryptedLapsBlob
    {
        public DateTime UpdatedUtc { get; set; }
        public uint Flags { get; set; }
        public byte[] ProtectedData { get; set; }
    }

    public static class WindowsLapsFormat
    {
        public const string LegacyPassword = "ms-Mcs-AdmPwd";
        public const string LegacyExpiration = "ms-Mcs-AdmPwdExpirationTime";
        public const string Password = "msLAPS-Password";
        public const string Expiration = "msLAPS-PasswordExpirationTime";
        public const string EncryptedPassword = "msLAPS-EncryptedPassword";
        public const string EncryptedHistory = "msLAPS-EncryptedPasswordHistory";
        public const string EncryptedDsrm = "msLAPS-EncryptedDSRMPassword";
        public const string EncryptedDsrmHistory = "msLAPS-EncryptedDSRMPasswordHistory";

        public static readonly string[] SearchAttributes = { "name", "dNSHostName", "operatingSystem", "description", "distinguishedName", LegacyExpiration, Expiration };

        public static string SourceLabel(string source)
        {
            switch (source)
            {
                case "ad-legacy": return "Active Directory · legacy Microsoft LAPS";
                case "ad": return "Active Directory · Windows LAPS";
                case "entra": return "Microsoft Entra ID · Windows LAPS";
                default: return source;
            }
        }

        // Card title, e.g. "Windows LAPS · current password" / "Legacy LAPS · current password" (mixed operation shows both).
        public static string Title(WindowsLapsCredential credential)
        {
            var source = credential.Source == "ad-legacy" ? "Legacy LAPS" : credential.Source == "entra" ? "Entra ID" : "Windows LAPS";
            var kind = KindLabel(credential.Kind);
            return source + " · " + char.ToLowerInvariant(kind[0]) + kind.Substring(1);
        }

        public static string KindLabel(string kind)
        {
            switch (kind)
            {
                case "current": return "Current password";
                case "history": return "Previous password";
                case "dsrm": return "DSRM password";
                case "dsrm-history": return "Previous DSRM password";
                default: return kind;
            }
        }

        // Computer names, DNS names and Entra device IDs; '*' only as a trailing prefix wildcard.
        public static bool ValidQuery(string query)
        {
            if (string.IsNullOrEmpty(query) || query.Length > 128) return false;
            for (var i = 0; i < query.Length; i++)
            {
                var c = query[i];
                var ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || (c == '*' && i == query.Length - 1 && i >= 2);
                if (!ok) return false;
            }
            return true;
        }

        // RFC 4515 escaping; ValidQuery already limits the characters, this is defence in depth.
        public static string LdapEscape(string value)
        {
            var text = new StringBuilder();
            foreach (var c in value ?? "")
            {
                if (c == '\\' || c == '*' || c == '(' || c == ')' || c == '\0' || c > 0x7E || c < 0x20) text.Append('\\').Append(((int)c & 0xFF).ToString("x2", CultureInfo.InvariantCulture));
                else text.Append(c);
            }
            return text.ToString();
        }

        // Only computers with a stored password are listed. Presence tests on the confidential password attributes match only
        // where the reading identity has the LAPS read permission, so the list shows exactly what can be revealed.
        public static string ComputerFilter(string query, bool legacy, bool modern)
        {
            var prefix = query.EndsWith("*", StringComparison.Ordinal);
            var value = LdapEscape(prefix ? query.Substring(0, query.Length - 1) : query) + (prefix ? "*" : "");
            var stored = (legacy ? "(" + LegacyPassword + "=*)" : "") + (modern ? "(" + Password + "=*)(" + EncryptedPassword + "=*)(" + EncryptedDsrm + "=*)" : "");
            return "(&(objectCategory=computer)(|(name=" + value + ")(dNSHostName=" + value + "))(|" + (stored.Length == 0 ? "(objectClass=__none__)" : stored) + "))";
        }

        public static string ODataLiteral(string value) { return "'" + (value ?? "").Replace("'", "''") + "'"; }

        // Large-integer FILETIME as AD returns it (decimal string); 0 or "never" values give null.
        public static DateTime? FileTime(string value)
        {
            long ticks;
            if (string.IsNullOrEmpty(value) || !long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out ticks)) return null;
            return FileTime(ticks);
        }

        public static DateTime? FileTime(long ticks)
        {
            if (ticks <= 0 || ticks >= DateTime.MaxValue.ToFileTimeUtc()) return null;
            return DateTime.FromFileTimeUtc(ticks);
        }

        public static DateTime? FileTimeHex(string value)
        {
            long ticks;
            if (string.IsNullOrEmpty(value) || !long.TryParse(value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out ticks)) return null;
            return FileTime(ticks);
        }

        // msLAPS-Encrypted*: 16-byte header (FILETIME high/low, blob size, flags), then a DPAPI-NG (CMS) blob.
        public static EncryptedLapsBlob ParseEncrypted(byte[] value)
        {
            if (value == null || value.Length < 17) throw new FormatException("The encrypted LAPS attribute is too short.");
            var high = BitConverter.ToUInt32(value, 0);
            var low = BitConverter.ToUInt32(value, 4);
            var size = BitConverter.ToUInt32(value, 8);
            var flags = BitConverter.ToUInt32(value, 12);
            if (size == 0 || size > value.Length - 16) throw new FormatException("The encrypted LAPS attribute has an invalid size.");
            var data = new byte[size];
            Buffer.BlockCopy(value, 16, data, 0, (int)size);
            var updated = FileTime(((long)high << 32) | low);
            return new EncryptedLapsBlob { UpdatedUtc = updated ?? DateTime.MinValue, Flags = flags, ProtectedData = data };
        }

        // Decrypted Windows LAPS blobs are UTF-16LE JSON, usually NUL-terminated.
        public static string DecryptedText(byte[] value)
        {
            if (value == null) return null;
            return Encoding.Unicode.GetString(value).TrimEnd('\0');
        }

        // {"n":"account","t":"<FILETIME hex>","p":"password"}; used by msLAPS-Password and decrypted blobs.
        public static WindowsLapsCredential ParsePayload(string json, string source, string kind)
        {
            var values = ParseFlatJson(json);
            string account, time, password;
            values.TryGetValue("n", out account);
            values.TryGetValue("t", out time);
            if (!values.TryGetValue("p", out password) || password == null) throw new FormatException("The LAPS payload contains no password.");
            return new WindowsLapsCredential { Source = source, Kind = kind, Account = account, Password = password, UpdatedUtc = FileTimeHex(time) };
        }

        // Graph returns passwordBase64; the bytes are UTF-8 in practice, UTF-16LE in the documentation samples.
        public static string GraphPassword(string base64)
        {
            var bytes = Convert.FromBase64String(base64 ?? "");
            var utf16 = bytes.Length >= 2 && bytes.Length % 2 == 0;
            for (var i = 1; utf16 && i < bytes.Length; i += 2) if (bytes[i] != 0) utf16 = false;
            return (utf16 ? Encoding.Unicode.GetString(bytes) : Encoding.UTF8.GetString(bytes)).TrimEnd('\0');
        }

        // Minimal parser for a flat JSON object whose values are strings, numbers, booleans or null.
        public static Dictionary<string, string> ParseFlatJson(string json)
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            var text = json ?? "";
            var i = 0;
            Skip(text, ref i);
            Expect(text, ref i, '{');
            Skip(text, ref i);
            if (i < text.Length && text[i] == '}') { i++; return Finish(text, i, result); }
            while (true)
            {
                Skip(text, ref i);
                var name = ReadString(text, ref i);
                Skip(text, ref i);
                Expect(text, ref i, ':');
                Skip(text, ref i);
                string value;
                if (i < text.Length && text[i] == '"') value = ReadString(text, ref i);
                else
                {
                    var start = i;
                    while (i < text.Length && text[i] != ',' && text[i] != '}' && !char.IsWhiteSpace(text[i])) i++;
                    value = text.Substring(start, i - start);
                    if (value == "null") value = null;
                    else if (value.Length == 0 || (value != "true" && value != "false" && !IsNumber(value))) throw new FormatException("Invalid JSON value.");
                }
                result[name] = value;
                Skip(text, ref i);
                if (i < text.Length && text[i] == ',') { i++; continue; }
                Expect(text, ref i, '}');
                return Finish(text, i, result);
            }
        }

        private static Dictionary<string, string> Finish(string text, int i, Dictionary<string, string> result)
        {
            Skip(text, ref i);
            if (i != text.Length) throw new FormatException("Unexpected data after the JSON object.");
            return result;
        }

        private static bool IsNumber(string value)
        {
            double number;
            return double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out number);
        }

        private static void Skip(string text, ref int i) { while (i < text.Length && char.IsWhiteSpace(text[i])) i++; }

        private static void Expect(string text, ref int i, char c)
        {
            if (i >= text.Length || text[i] != c) throw new FormatException("Invalid JSON: '" + c + "' expected.");
            i++;
        }

        private static string ReadString(string text, ref int i)
        {
            Expect(text, ref i, '"');
            var value = new StringBuilder();
            while (true)
            {
                if (i >= text.Length) throw new FormatException("Unterminated JSON string.");
                var c = text[i++];
                if (c == '"') return value.ToString();
                if (c != '\\') { value.Append(c); continue; }
                if (i >= text.Length) throw new FormatException("Unterminated JSON escape.");
                var e = text[i++];
                switch (e)
                {
                    case '"': value.Append('"'); break;
                    case '\\': value.Append('\\'); break;
                    case '/': value.Append('/'); break;
                    case 'b': value.Append('\b'); break;
                    case 'f': value.Append('\f'); break;
                    case 'n': value.Append('\n'); break;
                    case 'r': value.Append('\r'); break;
                    case 't': value.Append('\t'); break;
                    case 'u':
                        if (i + 4 > text.Length) throw new FormatException("Invalid JSON unicode escape.");
                        value.Append((char)int.Parse(text.Substring(i, 4), NumberStyles.HexNumber, CultureInfo.InvariantCulture));
                        i += 4;
                        break;
                    default: throw new FormatException("Invalid JSON escape.");
                }
            }
        }
    }

    public sealed class DecryptOutcome
    {
        public byte[] Data { get; set; }
        public string Error { get; set; }
    }

    public sealed class ActiveDirectoryLapsOptions
    {
        public bool Legacy { get; set; }
        public bool Modern { get; set; }
        public bool Decrypt { get; set; }
        public bool History { get; set; }
    }

    // Turns the LAPS attributes of one computer object into credentials. Attribute values are string (legacy and
    // msLAPS-Password, expiration times) or byte[] (encrypted attributes). Decryption is batched so the container's
    // Python helper needs one process and one key lookup per computer.
    public static class ActiveDirectoryLapsReader
    {
        public static readonly string[] RevealAttributes =
        {
            "name", WindowsLapsFormat.LegacyPassword, WindowsLapsFormat.LegacyExpiration, WindowsLapsFormat.Password, WindowsLapsFormat.Expiration,
            WindowsLapsFormat.EncryptedPassword, WindowsLapsFormat.EncryptedHistory, WindowsLapsFormat.EncryptedDsrm, WindowsLapsFormat.EncryptedDsrmHistory
        };

        public static WindowsLapsResult Read(IDictionary<string, object[]> attributes, ActiveDirectoryLapsOptions options, Func<IList<byte[]>, IList<DecryptOutcome>> decrypt)
        {
            var result = new WindowsLapsResult();
            var expires = WindowsLapsFormat.FileTime(Text(attributes, WindowsLapsFormat.Expiration));
            if (options.Modern)
            {
                var plain = Text(attributes, WindowsLapsFormat.Password);
                if (plain != null)
                {
                    try
                    {
                        var credential = WindowsLapsFormat.ParsePayload(plain, "ad", "current");
                        credential.ExpiresUtc = expires;
                        result.Credentials.Add(credential);
                    }
                    catch (FormatException) { result.Errors.Add("msLAPS-Password could not be parsed."); }
                }
                var pending = new List<KeyValuePair<string, EncryptedLapsBlob>>();
                AddEncrypted(attributes, WindowsLapsFormat.EncryptedPassword, "current", pending, result, true);
                if (options.History) AddEncrypted(attributes, WindowsLapsFormat.EncryptedHistory, "history", pending, result, false);
                AddEncrypted(attributes, WindowsLapsFormat.EncryptedDsrm, "dsrm", pending, result, true);
                if (options.History) AddEncrypted(attributes, WindowsLapsFormat.EncryptedDsrmHistory, "dsrm-history", pending, result, false);
                if (pending.Count > 0 && !options.Decrypt)
                    result.Errors.Add("Encrypted Windows LAPS passwords are stored for this computer, but decryption is disabled (WindowsLapsAdDecrypt).");
                else if (pending.Count > 0)
                {
                    IList<DecryptOutcome> outcomes;
                    try { outcomes = decrypt(pending.ConvertAll(p => p.Value.ProtectedData)); }
                    catch (Exception ex) { outcomes = null; result.Errors.Add("Encrypted Windows LAPS passwords could not be decrypted: " + ex.Message); }
                    for (var i = 0; outcomes != null && i < pending.Count; i++)
                    {
                        var kind = pending[i].Key;
                        var blob = pending[i].Value;
                        var outcome = i < outcomes.Count ? outcomes[i] : null;
                        if (outcome == null || outcome.Data == null)
                        {
                            result.Credentials.Add(new WindowsLapsCredential { Source = "ad", Kind = kind, Encrypted = true, UpdatedUtc = blob.UpdatedUtc, Error = outcome == null ? "No result." : outcome.Error });
                            continue;
                        }
                        try
                        {
                            var credential = WindowsLapsFormat.ParsePayload(WindowsLapsFormat.DecryptedText(outcome.Data), "ad", kind);
                            credential.Encrypted = true;
                            if (!credential.UpdatedUtc.HasValue) credential.UpdatedUtc = blob.UpdatedUtc;
                            if (kind == "current") credential.ExpiresUtc = expires;
                            result.Credentials.Add(credential);
                        }
                        catch (FormatException) { result.Credentials.Add(new WindowsLapsCredential { Source = "ad", Kind = kind, Encrypted = true, UpdatedUtc = blob.UpdatedUtc, Error = "The decrypted payload could not be parsed." }); }
                    }
                }
            }
            if (options.Legacy)
            {
                var legacy = Text(attributes, WindowsLapsFormat.LegacyPassword);
                if (legacy != null)
                    result.Credentials.Add(new WindowsLapsCredential
                    {
                        Source = "ad-legacy", Kind = "current", Account = null, Password = legacy,
                        ExpiresUtc = WindowsLapsFormat.FileTime(Text(attributes, WindowsLapsFormat.LegacyExpiration))
                    });
            }
            // Current first (Windows LAPS before legacy), then history newest first.
            result.Credentials.Sort((a, b) =>
            {
                var rank = Rank(a).CompareTo(Rank(b));
                if (rank != 0) return rank;
                return Nullable.Compare(b.UpdatedUtc, a.UpdatedUtc);
            });
            return result;
        }

        private static int Rank(WindowsLapsCredential credential)
        {
            switch (credential.Kind)
            {
                case "current": return credential.Source == "ad-legacy" ? 1 : 0;
                case "dsrm": return 2;
                case "history": return 3;
                default: return 4;
            }
        }

        private static void AddEncrypted(IDictionary<string, object[]> attributes, string name, string kind, List<KeyValuePair<string, EncryptedLapsBlob>> pending, WindowsLapsResult result, bool single)
        {
            object[] values;
            if (!attributes.TryGetValue(name, out values) || values == null) return;
            foreach (var value in values)
            {
                var bytes = value as byte[];
                if (bytes == null) continue;
                try { pending.Add(new KeyValuePair<string, EncryptedLapsBlob>(kind, WindowsLapsFormat.ParseEncrypted(bytes))); }
                catch (FormatException ex) { result.Errors.Add(name + ": " + ex.Message); }
                if (single) break;
            }
        }

        public static string Text(IDictionary<string, object[]> attributes, string name)
        {
            object[] values;
            if (attributes == null || !attributes.TryGetValue(name, out values) || values == null || values.Length == 0) return null;
            var text = values[0] as string;
            if (text != null) return text;
            var bytes = values[0] as byte[];
            return bytes == null ? null : Encoding.UTF8.GetString(bytes);
        }
    }

    // Windows-only: CNG DPAPI (DPAPI-NG) as used by Get-LapsADPassword. The calling identity (IIS application
    // pool account) must be allowed by the blob's protection descriptor (ADPasswordEncryptionPrincipal) and the
    // server must reach a domain controller (Group Key Distribution Service).
    public static class NativeDpapiNg
    {
        private const uint NCRYPT_SILENT_FLAG = 0x40;

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptUnprotectSecret(out IntPtr descriptor, uint flags, byte[] protectedBlob, uint protectedLength, IntPtr memoryParameters, IntPtr window, out IntPtr data, out uint dataLength);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        private static extern int NCryptCreateProtectionDescriptor(string descriptorString, uint flags, out IntPtr descriptor);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptProtectSecret(IntPtr descriptor, uint flags, byte[] data, uint dataLength, IntPtr memoryParameters, IntPtr window, out IntPtr protectedBlob, out uint protectedLength);

        [DllImport("ncrypt.dll")]
        private static extern int NCryptCloseProtectionDescriptor(IntPtr descriptor);

        [DllImport("kernel32.dll")]
        private static extern IntPtr LocalFree(IntPtr memory);

        public static byte[] Unprotect(byte[] blob)
        {
            IntPtr descriptor, data; uint length;
            var status = NCryptUnprotectSecret(out descriptor, NCRYPT_SILENT_FLAG, blob, (uint)blob.Length, IntPtr.Zero, IntPtr.Zero, out data, out length);
            if (descriptor != IntPtr.Zero) NCryptCloseProtectionDescriptor(descriptor);
            if (status != 0) throw new System.Security.Cryptography.CryptographicException(Describe(status));
            return Take(data, length);
        }

        // Used by the tests ("LOCAL=user") and for diagnostics; LAPS itself protects to a SID descriptor.
        public static byte[] Protect(string descriptorString, byte[] data)
        {
            IntPtr descriptor;
            var status = NCryptCreateProtectionDescriptor(descriptorString, 0, out descriptor);
            if (status != 0) throw new System.Security.Cryptography.CryptographicException(Describe(status));
            try
            {
                IntPtr blob; uint length;
                status = NCryptProtectSecret(descriptor, NCRYPT_SILENT_FLAG, data, (uint)data.Length, IntPtr.Zero, IntPtr.Zero, out blob, out length);
                if (status != 0) throw new System.Security.Cryptography.CryptographicException(Describe(status));
                return Take(blob, length);
            }
            finally { NCryptCloseProtectionDescriptor(descriptor); }
        }

        private static byte[] Take(IntPtr memory, uint length)
        {
            try
            {
                var result = new byte[length];
                if (length > 0) Marshal.Copy(memory, result, 0, (int)length);
                return result;
            }
            finally { if (memory != IntPtr.Zero) LocalFree(memory); }
        }

        public static string Describe(int status)
        {
            switch ((uint)status)
            {
                case 0x80090029: return "DPAPI-NG is not supported for this blob (0x80090029).";
                case 0x80070005: return "Access denied: this server's identity is not allowed to decrypt the password. Add the application pool account to the group configured in the LAPS policy 'Configure authorized password decryptors' (0x80070005).";
                case 0x8009002C: return "The decryption key is not available (0x8009002C). Check that a domain controller is reachable.";
                default: return "DPAPI-NG decryption failed (0x" + ((uint)status).ToString("X8", CultureInfo.InvariantCulture) + ").";
            }
        }
    }
}
