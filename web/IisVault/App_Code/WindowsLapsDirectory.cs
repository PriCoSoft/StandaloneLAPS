using System;
using System.Collections;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web.Script.Serialization;

namespace StandaloneLapsWeb
{
    // web.config switches for the read-only Windows LAPS lookup. Everything is off unless enabled.
    public static class WindowsLapsSettings
    {
        private static bool Flag(string name, bool fallback)
        {
            var value = Vault.Setting(name).Trim();
            if (value.Length == 0) return fallback;
            return string.Equals(value, "true", StringComparison.OrdinalIgnoreCase) || value == "1";
        }

        public static bool AdEnabled { get { return Flag("WindowsLapsAdEnabled", false); } }
        public static string AdServer { get { return Vault.Setting("WindowsLapsAdServer").Trim(); } }
        public static string AdSearchBase { get { return Vault.Setting("WindowsLapsAdSearchBase").Trim(); } }
        public static bool AdUseSsl { get { return Flag("WindowsLapsAdUseSsl", false); } }
        public static ActiveDirectoryLapsOptions AdOptions
        {
            get
            {
                return new ActiveDirectoryLapsOptions
                {
                    Legacy = Flag("WindowsLapsAdLegacy", true), Modern = Flag("WindowsLapsAdModern", true),
                    Decrypt = Flag("WindowsLapsAdDecrypt", true), History = Flag("WindowsLapsAdHistory", true)
                };
            }
        }

        public static bool EntraEnabled { get { return Flag("WindowsLapsEntraEnabled", false); } }
        public static string EntraTenantId { get { return First("WindowsLapsEntraTenantId", "EntraTenantId"); } }
        public static string EntraClientId { get { return First("WindowsLapsEntraClientId", "EntraClientId"); } }
        public static string EntraClientSecret { get { return Vault.Setting("WindowsLapsEntraClientSecret").Trim(); } }
        public static string EntraCertificateThumbprint { get { return Vault.Setting("WindowsLapsEntraCertificateThumbprint").Replace(" ", "").Trim(); } }
        public static bool EntraHistory { get { return Flag("WindowsLapsEntraHistory", true); } }

        // Optional write actions (administrators only): set the AD expiry to now / ask Intune to rotate.
        public static bool AdAllowExpire { get { return Flag("WindowsLapsAdAllowExpire", false); } }
        public static bool EntraAllowRotate { get { return Flag("WindowsLapsEntraAllowRotate", false); } }
        public static bool CanRotate(PortalIdentity identity, string source)
        {
            return identity != null && identity.IsAdmin && (source == "ad" ? AdEnabled && AdAllowExpire : source == "entra" && EntraEnabled && EntraAllowRotate);
        }

        // "Admin" (default) or "Reader": which SLAPS role may look up and reveal directory passwords.
        public static bool ReaderAllowed { get { return string.Equals(Vault.Setting("WindowsLapsRequiredRole").Trim(), "Reader", StringComparison.OrdinalIgnoreCase); } }
        public static bool Enabled { get { return AdEnabled || EntraEnabled; } }
        public static bool Allowed(PortalIdentity identity) { return identity != null && Enabled && (identity.IsAdmin || ReaderAllowed); }

        // For the Settings page: DNS domain of this server and the identity used towards AD.
        public static string DnsDomain
        {
            get { try { return System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().DomainName; } catch (Exception) { return ""; } }
        }

        public static string ProcessIdentity
        {
            get { using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent()) return identity.Name; }
        }

        // Application pool identities, NETWORK SERVICE and SYSTEM authenticate as the computer account on the network.
        public static string NetworkIdentity
        {
            get
            {
                var name = ProcessIdentity;
                if (name.StartsWith("IIS APPPOOL\\", StringComparison.OrdinalIgnoreCase) || string.Equals(name, "NT AUTHORITY\\NETWORK SERVICE", StringComparison.OrdinalIgnoreCase) || string.Equals(name, "NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase))
                    return "computer account " + Environment.MachineName + "$ (process " + name + ")";
                return name;
            }
        }

        private static string First(string name, string fallback)
        {
            var value = Vault.Setting(name).Trim();
            return value.Length > 0 ? value : Vault.Setting(fallback).Trim();
        }
    }

    public sealed class WindowsLapsException : Exception
    {
        public WindowsLapsException(string message) : base(message) { }
    }

    // Active Directory over LDAP with the application pool identity (Kerberos, signing and sealing, or LDAPS).
    // Encrypted Windows LAPS attributes are decrypted with NCryptUnprotectSecret under the same identity.
    public static class ActiveDirectoryLaps
    {
        public const int MaxResults = 25;

        private static LdapConnection Connect()
        {
            var server = WindowsLapsSettings.AdServer;
            var ssl = WindowsLapsSettings.AdUseSsl;
            var identifier = new LdapDirectoryIdentifier(server.Length == 0 ? null : server, ssl ? 636 : 389, false, false);
            var connection = new LdapConnection(identifier) { AuthType = AuthType.Negotiate, Timeout = TimeSpan.FromSeconds(20) };
            connection.SessionOptions.ProtocolVersion = 3;
            connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
            if (ssl) connection.SessionOptions.SecureSocketLayer = true;
            else { connection.SessionOptions.Signing = true; connection.SessionOptions.Sealing = true; }
            try { connection.Bind(); }
            catch (LdapException ex)
            {
                connection.Dispose();
                throw new WindowsLapsException("Cannot connect to Active Directory" + (server.Length == 0 ? "" : " (" + server + ")") + ": " + ex.Message + " Check that this server is domain-joined or WindowsLapsAdServer is reachable.");
            }
            return connection;
        }

        private static string SearchBase(LdapConnection connection)
        {
            var configured = WindowsLapsSettings.AdSearchBase;
            if (configured.Length > 0) return configured;
            var response = (SearchResponse)connection.SendRequest(new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "defaultNamingContext"));
            if (response.Entries.Count == 0 || response.Entries[0].Attributes["defaultNamingContext"] == null) throw new WindowsLapsException("The domain naming context could not be read. Set WindowsLapsAdSearchBase.");
            return (string)response.Entries[0].Attributes["defaultNamingContext"].GetValues(typeof(string))[0];
        }

        // Settings page "Test connection": bind, read RootDSE and the search base; no password attribute is read.
        public static string Test()
        {
            using (var connection = Connect())
            {
                var response = (SearchResponse)connection.SendRequest(new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "dnsHostName", "defaultNamingContext"));
                var root = response.Entries.Count == 0 ? null : response.Entries[0];
                var dc = root == null || root.Attributes["dnsHostName"] == null ? "?" : (string)root.Attributes["dnsHostName"].GetValues(typeof(string))[0];
                var searchBase = SearchBase(connection);
                var check = (SearchResponse)connection.SendRequest(new SearchRequest(searchBase, "(objectClass=*)", SearchScope.Base, "distinguishedName"));
                if (check.Entries.Count == 0) throw new WindowsLapsException("The search base " + searchBase + " was not found.");
                return "Connected to " + dc + " as " + WindowsLapsSettings.NetworkIdentity + ". Search base: " + searchBase + ".";
            }
        }

        public static List<WindowsLapsComputer> Search(string query)
        {
            if (!WindowsLapsFormat.ValidQuery(query)) throw new WindowsLapsException("Enter a computer name (letters, digits, '-', '.', '_'; '*' only at the end).");
            using (var connection = Connect())
            {
                var request = new SearchRequest(SearchBase(connection), WindowsLapsFormat.ComputerFilter(query, WindowsLapsSettings.AdOptions.Legacy, WindowsLapsSettings.AdOptions.Modern), SearchScope.Subtree,
                    WindowsLapsFormat.SearchAttributes.Concat(new[] { "objectGUID" }).ToArray()) { SizeLimit = MaxResults };
                SearchResultEntryCollection entries;
                try { entries = ((SearchResponse)connection.SendRequest(request)).Entries; }
                catch (DirectoryOperationException ex)
                {
                    var partial = ex.Response as SearchResponse;
                    if (partial == null || ex.Response.ResultCode != ResultCode.SizeLimitExceeded) throw new WindowsLapsException("Active Directory search failed: " + ex.Message);
                    entries = partial.Entries;
                }
                var result = new List<WindowsLapsComputer>();
                foreach (SearchResultEntry entry in entries)
                {
                    var values = Values(entry);
                    var guid = values.ContainsKey("objectGUID") ? values["objectGUID"][0] as byte[] : null;
                    if (guid == null || guid.Length != 16) continue;
                    result.Add(new WindowsLapsComputer
                    {
                        Source = "ad", Id = new Guid(guid).ToString("D"), DistinguishedName = entry.DistinguishedName, Name = ActiveDirectoryLapsReader.Text(values, "name"),
                        DnsName = ActiveDirectoryLapsReader.Text(values, "dNSHostName"), OperatingSystem = ActiveDirectoryLapsReader.Text(values, "operatingSystem"), Description = ActiveDirectoryLapsReader.Text(values, "description"),
                        LegacyExpiresUtc = WindowsLapsFormat.FileTime(ActiveDirectoryLapsReader.Text(values, WindowsLapsFormat.LegacyExpiration)),
                        ExpiresUtc = WindowsLapsFormat.FileTime(ActiveDirectoryLapsReader.Text(values, WindowsLapsFormat.Expiration))
                    });
                }
                return result.OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();
            }
        }

        // "Expire now" like Set-LapsADPasswordExpirationTime / Reset-AdmPwdPassword: the device rotates at its next cycle.
        // Needs Set-LapsADResetPasswordPermission (Windows LAPS) / Set-AdmPwdResetPasswordPermission (legacy) for this identity.
        public static string Expire(Guid id)
        {
            using (var connection = Connect())
            {
                SearchResponse response;
                try { response = (SearchResponse)connection.SendRequest(new SearchRequest("<GUID=" + id.ToString("D") + ">", "(objectCategory=computer)", SearchScope.Base, "name", WindowsLapsFormat.Expiration, WindowsLapsFormat.LegacyExpiration)); }
                catch (DirectoryOperationException ex) { throw new WindowsLapsException("Active Directory lookup failed: " + ex.Message); }
                if (response.Entries.Count == 0) throw new WindowsLapsException("The computer was not found.");
                var dn = response.Entries[0].DistinguishedName;
                var searchBase = WindowsLapsSettings.AdSearchBase;
                if (searchBase.Length > 0 && !dn.EndsWith(searchBase, StringComparison.OrdinalIgnoreCase)) throw new WindowsLapsException("The computer is outside WindowsLapsAdSearchBase.");
                var values = Values(response.Entries[0]);
                var options = WindowsLapsSettings.AdOptions;
                var modern = options.Modern && values.ContainsKey(WindowsLapsFormat.Expiration);
                var legacy = options.Legacy && values.ContainsKey(WindowsLapsFormat.LegacyExpiration);
                if (!modern && !legacy) throw new WindowsLapsException("No LAPS expiry is stored for this computer, so there is no LAPS password to rotate.");
                var now = DateTime.UtcNow.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture);
                var changes = new List<DirectoryAttributeModification>();
                foreach (var name in (modern ? new[] { WindowsLapsFormat.Expiration } : new string[0]).Concat(legacy ? new[] { WindowsLapsFormat.LegacyExpiration } : new string[0]))
                {
                    var change = new DirectoryAttributeModification { Name = name, Operation = DirectoryAttributeOperation.Replace };
                    change.Add(now);
                    changes.Add(change);
                }
                try { connection.SendRequest(new ModifyRequest(dn, changes.ToArray())); }
                catch (DirectoryOperationException ex)
                {
                    if (ex.Response != null && ex.Response.ResultCode == ResultCode.InsufficientAccessRights)
                        throw new WindowsLapsException("Access denied: " + WindowsLapsSettings.NetworkIdentity + " may not change the LAPS expiry. Grant it with Set-LapsADResetPasswordPermission" + (legacy ? " and Set-AdmPwdResetPasswordPermission" : "") + " on the OU.");
                    throw new WindowsLapsException("Active Directory refused the change: " + ex.Message);
                }
                return WindowsLapsFormat.ExpireMessage(modern, legacy);
            }
        }

        public static WindowsLapsComputer Find(Guid id, out WindowsLapsResult credentials, bool reveal)
        {
            credentials = null;
            using (var connection = Connect())
            {
                var attributes = reveal ? ActiveDirectoryLapsReader.RevealAttributes.Concat(WindowsLapsFormat.SearchAttributes).Distinct().ToArray() : WindowsLapsFormat.SearchAttributes;
                SearchResponse response;
                try { response = (SearchResponse)connection.SendRequest(new SearchRequest("<GUID=" + id.ToString("D") + ">", "(objectCategory=computer)", SearchScope.Base, attributes)); }
                catch (DirectoryOperationException ex)
                {
                    if (ex.Response != null && ex.Response.ResultCode == ResultCode.NoSuchObject) return null;
                    throw new WindowsLapsException("Active Directory lookup failed: " + ex.Message);
                }
                if (response.Entries.Count == 0) return null;
                var values = Values(response.Entries[0]);
                var dn = response.Entries[0].DistinguishedName;
                var searchBase = WindowsLapsSettings.AdSearchBase;
                if (searchBase.Length > 0 && !dn.EndsWith(searchBase, StringComparison.OrdinalIgnoreCase)) return null;
                if (reveal) credentials = ActiveDirectoryLapsReader.Read(values, WindowsLapsSettings.AdOptions, DecryptAll);
                return new WindowsLapsComputer
                {
                    Source = "ad", Id = id.ToString("D"), DistinguishedName = dn, Name = ActiveDirectoryLapsReader.Text(values, "name"), DnsName = ActiveDirectoryLapsReader.Text(values, "dNSHostName"),
                    OperatingSystem = ActiveDirectoryLapsReader.Text(values, "operatingSystem"), Description = ActiveDirectoryLapsReader.Text(values, "description"),
                    LegacyExpiresUtc = WindowsLapsFormat.FileTime(ActiveDirectoryLapsReader.Text(values, WindowsLapsFormat.LegacyExpiration)),
                    ExpiresUtc = WindowsLapsFormat.FileTime(ActiveDirectoryLapsReader.Text(values, WindowsLapsFormat.Expiration))
                };
            }
        }

        private static IList<DecryptOutcome> DecryptAll(IList<byte[]> blobs)
        {
            var outcomes = new List<DecryptOutcome>();
            foreach (var blob in blobs)
            {
                try { outcomes.Add(new DecryptOutcome { Data = NativeDpapiNg.Unprotect(blob) }); }
                catch (CryptographicException ex) { outcomes.Add(new DecryptOutcome { Error = ex.Message }); }
            }
            return outcomes;
        }

        private static readonly HashSet<string> BinaryAttributes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "objectGUID", WindowsLapsFormat.EncryptedPassword, WindowsLapsFormat.EncryptedHistory, WindowsLapsFormat.EncryptedDsrm, WindowsLapsFormat.EncryptedDsrmHistory
        };

        private static Dictionary<string, object[]> Values(SearchResultEntry entry)
        {
            var values = new Dictionary<string, object[]>(StringComparer.OrdinalIgnoreCase);
            foreach (string name in entry.Attributes.AttributeNames)
            {
                var attribute = entry.Attributes[name];
                values[name] = attribute.GetValues(BinaryAttributes.Contains(name) ? typeof(byte[]) : typeof(string));
            }
            return values;
        }
    }

    // Microsoft Entra ID through Microsoft Graph (deviceLocalCredentials), app-only with a client secret or a
    // certificate from LocalMachine\My. Requires the application permission DeviceLocalCredential.Read.All.
    public static class EntraLaps
    {
        private const string Graph = "https://graph.microsoft.com/v1.0/";
        private const string GraphBeta = "https://graph.microsoft.com/beta/";
        private static readonly object Gate = new object();
        private static string token;
        private static DateTime tokenExpiresUtc;

        public static List<WindowsLapsComputer> Search(string query)
        {
            Guid id;
            if (Guid.TryParse(query, out id))
            {
                var single = Find(id);
                return single == null ? new List<WindowsLapsComputer>() : new List<WindowsLapsComputer> { single };
            }
            if (!WindowsLapsFormat.ValidQuery(query)) throw new WindowsLapsException("Enter a device name or Entra device ID.");
            var filter = query.EndsWith("*", StringComparison.Ordinal)
                ? "startswith(deviceName," + WindowsLapsFormat.ODataLiteral(query.TrimEnd('*')) + ")"
                : "deviceName eq " + WindowsLapsFormat.ODataLiteral(query);
            var json = Get("directory/deviceLocalCredentials?$filter=" + Uri.EscapeDataString(filter) + "&$top=" + ActiveDirectoryLaps.MaxResults);
            return ParseDevices(json);
        }

        public static WindowsLapsComputer Find(Guid id)
        {
            try { return ParseDevices(Get("directory/deviceLocalCredentials/" + id.ToString("D"))).FirstOrDefault(); }
            catch (WindowsLapsNotFoundException) { return null; }
        }

        // Intune remote action "Rotate local admin password" (Graph beta). Needs DeviceManagementManagedDevices.Read.All and
        // DeviceManagementManagedDevices.PrivilegedOperations.All (application) and an Intune-managed device.
        public static string Rotate(Guid deviceId)
        {
            var json = Get("deviceManagement/managedDevices?$filter=" + Uri.EscapeDataString("azureADDeviceId eq " + WindowsLapsFormat.ODataLiteral(deviceId.ToString("D"))) + "&$select=id,deviceName");
            var managed = Items(json).Select(item => Text(item, "id")).FirstOrDefault(id => !string.IsNullOrEmpty(id));
            if (managed == null) throw new WindowsLapsException("This device is not managed by Microsoft Intune; a rotation can only be requested for Intune-managed devices.");
            Send(GraphBeta + "deviceManagement/managedDevices/" + Uri.EscapeDataString(managed) + "/rotateLocalAdminPassword", "POST", "", AccessToken(), "application/json");
            return "Intune was asked to rotate the local administrator password. The device changes it at its next check-in, then backs up the new password to Entra ID.";
        }

        public static WindowsLapsResult Read(Guid id, out WindowsLapsComputer computer)
        {
            var json = Get("directory/deviceLocalCredentials/" + id.ToString("D") + "?$select=id,deviceName,lastBackupDateTime,refreshDateTime,credentials");
            computer = ParseDevices(json).FirstOrDefault();
            return ParseCredentials(json, WindowsLapsSettings.EntraHistory);
        }

        // ---- Parsing (public for tests) ---------------------------------------------------------------

        public static List<WindowsLapsComputer> ParseDevices(string json)
        {
            var result = new List<WindowsLapsComputer>();
            foreach (var item in Items(json))
            {
                Guid id;
                if (!Guid.TryParse(Text(item, "id"), out id)) continue;
                result.Add(new WindowsLapsComputer
                {
                    Source = "entra", Id = id.ToString("D"), Name = Text(item, "deviceName"),
                    LastBackupUtc = Date(Text(item, "lastBackupDateTime")), ExpiresUtc = Date(Text(item, "refreshDateTime"))
                });
            }
            return result.OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        public static WindowsLapsResult ParseCredentials(string json, bool history)
        {
            var result = new WindowsLapsResult();
            var item = Items(json).FirstOrDefault();
            if (item == null) { result.Errors.Add("Microsoft Graph returned no device."); return result; }
            var refresh = Date(Text(item, "refreshDateTime"));
            var list = item.ContainsKey("credentials") ? item["credentials"] as IEnumerable : null;
            var credentials = new List<WindowsLapsCredential>();
            foreach (var entry in (list ?? new object[0]).OfType<Dictionary<string, object>>())
            {
                var credential = new WindowsLapsCredential { Source = "entra", Account = Text(entry, "accountName"), UpdatedUtc = Date(Text(entry, "backupDateTime")) };
                try { credential.Password = WindowsLapsFormat.GraphPassword(Text(entry, "passwordBase64")); }
                catch (FormatException) { credential.Error = "The password returned by Microsoft Graph is not valid base64."; }
                credentials.Add(credential);
            }
            credentials = credentials.OrderByDescending(c => c.UpdatedUtc ?? DateTime.MinValue).ToList();
            for (var i = 0; i < credentials.Count; i++)
            {
                credentials[i].Kind = i == 0 ? "current" : "history";
                if (i == 0) credentials[i].ExpiresUtc = refresh;
                if (i == 0 || history) result.Credentials.Add(credentials[i]);
            }
            if (credentials.Count == 0) result.Errors.Add("No password is backed up for this device in Microsoft Entra ID, or the application lacks DeviceLocalCredential.Read.All.");
            return result;
        }

        private static IEnumerable<Dictionary<string, object>> Items(string json)
        {
            var document = new JavaScriptSerializer { MaxJsonLength = 4194304, RecursionLimit = 16 }.DeserializeObject(json) as Dictionary<string, object>;
            if (document == null) yield break;
            object value;
            if (!document.TryGetValue("value", out value)) { yield return document; yield break; }
            var single = value as Dictionary<string, object>;
            if (single != null) { yield return single; yield break; }
            var many = value as IEnumerable;
            if (many == null) yield break;
            foreach (var entry in many.OfType<Dictionary<string, object>>()) yield return entry;
        }

        private static string Text(IDictionary<string, object> values, string name)
        {
            object value;
            return values.TryGetValue(name, out value) ? value as string : null;
        }

        private static DateTime? Date(string value)
        {
            DateTime parsed;
            return DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out parsed) ? parsed : (DateTime?)null;
        }

        // ---- Token and HTTP ---------------------------------------------------------------------------

        // Signed JWT for client assertions and key-rollover proofs (RS256 with x5t and x5t#S256 headers).
        public static string SignJwt(X509Certificate2 certificate, Dictionary<string, object> claims)
        {
            var serializer = new JavaScriptSerializer();
            byte[] sha256;
            using (var hash = SHA256.Create()) sha256 = hash.ComputeHash(certificate.RawData);
            var header = serializer.Serialize(new Dictionary<string, object> { { "alg", "RS256" }, { "typ", "JWT" }, { "x5t", EntraTokenValidator.Base64UrlEncode(certificate.GetCertHash()) }, { "x5t#S256", EntraTokenValidator.Base64UrlEncode(sha256) } });
            var unsigned = EntraTokenValidator.Base64UrlEncode(Encoding.UTF8.GetBytes(header)) + "." + EntraTokenValidator.Base64UrlEncode(Encoding.UTF8.GetBytes(serializer.Serialize(claims)));
            using (var rsa = certificate.GetRSAPrivateKey())
            {
                if (rsa == null) throw new WindowsLapsException("The Entra application certificate has no usable RSA private key.");
                return unsigned + "." + EntraTokenValidator.Base64UrlEncode(rsa.SignData(Encoding.ASCII.GetBytes(unsigned), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
            }
        }

        private static long Epoch(DateTime utcNow) { return (long)(utcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds; }

        // RFC 7523 client assertion for the token endpoint.
        public static string ClientAssertion(X509Certificate2 certificate, string tenantId, string clientId, DateTime utcNow)
        {
            var now = Epoch(utcNow);
            return SignJwt(certificate, new Dictionary<string, object>
            {
                { "aud", "https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/token" }, { "iss", clientId }, { "sub", clientId },
                { "jti", Guid.NewGuid().ToString("D") }, { "nbf", now - 60 }, { "iat", now }, { "exp", now + 600 }
            });
        }

        // Proof of possession for applications/{objectId}/addKey and removeKey (signed with a currently valid key).
        public static string KeyProof(X509Certificate2 certificate, string objectId, DateTime utcNow)
        {
            var now = Epoch(utcNow);
            return SignJwt(certificate, new Dictionary<string, object> { { "aud", "00000002-0000-0000-c000-000000000000" }, { "iss", objectId }, { "nbf", now }, { "exp", now + 600 } });
        }

        // Which credential is used: certificate from web.config > certificate from the setup > client secret.
        public static string CredentialSource
        {
            get
            {
                if (WindowsLapsSettings.EntraCertificateThumbprint.Length > 0) return "Certificate " + WindowsLapsSettings.EntraCertificateThumbprint + " from LocalMachine\\My (web.config)";
                var state = EntraAppCredential.Load();
                if (!string.IsNullOrEmpty(state.current)) return "Certificate " + state.currentThumbprint + " created by the setup (renewed automatically)";
                if (WindowsLapsSettings.EntraClientSecret.Length > 0) return "Client secret (web.config)";
                return "Not configured";
            }
        }

        private static X509Certificate2 StoreCertificate(string thumbprint)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                var certificate = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Cast<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey);
                if (certificate == null) throw new WindowsLapsException("The certificate " + thumbprint + " (WindowsLapsEntraCertificateThumbprint) with private key was not found in LocalMachine\\My, or the application pool cannot read its key.");
                return certificate;
            }
        }

        private static void Ids(out string tenant, out string client)
        {
            Guid t, c;
            if (!Guid.TryParse(WindowsLapsSettings.EntraTenantId, out t) || !Guid.TryParse(WindowsLapsSettings.EntraClientId, out c))
                throw new WindowsLapsException("Set WindowsLapsEntraTenantId and WindowsLapsEntraClientId (or EntraTenantId/EntraClientId).");
            tenant = t.ToString("D"); client = c.ToString("D");
        }

        // Requests an app-only Graph token with the given certificate (or the configured secret when null).
        private static string RequestToken(X509Certificate2 certificate, out int expiresIn)
        {
            string tenant, client;
            Ids(out tenant, out client);
            var form = "client_id=" + Uri.EscapeDataString(client) + "&grant_type=client_credentials&scope=" + Uri.EscapeDataString("https://graph.microsoft.com/.default");
            if (certificate != null)
                form += "&client_assertion_type=" + Uri.EscapeDataString("urn:ietf:params:oauth:client-assertion-type:jwt-bearer") +
                        "&client_assertion=" + Uri.EscapeDataString(ClientAssertion(certificate, tenant, client, DateTime.UtcNow));
            else if (WindowsLapsSettings.EntraClientSecret.Length > 0) form += "&client_secret=" + Uri.EscapeDataString(WindowsLapsSettings.EntraClientSecret);
            else throw new WindowsLapsException("No Graph credential: run the Entra setup on the Settings page, or set WindowsLapsEntraCertificateThumbprint / WindowsLapsEntraClientSecret.");
            var response = Send("https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token", "POST", form, null, "application/x-www-form-urlencoded");
            var document = new JavaScriptSerializer().DeserializeObject(response) as Dictionary<string, object>;
            object value, expires;
            if (document == null || !document.TryGetValue("access_token", out value) || !(value is string)) throw new WindowsLapsException("Microsoft Entra ID returned no access token.");
            expiresIn = document.TryGetValue("expires_in", out expires) ? Convert.ToInt32(expires, CultureInfo.InvariantCulture) : 3600;
            return (string)value;
        }

        private static string AccessToken()
        {
            MaybeRenew();
            lock (Gate)
            {
                if (token != null && DateTime.UtcNow < tokenExpiresUtc) return token;
                int seconds;
                var thumbprint = WindowsLapsSettings.EntraCertificateThumbprint;
                var certificate = thumbprint.Length > 0 ? StoreCertificate(thumbprint) : EntraAppCredential.Current();
                try { token = RequestToken(certificate, out seconds); }
                finally { if (certificate != null) certificate.Dispose(); }
                tokenExpiresUtc = DateTime.UtcNow.AddSeconds(Math.Max(60, seconds - 300));
                return token;
            }
        }

        public static void ResetToken() { lock (Gate) { token = null; } }

        // Settings page "Test connection": token plus one Graph call that needs DeviceLocalCredential.Read(Basic).All.
        public static string Test()
        {
            ResetToken();
            var json = Get("directory/deviceLocalCredentials?$top=1&$select=id,deviceName");
            return "Token acquired with: " + CredentialSource + ". Microsoft Graph access to deviceLocalCredentials works (" + ParseDevices(json).Count + " sample entry read, no passwords).";
        }

        // ---- Automatic renewal of the setup certificate (Graph addKey with proof of possession) ----------

        private static readonly object RenewGate = new object();
        private static DateTime lastAutomaticAttempt = DateTime.MinValue;

        // Called before each token request: renews 30 days before expiry, at most once per hour. Failures are stored
        // and shown on the Settings page; the current certificate keeps working until it expires.
        public static void MaybeRenew()
        {
            if (WindowsLapsSettings.EntraCertificateThumbprint.Length > 0) return;
            var state = EntraAppCredential.Load();
            if (string.IsNullOrEmpty(state.current) || string.IsNullOrEmpty(state.objectId)) return;
            if (string.IsNullOrEmpty(state.pending) && !EntraAppCredential.NeedsRenewal(state, DateTime.UtcNow)) return;
            lock (RenewGate)
            {
                if (DateTime.UtcNow - lastAutomaticAttempt < TimeSpan.FromHours(1)) return;
                lastAutomaticAttempt = DateTime.UtcNow;
            }
            try { Renew("system:entra-renewal"); }
            catch (WindowsLapsException) { }
        }

        // Adds a new certificate to the app registration (proof signed with the current one), switches to it as soon as
        // Entra accepts it, then removes the previous key if its key ID is known. Returns a status text.
        public static string Renew(string actor)
        {
            lock (RenewGate)
            {
                var state = EntraAppCredential.Load();
                state.lastAttemptUtc = EntraAppCredential.Stamp(DateTime.UtcNow);
                try
                {
                    if (string.IsNullOrEmpty(state.current)) throw new WindowsLapsException("No setup certificate exists yet.");
                    Guid objectId;
                    if (!Guid.TryParse(state.objectId, out objectId)) throw new WindowsLapsException("Enter the application's Object ID in the setup to allow automatic renewal.");
                    if (string.IsNullOrEmpty(state.pending))
                    {
                        X509Certificate2 created;
                        var pfx = EntraAppCredential.NewCertificate(DateTime.UtcNow, out created);
                        using (created)
                        using (var current = EntraAppCredential.OpenProtected(state.current))
                        {
                            int seconds;
                            var bearer = RequestToken(current, out seconds);
                            var serializer = new JavaScriptSerializer();
                            var body = serializer.Serialize(new Dictionary<string, object>
                            {
                                { "keyCredential", new Dictionary<string, object> { { "type", "AsymmetricX509Cert" }, { "usage", "Verify" }, { "key", Convert.ToBase64String(created.RawData) } } },
                                { "passwordCredential", null }, { "proof", KeyProof(current, objectId.ToString("D"), DateTime.UtcNow) }
                            });
                            var added = serializer.DeserializeObject(Send(Graph + "applications/" + objectId.ToString("D") + "/addKey", "POST", body, bearer, "application/json")) as Dictionary<string, object>;
                            object keyId;
                            state.pending = EntraAppCredential.Protect(pfx);
                            state.pendingThumbprint = created.Thumbprint;
                            state.pendingNotAfter = EntraAppCredential.Stamp(created.NotAfter);
                            state.pendingKeyId = added != null && added.TryGetValue("keyId", out keyId) ? keyId as string : null;
                            state.pendingCreatedUtc = EntraAppCredential.Stamp(DateTime.UtcNow);
                            EntraAppCredential.Save(state);
                            Vault.AuditTarget(actor, "entra-graph-certificate-added", created.Thumbprint);
                        }
                    }
                    var message = Activate(state, actor);
                    state.lastRenewalError = null;
                    EntraAppCredential.Save(state);
                    return message;
                }
                catch (WindowsLapsException ex)
                {
                    state.lastRenewalError = ex.Message;
                    EntraAppCredential.Save(state);
                    throw;
                }
            }
        }

        // The new key can take a few minutes to replicate; until a token works with it, the current one stays active.
        private static string Activate(EntraCredentialState state, string actor)
        {
            using (var pending = EntraAppCredential.OpenProtected(state.pending))
            {
                int seconds;
                string bearer;
                try { bearer = RequestToken(pending, out seconds); }
                catch (WindowsLapsException)
                {
                    return "The new certificate " + state.pendingThumbprint + " was added to the app registration. It becomes active as soon as Entra ID accepts it (usually within minutes); the current certificate stays in use until then.";
                }
                var previousKeyId = state.currentKeyId;
                var previousThumbprint = state.currentThumbprint;
                state.current = state.pending; state.currentThumbprint = state.pendingThumbprint; state.currentNotAfter = state.pendingNotAfter;
                state.currentKeyId = state.pendingKeyId; state.currentCreatedUtc = state.pendingCreatedUtc;
                state.pending = state.pendingThumbprint = state.pendingNotAfter = state.pendingKeyId = state.pendingCreatedUtc = null;
                state.lastRenewalUtc = EntraAppCredential.Stamp(DateTime.UtcNow);
                EntraAppCredential.Save(state);
                ResetToken();
                Vault.AuditTarget(actor, "entra-graph-certificate-activated", state.currentThumbprint);
                var removed = "";
                Guid keyId, objectId;
                if (Guid.TryParse(previousKeyId, out keyId) && Guid.TryParse(state.objectId, out objectId))
                {
                    try
                    {
                        var body = new JavaScriptSerializer().Serialize(new Dictionary<string, object> { { "keyId", keyId.ToString("D") }, { "proof", KeyProof(pending, objectId.ToString("D"), DateTime.UtcNow) } });
                        Send(Graph + "applications/" + objectId.ToString("D") + "/removeKey", "POST", body, bearer, "application/json");
                        removed = " The previous certificate " + previousThumbprint + " was removed from the app registration.";
                    }
                    catch (WindowsLapsException ex) { removed = " The previous certificate could not be removed (" + ex.Message + "); it expires on its own."; }
                }
                else if (previousThumbprint != null) removed = " The previous certificate " + previousThumbprint + " stays in the app registration until it expires (you can remove it there).";
                return "Renewed: certificate " + state.currentThumbprint + " is active until " + state.currentNotAfter.Substring(0, 10) + "." + removed;
            }
        }

        private static string Get(string relative) { return Send(Graph + relative, "GET", null, AccessToken(), null); }

        // Test hook: replaces the HTTP call (url, method, body, bearer) => response body.
        public static Func<string, string, string, string, string> Transport;

        private static string Send(string url, string method, string body, string bearer, string contentType)
        {
            if (Transport != null) return Transport(url, method, body, bearer);
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = method; request.Timeout = 20000; request.ReadWriteTimeout = 20000; request.AllowAutoRedirect = false;
            request.UserAgent = "PriCoSoft-SLAPS/" + AppVersion.Number;
            request.Headers["ocp-client-name"] = "PriCoSoft SLAPS";
            request.Headers["ocp-client-version"] = AppVersion.Number;
            if (bearer != null) request.Headers[HttpRequestHeader.Authorization] = "Bearer " + bearer;
            var proxy = Vault.Setting("OutboundProxyUrl");
            if (!string.IsNullOrWhiteSpace(proxy)) request.Proxy = new WebProxy(new Uri(proxy, UriKind.Absolute));
            try
            {
                if (body != null)
                {
                    var bytes = Encoding.UTF8.GetBytes(body);
                    request.ContentType = contentType;
                    request.ContentLength = bytes.Length;
                    using (var stream = request.GetRequestStream()) stream.Write(bytes, 0, bytes.Length);
                }
                using (var response = (HttpWebResponse)request.GetResponse())
                using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8)) return reader.ReadToEnd();
            }
            catch (WebException ex)
            {
                var http = ex.Response as HttpWebResponse;
                if (http == null) throw new WindowsLapsException("Microsoft Entra ID / Graph is not reachable (" + ex.Status + "). Check outbound HTTPS or OutboundProxyUrl.");
                string detail;
                using (var reader = new StreamReader(http.GetResponseStream(), Encoding.UTF8)) detail = ErrorText(reader.ReadToEnd());
                if (http.StatusCode == HttpStatusCode.NotFound && method == "GET") throw new WindowsLapsNotFoundException();
                if (http.StatusCode == HttpStatusCode.Forbidden) throw new WindowsLapsException("Microsoft Graph denied access (403). Grant the application permission " + (url.Contains("/deviceManagement/") ? "DeviceManagementManagedDevices.Read.All and DeviceManagementManagedDevices.PrivilegedOperations.All (Intune license required)" : "DeviceLocalCredential.Read.All") + " with admin consent. " + detail);
                throw new WindowsLapsException("Microsoft Entra ID / Graph returned " + (int)http.StatusCode + ". " + detail);
            }
        }

        public static string ErrorText(string json)
        {
            try
            {
                var document = new JavaScriptSerializer().DeserializeObject(json) as Dictionary<string, object>;
                if (document == null) return "";
                object error;
                if (document.TryGetValue("error", out error) && error is Dictionary<string, object>) return Text((Dictionary<string, object>)error, "message") ?? "";
                return Text(document, "error_description") ?? Text(document, "error") ?? "";
            }
            catch (ArgumentException) { return ""; }
            catch (InvalidOperationException) { return ""; }
        }
    }

    public sealed class WindowsLapsNotFoundException : Exception { }
}
