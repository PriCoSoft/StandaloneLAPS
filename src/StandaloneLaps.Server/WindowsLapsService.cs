using System.Diagnostics;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using StandaloneLapsWeb;

namespace StandaloneLaps.Server;

// Settings for the read-only Windows LAPS lookup (Slaps__WindowsLaps* environment variables). Everything is off by default.
public sealed class WindowsLapsOptions
{
    public bool ReaderAllowed { get; init; }
    public bool AdEnabled { get; init; }
    public string AdServer { get; init; }
    public bool AdUseSsl { get; init; } = true;
    public int AdPort { get; init; }
    public string AdSearchBase { get; init; }
    public string AdUsername { get; init; }
    public string AdPassword { get; init; }
    public string AdCaDirectory { get; init; }
    public bool AdLegacy { get; init; } = true;
    public bool AdModern { get; init; } = true;
    public bool AdDecrypt { get; init; } = true;
    public bool AdHistory { get; init; } = true;
    public string DecryptMode { get; init; } = "auto";      // auto | native | python
    public string DecryptServer { get; init; }
    public string DecryptAuth { get; init; } = "negotiate";  // negotiate | kerberos | ntlm (dpapi-ng auth_protocol)
    public string Python { get; init; } = "python3";
    public string DpapiScript { get; init; }
    public bool EntraEnabled { get; init; }
    public string EntraTenantId { get; init; }
    public string EntraClientId { get; init; }
    public string EntraClientSecret { get; init; }
    public string EntraCertificatePath { get; init; }
    public string EntraCertificatePassword { get; init; }
    public bool EntraHistory { get; init; } = true;

    public bool Enabled => AdEnabled || EntraEnabled;
    public bool Allowed(PortalUser user) => Enabled && user != null && (user.IsAdmin || (ReaderAllowed && user.IsReader));
    public int EffectivePort => AdPort > 0 ? AdPort : AdUseSsl ? 636 : 389;

    // Native DPAPI-NG needs Windows and the process identity; explicit credentials or Linux use the Python helper.
    public bool UsePython => DecryptMode.Equals("python", StringComparison.OrdinalIgnoreCase) ||
        (!DecryptMode.Equals("native", StringComparison.OrdinalIgnoreCase) && (!OperatingSystem.IsWindows() || !string.IsNullOrEmpty(AdUsername)));

    public void Validate()
    {
        if (AdEnabled)
        {
            if (!OperatingSystem.IsWindows() && string.IsNullOrEmpty(AdServer))
                throw new InvalidOperationException("Slaps:WindowsLapsAdServer must name a domain controller or the domain DNS name when WindowsLapsAdEnabled=true.");
            if (!OperatingSystem.IsWindows() && (string.IsNullOrEmpty(AdUsername) || string.IsNullOrEmpty(AdPassword)))
                throw new InvalidOperationException("Set Slaps:WindowsLapsAdUsername (UPN) and Slaps:WindowsLapsAdPassword[File] for the Active Directory lookup.");
            if (!string.IsNullOrEmpty(AdUsername) && !AdUseSsl && !OperatingSystem.IsWindows())
                throw new InvalidOperationException("Slaps:WindowsLapsAdUseSsl must stay true: the service account password would otherwise be sent in clear text (simple bind).");
            if (DecryptMode is not ("auto" or "native" or "python")) throw new InvalidOperationException("Slaps:WindowsLapsAdDecryptMode must be auto, native or python.");
            if (DecryptMode == "native" && !OperatingSystem.IsWindows()) throw new InvalidOperationException("Slaps:WindowsLapsAdDecryptMode=native requires Windows.");
            if (DecryptAuth is not ("negotiate" or "kerberos" or "ntlm")) throw new InvalidOperationException("Slaps:WindowsLapsAdDecryptAuth must be negotiate, kerberos or ntlm.");
        }
        if (EntraEnabled)
        {
            if (!Guid.TryParse(EntraTenantId, out _) || !Guid.TryParse(EntraClientId, out _))
                throw new InvalidOperationException("Set Slaps:WindowsLapsEntraTenantId and Slaps:WindowsLapsEntraClientId (defaults: tenant from OidcAuthority, OidcClientId).");
            if (string.IsNullOrEmpty(EntraCertificatePath) && string.IsNullOrEmpty(EntraClientSecret))
                throw new InvalidOperationException("Set Slaps:WindowsLapsEntraCertificatePath (PFX, recommended) or Slaps:WindowsLapsEntraClientSecret[File] for the Entra lookup.");
        }
    }
}

public sealed class WindowsLapsException(string message) : Exception(message);

// Active Directory (LDAP; LDAPS simple bind on Linux, Kerberos on Windows), DPAPI-NG decryption (native ncrypt.dll on
// Windows, the Python dpapi-ng library elsewhere, like LAPS-WebUI) and Microsoft Entra ID via Microsoft Graph.
public sealed class WindowsLapsService
{
    public const int MaxResults = 25;
    private const string Graph = "https://graph.microsoft.com/v1.0/";
    private readonly WindowsLapsOptions options;
    private readonly HttpClient http;
    private readonly SemaphoreSlim tokenGate = new(1, 1);
    private string token;
    private DateTime tokenExpiresUtc;

    public WindowsLapsService(ServerOptions server, HttpMessageHandler handler = null)
    {
        options = server.WindowsLaps;
        http = handler == null ? new HttpClient() : new HttpClient(handler);
        http.Timeout = TimeSpan.FromSeconds(20);
        http.DefaultRequestHeaders.UserAgent.ParseAdd("PriCoSoft-SLAPS/" + AppVersion.Number);
        http.DefaultRequestHeaders.Add("ocp-client-name", "PriCoSoft SLAPS");
        http.DefaultRequestHeaders.Add("ocp-client-version", AppVersion.Number);
    }

    public WindowsLapsOptions Options => options;

    // ---- Active Directory -----------------------------------------------------------------------------

    private LdapConnection Connect()
    {
        var identifier = new LdapDirectoryIdentifier(options.AdServer, options.EffectivePort, false, false);
        var connection = new LdapConnection(identifier) { Timeout = TimeSpan.FromSeconds(20) };
        connection.SessionOptions.ProtocolVersion = 3;
        connection.SessionOptions.ReferralChasing = ReferralChasingOptions.None;
        if (!string.IsNullOrEmpty(options.AdCaDirectory) && !OperatingSystem.IsWindows()) connection.SessionOptions.TrustedCertificatesDirectory = options.AdCaDirectory;
        if (options.AdUseSsl) connection.SessionOptions.SecureSocketLayer = true;
        if (OperatingSystem.IsWindows())
        {
            connection.AuthType = AuthType.Negotiate;
            if (!options.AdUseSsl) { connection.SessionOptions.Signing = true; connection.SessionOptions.Sealing = true; }
            if (!string.IsNullOrEmpty(options.AdUsername)) connection.Credential = new NetworkCredential(options.AdUsername, options.AdPassword);
        }
        else
        {
            if (!string.IsNullOrEmpty(options.AdCaDirectory)) connection.SessionOptions.StartNewTlsSessionContext();
            connection.AuthType = AuthType.Basic;
            connection.Credential = new NetworkCredential(options.AdUsername, options.AdPassword);
        }
        try { connection.Bind(); }
        catch (Exception ex) when (ex is LdapException or DirectoryOperationException or PlatformNotSupportedException or DllNotFoundException)
        {
            connection.Dispose();
            throw new WindowsLapsException("Cannot connect to Active Directory" + (options.AdServer == null ? "" : " (" + options.AdServer + ":" + options.EffectivePort + ")") + ": " + ex.Message);
        }
        return connection;
    }

    private string SearchBase(LdapConnection connection)
    {
        if (!string.IsNullOrEmpty(options.AdSearchBase)) return options.AdSearchBase;
        var response = (SearchResponse)connection.SendRequest(new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "defaultNamingContext"));
        var value = response.Entries.Count == 0 ? null : response.Entries[0].Attributes["defaultNamingContext"];
        if (value == null) throw new WindowsLapsException("The domain naming context could not be read. Set Slaps:WindowsLapsAdSearchBase.");
        return (string)value.GetValues(typeof(string))[0];
    }

    // Settings page "Test connection": bind, RootDSE and search base; no password attribute is read.
    public string TestAd()
    {
        using var connection = Connect();
        var root = ((SearchResponse)connection.SendRequest(new SearchRequest(null, "(objectClass=*)", SearchScope.Base, "dnsHostName", "defaultNamingContext"))).Entries;
        var dc = root.Count == 0 || root[0].Attributes["dnsHostName"] == null ? "?" : (string)root[0].Attributes["dnsHostName"].GetValues(typeof(string))[0];
        var searchBase = SearchBase(connection);
        if (((SearchResponse)connection.SendRequest(new SearchRequest(searchBase, "(objectClass=*)", SearchScope.Base, "distinguishedName"))).Entries.Count == 0)
            throw new WindowsLapsException("The search base " + searchBase + " was not found.");
        return "Connected to " + dc + " as " + (options.AdUsername ?? Environment.UserName) + ". Search base: " + searchBase + ".";
    }

    public string CredentialSource => !string.IsNullOrEmpty(options.EntraCertificatePath) ? "Certificate " + options.EntraCertificatePath : !string.IsNullOrEmpty(options.EntraClientSecret) ? "Client secret" : "Not configured";

    public async Task<string> TestEntra()
    {
        token = null;
        var json = await GraphGet("directory/deviceLocalCredentials?$top=1&$select=id,deviceName");
        return "Token acquired with: " + CredentialSource + ". Microsoft Graph access to deviceLocalCredentials works (" + ParseDevices(json).Count + " sample entry read, no passwords).";
    }

    public List<WindowsLapsComputer> SearchAd(string query)
    {
        if (!WindowsLapsFormat.ValidQuery(query)) throw new WindowsLapsException("Enter a computer name (letters, digits, '-', '.', '_'; '*' only at the end).");
        using var connection = Connect();
        var request = new SearchRequest(SearchBase(connection), WindowsLapsFormat.ComputerFilter(query, options.AdLegacy, options.AdModern), SearchScope.Subtree,
            WindowsLapsFormat.SearchAttributes.Append("objectGUID").ToArray()) { SizeLimit = MaxResults };
        SearchResultEntryCollection entries;
        try { entries = ((SearchResponse)connection.SendRequest(request)).Entries; }
        catch (DirectoryOperationException ex) when (ex.Response is SearchResponse partial && ex.Response.ResultCode == ResultCode.SizeLimitExceeded) { entries = partial.Entries; }
        catch (DirectoryOperationException ex) { throw new WindowsLapsException("Active Directory search failed: " + ex.Message); }
        var result = new List<WindowsLapsComputer>();
        foreach (SearchResultEntry entry in entries)
        {
            var values = Values(entry);
            if (!values.TryGetValue("objectGUID", out var guid) || guid.Length == 0 || guid[0] is not byte[] { Length: 16 } bytes) continue;
            result.Add(Computer(values, new Guid(bytes), entry.DistinguishedName));
        }
        return result.OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public async Task<(WindowsLapsComputer Computer, WindowsLapsResult Credentials)> ReadAd(Guid id, bool reveal)
    {
        Dictionary<string, object[]> values;
        string dn;
        using (var connection = Connect())
        {
            var attributes = reveal ? ActiveDirectoryLapsReader.RevealAttributes.Concat(WindowsLapsFormat.SearchAttributes).Distinct().ToArray() : WindowsLapsFormat.SearchAttributes;
            SearchResponse response;
            try { response = (SearchResponse)connection.SendRequest(new SearchRequest("<GUID=" + id.ToString("D") + ">", "(objectCategory=computer)", SearchScope.Base, attributes)); }
            catch (DirectoryOperationException ex) when (ex.Response?.ResultCode == ResultCode.NoSuchObject) { return (null, null); }
            catch (DirectoryOperationException ex) { throw new WindowsLapsException("Active Directory lookup failed: " + ex.Message); }
            if (response.Entries.Count == 0) return (null, null);
            values = Values(response.Entries[0]);
            dn = response.Entries[0].DistinguishedName;
        }
        if (!string.IsNullOrEmpty(options.AdSearchBase) && !dn.EndsWith(options.AdSearchBase, StringComparison.OrdinalIgnoreCase)) return (null, null);
        var computer = Computer(values, id, dn);
        if (!reveal) return (computer, null);
        // Decryption may start a helper process; collect the blobs first, decrypt in one batch.
        var adOptions = new ActiveDirectoryLapsOptions { Legacy = options.AdLegacy, Modern = options.AdModern, Decrypt = options.AdDecrypt, History = options.AdHistory };
        IList<byte[]> pending = null;
        ActiveDirectoryLapsReader.Read(values, adOptions, blobs => { pending = blobs; return blobs.Select(_ => new DecryptOutcome { Error = "pending" }).ToList(); });
        IList<DecryptOutcome> outcomes = pending == null ? Array.Empty<DecryptOutcome>() : await Decrypt(pending);
        var credentials = ActiveDirectoryLapsReader.Read(values, adOptions, _ => outcomes);
        return (computer, credentials);
    }

    private static WindowsLapsComputer Computer(Dictionary<string, object[]> values, Guid id, string dn) => new()
    {
        Source = "ad", Id = id.ToString("D"), DistinguishedName = dn, Name = ActiveDirectoryLapsReader.Text(values, "name"),
        DnsName = ActiveDirectoryLapsReader.Text(values, "dNSHostName"), OperatingSystem = ActiveDirectoryLapsReader.Text(values, "operatingSystem"), Description = ActiveDirectoryLapsReader.Text(values, "description"),
        LegacyExpiresUtc = WindowsLapsFormat.FileTime(ActiveDirectoryLapsReader.Text(values, WindowsLapsFormat.LegacyExpiration)),
        ExpiresUtc = WindowsLapsFormat.FileTime(ActiveDirectoryLapsReader.Text(values, WindowsLapsFormat.Expiration))
    };

    private static readonly HashSet<string> BinaryAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "objectGUID", WindowsLapsFormat.EncryptedPassword, WindowsLapsFormat.EncryptedHistory, WindowsLapsFormat.EncryptedDsrm, WindowsLapsFormat.EncryptedDsrmHistory
    };

    private static Dictionary<string, object[]> Values(SearchResultEntry entry)
    {
        var values = new Dictionary<string, object[]>(StringComparer.OrdinalIgnoreCase);
        foreach (string name in entry.Attributes.AttributeNames)
            values[name] = entry.Attributes[name].GetValues(BinaryAttributes.Contains(name) ? typeof(byte[]) : typeof(string));
        return values;
    }

    // ---- DPAPI-NG ---------------------------------------------------------------------------------------

    public async Task<IList<DecryptOutcome>> Decrypt(IList<byte[]> blobs)
    {
        if (!options.UsePython)
        {
            return blobs.Select(blob =>
            {
                try { return new DecryptOutcome { Data = NativeDpapiNg.Unprotect(blob) }; }
                catch (CryptographicException ex) { return new DecryptOutcome { Error = ex.Message }; }
            }).ToList();
        }
        return await PythonDecrypt(blobs);
    }

    // Runs the dpapi-ng helper once per reveal; credentials and blobs go through stdin, never the command line.
    private async Task<IList<DecryptOutcome>> PythonDecrypt(IList<byte[]> blobs)
    {
        var request = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["server"] = options.DecryptServer ?? options.AdServer, ["username"] = options.AdUsername, ["password"] = options.AdPassword,
            ["auth"] = options.DecryptAuth, ["blobs"] = blobs.Select(Convert.ToBase64String).ToArray()
        });
        var start = new ProcessStartInfo(options.Python)
        {
            RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8, StandardErrorEncoding = Encoding.UTF8
        };
        start.ArgumentList.Add(options.DpapiScript);
        Process process;
        try { process = Process.Start(start) ?? throw new WindowsLapsException("The DPAPI-NG helper could not be started."); }
        catch (System.ComponentModel.Win32Exception ex) { throw new WindowsLapsException("Python (" + options.Python + ") for the DPAPI-NG helper was not found: " + ex.Message); }
        using (process)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try
            {
                var output = process.StandardOutput.ReadToEndAsync(timeout.Token);
                var error = process.StandardError.ReadToEndAsync(timeout.Token);
                await process.StandardInput.WriteAsync(request.AsMemory(), timeout.Token);
                process.StandardInput.Close();
                await process.WaitForExitAsync(timeout.Token);
                return ParseHelperOutput(await output, blobs.Count, (await error).Trim());
            }
            catch (OperationCanceledException)
            {
                try { process.Kill(true); } catch (InvalidOperationException) { }
                throw new WindowsLapsException("The DPAPI-NG helper did not answer within 60 seconds. Check that the domain controller is reachable (RPC 135 and dynamic ports).");
            }
        }
    }

    public static IList<DecryptOutcome> ParseHelperOutput(string output, int count, string error)
    {
        JsonDocument document;
        try { document = JsonDocument.Parse(output); }
        catch (JsonException) { throw new WindowsLapsException("The DPAPI-NG helper failed" + (error.Length == 0 ? "." : ": " + Last(error))); }
        using (document)
        {
            var root = document.RootElement;
            if (root.TryGetProperty("error", out var failure)) throw new WindowsLapsException("DPAPI-NG helper: " + failure.GetString());
            if (!root.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array || results.GetArrayLength() != count)
                throw new WindowsLapsException("The DPAPI-NG helper returned an unexpected answer.");
            return results.EnumerateArray().Select(r =>
                r.TryGetProperty("data", out var data) ? new DecryptOutcome { Data = Convert.FromBase64String(data.GetString() ?? "") }
                : new DecryptOutcome { Error = r.TryGetProperty("error", out var e) ? e.GetString() : "Unknown error." }).ToList();
        }
    }

    private static string Last(string text)
    {
        var lines = text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var line = lines.Length == 0 ? text : lines[^1];
        return line.Length > 300 ? line[..300] : line;
    }

    // ---- Microsoft Entra ID -------------------------------------------------------------------------------

    public async Task<List<WindowsLapsComputer>> SearchEntra(string query)
    {
        if (Guid.TryParse(query, out var id))
        {
            var single = await FindEntra(id);
            return single == null ? new List<WindowsLapsComputer>() : new List<WindowsLapsComputer> { single };
        }
        if (!WindowsLapsFormat.ValidQuery(query)) throw new WindowsLapsException("Enter a device name or Entra device ID.");
        var filter = query.EndsWith('*') ? "startswith(deviceName," + WindowsLapsFormat.ODataLiteral(query.TrimEnd('*')) + ")" : "deviceName eq " + WindowsLapsFormat.ODataLiteral(query);
        return ParseDevices(await GraphGet("directory/deviceLocalCredentials?$filter=" + Uri.EscapeDataString(filter) + "&$top=" + MaxResults));
    }

    public async Task<WindowsLapsComputer> FindEntra(Guid id) =>
        ParseDevices(await GraphGet("directory/deviceLocalCredentials/" + id.ToString("D"), allowNotFound: true)).FirstOrDefault();

    public async Task<(WindowsLapsComputer Computer, WindowsLapsResult Credentials)> ReadEntra(Guid id)
    {
        var json = await GraphGet("directory/deviceLocalCredentials/" + id.ToString("D") + "?$select=id,deviceName,lastBackupDateTime,refreshDateTime,credentials", allowNotFound: true);
        var computer = ParseDevices(json).FirstOrDefault();
        return computer == null ? (null, null) : (computer, ParseCredentials(json, options.EntraHistory));
    }

    private static IEnumerable<JsonElement> Items(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) yield break;
        if (!root.TryGetProperty("value", out var value)) { yield return root; yield break; }
        if (value.ValueKind == JsonValueKind.Object) { yield return value; yield break; }
        if (value.ValueKind == JsonValueKind.Array) foreach (var item in value.EnumerateArray()) if (item.ValueKind == JsonValueKind.Object) yield return item;
    }

    private static string Text(JsonElement item, string name) => item.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    private static DateTime? Date(string value) => DateTime.TryParse(value, CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out var parsed) ? parsed : null;

    public static List<WindowsLapsComputer> ParseDevices(string json)
    {
        if (string.IsNullOrEmpty(json)) return new List<WindowsLapsComputer>();
        using var document = JsonDocument.Parse(json);
        return Items(document.RootElement)
            .Where(item => Guid.TryParse(Text(item, "id"), out _))
            .Select(item => new WindowsLapsComputer
            {
                Source = "entra", Id = Guid.Parse(Text(item, "id")).ToString("D"), Name = Text(item, "deviceName"),
                LastBackupUtc = Date(Text(item, "lastBackupDateTime")), ExpiresUtc = Date(Text(item, "refreshDateTime"))
            })
            .OrderBy(c => c.Name, StringComparer.OrdinalIgnoreCase).ToList();
    }

    public static WindowsLapsResult ParseCredentials(string json, bool history)
    {
        var result = new WindowsLapsResult();
        using var document = JsonDocument.Parse(json);
        var item = Items(document.RootElement).Cast<JsonElement?>().FirstOrDefault();
        if (item == null) { result.Errors.Add("Microsoft Graph returned no device."); return result; }
        var refresh = Date(Text(item.Value, "refreshDateTime"));
        var credentials = new List<WindowsLapsCredential>();
        if (item.Value.TryGetProperty("credentials", out var list) && list.ValueKind == JsonValueKind.Array)
            foreach (var entry in list.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.Object))
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

    public static string ClientAssertion(X509Certificate2 certificate, string tenantId, string clientId, DateTime utcNow)
    {
        var now = new DateTimeOffset(utcNow).ToUnixTimeSeconds();
        static string B64(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var header = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["alg"] = "RS256", ["typ"] = "JWT", ["x5t"] = B64(certificate.GetCertHash()), ["x5t#S256"] = B64(certificate.GetCertHash(HashAlgorithmName.SHA256))
        });
        var claims = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["aud"] = "https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/token", ["iss"] = clientId, ["sub"] = clientId,
            ["jti"] = Guid.NewGuid().ToString("D"), ["nbf"] = now - 60, ["iat"] = now, ["exp"] = now + 600
        });
        var unsigned = B64(header) + "." + B64(claims);
        using var rsa = certificate.GetRSAPrivateKey() ?? throw new WindowsLapsException("The Entra application certificate has no RSA private key.");
        return unsigned + "." + B64(rsa.SignData(Encoding.ASCII.GetBytes(unsigned), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    private async Task<string> AccessToken()
    {
        await tokenGate.WaitAsync();
        try
        {
            if (token != null && DateTime.UtcNow < tokenExpiresUtc) return token;
            var form = new Dictionary<string, string>
            {
                ["client_id"] = options.EntraClientId, ["grant_type"] = "client_credentials", ["scope"] = "https://graph.microsoft.com/.default"
            };
            if (!string.IsNullOrEmpty(options.EntraCertificatePath))
            {
                X509Certificate2 certificate;
                try { certificate = X509CertificateLoader.LoadPkcs12FromFile(options.EntraCertificatePath, options.EntraCertificatePassword, X509KeyStorageFlags.EphemeralKeySet); }
                catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
                { throw new WindowsLapsException("The Entra application certificate (WindowsLapsEntraCertificatePath) cannot be loaded: " + ex.Message); }
                using (certificate)
                {
                    form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
                    form["client_assertion"] = ClientAssertion(certificate, options.EntraTenantId, options.EntraClientId, DateTime.UtcNow);
                }
            }
            else form["client_secret"] = options.EntraClientSecret;
            var json = await Send(new HttpRequestMessage(HttpMethod.Post, "https://login.microsoftonline.com/" + options.EntraTenantId + "/oauth2/v2.0/token") { Content = new FormUrlEncodedContent(form) }, false);
            using var document = JsonDocument.Parse(json);
            token = Text(document.RootElement, "access_token") ?? throw new WindowsLapsException("Microsoft Entra ID returned no access token.");
            var seconds = document.RootElement.TryGetProperty("expires_in", out var expires) && expires.TryGetInt32(out var value) ? value : 3600;
            tokenExpiresUtc = DateTime.UtcNow.AddSeconds(Math.Max(60, seconds - 300));
            return token;
        }
        finally { tokenGate.Release(); }
    }

    private async Task<string> GraphGet(string relative, bool allowNotFound = false)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, Graph + relative);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await AccessToken());
        return await Send(request, allowNotFound);
    }

    private async Task<string> Send(HttpRequestMessage request, bool allowNotFound)
    {
        HttpResponseMessage response;
        try { response = await http.SendAsync(request); }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
        { throw new WindowsLapsException("Microsoft Entra ID / Graph is not reachable: " + ex.Message); }
        using (response)
        {
            var body = await response.Content.ReadAsStringAsync();
            if (response.IsSuccessStatusCode) return body;
            if (response.StatusCode == HttpStatusCode.NotFound && allowNotFound) return null;
            var detail = ErrorText(body);
            if (response.StatusCode == HttpStatusCode.Forbidden)
                throw new WindowsLapsException("Microsoft Graph denied access (403). Grant the application permission DeviceLocalCredential.Read.All with admin consent. " + detail);
            throw new WindowsLapsException("Microsoft Entra ID / Graph returned " + (int)response.StatusCode + ". " + detail);
        }
    }

    public static string ErrorText(string json)
    {
        try
        {
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;
            if (root.TryGetProperty("error", out var error) && error.ValueKind == JsonValueKind.Object) return Text(error, "message") ?? "";
            return Text(root, "error_description") ?? Text(root, "error") ?? "";
        }
        catch (JsonException) { return ""; }
    }
}
