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
    public bool AdAllowExpire { get; init; }
    public bool EntraAllowRotate { get; init; }
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
    // Optional write actions, administrators only: AD expiry to now / Intune rotation.
    public bool CanRotate(PortalUser user, string source) => user != null && user.IsAdmin && (source == "ad" ? AdEnabled && AdAllowExpire : source == "entra" && EntraEnabled && EntraAllowRotate);
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
        }
    }
}

public sealed class WindowsLapsException(string message) : Exception(message);

// State of the Entra setup certificate (slaps_settings "entra-setup"); the certificates themselves are in slaps_keys.
public sealed class EntraSetupState
{
    public string ObjectId { get; set; }
    public string CurrentThumbprint { get; set; }
    public DateTime? CurrentNotAfter { get; set; }
    public DateTime? CurrentCreatedUtc { get; set; }
    public string CurrentKeyId { get; set; }
    public string PendingThumbprint { get; set; }
    public DateTime? PendingNotAfter { get; set; }
    public DateTime? PendingCreatedUtc { get; set; }
    public string PendingKeyId { get; set; }
    public DateTime? LastAttemptUtc { get; set; }
    public DateTime? LastRenewalUtc { get; set; }
    public string LastRenewalError { get; set; }
    public DateTime? ConsentUtc { get; set; }
    public string ConsentBy { get; set; }
    public string ConsentResult { get; set; }
}

// Active Directory (LDAP; LDAPS simple bind on Linux, Kerberos on Windows), DPAPI-NG decryption (native ncrypt.dll on
// Windows, the Python dpapi-ng library elsewhere, like LAPS-WebUI) and Microsoft Entra ID via Microsoft Graph.
public sealed class WindowsLapsService
{
    public const int MaxResults = 25;
    private const string Graph = "https://graph.microsoft.com/v1.0/";
    private const string GraphBeta = "https://graph.microsoft.com/beta/";
    private readonly WindowsLapsOptions options;
    private readonly HttpClient http;
    private readonly SemaphoreSlim tokenGate = new(1, 1);
    private string token;
    private DateTime tokenExpiresUtc;
    private readonly VaultStore store;
    private readonly KeyVault keys;
    private readonly string hostName;

    public WindowsLapsService(ServerOptions server, HttpMessageHandler handler = null, VaultStore store = null, KeyVault keys = null)
    {
        options = server.WindowsLaps;
        this.store = store;
        this.keys = keys;
        hostName = server.HostName;
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

    // "Expire now" like Set-LapsADPasswordExpirationTime; needs Set-LapsADResetPasswordPermission / Set-AdmPwdResetPasswordPermission.
    public string ExpireAd(Guid id)
    {
        using var connection = Connect();
        SearchResponse response;
        try { response = (SearchResponse)connection.SendRequest(new SearchRequest("<GUID=" + id.ToString("D") + ">", "(objectCategory=computer)", SearchScope.Base, "name", WindowsLapsFormat.Expiration, WindowsLapsFormat.LegacyExpiration)); }
        catch (DirectoryOperationException ex) { throw new WindowsLapsException("Active Directory lookup failed: " + ex.Message); }
        if (response.Entries.Count == 0) throw new WindowsLapsException("The computer was not found.");
        var dn = response.Entries[0].DistinguishedName;
        if (!string.IsNullOrEmpty(options.AdSearchBase) && !dn.EndsWith(options.AdSearchBase, StringComparison.OrdinalIgnoreCase)) throw new WindowsLapsException("The computer is outside WindowsLapsAdSearchBase.");
        var values = Values(response.Entries[0]);
        var modern = options.AdModern && values.ContainsKey(WindowsLapsFormat.Expiration);
        var legacy = options.AdLegacy && values.ContainsKey(WindowsLapsFormat.LegacyExpiration);
        if (!modern && !legacy) throw new WindowsLapsException("No LAPS expiry is stored for this computer, so there is no LAPS password to rotate.");
        var now = DateTime.UtcNow.ToFileTimeUtc().ToString(CultureInfo.InvariantCulture);
        var changes = new List<DirectoryAttributeModification>();
        foreach (var name in new[] { modern ? WindowsLapsFormat.Expiration : null, legacy ? WindowsLapsFormat.LegacyExpiration : null }.Where(n => n != null))
        {
            var change = new DirectoryAttributeModification { Name = name, Operation = DirectoryAttributeOperation.Replace };
            change.Add(now);
            changes.Add(change);
        }
        try { connection.SendRequest(new ModifyRequest(dn, changes.ToArray())); }
        catch (DirectoryOperationException ex) when (ex.Response?.ResultCode == ResultCode.InsufficientAccessRights)
        { throw new WindowsLapsException("Access denied: the service account may not change the LAPS expiry. Grant it with Set-LapsADResetPasswordPermission" + (legacy ? " and Set-AdmPwdResetPasswordPermission" : "") + " on the OU."); }
        catch (DirectoryOperationException ex) { throw new WindowsLapsException("Active Directory refused the change: " + ex.Message); }
        return WindowsLapsFormat.ExpireMessage(modern, legacy);
    }

    // Intune remote action "Rotate local admin password" (Graph beta), Intune-managed devices only.
    public async Task<string> RotateEntra(Guid deviceId)
    {
        var json = await GraphGet("deviceManagement/managedDevices?$filter=" + Uri.EscapeDataString("azureADDeviceId eq " + WindowsLapsFormat.ODataLiteral(deviceId.ToString("D"))) + "&$select=id,deviceName");
        string managed = null;
        using (var document = JsonDocument.Parse(json ?? "{}")) managed = Items(document.RootElement).Select(i => Text(i, "id")).FirstOrDefault(i => !string.IsNullOrEmpty(i));
        if (managed == null) throw new WindowsLapsException("This device is not managed by Microsoft Intune; a rotation can only be requested for Intune-managed devices.");
        var request = new HttpRequestMessage(HttpMethod.Post, GraphBeta + "deviceManagement/managedDevices/" + Uri.EscapeDataString(managed) + "/rotateLocalAdminPassword");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", await AccessToken());
        await Send(request, false);
        return "Intune was asked to rotate the local administrator password. The device changes it at its next check-in, then backs up the new password to Entra ID.";
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

    private static string B64(byte[] value) => Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    // Signed JWT for client assertions and key-rollover proofs (RS256 with x5t and x5t#S256 headers).
    public static string SignJwt(X509Certificate2 certificate, Dictionary<string, object> claims)
    {
        var header = JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, object>
        {
            ["alg"] = "RS256", ["typ"] = "JWT", ["x5t"] = B64(certificate.GetCertHash()), ["x5t#S256"] = B64(certificate.GetCertHash(HashAlgorithmName.SHA256))
        });
        var unsigned = B64(header) + "." + B64(JsonSerializer.SerializeToUtf8Bytes(claims));
        using var rsa = certificate.GetRSAPrivateKey() ?? throw new WindowsLapsException("The Entra application certificate has no RSA private key.");
        return unsigned + "." + B64(rsa.SignData(Encoding.ASCII.GetBytes(unsigned), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
    }

    public static string ClientAssertion(X509Certificate2 certificate, string tenantId, string clientId, DateTime utcNow)
    {
        var now = new DateTimeOffset(utcNow).ToUnixTimeSeconds();
        return SignJwt(certificate, new Dictionary<string, object>
        {
            ["aud"] = "https://login.microsoftonline.com/" + tenantId + "/oauth2/v2.0/token", ["iss"] = clientId, ["sub"] = clientId,
            ["jti"] = Guid.NewGuid().ToString("D"), ["nbf"] = now - 60, ["iat"] = now, ["exp"] = now + 600
        });
    }

    // Proof of possession for applications/{objectId}/addKey and removeKey (signed with a currently valid key).
    public static string KeyProof(X509Certificate2 certificate, string objectId, DateTime utcNow)
    {
        var now = new DateTimeOffset(utcNow).ToUnixTimeSeconds();
        return SignJwt(certificate, new Dictionary<string, object> { ["aud"] = "00000002-0000-0000-c000-000000000000", ["iss"] = objectId, ["nbf"] = now, ["exp"] = now + 600 });
    }

    // Requests an app-only Graph token with the given certificate, or the configured client secret when null.
    private async Task<(string Token, int Seconds)> RequestToken(X509Certificate2 certificate)
    {
        if (!Guid.TryParse(options.EntraTenantId, out _) || !Guid.TryParse(options.EntraClientId, out _))
            throw new WindowsLapsException("Set Slaps__WindowsLapsEntraTenantId and Slaps__WindowsLapsEntraClientId (defaults: tenant from OidcAuthority, OidcClientId).");
        var form = new Dictionary<string, string> { ["client_id"] = options.EntraClientId, ["grant_type"] = "client_credentials", ["scope"] = "https://graph.microsoft.com/.default" };
        if (certificate != null)
        {
            form["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
            form["client_assertion"] = ClientAssertion(certificate, options.EntraTenantId, options.EntraClientId, DateTime.UtcNow);
        }
        else if (!string.IsNullOrEmpty(options.EntraClientSecret)) form["client_secret"] = options.EntraClientSecret;
        else throw new WindowsLapsException("No Graph credential: run the Entra setup on the Settings page, or set Slaps__WindowsLapsEntraCertificatePath / Slaps__WindowsLapsEntraClientSecret.");
        var json = await Send(new HttpRequestMessage(HttpMethod.Post, "https://login.microsoftonline.com/" + options.EntraTenantId + "/oauth2/v2.0/token") { Content = new FormUrlEncodedContent(form) }, false);
        using var document = JsonDocument.Parse(json);
        var value = Text(document.RootElement, "access_token") ?? throw new WindowsLapsException("Microsoft Entra ID returned no access token.");
        return (value, document.RootElement.TryGetProperty("expires_in", out var expires) && expires.TryGetInt32(out var seconds) ? seconds : 3600);
    }

    // Credential precedence: PFX from the environment > certificate of the setup (database) > client secret.
    private X509Certificate2 SigningCertificate()
    {
        if (!string.IsNullOrEmpty(options.EntraCertificatePath))
        {
            try { return X509CertificateLoader.LoadPkcs12FromFile(options.EntraCertificatePath, options.EntraCertificatePassword, X509KeyStorageFlags.EphemeralKeySet); }
            catch (Exception ex) when (ex is CryptographicException or IOException or UnauthorizedAccessException)
            { throw new WindowsLapsException("The Entra application certificate (WindowsLapsEntraCertificatePath) cannot be loaded: " + ex.Message); }
        }
        return keys?.OpenKey(GraphKey);
    }

    private async Task<string> AccessToken()
    {
        await MaybeRenew();
        await tokenGate.WaitAsync();
        try
        {
            if (token != null && DateTime.UtcNow < tokenExpiresUtc) return token;
            using var certificate = SigningCertificate();
            var (value, seconds) = await RequestToken(certificate);
            token = value;
            tokenExpiresUtc = DateTime.UtcNow.AddSeconds(Math.Max(60, seconds - 300));
            return token;
        }
        finally { tokenGate.Release(); }
    }

    public void ResetToken() => token = null;

    // ---- Entra setup: certificate created by SLAPS, stored encrypted with the master key, renewed by itself ----

    public const string GraphKey = "graph", GraphPendingKey = "graph-pending", SetupDocument = "entra-setup";
    public const int ValidityDays = 365, RenewBeforeDays = 30;
    private readonly SemaphoreSlim renewGate = new(1, 1);
    private DateTime lastAutomaticAttempt = DateTime.MinValue;

    public EntraSetupState SetupState()
    {
        var json = store?.GetDocument(SetupDocument);
        return json == null ? new EntraSetupState() : JsonSerializer.Deserialize<EntraSetupState>(json) ?? new EntraSetupState();
    }

    public void SaveSetupState(EntraSetupState state) => store.SetDocument(SetupDocument, JsonSerializer.Serialize(state));

    public bool SetupConfigured => store?.Key(GraphKey) != null;

    public static X509Certificate2 NewGraphCertificate(DateTime utcNow, string host)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=SLAPS Graph access " + host, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(KeyVault.ClientAuthOid) }, false));
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        using var created = request.CreateSelfSigned(new DateTimeOffset(utcNow.AddMinutes(-10)), new DateTimeOffset(utcNow.AddDays(ValidityDays)));
        return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
    }

    // Setup step 1: a new certificate replaces the current one; its public part must then be uploaded to Entra ID.
    public EntraSetupState CreateSetupCertificate(string actor)
    {
        using var certificate = NewGraphCertificate(DateTime.UtcNow, hostName);
        store.ReplaceKey(keys.Protect(GraphKey, certificate), actor);
        if (store.Key(GraphPendingKey) != null) store.RemoveKey(GraphPendingKey, actor);
        var state = SetupState();
        state.CurrentThumbprint = certificate.Thumbprint;
        state.CurrentNotAfter = certificate.NotAfter.ToUniversalTime();
        state.CurrentCreatedUtc = DateTime.UtcNow;
        state.CurrentKeyId = null;
        state.PendingThumbprint = null; state.PendingNotAfter = null; state.PendingKeyId = null; state.PendingCreatedUtc = null;
        state.LastRenewalError = null;
        SaveSetupState(state);
        token = null;
        return state;
    }

    public byte[] SetupPublicCertificate()
    {
        using var certificate = keys?.OpenKey(GraphKey);
        return certificate?.RawData;
    }

    public string CredentialSource
    {
        get
        {
            if (!string.IsNullOrEmpty(options.EntraCertificatePath)) return "Certificate " + options.EntraCertificatePath + " (environment)";
            if (SetupConfigured) return "Certificate " + SetupState().CurrentThumbprint + " created by the setup (renewed automatically)";
            if (!string.IsNullOrEmpty(options.EntraClientSecret)) return "Client secret (environment)";
            return "Not configured";
        }
    }

    public static bool NeedsRenewal(EntraSetupState state, DateTime utcNow) => state.CurrentNotAfter.HasValue && state.CurrentNotAfter.Value - utcNow < TimeSpan.FromDays(RenewBeforeDays);

    // Before each token request: renews 30 days before expiry, at most once per hour; errors stay on the setup page.
    private async Task MaybeRenew()
    {
        if (store == null || !string.IsNullOrEmpty(options.EntraCertificatePath) || !SetupConfigured) return;
        var state = SetupState();
        if (string.IsNullOrEmpty(state.ObjectId) || (state.PendingThumbprint == null && !NeedsRenewal(state, DateTime.UtcNow))) return;
        if (DateTime.UtcNow - lastAutomaticAttempt < TimeSpan.FromHours(1)) return;
        lastAutomaticAttempt = DateTime.UtcNow;
        try { await Renew("system:entra-renewal"); } catch (WindowsLapsException) { }
    }

    // Adds a new certificate to the app registration (proof signed with the current one), switches to it as soon as
    // Entra accepts it and removes the previous key if its key ID is known. Returns a status text.
    public async Task<string> Renew(string actor)
    {
        await renewGate.WaitAsync();
        var state = SetupState();
        state.LastAttemptUtc = DateTime.UtcNow;
        try
        {
            if (!SetupConfigured) throw new WindowsLapsException("No setup certificate exists yet.");
            if (!Guid.TryParse(state.ObjectId, out var objectId)) throw new WindowsLapsException("Enter the application's Object ID in the setup to allow automatic renewal.");
            if (store.Key(GraphPendingKey) == null)
            {
                using var created = NewGraphCertificate(DateTime.UtcNow, hostName);
                using var current = keys.OpenKey(GraphKey);
                var (bearer, _) = await RequestToken(current);
                var body = JsonSerializer.Serialize(new Dictionary<string, object>
                {
                    ["keyCredential"] = new Dictionary<string, object> { ["type"] = "AsymmetricX509Cert", ["usage"] = "Verify", ["key"] = Convert.ToBase64String(created.RawData) },
                    ["passwordCredential"] = null, ["proof"] = KeyProof(current, objectId.ToString("D"), DateTime.UtcNow)
                });
                var request = new HttpRequestMessage(HttpMethod.Post, Graph + "applications/" + objectId.ToString("D") + "/addKey") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
                var answer = await Send(request, false);
                string keyId = null;
                if (!string.IsNullOrEmpty(answer)) { using var document = JsonDocument.Parse(answer); keyId = Text(document.RootElement, "keyId"); }
                store.ReplaceKey(keys.Protect(GraphPendingKey, created), actor);
                state.PendingThumbprint = created.Thumbprint; state.PendingNotAfter = created.NotAfter.ToUniversalTime();
                state.PendingKeyId = keyId; state.PendingCreatedUtc = DateTime.UtcNow;
                SaveSetupState(state);
            }
            var message = await Activate(state, actor, objectId);
            state.LastRenewalError = null;
            SaveSetupState(state);
            return message;
        }
        catch (WindowsLapsException ex)
        {
            state.LastRenewalError = ex.Message;
            SaveSetupState(state);
            throw;
        }
        finally { renewGate.Release(); }
    }

    // A new key can take minutes to replicate; until a token works with it, the current certificate stays active.
    private async Task<string> Activate(EntraSetupState state, string actor, Guid objectId)
    {
        using var pending = keys.OpenKey(GraphPendingKey);
        string bearer;
        try { (bearer, _) = await RequestToken(pending); }
        catch (WindowsLapsException)
        {
            return "The new certificate " + state.PendingThumbprint + " was added to the app registration. It becomes active as soon as Entra ID accepts it (usually within minutes); the current certificate stays in use until then.";
        }
        var previousKeyId = state.CurrentKeyId;
        var previousThumbprint = state.CurrentThumbprint;
        store.ReplaceKey(keys.Protect(GraphKey, pending), actor);
        store.RemoveKey(GraphPendingKey, actor);
        state.CurrentThumbprint = state.PendingThumbprint; state.CurrentNotAfter = state.PendingNotAfter;
        state.CurrentKeyId = state.PendingKeyId; state.CurrentCreatedUtc = state.PendingCreatedUtc;
        state.PendingThumbprint = null; state.PendingNotAfter = null; state.PendingKeyId = null; state.PendingCreatedUtc = null;
        state.LastRenewalUtc = DateTime.UtcNow;
        SaveSetupState(state);
        token = null;
        store.Audit(actor, "entra-graph-certificate-activated-" + state.CurrentThumbprint, Guid.Empty, Guid.Empty);
        var removed = "";
        if (Guid.TryParse(previousKeyId, out var keyId))
        {
            try
            {
                var body = JsonSerializer.Serialize(new Dictionary<string, object> { ["keyId"] = keyId.ToString("D"), ["proof"] = KeyProof(pending, objectId.ToString("D"), DateTime.UtcNow) });
                var request = new HttpRequestMessage(HttpMethod.Post, Graph + "applications/" + objectId.ToString("D") + "/removeKey") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", bearer);
                await Send(request, false);
                removed = " The previous certificate " + previousThumbprint + " was removed from the app registration.";
            }
            catch (WindowsLapsException ex) { removed = " The previous certificate could not be removed (" + ex.Message + "); it expires on its own."; }
        }
        else if (previousThumbprint != null) removed = " The previous certificate " + previousThumbprint + " stays in the app registration until it expires (you can remove it there).";
        return "Renewed: certificate " + state.CurrentThumbprint + " is active until " + state.CurrentNotAfter?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) + "." + removed;
    }

    public string AdminConsentUrl(string redirectUri, string state) =>
        "https://login.microsoftonline.com/" + options.EntraTenantId + "/v2.0/adminconsent?client_id=" + Uri.EscapeDataString(options.EntraClientId ?? "") +
        "&scope=" + Uri.EscapeDataString("https://graph.microsoft.com/.default") + "&redirect_uri=" + Uri.EscapeDataString(redirectUri) + "&state=" + Uri.EscapeDataString(state);

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
                throw new WindowsLapsException("Microsoft Graph denied access (403). Grant the application permission " + (request.RequestUri?.AbsolutePath.Contains("/deviceManagement/") == true ? "DeviceManagementManagedDevices.Read.All and DeviceManagementManagedDevices.PrivilegedOperations.All (Intune license required)" : "DeviceLocalCredential.Read.All") + " with admin consent. " + detail);
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