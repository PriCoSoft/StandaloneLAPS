using System.IO.Compression;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Configuration;
using StandaloneLaps.Server;
using AgentEnvelope = StandaloneLapsWeb.Envelope;
using AgentPayload = StandaloneLapsWeb.Payload;

namespace StandaloneLaps.Server.Tests;

// Starts the container server in-process (SQLite, development sign-in on loopback) and drives it like the
// Windows agent and installer do: client-certificate HTTPS, the agent's own EnvelopeCrypto, portal forms.
internal static class TestRunner
{
    private static int passed, failed;

    private static void Check(string name, bool condition, string detail = null)
    {
        if (condition) { passed++; Console.WriteLine("  ok   " + name); }
        else { failed++; Console.WriteLine("  FAIL " + name + (detail == null ? "" : " - " + detail)); }
    }

    private static int FreePort()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static async Task<int> Main(string[] args)
    {
        // Stand-in for the Python dpapi-ng helper (same stdin/stdout protocol), see WindowsLapsTests.
        if (args.Length == 1 && args[0] == WindowsLapsTests.FakeHelperArgument) return WindowsLapsTests.FakeHelper();
        var root = Path.Combine(Path.GetTempPath(), "slaps-server-tests-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(root);
        try
        {
            await Run(root);
        }
        catch (Exception ex)
        {
            failed++;
            Console.WriteLine("  FAIL unexpected exception: " + ex);
        }
        finally
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try { Directory.Delete(root, true); } catch (IOException) { } catch (UnauthorizedAccessException) { }
        }
        Console.WriteLine($"{passed} passed, {failed} failed");
        return failed == 0 ? 0 : 1;
    }

    private static Dictionary<string, string> Config(string root, string masterKey, int portal, int agent) => new()
    {
        ["Slaps:PortalPort"] = portal.ToString(), ["Slaps:AgentPort"] = agent.ToString(),
        ["Slaps:PublicUrl"] = $"https://localhost:{portal}/", ["Slaps:AgentApiUrl"] = $"https://localhost:{agent}/",
        ["Slaps:DataDirectory"] = Path.Combine(root, "data"), ["Slaps:AgentPackageDirectory"] = Path.Combine(root, "agent-package"),
        ["Slaps:MasterKey"] = masterKey, ["Slaps:AuthMode"] = "Development", ["Slaps:TlsDnsNames"] = "localhost;127.0.0.1",
        ["Logging:LogLevel:Default"] = "Warning",
        // Windows LAPS lookup against a closed local port: the page and error handling are exercised without touching a real directory.
        ["Slaps:WindowsLapsAdEnabled"] = "true", ["Slaps:WindowsLapsAdServer"] = "127.0.0.1", ["Slaps:WindowsLapsAdPort"] = "1", ["Slaps:WindowsLapsAdUseSsl"] = "false", ["Slaps:WindowsLapsAdAllowExpire"] = "true"
    };

    private static void CreateAgentFiles(string directory)
    {
        Directory.CreateDirectory(Path.Combine(directory, "linux"));
        foreach (var name in ClientPackages.AgentFiles) File.WriteAllText(Path.Combine(directory, name), "test " + name);
        foreach (var name in ClientPackages.LinuxAgentFiles) File.WriteAllText(Path.Combine(directory, "linux", name), "test " + name);
    }

    private static async Task Run(string root)
    {
        Environment.SetEnvironmentVariable("ASPNETCORE_ENVIRONMENT", "Development");
        CreateAgentFiles(Path.Combine(root, "agent-package"));
        var masterKey = Convert.ToBase64String(RandomNumberGenerator.GetBytes(36));
        int portal = FreePort(), agent = FreePort();
        var config = Config(root, masterKey, portal, agent);

        await WindowsLapsTests.Run(Check);

        Console.WriteLine("Configuration");
        Check("missing master key is rejected", Throws<InvalidOperationException>(() => ServerProgram.Build(Array.Empty<string>(), new Dictionary<string, string>(config) { ["Slaps:MasterKey"] = "short" })));
        Check("same portal and agent port is rejected", Throws<InvalidOperationException>(() => ServerProgram.Build(Array.Empty<string>(), new Dictionary<string, string>(config) { ["Slaps:AgentPort"] = portal.ToString() })));

        var app = ServerProgram.Build(Array.Empty<string>(), config);
        await app.StartAsync();
        var keys = (KeyVault)app.Services.GetService(typeof(KeyVault));
        var store = (VaultStore)app.Services.GetService(typeof(VaultStore));
        var packages = (ClientPackages)app.Services.GetService(typeof(ClientPackages));
        var tlsThumbprint = keys.Tls.Thumbprint;
        try
        {
            Console.WriteLine("Keys");
            Check("CA is RSA 4096 CA certificate", keys.Ca.GetRSAPublicKey().KeySize == 4096 && keys.Ca.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority);
            Check("recovery is RSA 4096 with private key", keys.Recovery.GetRSAPublicKey().KeySize == 4096 && keys.Recovery.HasPrivateKey);
            Check("generated TLS certificate covers localhost and is no CA", keys.Tls.MatchesHostname("localhost") && !keys.Tls.Extensions.OfType<X509BasicConstraintsExtension>().Single().CertificateAuthority);
            Check("stored keys are encrypted (PKCS#12 does not open without the master key)", Throws<CryptographicException>(() => X509CertificateLoader.LoadPkcs12(store.Key(KeyVault.RecoveryKey).Pkcs12, null)));

            using var portalClient = PortalClient(tlsThumbprint, out var cookies);
            var baseUrl = $"https://localhost:{portal}/";
            Console.WriteLine("Portal port");
            Check("healthz answers ok", await portalClient.GetStringAsync(baseUrl + "healthz") == "ok");
            var home = await portalClient.GetAsync(baseUrl);
            var homeHtml = await home.Content.ReadAsStringAsync();
            Check("device list renders for development admin", home.StatusCode == HttpStatusCode.OK && homeHtml.Contains("No devices here yet"), ((int)home.StatusCode).ToString());
            Check("security headers are set", home.Headers.Contains("Content-Security-Policy") && home.Headers.GetValues("X-Frame-Options").First() == "DENY");
            Check("style sheet is served", (await portalClient.GetAsync(baseUrl + "style.css")).StatusCode == HttpStatusCode.OK);
            Check("agent API is not served on the portal port", (await portalClient.GetAsync(baseUrl + "api.aspx?device=" + Guid.NewGuid())).StatusCode == HttpStatusCode.NotFound);
            var settings = await portalClient.GetStringAsync(baseUrl + "settings");
            Check("settings page lists CA, recovery and TLS certificates", settings.Contains("SLAPS CA") && settings.Contains("Recovery certificate") && settings.Contains("TLS certificate"));
            var certificate = await portalClient.GetByteArrayAsync(baseUrl + "certificate?sha=" + Wire.Sha256(keys.Tls.RawData) + "&format=cer");
            Check("TLS certificate download is DER of the served certificate", Wire.Sha256(certificate) == Wire.Sha256(keys.Tls.RawData));

            Console.WriteLine("Add client in the portal");
            var addPage = await portalClient.GetStringAsync(baseUrl + "addclient");
            var addResponse = await portalClient.PostAsync(baseUrl + "addclient", Form(addPage, ("name", "DMZ-WEB-01"), ("platform", "windows")));
            var addHtml = await addResponse.Content.ReadAsStringAsync();
            var pfxPassword = Regex.Match(addHtml, "shown only once</strong><code>([^<]+)</code>").Groups[1].Value;
            var token = Regex.Match(addHtml, "package\\?id=([0-9a-f]{32})").Groups[1].Value;
            Check("package created with one-time PFX password", pfxPassword.Length == 24 && token.Length == 32, ((int)addResponse.StatusCode).ToString());
            Check("POST without antiforgery token is rejected", (await portalClient.PostAsync(baseUrl + "addclient", new FormUrlEncodedContent(new Dictionary<string, string> { ["name"] = "X" }))).StatusCode == HttpStatusCode.BadRequest);
            var zip = await portalClient.GetByteArrayAsync(baseUrl + "package?id=" + token);
            using var archive = new ZipArchive(new MemoryStream(zip));
            var names = archive.Entries.Select(e => e.FullName).ToArray();
            Check("Windows package layout matches the IIS backend", new[] { "slaps-settings.json", "agent.pfx", "recovery.cer", "bin/StandaloneLaps.Agent.exe", "bin/StandaloneLaps.Agent.exe.config", "Install-SlapsAgent.ps1", "Install.cmd", "README.txt" }
                .All(n => names.Contains("SLAPS-Agent-DMZ-WEB-01/" + n)), string.Join(",", names));
            var settingsJson = JsonDocument.Parse(Read(archive, "slaps-settings.json")).RootElement;
            var deviceId = Guid.Parse(settingsJson.GetProperty("deviceId").GetString());
            Check("settings point to the agent port", settingsJson.GetProperty("apiUrl").GetString() == $"https://localhost:{agent}/");
            var recovery = X509CertificateLoader.LoadCertificate(Read(archive, "recovery.cer"));
            Check("recovery fingerprint in settings matches recovery.cer", settingsJson.GetProperty("recoveryCertificateSha256").GetString() == Wire.Sha256(recovery.RawData));
            using var agentCertificate = X509CertificateLoader.LoadPkcs12(Read(archive, "agent.pfx"), pfxPassword, X509KeyStorageFlags.UserKeySet);
            Check("agent certificate matches pin and is accepted by the CA check", settingsJson.GetProperty("clientCertificateSha256").GetString() == Wire.Sha256(agentCertificate.RawData) && keys.IsAgentCertificate(agentCertificate));
            Check("CA check rejects a self-signed client certificate", !keys.IsAgentCertificate(SelfSigned()));

            Console.WriteLine("Agent API (wire format of the Windows agent)");
            var apiBase = $"https://localhost:{agent}/api.aspx?device={deviceId:D}";
            using var agentClient = AgentClient(tlsThumbprint, agentCertificate);
            using (var anonymous = AgentClient(tlsThumbprint, null))
                Check("handshake without client certificate fails", await Fails(() => anonymous.GetAsync(apiBase)));
            using (var foreign = AgentClient(tlsThumbprint, SelfSigned()))
                Check("handshake with a foreign client certificate fails", await Fails(() => foreign.GetAsync(apiBase)));
            var history = await agentClient.GetAsync(apiBase);
            Check("installer probe: history GET returns 200 []", history.StatusCode == HttpStatusCode.OK && await history.Content.ReadAsStringAsync() == "[]");
            var junk = await agentClient.PutAsync(apiBase + "&rotation=" + Guid.NewGuid(), Json("{\"probe\":true}"));
            Check("installer probe: junk PUT returns 400", junk.StatusCode == HttpStatusCode.BadRequest);
            Check("portal pages are not served on the agent port", (await agentClient.GetAsync($"https://localhost:{agent}/")).StatusCode == HttpStatusCode.NotFound);
            Check("other device ID is forbidden", (await agentClient.GetAsync($"https://localhost:{agent}/api.aspx?device={Guid.NewGuid():D}")).StatusCode == HttpStatusCode.Forbidden);

            var framework = FrameworkProbe(root, Read(archive, "agent.pfx"), pfxPassword, apiBase, tlsThumbprint);
            Check(".NET Framework HttpWebRequest (Windows agent stack) authenticates: GET 200 / PUT 400", framework == "200 [] 400", framework);

            var rotation = Guid.NewGuid();
            var envelope = AgentEncrypt(deviceId, rotation, recovery, "Secret-Pass-1!");
            var put = await agentClient.PutAsync(apiBase + "&rotation=" + rotation, Json(StandaloneLapsWeb.EnvelopeJson.Serialize(envelope)));
            Check("agent envelope PUT returns 204", put.StatusCode == HttpStatusCode.NoContent, ((int)put.StatusCode).ToString());
            var readBack = await agentClient.GetStringAsync(apiBase + "&rotation=" + rotation);
            Check("read-back is identical for the agent's serializer", StandaloneLapsWeb.EnvelopeJson.Serialize(StandaloneLapsWeb.EnvelopeJson.Deserialize<AgentEnvelope>(readBack)) == StandaloneLapsWeb.EnvelopeJson.Serialize(envelope));
            Check("identical retry PUT returns 204", (await agentClient.PutAsync(apiBase + "&rotation=" + rotation, Json(StandaloneLapsWeb.EnvelopeJson.Serialize(envelope)))).StatusCode == HttpStatusCode.NoContent);
            var other = AgentEncrypt(deviceId, rotation, recovery, "Different");
            Check("different content for an existing rotation returns 409", (await agentClient.PutAsync(apiBase + "&rotation=" + rotation, Json(StandaloneLapsWeb.EnvelopeJson.Serialize(other)))).StatusCode == HttpStatusCode.Conflict);
            Check("applied report returns 204", (await agentClient.PostAsync(apiBase + "&rotation=" + rotation + "&action=applied", new ByteArrayContent(Array.Empty<byte>()))).StatusCode == HttpStatusCode.NoContent);
            Check("applied report for unknown rotation returns 404", (await agentClient.PostAsync(apiBase + "&rotation=" + Guid.NewGuid() + "&action=applied", new ByteArrayContent(Array.Empty<byte>()))).StatusCode == HttpStatusCode.NotFound);
            var historyJson = JsonDocument.Parse(await agentClient.GetStringAsync(apiBase)).RootElement;
            Check("history lists the version as applied", historyJson.GetArrayLength() == 1 && historyJson[0].GetProperty("rotationId").GetGuid() == rotation && historyJson[0].GetProperty("appliedReportedUtc").ValueKind == JsonValueKind.String);
            Check("server decrypts the agent envelope", keys.Reveal(store.Get(deviceId, rotation).Envelope).password == "Secret-Pass-1!");
            Check("agent EnvelopeCrypto decrypts a server-encrypted envelope", AgentDecrypt(Wire.Encrypt(new Payload { version = 1, deviceId = deviceId.ToString("D"), rotationId = rotation, createdUtc = DateTimeOffset.UtcNow.ToString("O"), password = "x" }, keys.Recovery), keys.Recovery) == "x");

            Console.WriteLine("Portal recovery");
            var drawerUrl = baseUrl + $"?device={deviceId:D}&tab=history&rotation={rotation:D}";
            var drawer = await portalClient.GetStringAsync(drawerUrl);
            Check("history drawer shows the version", drawer.Contains(rotation.ToString("D")) && drawer.Contains("Reported applied"));
            var reveal = await (await portalClient.PostAsync(drawerUrl, Form(drawer, ("action", "reveal")))).Content.ReadAsStringAsync();
            Check("reveal shows account and password", reveal.Contains("Secret-Pass-1!") && reveal.Contains("TESTHOST\\Administrator"));
            var download = await portalClient.GetStringAsync(baseUrl + $"download?device={deviceId:D}&rotation={rotation:D}");
            Check("encrypted envelope download", download.Contains(rotation.ToString("D")) && !download.Contains("Secret-Pass-1!"));
            Check("revealed password has copy and show buttons", reveal.Contains("data-copy=") && reveal.Contains("data-toggle=") && reveal.Contains("data-secret") && reveal.Contains("<script src=\"copy.js\"></script>"));

            Console.WriteLine("Password tab (current password first)");
            var passwordTab = await portalClient.GetStringAsync(baseUrl + $"?device={deviceId:D}");
            Check("device opens on the Password tab with the newest version", passwordTab.Contains("Current local administrator password") && passwordTab.Contains("Show password") && passwordTab.Contains("tab=password&amp;rotation=" + rotation.ToString("D")) && !passwordTab.Contains("Secret-Pass-1!"));
            Check("history and details are separate tabs", passwordTab.Contains("tab=history") && passwordTab.Contains("tab=details") && passwordTab.Contains(">Details</a>"));
            var currentUrl = baseUrl + $"?device={deviceId:D}&tab=password&rotation={rotation:D}";
            var current = await (await portalClient.PostAsync(currentUrl, Form(passwordTab, ("action", "reveal")))).Content.ReadAsStringAsync();
            Check("one click on the Password tab reveals the current password", current.Contains("Secret-Pass-1!") && current.Contains("TESTHOST\\Administrator") && current.Contains("Current local administrator password") && !current.Contains(">Show password</button>"));
            Check("old ?tab=overview links open the Password tab", (await portalClient.GetStringAsync(baseUrl + $"?device={deviceId:D}&tab=overview")).Contains("Current local administrator password"));
            Check("copy script is served", (await portalClient.GetStringAsync(baseUrl + "copy.js")).Contains("navigator.clipboard"));

            Console.WriteLine("Windows LAPS page");
            var lapsPage = await portalClient.GetAsync(baseUrl + "windowslaps");
            var lapsHtml = await lapsPage.Content.ReadAsStringAsync();
            Check("Windows LAPS page and navigation item for administrators", lapsPage.StatusCode == HttpStatusCode.OK && lapsHtml.Contains("Search for a computer") && lapsHtml.Contains("href=\"windowslaps\"") && lapsHtml.Contains("Active Directory: on") && lapsHtml.Contains("Microsoft Entra ID: off"));
            var unreachable = await portalClient.GetStringAsync(baseUrl + "windowslaps?q=SRV-APP01");
            Check("unreachable domain controller is reported on the page, not as a server error", unreachable.Contains("Active Directory: Cannot connect to Active Directory"));
            var injection = await portalClient.GetStringAsync(baseUrl + "windowslaps?q=" + Uri.EscapeDataString("x)(objectClass=*"));
            Check("LDAP filter characters are rejected before any directory access", injection.Contains("Enter a computer name") && !injection.Contains("Cannot connect"));
            var readerRequest = new HttpRequestMessage(HttpMethod.Get, baseUrl + "windowslaps");
            readerRequest.Headers.Add("X-Slaps-Development-Role", "reader");
            Check("readers cannot open Windows LAPS unless WindowsLapsRequiredRole=Reader", (await portalClient.SendAsync(readerRequest)).StatusCode == HttpStatusCode.Forbidden);
            var readerHome = new HttpRequestMessage(HttpMethod.Get, baseUrl);
            readerHome.Headers.Add("X-Slaps-Development-Role", "reader");
            Check("readers do not see the Windows LAPS navigation item", !(await (await portalClient.SendAsync(readerHome)).Content.ReadAsStringAsync()).Contains("href=\"windowslaps\""));
            Check("search panel explains that only computers with a stored password are listed", lapsHtml.Contains("Only computers with a stored LAPS password are listed") && lapsHtml.Contains("class=\"search-panel\""));
            Check("device table is sortable and resizable (copy.js)", passwordTab.Contains("class=\"device-table sortable\"") && passwordTab.Contains("data-sort=\"number\"") && (await portalClient.GetStringAsync(baseUrl + "copy.js")).Contains("col-resizer"));
            var settingsLaps = await portalClient.GetStringAsync(baseUrl + "settings");
            Check("settings show the Windows LAPS configuration", settingsLaps.Contains("Windows LAPS lookup") && settingsLaps.Contains("127.0.0.1") && settingsLaps.Contains("Test Active Directory connection") && settingsLaps.Contains("Microsoft Entra ID"));
            var adTest = await (await portalClient.PostAsync(baseUrl + "settings", Form(settingsLaps, ("action", "test-ad")))).Content.ReadAsStringAsync();
            Check("Active Directory connection test reports the failure on the page", adTest.Contains("notice danger") && adTest.Contains("Cannot connect to Active Directory"));
            var ajaxRequest = new HttpRequestMessage(HttpMethod.Post, baseUrl + "settings") { Content = Form(settingsLaps, ("action", "test-ad")) };
            ajaxRequest.Headers.Add("X-Slaps-Ajax", "1");
            var ajaxResponse = await portalClient.SendAsync(ajaxRequest);
            var ajaxJson = JsonDocument.Parse(await ajaxResponse.Content.ReadAsStringAsync()).RootElement;
            Check("connection tests answer as JSON for in-place display (no page reload)", ajaxResponse.Content.Headers.ContentType?.MediaType == "application/json" && !ajaxJson.GetProperty("ok").GetBoolean() && ajaxJson.GetProperty("message").GetString().Contains("Cannot connect") && settingsLaps.Contains("data-ajax"));
            var expireUrl = baseUrl + "windowslaps?source=ad&id=" + Guid.NewGuid() + "&tab=password";
            var expireRequest = new HttpRequestMessage(HttpMethod.Post, expireUrl) { Content = Form(settingsLaps, ("action", "expire")) };
            expireRequest.Headers.Add("X-Slaps-Ajax", "1");
            var expireJson = JsonDocument.Parse(await (await portalClient.SendAsync(expireRequest)).Content.ReadAsStringAsync()).RootElement;
            Check("expire now (AD) answers in place and reports an unreachable directory", !expireJson.GetProperty("ok").GetBoolean() && expireJson.GetProperty("message").GetString().Contains("Cannot connect"));
            var readerExpire = new HttpRequestMessage(HttpMethod.Post, expireUrl) { Content = Form(settingsLaps, ("action", "expire")) };
            readerExpire.Headers.Add("X-Slaps-Development-Role", "reader");
            Check("readers cannot expire passwords", (await portalClient.SendAsync(readerExpire)).StatusCode == HttpStatusCode.Forbidden);
            Check("Windows LAPS reveal without antiforgery token is rejected", (await portalClient.PostAsync(baseUrl + "windowslaps?source=ad&id=" + Guid.NewGuid() + "&tab=password", new FormUrlEncodedContent(new Dictionary<string, string> { ["action"] = "reveal" }))).StatusCode == HttpStatusCode.BadRequest);

            Console.WriteLine("Retention, delete, restore, rekey");
            store.SetHistoryLimit(2, "test");
            for (var i = 0; i < 3; i++)
            {
                var id = Guid.NewGuid();
                await agentClient.PutAsync(apiBase + "&rotation=" + id, Json(StandaloneLapsWeb.EnvelopeJson.Serialize(AgentEncrypt(deviceId, id, recovery, "P" + i))));
                await Task.Delay(20);
            }
            var trimmed = store.History(deviceId, 0, 100);
            Check("history limit 2 keeps newest plus the applied version", trimmed.Length == 2 && trimmed.Any(e => e.rotationId == rotation), trimmed.Length.ToString());
            store.SetDeleted(deviceId, true, "test");
            Check("deleted device: agent is forbidden", (await agentClient.GetAsync(apiBase)).StatusCode == HttpStatusCode.Forbidden);
            store.SetDeleted(deviceId, false, "test");
            Check("restored device: agent works again", (await agentClient.GetAsync(apiBase)).StatusCode == HttpStatusCode.OK);
            var rekey = packages.Create("DMZ-WEB-01", deviceId, "test", ClientPackages.Linux);
            Check("rekey keeps the device ID", rekey.Client.DeviceId == deviceId.ToString("D"));
            Check("old certificate is rejected after rekey", (await agentClient.GetAsync(apiBase)).StatusCode == HttpStatusCode.Forbidden);
            var (linuxInfo, linuxZip) = store.Package(rekey.Package.Token);
            using (var linux = new ZipArchive(new MemoryStream(linuxZip)))
                Check("Linux package contains install.sh and versioned .deb", linuxInfo.FileName.EndsWith("-linux.zip") && linux.Entries.Any(e => e.FullName.EndsWith("/install.sh")) &&
                    linux.Entries.Any(e => e.FullName.EndsWith("_" + StandaloneLapsWeb.AppVersion.Number + "_all.deb")));
            Check("duplicate active device name is rejected", Throws<ArgumentException>(() => packages.Create("dmz-web-01", null, "test", ClientPackages.Windows)));
            Check("invalid device name is rejected", Throws<ArgumentException>(() => packages.Create("bad/name", null, "test", ClientPackages.Windows)));
        }
        finally
        {
            await app.StopAsync();
            await app.DisposeAsync();
        }

        Console.WriteLine("Restart and master key");
        var restarted = ServerProgram.Build(Array.Empty<string>(), Config(root, masterKey, FreePort(), FreePort()));
        var restartedKeys = (KeyVault)restarted.Services.GetService(typeof(KeyVault));
        Check("restart reuses the generated TLS certificate", restartedKeys.Tls.Thumbprint == tlsThumbprint);
        await restarted.DisposeAsync();
        Check("wrong master key fails with a clear error", Throws<InvalidOperationException>(() => ServerProgram.Build(Array.Empty<string>(), Config(root, Convert.ToBase64String(RandomNumberGenerator.GetBytes(36)), FreePort(), FreePort())), "SLAPS_MASTER_KEY"));

        Console.WriteLine("Import from an IIS vault");
        ImportCheck(root, masterKey);
    }

    private static void ImportCheck(string root, string masterKey)
    {
        var appData = Path.Combine(root, "iis", "App_Data");
        var device = Guid.NewGuid();
        var rotation = Guid.NewGuid();
        Directory.CreateDirectory(Path.Combine(appData, "Vault", "_clients"));
        Directory.CreateDirectory(Path.Combine(appData, "Vault", device.ToString("D")));
        using var recovery = new CertificateRequest("CN=Test Recovery", RSA.Create(3072), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var envelope = AgentEncrypt(device, rotation, recovery, "Imported!");
        var sha = new string('A', 64);
        // JavaScriptSerializer output of the IIS vault.
        File.WriteAllText(Path.Combine(appData, "Vault", "_clients", device.ToString("D") + ".json"),
            "{\"certificateSha256\":\"" + sha + "\",\"role\":\"agent\",\"deviceId\":\"" + device.ToString("D") + "\",\"displayName\":\"IIS-SRV\",\"createdUtc\":\"2026-11-01T10:00:00.0000000+00:00\",\"createdBy\":\"entra:x\"}");
        File.WriteAllText(Path.Combine(appData, "Vault", device.ToString("D"), rotation.ToString("D") + ".record.json"),
            "{\"envelope\":" + StandaloneLapsWeb.EnvelopeJson.Serialize(envelope) + ",\"receivedUtc\":\"2026-11-02T10:00:00.0000000+00:00\"}");
        File.WriteAllText(Path.Combine(appData, "Vault", device.ToString("D"), rotation.ToString("D") + ".applied.json"), "\"2026-11-02T10:01:00.0000000+00:00\"");
        File.WriteAllText(Path.Combine(appData, "Vault", "settings.json"), "{\"historyLimit\":30}");
        File.WriteAllText(Path.Combine(appData, "clients.json"), "[]");
        var database = Path.Combine(root, "import", "slaps.db");
        Environment.SetEnvironmentVariable("Slaps__ConnectionString", "Data Source=" + database);
        Environment.SetEnvironmentVariable("Slaps__DataDirectory", Path.Combine(root, "import"));
        Environment.SetEnvironmentVariable("SLAPS_MASTER_KEY", masterKey);
        try
        {
            Check("import-iis-vault succeeds", Tools.ImportIisVault(new[] { appData }) == 0);
            var store = new VaultStore(ServerOptions.Load(new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddEnvironmentVariables().Build()));
            var history = store.History(device, 0, 100);
            Check("imported device, version, applied report and history limit", store.Client(device)?.DisplayName == "IIS-SRV" && history.Length == 1 && history[0].appliedReportedUtc != null && store.HistoryLimit == 30);
            Check("imported envelope still decrypts", Wire.Decrypt(store.Get(device, rotation).Envelope, recovery).password == "Imported!");
        }
        finally
        {
            Environment.SetEnvironmentVariable("Slaps__ConnectionString", null);
            Environment.SetEnvironmentVariable("Slaps__DataDirectory", null);
            Environment.SetEnvironmentVariable("SLAPS_MASTER_KEY", null);
        }
    }

    // ---- Helpers --------------------------------------------------------------------------------------

    // Windows PowerShell 5.1 runs on .NET Framework, i.e. the same HttpWebRequest/Schannel client code as the agent service.
    private static string FrameworkProbe(string root, byte[] pfx, string password, string apiBase, string tlsThumbprint)
    {
        var pfxPath = Path.Combine(root, "probe.pfx");
        var scriptPath = Path.Combine(root, "probe.ps1");
        File.WriteAllBytes(pfxPath, pfx);
        File.WriteAllText(scriptPath, @"param($Pfx, $Password, $Url, $Thumbprint)
$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[Net.ServicePointManager]::ServerCertificateValidationCallback = { param($s, $c) $c.GetCertHashString() -eq $Thumbprint }
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($Pfx, $Password, 'UserKeySet')
function Call($method, $url, $body) {
  $r = [Net.HttpWebRequest]::Create($url); $r.Method = $method; $r.ClientCertificates.Add($cert) | Out-Null; $r.ContentType = 'application/json'
  if ($body) { $b = [Text.Encoding]::UTF8.GetBytes($body); $r.ContentLength = $b.Length; $s = $r.GetRequestStream(); $s.Write($b, 0, $b.Length); $s.Close() }
  try { $resp = $r.GetResponse() } catch [Net.WebException] { if ($_.Exception.Response) { return [string][int]$_.Exception.Response.StatusCode } throw }
  $text = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd(); return ([string][int]$resp.StatusCode + ' ' + $text)
}
$a = Call 'GET' $Url $null
$b = Call 'PUT' ($Url + '&rotation=' + [guid]::NewGuid()) '{""probe"":true}'
Write-Output ($a + ' ' + $b)
");
        var start = new System.Diagnostics.ProcessStartInfo("powershell.exe") { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var argument in new[] { "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", scriptPath, "-Pfx", pfxPath, "-Password", password, "-Url", apiBase, "-Thumbprint", tlsThumbprint })
            start.ArgumentList.Add(argument);
        using var process = System.Diagnostics.Process.Start(start);
        var output = process.StandardOutput.ReadToEnd().Trim();
        var error = process.StandardError.ReadToEnd().Trim();
        process.WaitForExit();
        File.Delete(pfxPath);
        return output.Length > 0 ? output : error;
    }

    private static AgentEnvelope AgentEncrypt(Guid device, Guid rotation, X509Certificate2 recovery, string password) =>
        StandaloneLapsWeb.EnvelopeCrypto.Encrypt(new AgentPayload
        {
            version = 1, deviceId = device.ToString("D"), rotationId = rotation, createdUtc = DateTimeOffset.UtcNow.ToString("O"),
            computerName = "TESTHOST", accountName = "Administrator", accountSid = "S-1-5-21-1-2-3-500", password = password
        }, recovery);

    private static string AgentDecrypt(Envelope envelope, X509Certificate2 recovery) =>
        StandaloneLapsWeb.EnvelopeCrypto.Decrypt(StandaloneLapsWeb.EnvelopeJson.Deserialize<AgentEnvelope>(JsonSerializer.Serialize(envelope, Wire.Json)), recovery).password;

    private static X509Certificate2 SelfSigned()
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=Foreign", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(KeyVault.ClientAuthOid) }, false));
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        return X509CertificateLoader.LoadPkcs12(created.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.UserKeySet);
    }

    private static HttpClient PortalClient(string tlsThumbprint, out CookieContainer cookies)
    {
        cookies = new CookieContainer();
        var handler = new SocketsHttpHandler { CookieContainer = cookies, AllowAutoRedirect = false };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, _, _) => certificate != null && new X509Certificate2(certificate).Thumbprint == tlsThumbprint;
        return new HttpClient(handler);
    }

    private static HttpClient AgentClient(string tlsThumbprint, X509Certificate2 certificate)
    {
        var handler = new SocketsHttpHandler { AllowAutoRedirect = false };
        handler.SslOptions.RemoteCertificateValidationCallback = (_, server, _, _) => server != null && new X509Certificate2(server).Thumbprint == tlsThumbprint;
        handler.SslOptions.EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12;
        if (certificate != null) handler.SslOptions.ClientCertificates = new X509CertificateCollection { certificate };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
    }

    private static FormUrlEncodedContent Form(string html, params (string Name, string Value)[] fields)
    {
        var values = fields.ToDictionary(f => f.Name, f => f.Value);
        values["__RequestVerificationToken"] = WebUtility.HtmlDecode(Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value);
        return new FormUrlEncodedContent(values);
    }

    private static StringContent Json(string body) => new(body, Encoding.UTF8, new MediaTypeHeaderValue("application/json"));

    private static byte[] Read(ZipArchive archive, string suffix)
    {
        using var stream = archive.Entries.Single(e => e.FullName.EndsWith("/" + suffix)).Open();
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }

    private static bool Throws<T>(Action action, string messagePart = null) where T : Exception
    {
        try { action(); return false; }
        catch (T ex) { return messagePart == null || ex.Message.Contains(messagePart); }
    }

    private static async Task<bool> Fails(Func<Task<HttpResponseMessage>> request)
    {
        try { await request(); return false; }
        catch (HttpRequestException) { return true; }
        catch (TaskCanceledException) { return true; }
    }
}
