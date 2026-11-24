using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using StandaloneLaps.Server;
using StandaloneLapsWeb;

namespace StandaloneLaps.Server.Tests;

// Windows LAPS lookup in the container server without a directory: option validation, Graph flow against a fake
// HTTP handler, the DPAPI-NG helper protocol (this test executable stands in for Python) and native DPAPI-NG.
internal static class WindowsLapsTests
{
    public const string FakeHelperArgument = "--fake-dpapi-ng-helper";

    public static async Task Run(Action<string, bool, string> check)
    {
        Console.WriteLine("Windows LAPS lookup");
        Options(check);
        await Graph(check);
        await Helper(check);
        await Native(check);
    }

    private static ServerOptions Load(Dictionary<string, string> values) =>
        ServerOptions.Load(new Microsoft.Extensions.Configuration.ConfigurationBuilder().AddInMemoryCollection(values.ToDictionary(p => "Slaps:" + p.Key, p => p.Value)).Build());

    private static void Options(Action<string, bool, string> check)
    {
        var defaults = Load(new Dictionary<string, string>());
        check("Windows LAPS lookup is off by default", !defaults.WindowsLaps.Enabled && !defaults.WindowsLaps.ReaderAllowed, null);
        var entra = Load(new Dictionary<string, string> { ["OidcAuthority"] = "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0", ["OidcClientId"] = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", ["WindowsLapsEntraEnabled"] = "true", ["WindowsLapsEntraClientSecret"] = "s" });
        check("Entra tenant and client default to the OIDC sign-in values", entra.WindowsLaps.EntraTenantId == "11111111-2222-3333-4444-555555555555" && entra.WindowsLaps.EntraClientId == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", null);
        check("Entra lookup without secret or certificate is rejected", Throws(() => Load(new Dictionary<string, string> { ["WindowsLapsEntraEnabled"] = "true", ["WindowsLapsEntraTenantId"] = Guid.NewGuid().ToString(), ["WindowsLapsEntraClientId"] = Guid.NewGuid().ToString() })), null);
        check("invalid decrypt mode is rejected", Throws(() => Load(new Dictionary<string, string> { ["WindowsLapsAdEnabled"] = "true", ["WindowsLapsAdServer"] = "dc", ["WindowsLapsAdUsername"] = "u", ["WindowsLapsAdPassword"] = "p", ["WindowsLapsAdDecryptMode"] = "magic" })), null);
        var explicitCredentials = new WindowsLapsOptions { AdEnabled = true, AdUsername = "svc@corp.example", AdPassword = "x" };
        check("explicit AD credentials use the Python helper (native DPAPI-NG only uses the process identity)", explicitCredentials.UsePython && !new WindowsLapsOptions { AdEnabled = true }.UsePython == OperatingSystem.IsWindows(), null);
        var reader = new WindowsLapsOptions { AdEnabled = true, ReaderAllowed = true };
        check("WindowsLapsRequiredRole=Reader admits readers", reader.Allowed(new PortalUser { IsReader = true }) && !new WindowsLapsOptions { AdEnabled = true }.Allowed(new PortalUser { IsReader = true }), null);
    }

    private sealed class FakeGraph : HttpMessageHandler
    {
        public readonly List<string> Requests = new();
        public int TokenRequests;

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var url = Uri.UnescapeDataString(request.RequestUri!.AbsoluteUri);
            Requests.Add(request.Method + " " + url);
            if (url.Contains("/oauth2/v2.0/token"))
            {
                TokenRequests++;
                var form = await request.Content!.ReadAsStringAsync(cancellationToken);
                if (!form.Contains("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer") || !form.Contains("scope=https%3A%2F%2Fgraph.microsoft.com%2F.default"))
                    return Json(HttpStatusCode.BadRequest, "{\"error\":\"invalid_client\",\"error_description\":\"bad form\"}");
                return Json(HttpStatusCode.OK, "{\"access_token\":\"token-1\",\"expires_in\":3599}");
            }
            if (request.Headers.Authorization?.Parameter != "token-1" || !request.Headers.Contains("ocp-client-name")) return Json(HttpStatusCode.Unauthorized, "{}");
            if (url.Contains("deviceName eq 'SRV-ENTRA'"))
                return Json(HttpStatusCode.OK, "{\"value\":[{\"id\":\"b465e4e8-e4e8-b465-e8e4-65b4e8e465b4\",\"deviceName\":\"SRV-ENTRA\",\"lastBackupDateTime\":\"2026-11-01T10:00:00Z\",\"refreshDateTime\":\"2026-12-01T10:00:00Z\"}]}");
            if (url.Contains("b465e4e8-e4e8-b465-e8e4-65b4e8e465b4?$select="))
                return Json(HttpStatusCode.OK, "{\"id\":\"b465e4e8-e4e8-b465-e8e4-65b4e8e465b4\",\"deviceName\":\"SRV-ENTRA\",\"refreshDateTime\":\"2026-12-01T10:00:00Z\",\"credentials\":[" +
                    "{\"accountName\":\"LocalAdmin\",\"backupDateTime\":\"2026-11-01T10:00:00Z\",\"passwordBase64\":\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes("Entra-Current")) + "\"}," +
                    "{\"accountName\":\"LocalAdmin\",\"backupDateTime\":\"2026-10-01T10:00:00Z\",\"passwordBase64\":\"" + Convert.ToBase64String(Encoding.UTF8.GetBytes("Entra-Old")) + "\"}]}");
            if (url.Contains("deviceName eq 'DENIED'")) return Json(HttpStatusCode.Forbidden, "{\"error\":{\"code\":\"Authorization_RequestDenied\",\"message\":\"Insufficient privileges to complete the operation.\"}}");
            if (url.Contains("/deviceLocalCredentials/")) return Json(HttpStatusCode.NotFound, "{\"error\":{\"message\":\"not found\"}}");
            if (url.Contains("/v1.0/deviceManagement/managedDevices?") && url.Contains("azureADDeviceId eq 'b465e4e8-e4e8-b465-e8e4-65b4e8e465b4'"))
                return Json(HttpStatusCode.OK, "{\"value\":[{\"id\":\"md-0001\",\"deviceName\":\"SRV-ENTRA\"}]}");
            if (url.Contains("/v1.0/deviceManagement/managedDevices?")) return Json(HttpStatusCode.OK, "{\"value\":[]}");
            if (request.Method == HttpMethod.Post && url.EndsWith("/beta/deviceManagement/managedDevices/md-0001/rotateLocalAdminPassword")) { Requests.Add("ROTATED"); return new HttpResponseMessage(HttpStatusCode.NoContent); }
            return Json(HttpStatusCode.OK, "{\"value\":[]}");
        }

        private static HttpResponseMessage Json(HttpStatusCode status, string body) => new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
    }

    private static async Task Graph(Action<string, bool, string> check)
    {
        var directory = Path.Combine(Path.GetTempPath(), "slaps-laps-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(directory);
        try
        {
            using var key = RSA.Create(2048);
            var request = new CertificateRequest("CN=SLAPS Graph test", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddDays(1));
            var pfx = Path.Combine(directory, "graph.pfx");
            File.WriteAllBytes(pfx, certificate.Export(X509ContentType.Pkcs12, "pfx-pass"));
            var options = new ServerOptions
            {
                WindowsLaps = new WindowsLapsOptions
                {
                    EntraEnabled = true, EntraTenantId = "11111111-2222-3333-4444-555555555555", EntraClientId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    EntraCertificatePath = pfx, EntraCertificatePassword = "pfx-pass", EntraHistory = true
                }
            };
            var fake = new FakeGraph();
            var service = new WindowsLapsService(options, fake);
            var found = await service.SearchEntra("SRV-ENTRA");
            check("Entra search by exact device name through Graph", found.Count == 1 && found[0].Source == "entra" && found[0].Name == "SRV-ENTRA" && found[0].ExpiresUtc == new DateTime(2026, 12, 1, 10, 0, 0, DateTimeKind.Utc), string.Join(" | ", fake.Requests));
            var (computer, credentials) = await service.ReadEntra(Guid.Parse(found[0].Id));
            check("Entra reveal returns current and previous password", computer.Name == "SRV-ENTRA" && credentials.Credentials.Count == 2 && credentials.Credentials[0].Kind == "current" && credentials.Credentials[0].Password == "Entra-Current" && credentials.Credentials[1].Password == "Entra-Old", null);
            check("access token is cached between Graph calls", fake.TokenRequests == 1, fake.TokenRequests.ToString());
            check("unknown Entra device ID gives no result instead of an error", (await service.SearchEntra(Guid.NewGuid().ToString())).Count == 0, null);
            var rotated = await service.RotateEntra(Guid.Parse("b465e4e8-e4e8-b465-e8e4-65b4e8e465b4"));
            check("Intune rotation: managed device looked up by Entra device ID, rotateLocalAdminPassword called", rotated.Contains("Intune was asked") && fake.Requests.Contains("ROTATED"), string.Join(" | ", fake.Requests));
            var notManaged = false;
            try { await service.RotateEntra(Guid.NewGuid()); } catch (WindowsLapsException ex) { notManaged = ex.Message.Contains("not managed by Microsoft Intune"); }
            check("rotation for a device without Intune is refused with a clear message", notManaged, null);
            var denied = false;
            try { await service.SearchEntra("DENIED"); } catch (WindowsLapsException ex) { denied = ex.Message.Contains("DeviceLocalCredential.Read.All") && ex.Message.Contains("Insufficient privileges"); }
            check("missing Graph permission is explained", denied, null);

            var jwt = WindowsLapsService.ClientAssertion(certificate, "11111111-2222-3333-4444-555555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", DateTime.UtcNow);
            var parts = jwt.Split('.');
            static byte[] Decode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
            var claims = JsonDocument.Parse(Decode(parts[1])).RootElement;
            check("client assertion is a valid RS256 JWT for the token endpoint", key.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), Decode(parts[2]), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1)
                && claims.GetProperty("aud").GetString() == "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token" && claims.GetProperty("sub").GetString() == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", null);
            check("Graph parsing matches the IIS portal (documented value wrapper, UTF-16 sample)", WindowsLapsService.ParseCredentials("{\"value\":{\"id\":\"b465e4e8-e4e8-b465-e8e4-65b4e8e465b4\",\"credentials\":[{\"accountName\":\"A\",\"backupDateTime\":\"2023-04-21T13:45:30Z\",\"passwordBase64\":\"UQBRAEAAZAA4AGYAOABnAFkA\"}]}}", true).Credentials.Single().Password == "QQ@d8f8gY", null);
        }
        finally { try { Directory.Delete(directory, true); } catch (IOException) { } }
    }

    // ---- DPAPI-NG helper protocol ------------------------------------------------------------------------

    // Echo "decryption": returns each blob unchanged, a single 0xFF byte fails. Checks that the credentials arrived on stdin.
    public static int FakeHelper()
    {
        var request = JsonDocument.Parse(Console.In.ReadToEnd()).RootElement;
        if (request.GetProperty("username").GetString() != "svc@corp.example" || request.GetProperty("password").GetString() != "Svc-Pass" || request.GetProperty("server").GetString() != "dc01.corp.example")
        {
            Console.Out.Write("{\"error\":\"credentials missing\"}");
            return 0;
        }
        var results = request.GetProperty("blobs").EnumerateArray().Select(b =>
        {
            var data = Convert.FromBase64String(b.GetString());
            return data.Length == 1 && data[0] == 0xFF ? (object)new Dictionary<string, string> { ["error"] = "KeyError: unknown root key" } : new Dictionary<string, string> { ["data"] = b.GetString() };
        }).ToArray();
        Console.Out.Write(JsonSerializer.Serialize(new { results }));
        return 0;
    }

    private static async Task Helper(Action<string, bool, string> check)
    {
        var exe = Path.ChangeExtension(typeof(WindowsLapsTests).Assembly.Location, OperatingSystem.IsWindows() ? ".exe" : null);
        if (!File.Exists(exe)) { check("fake DPAPI-NG helper executable exists", false, exe); return; }
        var options = new ServerOptions
        {
            WindowsLaps = new WindowsLapsOptions
            {
                AdEnabled = true, AdServer = "dc01.corp.example", AdUsername = "svc@corp.example", AdPassword = "Svc-Pass", DecryptMode = "python",
                Python = exe, DpapiScript = FakeHelperArgument
            }
        };
        var service = new WindowsLapsService(options);
        var payload = Encoding.Unicode.GetBytes("{\"n\":\"LapsAdmin\",\"t\":\"1dc5d2a2b3c4000\",\"p\":\"Helper-Pw\"}\0");
        var outcomes = await service.Decrypt(new[] { payload, new byte[] { 0xFF } });
        check("helper protocol: blobs and credentials via stdin, results per blob", outcomes.Count == 2 && outcomes[0].Data.SequenceEqual(payload) && outcomes[1].Error == "KeyError: unknown root key", outcomes.Count + " " + outcomes.LastOrDefault()?.Error);
        var wrong = new WindowsLapsService(new ServerOptions { WindowsLaps = new WindowsLapsOptions { AdEnabled = true, AdServer = "other", AdUsername = "x", AdPassword = "y", DecryptMode = "python", Python = exe, DpapiScript = FakeHelperArgument } });
        var reported = false;
        try { await wrong.Decrypt(new[] { payload }); } catch (WindowsLapsException ex) { reported = ex.Message.Contains("credentials missing"); }
        check("helper-level error is reported", reported, null);
        var missing = new WindowsLapsService(new ServerOptions { WindowsLaps = new WindowsLapsOptions { AdEnabled = true, DecryptMode = "python", Python = Path.Combine(Path.GetTempPath(), "no-python-here.exe"), DpapiScript = "x" } });
        reported = false;
        try { await missing.Decrypt(new[] { payload }); } catch (WindowsLapsException ex) { reported = ex.Message.Contains("was not found"); }
        check("missing Python is reported clearly", reported, null);
        check("malformed helper output is reported", Throws(() => WindowsLapsService.ParseHelperOutput("Traceback ...", 1, "ModuleNotFoundError: No module named 'dpapi_ng'")), null);
    }

    private static async Task Native(Action<string, bool, string> check)
    {
        if (!OperatingSystem.IsWindows()) return;
        var service = new WindowsLapsService(new ServerOptions { WindowsLaps = new WindowsLapsOptions { AdEnabled = true, DecryptMode = "native" } });
        var secret = Encoding.Unicode.GetBytes("{\"n\":\"Administrator\",\"t\":\"1dc5d2a2b3c4000\",\"p\":\"Native-Pw\"}\0");
        var blob = NativeDpapiNg.Protect("LOCAL=user", secret);
        var outcome = (await service.Decrypt(new[] { blob })).Single();
        check("native DPAPI-NG decryption on Windows (container server)", WindowsLapsFormat.ParsePayload(WindowsLapsFormat.DecryptedText(outcome.Data), "ad", "current").Password == "Native-Pw", outcome.Error);
    }

    private static bool Throws(Action action)
    {
        try { action(); return false; }
        catch (InvalidOperationException) { return true; }
        catch (WindowsLapsException) { return true; }
    }
}
