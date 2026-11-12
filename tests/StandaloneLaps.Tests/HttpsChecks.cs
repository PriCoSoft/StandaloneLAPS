using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using StandaloneLaps;
using StandaloneLaps.Api;

internal static class HttpsChecks
{
    public static async Task<int> RunAsync(string directory, X509Certificate2 recovery)
    {
        var checks = 0;
        void Check(bool ok, string label) { if (!ok) throw new Exception("FAILED: " + label); checks++; Console.WriteLine("PASS HTTPS " + label); }
        using var server = CreateCertificate("server", "1.3.6.1.5.5.7.3.1");
        using var agent = CreateCertificate("agent", "1.3.6.1.5.5.7.3.2");
        using var reader = CreateCertificate("reader", "1.3.6.1.5.5.7.3.2");
        using var stranger = CreateCertificate("stranger", "1.3.6.1.5.5.7.3.2");
        var device = Guid.NewGuid();
        var options = new VaultOptions { DataDirectory = directory, ServerCertificateSha256 = SecretEncryption.Fingerprint(server),
            Clients = [
                new VaultClient { CertificateSha256 = SecretEncryption.Fingerprint(agent), Role = "agent", DeviceId = device.ToString("D") },
                new VaultClient { CertificateSha256 = SecretEncryption.Fingerprint(reader), Role = "reader" }
            ] };
        options.Validate();
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.Services.AddRateLimiter(_ => { });
        builder.WebHost.ConfigureKestrel(k => k.Listen(IPAddress.Loopback, 0, listen => listen.UseHttps(https =>
        {
            https.ServerCertificate = server;
            https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
            https.ClientCertificateValidation = (certificate, _, _) => options.Authorize(certificate) is not null;
        })));
        await using var app = builder.Build();
        VaultApplication.Configure(app, options, new VaultRepository(directory));
        await app.StartAsync();
        try
        {
            var address = app.Services.GetRequiredService<IServer>().Features.Get<IServerAddressesFeature>()!.Addresses.Single();
            HttpClient Client(X509Certificate2? certificate)
            {
                var handler = new HttpClientHandler { AllowAutoRedirect = false };
                if (certificate is not null) handler.ClientCertificates.Add(certificate);
                // Test-only trust in this ephemeral loopback server certificate. Production uses Windows trust.
                handler.ServerCertificateCustomValidationCallback = (_, presented, _, _) =>
                    presented is not null && SecretEncryption.Fingerprint(presented) == SecretEncryption.Fingerprint(server);
                return new HttpClient(handler) { BaseAddress = new Uri(address), Timeout = TimeSpan.FromSeconds(10) };
            }
            var rotation = Guid.NewGuid();
            var path = $"/api/v1/devices/{device:D}/rotations/{rotation:D}";
            var envelope = SecretEncryption.Encrypt(new SecretPayload(1, device.ToString("D"), "TEST", "Administrator",
                "S-1-5-21-1-2-3-500", rotation, DateTimeOffset.UtcNow, RotationEngine.GeneratePassword(32)), recovery);
            using var writerHttp = Client(agent);
            var client = new StandaloneLaps.Agent.ApiBackupClient(writerHttp, device.ToString("D"));
            await client.StoreAndVerifyAsync(envelope, default);
            Check(true, "agent upload and read-back over mutual TLS");
            using (var conflict = await writerHttp.PutAsJsonAsync(path, envelope with { CreatedUtc = envelope.CreatedUtc.AddSeconds(1) }))
                Check(conflict.StatusCode == HttpStatusCode.Conflict, "existing ID rejects different content");
            using (var invalid = await writerHttp.PutAsJsonAsync(path, envelope with { Tag = "bad" }))
                Check(invalid.StatusCode == HttpStatusCode.BadRequest, "invalid envelope returns 400");
            using (var forbidden = await writerHttp.GetAsync($"/api/v1/devices/{Guid.NewGuid():D}/rotations"))
                Check(forbidden.StatusCode == HttpStatusCode.Forbidden, "agent cannot read another device");
            using (var forbiddenWrite = await writerHttp.PutAsJsonAsync($"/api/v1/devices/{Guid.NewGuid():D}/rotations/{rotation:D}", envelope))
                Check(forbiddenWrite.StatusCode == HttpStatusCode.Forbidden, "agent cannot write another device");
            await client.ReportAppliedAsync(rotation, default);
            using var readerHttp = Client(reader);
            var history = await readerHttp.GetFromJsonAsync<HistoryEntry[]>($"/api/v1/devices/{device:D}/rotations");
            Check(history is [{ AppliedReportedUtc: not null }], "reader retrieves history and applied status");
            using (var forbidden = await readerHttp.PutAsJsonAsync(path, envelope))
                Check(forbidden.StatusCode == HttpStatusCode.Forbidden, "reader cannot write");
            using (var forbidden = await readerHttp.PostAsync(path + "/applied", null))
                Check(forbidden.StatusCode == HttpStatusCode.Forbidden, "reader cannot report application");
            using (var response = await readerHttp.GetAsync(path))
            {
                Check(response.Headers.CacheControl?.NoStore == true, "responses prohibit caching");
                var stored = await response.Content.ReadFromJsonAsync<Envelope>();
                Check(stored is not null && SecretEncryption.Decrypt(stored, recovery).Password ==
                    SecretEncryption.Decrypt(envelope, recovery).Password, "download and offline decryption");
            }
            foreach (var certificate in new X509Certificate2?[] { null, stranger })
            {
                using var denied = Client(certificate);
                var rejected = false;
                try { using var response = await denied.GetAsync(path); rejected = !response.IsSuccessStatusCode; }
                catch (HttpRequestException) { rejected = true; }
                Check(rejected, certificate is null ? "missing certificate rejected" : "unknown certificate rejected");
            }
        }
        finally { await app.StopAsync(); }
        return checks;
    }

    private static X509Certificate2 CreateCertificate(string name, string eku)
    {
        using var rsa = RSA.Create(3072);
        var request = new CertificateRequest("CN=Test-" + name, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new(eku) }, true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        var san = new SubjectAlternativeNameBuilder(); san.AddIpAddress(IPAddress.Loopback);
        request.CertificateExtensions.Add(san.Build());
        using var created = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddHours(1));
        // Windows Schannel needs a key container rather than an ephemeral CNG key for TLS.
        // No certificate-store import and no PersistKeySet: .NET removes the temporary key on disposal.
        var pfx = created.Export(X509ContentType.Pfx);
        try { return X509CertificateLoader.LoadPkcs12(pfx, null, X509KeyStorageFlags.UserKeySet); }
        finally { CryptographicOperations.ZeroMemory(pfx); }
    }
}
