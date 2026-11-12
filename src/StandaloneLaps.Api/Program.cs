using System.Security.Cryptography.X509Certificates;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using StandaloneLaps;
using StandaloneLaps.Api;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions { Args = args, ContentRootPath = AppContext.BaseDirectory });
builder.Services.AddWindowsService(options => options.ServiceName = "StandaloneLapsApi");
var options = builder.Configuration.GetSection("Vault").Get<VaultOptions>() ?? throw new InvalidOperationException("Missing Vault configuration.");
options.Validate();
using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
store.Open(OpenFlags.ReadOnly);
using var serverCertificate = store.Certificates.Cast<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey &&
    SecretEncryption.Fingerprint(c).Equals(options.ServerCertificateSha256, StringComparison.OrdinalIgnoreCase))
    ?? throw new InvalidOperationException("HTTPS certificate with private key not found in LocalMachine/My.");
builder.WebHost.ConfigureKestrel(kestrel =>
{
    kestrel.Limits.MaxRequestBodySize = 65536;
    kestrel.ListenAnyIP(options.Port, listen => listen.UseHttps(https =>
    {
        https.ServerCertificate = serverCertificate;
        https.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
        // Explicit SHA-256 pinning is the client trust model, including private-CA/self-signed clients.
        // Remove a fingerprint from config and restart the API to revoke it.
        https.ClientCertificateValidation = (certificate, _, _) => options.Authorize(certificate) is not null;
    }));
});
builder.Services.AddRateLimiter(rate =>
{
    rate.RejectionStatusCode = 429;
    rate.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(context.Connection.ClientCertificate is { } cert
            ? SecretEncryption.Fingerprint(cert) : "anonymous", _ => new FixedWindowRateLimiterOptions
            { PermitLimit = 60, Window = TimeSpan.FromMinutes(1), QueueLimit = 0 }));
});
var repository = new VaultRepository(options.DataDirectory);
var app = builder.Build();
VaultApplication.Configure(app, options, repository);
await app.RunAsync();
