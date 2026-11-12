using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using StandaloneLaps;
using StandaloneLaps.Agent;

if (args.Length > 0 && args[0] == "recover")
{
    if (args.Length != 3) { Console.Error.WriteLine("Usage: StandaloneLaps.Agent recover <envelope.json> <recovery.pfx>"); return 2; }
    Console.Error.Write("PFX password: ");
    var password = new System.Text.StringBuilder();
    while (true)
    {
        var key = Console.ReadKey(intercept: true);
        if (key.Key == ConsoleKey.Enter) break;
        if (key.Key == ConsoleKey.Backspace) { if (password.Length > 0) password.Length--; }
        else if (!char.IsControl(key.KeyChar)) password.Append(key.KeyChar);
    }
    Console.Error.WriteLine();
    try
    {
        using var certificate = X509CertificateLoader.LoadPkcs12FromFile(args[2], password.ToString(), X509KeyStorageFlags.EphemeralKeySet);
        password.Clear();
        var envelope = JsonSerializer.Deserialize<Envelope>(File.ReadAllBytes(args[1]), new JsonSerializerOptions(JsonSerializerDefaults.Web))
            ?? throw new InvalidDataException();
        var payload = SecretEncryption.Decrypt(envelope, certificate);
        Console.WriteLine($"Computer: {payload.ComputerName}\nAccount: {payload.AccountName}\nSID: {payload.AccountSid}\nCreated: {payload.CreatedUtc:O}\nPassword: {payload.Password}");
        return 0;
    }
    catch { Console.Error.WriteLine("Recovery failed. Check the envelope, certificate and PFX password."); return 1; }
}

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "StandaloneLapsAgent");
builder.Services.AddHostedService<RotationWorker>();
await builder.Build().RunAsync();
return 0;

sealed class RotationWorker(ILogger<RotationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Serialize within this process; SCM is the supported execution path. No run-once password-reset command.
        using var singleton = new Semaphore(1, 1, @"Global\StandaloneLapsAgentRotation");
        if (!singleton.WaitOne(0)) throw new InvalidOperationException("Another agent instance is already running.");
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var policy = Policy.Read();
                    if (policy is not null)
                    {
                        using var recipient = X509CertificateLoader.LoadCertificateFromFile(policy.RecoveryCertificatePath);
                        SecretEncryption.ValidateRecipient(recipient, policy.RecoveryCertificateSha256);
                        using var store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
                        store.Open(OpenFlags.ReadOnly);
                        using var client = store.Certificates.Cast<X509Certificate2>().FirstOrDefault(c =>
                            SecretEncryption.Fingerprint(c) == policy.ClientCertificateSha256 && c.HasPrivateKey)
                            ?? throw new InvalidOperationException("Client certificate with private key was not found.");
                        using var handler = new HttpClientHandler { AllowAutoRedirect = false };
                        handler.ClientCertificates.Add(client);
                        using var http = new HttpClient(handler) { BaseAddress = policy.ApiUrl, Timeout = TimeSpan.FromSeconds(30) };
                        var engine = new RotationEngine(new WindowsAccountManager(policy.AccountName), new StateStore(), new ApiBackupClient(http, policy.DeviceId));
                        if (await engine.RotateIfDueAsync(policy.DeviceId, policy.AgeDays, policy.Length, recipient, DateTimeOffset.UtcNow, stoppingToken, policy.Complexity))
                            logger.LogInformation(new EventId(1000), "Administrator password rotated and backup confirmed.");
                    }
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
                catch (Exception ex)
                {
                    // Never log secret payloads, HTTP bodies or exception messages from providers.
                    logger.LogError(new EventId(1001), "Rotation cycle failed ({ErrorType}); retry in five minutes. Inspect backup history for unconfirmed candidates.", ex.GetType().Name);
                }
                await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
            }
        }
        finally { singleton.Release(); }
    }
}
