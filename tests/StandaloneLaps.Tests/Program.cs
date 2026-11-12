using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using StandaloneLaps;
using StandaloneLaps.Agent;


var passed = 0;
void Check(bool condition, string label) { if (!condition) throw new Exception("FAILED: " + label); passed++; Console.WriteLine("PASS " + label); }
async Task Fails(Func<Task> action, string label)
{
    try { await action(); } catch { Check(true, label); return; }
    throw new Exception("FAILED: " + label);
}
var now = DateTimeOffset.UtcNow;
var device = Guid.NewGuid().ToString("D");
using var rsa = RSA.Create(3072);
var request = new CertificateRequest("CN=StandaloneLaps-Test-Recovery", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyEncipherment, true));
using var cert = request.CreateSelfSigned(now.AddDays(-1), now.AddDays(1));
SecretEncryption.ValidateRecipient(cert, SecretEncryption.Fingerprint(cert));
var payload = new SecretPayload(1, device, "TEST", "RenamedAdmin", "S-1-5-21-1-2-3-500", Guid.NewGuid(), now, RotationEngine.GeneratePassword(32));
var envelope = SecretEncryption.Encrypt(payload, cert);
Check(SecretEncryption.Decrypt(envelope, cert) == payload, "RSA-OAEP/AES-GCM round trip");
Check(!System.Text.Json.JsonSerializer.Serialize(envelope).Contains(payload.Password, StringComparison.Ordinal), "Envelope contains no plaintext password");
await Fails(() => Task.Run(() => SecretEncryption.Decrypt(envelope with { DeviceId = Guid.NewGuid().ToString("D") }, cert)), "Metadata tampering rejected");
var corrupted = Convert.FromBase64String(envelope.Ciphertext); corrupted[0] ^= 1;
await Fails(() => Task.Run(() => SecretEncryption.Decrypt(envelope with { Ciphertext = Convert.ToBase64String(corrupted) }, cert)), "Ciphertext tampering rejected");
await Fails(() => Task.Run(() => SecretEncryption.ValidateRecipient(cert, new string('0', 64))), "Recovery certificate pin mismatch rejected");
for (var i = 0; i < 100; i++)
{
    var p = RotationEngine.GeneratePassword(32);
    if (p.Length != 32 || !p.Any(char.IsUpper) || !p.Any(char.IsLower) || !p.Any(char.IsDigit) || !p.Any(c => !char.IsLetterOrDigit(c))) throw new Exception("Password categories missing.");
}
Check(true, "100 generated passwords meet length and category requirements");

var accounts = new FakeAccounts(); var state = new FakeState(); var backup = new FakeBackup();
var engine = new RotationEngine(accounts, state, backup);
backup.FailStore = true;
await Fails(() => engine.RotateIfDueAsync(device, 30, 32, cert, now, default), "Backup failure aborts rotation");
Check(accounts.Changes == 0 && state.Value is null, "Backup failure leaves account and state unchanged");
backup.FailStore = false;
accounts.FailChange = true;
await Fails(() => engine.RotateIfDueAsync(device, 30, 32, cert, now, default), "Account reset failure propagated");
Check(state.Value is null && backup.Reports == 0 && backup.Stored.Count == 1, "Failed reset preserves candidate without marking applied");
accounts.FailChange = false;
Check(await engine.RotateIfDueAsync(device, 30, 32, cert, now, default), "First successful rotation");
Check(SecretEncryption.Decrypt(backup.Stored.Last(), cert).Password == accounts.Password, "Backed-up password equals applied password");
Check(!await engine.RotateIfDueAsync(device, 30, 32, cert, now.AddDays(1), default), "Age interval respected");
Check(await engine.RotateIfDueAsync(device, 30, 32, cert, now.AddDays(30), default), "Rotation at expiration");
backup.FailReport = true;
await Fails(() => engine.RotateIfDueAsync(device, 30, 32, cert, now.AddDays(60), default), "Applied-report outage propagated");
backup.FailReport = false;
var reportsBeforeRetry = backup.Reports;
Check(!await engine.RotateIfDueAsync(device, 30, 32, cert, now.AddDays(61), default), "Report outage does not cause repeated password resets");
Check(backup.Reports == reportsBeforeRetry + 1, "Lost applied report retried without changing the password");
state.FailWrite = true;
await Fails(() => engine.RotateIfDueAsync(device, 30, 32, cert, now.AddDays(90), default), "State-write failure after reset propagated");
var uncertain = backup.Stored.Last().RotationId;
state.FailWrite = false;
Check(await engine.RotateIfDueAsync(device, 30, 32, cert, now.AddDays(90), default), "Restart after uncertain completion creates a fresh generation");
Check(backup.Stored.Any(e => e.RotationId == uncertain) && backup.Stored.Last().RotationId != uncertain, "Uncertain candidate retained in history");
using (var canceled = new CancellationTokenSource())
{
    canceled.Cancel(); var before = accounts.Changes;
    await Fails(() => engine.RotateIfDueAsync(device, 30, 32, cert, now.AddDays(120), canceled.Token), "Cancellation before mutation handled");
    Check(accounts.Changes == before, "Cancellation does not reset account");
}

using var handler = new FakeHandler(envelope);
using var http = new HttpClient(handler) { BaseAddress = new Uri("https://test.invalid/") };
var httpBackup = new ApiBackupClient(http, device);
await httpBackup.StoreAndVerifyAsync(envelope, default);
Check(handler.Methods.SequenceEqual(new[] { "PUT", "GET" }), "Agent uploads then reads back before reset");
handler.Mismatch = true;
await Fails(() => httpBackup.StoreAndVerifyAsync(envelope, default), "Backup read-back mismatch rejected");
handler.Status = HttpStatusCode.ServiceUnavailable;
await Fails(() => httpBackup.StoreAndVerifyAsync(envelope, default), "HTTP service outage rejected");

var settings = new AgentSettings { Enabled = true, DeviceId = device, ApiUrl = "https://vault.test/Laps/", ClientCertificateSha256 = new string('A', 64), RecoveryCertificatePath = @"C:\Recovery\public.cer", RecoveryCertificateSha256 = new string('B', 64) };
var native = new Dictionary<string, object?>();
var defaults = Policy.FromValues(settings, native);
Check(defaults.Length == 14 && defaults.AgeDays == 30 && defaults.Complexity == 4, "Native LAPS defaults honored");
native["PasswordLength"] = 48; native["PasswordAgeDays"] = 7; native["PasswordComplexity"] = 3; native["AdministratorAccountName"] = "RecoveryAdmin";
var mapped = Policy.FromValues(settings, native);
Check(mapped.Length == 48 && mapped.AgeDays == 7 && mapped.Complexity == 3 && mapped.AccountName == "RecoveryAdmin", "Built-in LAPS settings map to agent");
Check(mapped.ApiUrl.AbsolutePath == "/Laps/", "IIS application subdirectory supported");
native["BackupDirectory"] = 2;
await Fails(() => Task.Run(() => Policy.FromValues(settings, native)), "Concurrent native LAPS backup rejected");
native["BackupDirectory"] = 0; native["PasswordComplexity"] = 8;
await Fails(() => Task.Run(() => Policy.FromValues(settings, native)), "Unsupported passphrase mode rejected");
native["PasswordComplexity"] = 4; native["AutomaticAccountManagementEnabled"] = 1;
await Fails(() => Task.Run(() => Policy.FromValues(settings, native)), "Unsupported automatic management rejected");
for (var complexity = 1; complexity <= 4; complexity++)
{
    var password = RotationEngine.GeneratePassword(64, complexity);
    Check(password.Any(char.IsUpper) && (complexity == 1 ? password.All(char.IsUpper) : password.Any(char.IsLower)) &&
        (complexity < 3 ? !password.Any(char.IsDigit) : password.Any(char.IsDigit)) &&
        (complexity < 4 ? password.All(char.IsLetterOrDigit) : password.Any(c => !char.IsLetterOrDigit(c))), "Native complexity mode " + complexity);
}
var fixtureDirectory = Environment.GetEnvironmentVariable("STANDALONELAPS_TEST_FIXTURE");
if (!string.IsNullOrEmpty(fixtureDirectory))
{
    Directory.CreateDirectory(fixtureDirectory);
    File.WriteAllText(Path.Combine(fixtureDirectory, "envelope.json"), System.Text.Json.JsonSerializer.Serialize(envelope, new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web)));
    File.WriteAllBytes(Path.Combine(fixtureDirectory, "recovery.pfx"), cert.Export(X509ContentType.Pfx));
}
Console.WriteLine($"{passed} checks passed. No real local account, service, policy or certificate store was modified.");

sealed class FakeAccounts : IAccountManager
{
    public int Changes; public string? Password; public bool FailChange;
    public LocalAccount ResolveManagedAdministrator() => new("RenamedAdmin", "S-1-5-21-1-2-3-500");
    public void SetPassword(LocalAccount account, string password)
    { if (FailChange) throw new InvalidOperationException(); Changes++; Password = password; }
}
sealed class FakeState : IRotationStateStore
{
    public RotationState? Value; public bool FailWrite;
    public RotationState? Read() => Value;
    public void Write(RotationState state) { if (FailWrite) throw new IOException(); Value = state; }
}
sealed class FakeBackup : IBackupClient
{
    public bool FailStore, FailReport; public int Reports; public List<Envelope> Stored = [];
    public Task StoreAndVerifyAsync(Envelope envelope, CancellationToken cancellationToken)
    { cancellationToken.ThrowIfCancellationRequested(); if (FailStore) throw new IOException(); Stored.Add(envelope); return Task.CompletedTask; }
    public Task ReportAppliedAsync(Guid rotationId, CancellationToken cancellationToken)
    { if (FailReport) throw new IOException(); Reports++; return Task.CompletedTask; }
}
sealed class FakeHandler(Envelope envelope) : HttpMessageHandler
{
    public List<string> Methods = []; public bool Mismatch; public HttpStatusCode Status = HttpStatusCode.OK;
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Methods.Add(request.Method.Method);
        var result = new HttpResponseMessage(Status);
        if (request.Method == HttpMethod.Get) result.Content = JsonContent.Create(Mismatch ? envelope with { RotationId = Guid.NewGuid() } : envelope);
        return Task.FromResult(result);
    }
}
