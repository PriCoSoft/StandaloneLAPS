using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace StandaloneLaps;

public sealed class RotationEngine(IAccountManager accounts, IRotationStateStore stateStore, IBackupClient backup)
{
    public async Task<bool> RotateIfDueAsync(string deviceId, int ageDays, int length,
        X509Certificate2 recipient, DateTimeOffset now, CancellationToken cancellationToken, int complexity = 4)
    {
        if (!Guid.TryParseExact(deviceId, "D", out _) || ageDays is < 1 or > 365 || length is < 8 or > 64 || complexity is < 1 or > 4)
            throw new ArgumentException("Invalid rotation settings.");
        var account = accounts.ResolveManagedAdministrator();
        var state = stateStore.Read(); // Corrupt state fails closed; missing state triggers first rotation.
        if (state is not null && state.AccountSid == account.Sid)
        {
            if (state.LastAppliedUtc > now) throw new InvalidOperationException("System clock is earlier than recorded rotation.");
            if (now - state.LastAppliedUtc < TimeSpan.FromDays(ageDays))
            {
                // Repair a lost acknowledgement after a previous successful reset; API is idempotent.
                await backup.ReportAppliedAsync(state.RotationId, cancellationToken);
                return false;
            }
        }
        var id = Guid.NewGuid();
        var password = GeneratePassword(length, complexity);
        var envelope = SecretEncryption.Encrypt(new SecretPayload(1, deviceId, Environment.MachineName,
            account.Name, account.Sid, id, now, password), recipient);
        await backup.StoreAndVerifyAsync(envelope, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        accounts.SetPassword(account, password);
        // Persist before reporting. If this write fails, the next run safely creates another generation.
        stateStore.Write(new RotationState(account.Sid, now, id));
        // Failure here does not change local success state. Unconfirmed records remain recovery candidates.
        await backup.ReportAppliedAsync(id, cancellationToken);
        return true;
    }

    public static string GeneratePassword(int length, int complexity = 4)
    {
        if (length is < 8 or > 64) throw new ArgumentOutOfRangeException(nameof(length));
        if (complexity is < 1 or > 4) throw new ArgumentOutOfRangeException(nameof(complexity), "LAPS complexity 5-8 is not implemented.");
        const string upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ", lower = "abcdefghijklmnopqrstuvwxyz";
        const string digits = "0123456789", symbols = "!#$%&()*+,-.:;<=>?@[]^_{|}~";
        var result = new char[length];
        string[] categories = complexity switch { 1 => [upper], 2 => [upper, lower], 3 => [upper, lower, digits], _ => [upper, lower, digits, symbols] };
        var all = string.Concat(categories);
        for (var i = 0; i < length; i++)
        {
            var alphabet = i < categories.Length ? categories[i] : all;
            result[i] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
        }
        RandomNumberGenerator.Shuffle(result.AsSpan());
        return new string(result);
    }
}
