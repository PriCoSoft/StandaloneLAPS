namespace StandaloneLaps;

public sealed record SecretPayload(int Version, string DeviceId, string ComputerName, string AccountName,
    string AccountSid, Guid RotationId, DateTimeOffset CreatedUtc, string Password);

public sealed record Envelope(int Version, string DeviceId, Guid RotationId, DateTimeOffset CreatedUtc,
    string RecipientSha256, string WrappedKey, string Nonce, string Tag, string Ciphertext);

public sealed record HistoryEntry(Guid RotationId, DateTimeOffset CreatedUtc, DateTimeOffset ReceivedUtc,
    DateTimeOffset? AppliedReportedUtc);

public sealed record RotationState(string AccountSid, DateTimeOffset LastAppliedUtc, Guid RotationId);
public sealed record LocalAccount(string Name, string Sid);

public interface IBackupClient
{
    Task StoreAndVerifyAsync(Envelope envelope, CancellationToken cancellationToken);
    Task ReportAppliedAsync(Guid rotationId, CancellationToken cancellationToken);
}

public interface IAccountManager
{
    LocalAccount ResolveManagedAdministrator();
    void SetPassword(LocalAccount account, string password);
}

public interface IRotationStateStore
{
    RotationState? Read();
    void Write(RotationState state);
}
