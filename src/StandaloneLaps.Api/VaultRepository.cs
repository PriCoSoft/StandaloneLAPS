using System.Text.Json;

namespace StandaloneLaps.Api;

public sealed record StoredRecord(Envelope Envelope, DateTimeOffset ReceivedUtc);

// One local filesystem and one API process. External backups/retention run under a separate identity.
public sealed class VaultRepository(string root)
{
    private readonly object gate = new();
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private string DeviceDirectory(Guid device) => Path.Combine(root, device.ToString("D"));
    private string RecordPath(Guid device, Guid rotation) => Path.Combine(DeviceDirectory(device), rotation.ToString("D") + ".record.json");
    private string AppliedPath(Guid device, Guid rotation) => Path.Combine(DeviceDirectory(device), rotation.ToString("D") + ".applied.json");

    public bool Put(Guid device, Guid rotation, Envelope envelope)
    {
        lock (gate)
        {
            var path = RecordPath(device, rotation);
            if (File.Exists(path)) return Get(device, rotation)!.Envelope == envelope;
            Directory.CreateDirectory(DeviceDirectory(device));
            DurableFile.Write(path, JsonSerializer.SerializeToUtf8Bytes(new StoredRecord(envelope, DateTimeOffset.UtcNow), Json), false);
            return Get(device, rotation)!.Envelope == envelope;
        }
    }

    public StoredRecord? Get(Guid device, Guid rotation)
    {
        var path = RecordPath(device, rotation);
        return File.Exists(path) ? JsonSerializer.Deserialize<StoredRecord>(File.ReadAllBytes(path), Json)
            ?? throw new InvalidDataException("Invalid vault record.") : null;
    }

    public bool Applied(Guid device, Guid rotation)
    {
        lock (gate)
        {
            if (Get(device, rotation) is null) return false;
            var path = AppliedPath(device, rotation);
            if (!File.Exists(path)) DurableFile.Write(path, JsonSerializer.SerializeToUtf8Bytes(DateTimeOffset.UtcNow, Json), false);
            return true;
        }
    }

    public IReadOnlyList<HistoryEntry> History(Guid device, int skip, int take)
    {
        var directory = DeviceDirectory(device);
        if (!Directory.Exists(directory)) return [];
        return Directory.EnumerateFiles(directory, "*.record.json")
            .Select(path => JsonSerializer.Deserialize<StoredRecord>(File.ReadAllBytes(path), Json) ?? throw new InvalidDataException())
            .OrderByDescending(r => r.ReceivedUtc).ThenBy(r => r.Envelope.RotationId).Skip(skip).Take(take)
            .Select(r => new HistoryEntry(r.Envelope.RotationId, r.Envelope.CreatedUtc, r.ReceivedUtc,
                File.Exists(AppliedPath(device, r.Envelope.RotationId))
                    ? JsonSerializer.Deserialize<DateTimeOffset>(File.ReadAllBytes(AppliedPath(device, r.Envelope.RotationId)), Json) : null)).ToArray();
    }

    public static bool ValidEnvelope(Envelope envelope, Guid device, Guid rotation)
    {
        if (envelope.Version != 1 || envelope.DeviceId != device.ToString("D") || envelope.RotationId != rotation ||
            rotation == Guid.Empty || envelope.RecipientSha256 is not { Length: 64 } || !envelope.RecipientSha256.All(Uri.IsHexDigit)) return false;
        try
        {
            return Convert.FromBase64String(envelope.WrappedKey).Length is >= 384 and <= 1024 &&
                Convert.FromBase64String(envelope.Nonce).Length == 12 && Convert.FromBase64String(envelope.Tag).Length == 16 &&
                Convert.FromBase64String(envelope.Ciphertext).Length is >= 1 and <= 16384;
        }
        catch (Exception ex) when (ex is FormatException or ArgumentNullException) { return false; }
    }
}
