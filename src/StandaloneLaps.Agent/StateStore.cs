using System.Text.Json;

namespace StandaloneLaps.Agent;

public sealed class StateStore : IRotationStateStore
{
    private readonly string path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "StandaloneLaps", "state.json");
    public RotationState? Read() => File.Exists(path)
        ? JsonSerializer.Deserialize<RotationState>(File.ReadAllBytes(path)) ?? throw new InvalidDataException("Empty rotation state.")
        : null;
    public void Write(RotationState state) => DurableFile.Write(path, JsonSerializer.SerializeToUtf8Bytes(state), overwrite: true);
}
