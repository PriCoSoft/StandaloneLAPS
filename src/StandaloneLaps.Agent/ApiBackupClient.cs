using System.Net.Http.Json;
using System.Text.Json;

namespace StandaloneLaps.Agent;

public sealed class ApiBackupClient(HttpClient http, string deviceId) : IBackupClient
{
    public async Task StoreAndVerifyAsync(Envelope envelope, CancellationToken cancellationToken)
    {
        var path = $"api.aspx?device={deviceId}&rotation={envelope.RotationId:D}";
        using var response = await http.PutAsJsonAsync(path, envelope, cancellationToken);
        response.EnsureSuccessStatusCode();
        using var read = await http.GetAsync(path, cancellationToken);
        read.EnsureSuccessStatusCode();
        var stored = await read.Content.ReadFromJsonAsync<Envelope>(cancellationToken);
        if (stored != envelope) throw new InvalidDataException("Backup read-back mismatch. Password was not changed.");
    }
    public async Task ReportAppliedAsync(Guid rotationId, CancellationToken cancellationToken)
    {
        using var response = await http.PostAsync($"api.aspx?device={deviceId}&rotation={rotationId:D}&action=applied", null, cancellationToken);
        response.EnsureSuccessStatusCode();
    }
}
