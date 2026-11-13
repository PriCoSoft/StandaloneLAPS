using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;

namespace StandaloneLaps.Server;

// Agent API on the client-certificate port. Same path, query parameters, status codes and JSON as
// web/IisVault/api.aspx, so existing Windows and Linux agents only need a different apiUrl.
public sealed class AgentApi
{
    private sealed class Rate { public DateTime Window; public int Count; }
    private readonly ConcurrentDictionary<string, Rate> rates = new();
    private readonly VaultStore store;

    public AgentApi(VaultStore store)
    {
        this.store = store;
    }

    public bool Permit(string fingerprint)
    {
        var now = DateTime.UtcNow;
        var rate = rates.AddOrUpdate(fingerprint, _ => new Rate { Window = now, Count = 1 }, (_, existing) =>
        {
            lock (existing)
            {
                if (now - existing.Window >= TimeSpan.FromMinutes(1)) { existing.Window = now; existing.Count = 0; }
                existing.Count++;
                return existing;
            }
        });
        lock (rate) return rate.Count <= 60;
    }

    public async Task Handle(HttpContext context)
    {
        var response = context.Response;
        response.ContentType = "application/json";
        try
        {
            var certificate = await context.Connection.GetClientCertificateAsync();
            if (certificate == null) { response.StatusCode = 403; return; }
            var fingerprint = Wire.Sha256(certificate.RawData);
            var client = store.ClientByCertificate(fingerprint);
            if (client == null) { response.StatusCode = 403; return; }
            if (!Permit(fingerprint)) { response.StatusCode = 429; return; }
            var query = context.Request.Query;
            if (!Guid.TryParseExact(query["device"], "D", out var device) || device == Guid.Empty) { response.StatusCode = 400; return; }
            var hasRotation = Guid.TryParseExact(query["rotation"], "D", out var rotation) && rotation != Guid.Empty;
            var method = context.Request.Method;
            // An agent may only read and write its own device; deleted devices are blocked.
            if (client.Deleted || client.DeviceId != device.ToString("D")) { response.StatusCode = 403; return; }
            var actor = "certificate:" + fingerprint;
            if (method == "PUT" && hasRotation)
            {
                if (context.Request.ContentLength > 65536) { response.StatusCode = 413; return; }
                using var reader = new StreamReader(context.Request.Body, Encoding.UTF8);
                var buffer = new char[65537];
                var used = 0;
                int read;
                while (used < buffer.Length && (read = await reader.ReadAsync(buffer.AsMemory(used))) > 0) used += read;
                if (used > 65536) { response.StatusCode = 413; return; }
                Envelope envelope;
                try { envelope = JsonSerializer.Deserialize<Envelope>(new string(buffer, 0, used), Wire.Json); }
                catch (JsonException) { response.StatusCode = 400; return; }
                if (!Wire.Valid(envelope, device, rotation)) { response.StatusCode = 400; return; }
                store.Audit(actor, "backup-attempt", device, rotation);
                response.StatusCode = store.Put(device, rotation, envelope) ? 204 : 409;
            }
            else if (method == "POST" && hasRotation && query["action"] == "applied")
            {
                store.Audit(actor, "applied-report", device, rotation);
                response.StatusCode = store.Applied(device, rotation) ? 204 : 404;
            }
            else if (method == "GET" && hasRotation)
            {
                var record = store.Get(device, rotation);
                if (record == null) { response.StatusCode = 404; return; }
                store.Audit(actor, "envelope-read", device, rotation);
                await response.WriteAsync(JsonSerializer.Serialize(record.Envelope, Wire.Json));
            }
            else if (method == "GET" && string.IsNullOrEmpty(query["rotation"]))
            {
                int skip = 0, take = store.HistoryLimit;
                if ((query.ContainsKey("skip") && !int.TryParse(query["skip"], out skip)) || (query.ContainsKey("take") && !int.TryParse(query["take"], out take)) ||
                    skip < 0 || take < 1 || take > ServerOptions.MaxHistoryLimit) { response.StatusCode = 400; return; }
                store.Audit(actor, "history-read", device, Guid.Empty);
                await response.WriteAsync(JsonSerializer.Serialize(store.History(device, skip, take), Wire.Json));
            }
            else response.StatusCode = 400;
        }
        catch (UnauthorizedAccessException) { response.StatusCode = 403; }
        catch (ArgumentException) { response.StatusCode = 400; }
    }
}
