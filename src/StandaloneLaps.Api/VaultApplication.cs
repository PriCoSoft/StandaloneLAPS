using StandaloneLaps;

namespace StandaloneLaps.Api;

public static class VaultApplication
{
    public static void Configure(WebApplication app, VaultOptions options, VaultRepository repository)
    {
        app.Use(async (context, next) =>
        {
            context.Response.Headers.CacheControl = "no-store";
            if (!context.Request.IsHttps) { context.Response.StatusCode = 400; return; }
            var client = options.Authorize(await context.Connection.GetClientCertificateAsync());
            if (client is null) { context.Response.StatusCode = 403; return; }
            context.Items["client"] = client;
            await next();
        });
        app.UseRateLimiter();

        bool Allowed(HttpContext context, Guid device, bool write)
        {
            var client = (VaultClient)context.Items["client"]!;
            return write ? client.Role == "agent" && client.DeviceId == device.ToString("D")
                : client.Role == "reader" || client.DeviceId == device.ToString("D");
        }

        app.MapPut("/api/v1/devices/{device:guid}/rotations/{rotation:guid}",
            (HttpContext context, Guid device, Guid rotation, Envelope envelope) =>
            {
                if (!Allowed(context, device, true)) return Results.StatusCode(403);
                if (!VaultRepository.ValidEnvelope(envelope, device, rotation)) return Results.BadRequest();
                if (!repository.Put(device, rotation, envelope)) return Results.Conflict();
                app.Logger.LogInformation("Backup accepted for device {DeviceId}, rotation {RotationId}.", device, rotation);
                return Results.NoContent();
            });
        app.MapGet("/api/v1/devices/{device:guid}/rotations/{rotation:guid}",
            (HttpContext context, Guid device, Guid rotation) =>
            {
                if (!Allowed(context, device, false)) return Results.StatusCode(403);
                var record = repository.Get(device, rotation);
                if (record is null) return Results.NotFound();
                app.Logger.LogInformation("Backup read for device {DeviceId}, rotation {RotationId}.", device, rotation);
                return Results.Ok(record.Envelope);
            });
        app.MapPost("/api/v1/devices/{device:guid}/rotations/{rotation:guid}/applied",
            (HttpContext context, Guid device, Guid rotation) =>
            {
                if (!Allowed(context, device, true)) return Results.StatusCode(403);
                return repository.Applied(device, rotation) ? Results.NoContent() : Results.NotFound();
            });
        app.MapGet("/api/v1/devices/{device:guid}/rotations",
            (HttpContext context, Guid device, int? skip, int? take) =>
            {
                if (!Allowed(context, device, false)) return Results.StatusCode(403);
                if (skip is < 0 || take is < 1 or > 500) return Results.BadRequest();
                app.Logger.LogInformation("History read for device {DeviceId}.", device);
                return Results.Ok(repository.History(device, skip ?? 0, take ?? 100));
            });


    }
}
