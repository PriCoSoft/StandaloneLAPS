using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

namespace StandaloneLaps.Server;

// File downloads and sign-out (the counterparts of download.aspx, package.aspx, certificate.aspx and signout.aspx).
public static class PortalEndpoints
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/download", (HttpContext context, VaultStore store, ServerOptions options) =>
        {
            if (!Guid.TryParseExact(context.Request.Query["device"], "D", out var device) || !Guid.TryParseExact(context.Request.Query["rotation"], "D", out var rotation))
                return Results.BadRequest();
            var record = store.Get(device, rotation);
            if (record == null) return Results.NotFound();
            store.Audit(PortalAuth.User(context.User, options).Actor, "envelope-download", device, rotation);
            var json = JsonSerializer.SerializeToUtf8Bytes(record.Envelope, Wire.Json);
            return Results.File(json, "application/json", device.ToString("D") + "-" + rotation.ToString("D") + ".envelope.json");
        }).RequireAuthorization(PortalAuth.ReaderPolicy);

        app.MapGet("/package", (HttpContext context, VaultStore store, ServerOptions options) =>
        {
            var token = context.Request.Query["id"].ToString();
            if (token.Length != 32 || !token.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'))) return Results.NotFound();
            var (info, content) = store.Package(token);
            if (info == null) return Results.NotFound();
            store.Audit(PortalAuth.User(context.User, options).Actor, "client-package-download", Guid.Parse(info.DeviceId), Guid.Empty);
            return Results.File(content, "application/zip", info.FileName);
        }).RequireAuthorization(PortalAuth.AdminPolicy);

        app.MapGet("/certificate", (HttpContext context, KeyVault keys) =>
        {
            var sha = context.Request.Query["sha"].ToString();
            var match = keys.Describe().FirstOrDefault(c => string.Equals(c.Sha256, sha, StringComparison.OrdinalIgnoreCase));
            if (match == null) return Results.NotFound();
            return context.Request.Query["format"] == "pem"
                ? Results.File(Encoding.ASCII.GetBytes(KeyVault.Pem(match.Raw)), "application/x-pem-file", match.FileName + ".pem")
                : Results.File(match.Raw, "application/pkix-cert", match.FileName + ".cer");
        }).RequireAuthorization(PortalAuth.ReaderPolicy);

        app.MapGet("/signout", async (HttpContext context, ServerOptions options) =>
        {
            if (options.DevelopmentAuth) return Results.Redirect("/");
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return Results.SignOut(new AuthenticationProperties { RedirectUri = "/denied?signedout=1" },new[] { OpenIdConnectDefaults.AuthenticationScheme });
        });
    }
}
