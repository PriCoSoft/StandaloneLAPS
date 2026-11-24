using System.Globalization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;

namespace StandaloneLaps.Server.Pages;

// Entra part of the Windows LAPS lookup (administrators): certificate created and stored by SLAPS (encrypted with the
// master key), upload of its public part, Graph application permission with admin consent, automatic renewal, test.
public sealed class EntraSetupModel : PortalPage
{
    public const string ConsentPurpose = "StandaloneLaps.AdminConsent.v1";
    private readonly WindowsLapsService laps;
    private readonly IDataProtectionProvider protection;

    public EntraSetupModel(VaultStore store, ServerOptions options, WindowsLapsService laps, IDataProtectionProvider protection) : base(store, options)
    {
        this.laps = laps;
        this.protection = protection;
    }

    public override string Active => "settings";
    public WindowsLapsOptions Laps => Options.WindowsLaps;
    public EntraSetupState State = new();
    public bool Configured;
    public string Info, ErrorText;
    public string ConsentRedirectUri => Options.PublicUrl + "entra-consent";
    public string Portal(string blade) => "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/" + blade + "/appId/" + Uri.EscapeDataString(Laps.EntraClientId ?? "");
    public static string Day(DateTime? value) => CredentialHtml.Utc(value);

    private void Load()
    {
        State = laps.SetupState();
        Configured = laps.SetupConfigured;
    }

    public IActionResult OnGet(string download)
    {
        if (download == "cer")
        {
            var raw = laps.SetupPublicCertificate();
            if (raw == null) return NotFound();
            Store.Audit(Identity.Actor, "entra-graph-certificate-download", Guid.Empty, Guid.Empty);
            return File(raw, "application/pkix-cert", "slaps-graph-access.cer");
        }
        Load();
        return Page();
    }

    public async Task<IActionResult> OnPost(string action, string objectId, string confirmReplace)
    {
        Load();
        try
        {
            switch (action)
            {
                case "create":
                    if (Configured && confirmReplace != "yes") { ErrorText = "A certificate exists already. Confirm the checkbox to replace it (the new one must be uploaded again)."; break; }
                    var created = laps.CreateSetupCertificate(Identity.Actor);
                    Store.Audit(Identity.Actor, "entra-graph-certificate-created-" + created.CurrentThumbprint, Guid.Empty, Guid.Empty);
                    Info = "Certificate " + created.CurrentThumbprint + " created. Download it and upload it to the app registration (step 2).";
                    break;
                case "consent":
                    if (!Guid.TryParse(Laps.EntraTenantId, out _) || !Guid.TryParse(Laps.EntraClientId, out _)) { ErrorText = "Tenant and client ID are not configured (Slaps__WindowsLapsEntraTenantId / ClientId or the OIDC values)."; break; }
                    if (Options.PublicUrl == null) { ErrorText = "Slaps__PublicUrl is not set."; break; }
                    var state = protection.CreateProtector(ConsentPurpose).ToTimeLimitedDataProtector().Protect("consent", TimeSpan.FromMinutes(15));
                    Store.Audit(Identity.Actor, "entra-admin-consent-started", Guid.Empty, Guid.Empty);
                    return Redirect(laps.AdminConsentUrl(ConsentRedirectUri, state));
                case "object-id":
                    var text = (objectId ?? "").Trim();
                    if (text.Length > 0 && !Guid.TryParse(text, out _)) { ErrorText = "The Object ID is a GUID (App registration → Overview → Object ID)."; break; }
                    var current = laps.SetupState();
                    current.ObjectId = text.Length == 0 ? null : Guid.Parse(text).ToString("D");
                    laps.SaveSetupState(current);
                    Store.Audit(Identity.Actor, "entra-object-id-set", Guid.Empty, Guid.Empty);
                    Info = text.Length == 0 ? "Automatic renewal is off." : "Object ID saved. The certificate is renewed automatically " + WindowsLapsService.RenewBeforeDays + " days before it expires.";
                    break;
                case "renew":
                    Info = await laps.Renew(Identity.Actor);
                    break;
                case "test":
                    Info = await laps.TestEntra();
                    break;
                default:
                    return BadRequest();
            }
        }
        catch (WindowsLapsException ex) { ErrorText = ex.Message; }
        if (Request.Headers["X-Slaps-Ajax"] == "1") return new JsonResult(new { ok = ErrorText == null, message = ErrorText ?? Info });
        Load();
        return Page();
    }

    // Return of the admin consent (GET /entra-consent): records the result for the setup page.
    public static IResult CompleteConsent(HttpContext context, VaultStore store, ServerOptions options, WindowsLapsService laps, IDataProtectionProvider protection)
    {
        var request = context.Request;
        try
        {
            if (protection.CreateProtector(ConsentPurpose).ToTimeLimitedDataProtector().Unprotect(request.Query["state"].ToString()) != "consent") return Results.StatusCode(403);
        }
        catch (System.Security.Cryptography.CryptographicException) { return Results.StatusCode(403); }
        var user = PortalAuth.User(context.User, options);
        var granted = string.Equals(request.Query["admin_consent"], "True", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(request.Query["error"]);
        var detail = request.Query["error_description"].ToString();
        if (detail.Length == 0) detail = request.Query["error"].ToString();
        if (detail.Length > 300) detail = detail[..300];
        var state = laps.SetupState();
        state.ConsentUtc = DateTime.UtcNow;
        state.ConsentBy = user.DisplayName;
        state.ConsentResult = granted ? "granted" : "failed: " + detail;
        laps.SaveSetupState(state);
        store.Audit(user.Actor, granted ? "entra-admin-consent-granted" : "entra-admin-consent-failed", Guid.Empty, Guid.Empty);
        return Results.Redirect("/entrasetup");
    }

    public static string Date(DateTime? value) => value?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? "—";
}
