<%@ Page Language="C#" EnableViewState="false" EnableSessionState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
// Microsoft Entra ID sign-in. GET starts the authorization request; Entra posts the ID token back here.
protected string Message;
protected void Page_Load(object sender, EventArgs e)
{
    if (PortalAuth.Mode != "Entra") throw new HttpException(404, "Not found.");
    if (Request.HttpMethod == "GET" && Request.QueryString["state"] != null && (Request.QueryString["admin_consent"] != null || Request.QueryString["error"] != null))
    {
        // Return from the admin consent started in entrasetup.aspx (Windows LAPS lookup via Microsoft Graph).
        var admin = PortalAuth.Current(Request);
        if (admin == null || !admin.IsAdmin || !PortalAuth.ValidConsentState(Request.QueryString["state"])) throw new HttpException(403, "The admin consent response is not valid for this session.");
        var granted = string.Equals(Request.QueryString["admin_consent"], "True", StringComparison.OrdinalIgnoreCase) && Request.QueryString["error"] == null;
        var detail = (Request.QueryString["error_description"] ?? Request.QueryString["error"] ?? "");
        if (detail.Length > 300) detail = detail.Substring(0, 300);
        var state = EntraAppCredential.Load();
        state.consentUtc = EntraAppCredential.Stamp(DateTime.UtcNow);
        state.consentBy = admin.DisplayName;
        state.consentResult = granted ? "granted" : "failed: " + detail;
        EntraAppCredential.Save(state);
        Vault.AuditTarget(admin.Actor, granted ? "entra-admin-consent-granted" : "entra-admin-consent-failed", WindowsLapsSettings.EntraClientId);
        Response.Redirect("~/entrasetup.aspx", true);
        return;
    }
    if (Request.HttpMethod == "GET")
    {
        Response.Redirect(PortalAuth.BeginSignIn(Response, Request.QueryString["returnUrl"]), true);
        return;
    }
    if (Request.HttpMethod != "POST") throw new HttpException(400, "Unsupported request.");
    string target = null;
    try
    {
        string returnUrl;
        var identity = PortalAuth.CompleteSignIn(Context, out returnUrl);
        PortalAuth.StartSession(Response, identity, DateTime.UtcNow);
        // The display name in the target lets the audit page show names instead of object IDs.
        Vault.AuditTarget(identity.Actor, "portal-sign-in-" + identity.Role, identity.DisplayName);
        target = returnUrl;
    }
    catch (TokenValidationException ex)
    {
        Message = ex.Message;
        Vault.Audit("entra:unverified", "portal-sign-in-denied: " + ex.Message, Guid.Empty, Guid.Empty);
        Response.StatusCode = 403;
        Response.TrySkipIisCustomErrors = true;
    }
    if (target != null) Response.Redirect("~/" + target, true);
}
</script>
<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Sign in · PriCoSoft SLAPS</title><%= PortalLayout.HeadLinks %></head>
<body class="plain-page">
<header class="topbar"><%= PortalLayout.Brand("Default.aspx") %></header>
<main class="plain-card">
<h1>Sign-in failed</h1>
<p class="notice danger"><%= Server.HtmlEncode(Message ?? "The sign-in could not be completed.") %></p>
<a class="button" href="signin.aspx">Try again</a>
</main>
</body></html>
