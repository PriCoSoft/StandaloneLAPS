<%@ Page Language="C#" EnableViewState="false" EnableSessionState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
// Microsoft Entra ID sign-in. GET starts the authorization request; Entra posts the ID token back here.
protected string Message;
protected void Page_Load(object sender, EventArgs e)
{
    if (PortalAuth.Mode != "Entra") throw new HttpException(404, "Not found.");
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
        Vault.Audit(identity.Actor, "portal-sign-in-" + identity.Role, Guid.Empty, Guid.Empty);
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
