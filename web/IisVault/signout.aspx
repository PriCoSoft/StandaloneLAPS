<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
protected string EntraSignOut;
protected void Page_Load(object sender, EventArgs e)
{
    var identity = PortalAuth.Current(Request);
    if (identity != null) Vault.Audit(identity.Actor, "portal-sign-out", Guid.Empty, Guid.Empty);
    PortalAuth.EndSession(Response);
    if (Session != null) Session.Abandon();
    if (PortalAuth.Mode == "Entra") EntraSignOut = PortalAuth.SignOutUrl;
}
</script>
<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Signed out · PriCoSoft SLAPS</title><%= PortalLayout.HeadLinks %></head>
<body class="plain-page">
<header class="topbar"><%= PortalLayout.Brand("Default.aspx") %></header>
<main class="plain-card">
<h1>You are signed out</h1>
<p class="subtitle">Your SLAPS session has ended. Close the browser on shared workstations.</p>
<div class="form-actions"><a class="button" href="Default.aspx">Sign in again</a><% if (EntraSignOut != null) { %><a href="<%= Server.HtmlEncode(EntraSignOut) %>">Also sign out of Microsoft</a><% } %></div>
</main>
</body></html>
