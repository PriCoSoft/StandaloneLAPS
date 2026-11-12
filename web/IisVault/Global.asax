<%@ Application Language="C#" %>
<script runat="server">
void Application_Start(object sender, EventArgs e)
{
    StandaloneLapsWeb.Vault.EnforceRetention();
}
void Application_BeginRequest(object sender, EventArgs e)
{
    Response.Cache.SetCacheability(HttpCacheability.NoCache);
    Response.Cache.SetNoStore();
    Response.Headers["X-Content-Type-Options"] = "nosniff";
    Response.Headers["X-Frame-Options"] = "DENY";
    Response.Headers["Referrer-Policy"] = "no-referrer";
    Response.Headers["Content-Security-Policy"] = "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    if (!Request.IsSecureConnection) { Deny("HTTPS is required."); return; }
    // Only the certificate-authenticated agent API is reachable from outside PortalAllowedNetworks (e.g. the DMZ).
    var isApi = string.Equals(Request.AppRelativeCurrentExecutionFilePath, "~/api.aspx", StringComparison.OrdinalIgnoreCase);
    if (!isApi && !StandaloneLapsWeb.PortalAuth.IsInternal(Request))
        Deny("Access denied: the portal is not available from your network address " + Request.UserHostAddress + ". It must be listed in PortalAllowedNetworks (web.config).");
}
void Deny(string reason)
{
    // TrySkipIisCustomErrors keeps IIS from replacing the reason with its generic 403 page.
    Response.StatusCode = 403; Response.TrySkipIisCustomErrors = true;
    Response.ContentType = "text/plain";
    Response.Write(reason);
    CompleteRequest();
}
void Application_Error(object sender, EventArgs e)
{
    var error = Server.GetLastError();
    var http = error as HttpException;
    var code = http == null ? 500 : http.GetHttpCode();
    if (code != 400 && code != 403 && code != 404) code = 500;
    Server.ClearError();
    Response.Clear(); Response.StatusCode = code; Response.TrySkipIisCustomErrors = true;
    Response.ContentType = "text/plain";
    Response.Write(code == 403 ? "Access denied." : code == 404 ? "Not found." : "Request failed. Check configuration, data-directory permissions and certificate access.");
    CompleteRequest();
}
</script>
