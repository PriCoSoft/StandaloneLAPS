<%@ Page Language="C#" EnableViewState="false" EnableSessionState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    var identity = PortalAuth.Require(Context);
    if (!identity.IsAdmin) throw new HttpException(403, "Administrator access required.");
    var package = ClientPackages.Find(Request.QueryString["id"]);
    if (package == null) throw new HttpException(404, "The package does not exist or has expired. Issue a new certificate package.");
    Vault.Audit(identity.Actor, "client-package-download", Guid.Parse(package.deviceId), Guid.Empty);
    Response.ContentType = "application/zip";
    Response.AddHeader("Content-Disposition", "attachment; filename=\"" + package.fileName + "\"");
    Response.TransmitFile(ClientPackages.ZipPath(package.token));
}
</script>
