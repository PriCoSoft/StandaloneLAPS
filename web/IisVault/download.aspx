<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    var actor = PortalAuth.Require(Context).Actor;
    Guid device, rotation;
    if (!Guid.TryParseExact(Request.QueryString["device"], "D", out device) || !Guid.TryParseExact(Request.QueryString["rotation"], "D", out rotation))
    { Response.StatusCode = 400; return; }
    var record = Vault.Get(device, rotation);
    if (record == null) { Response.StatusCode = 404; return; }
    Vault.Audit(actor, "portal-download", device, rotation);
    Response.ContentType = "application/json";
    Response.AddHeader("Content-Disposition", "attachment; filename=\"" + rotation.ToString("D") + ".json\"");
    Response.Write(Vault.Json.Serialize(record.envelope));
}
</script>
