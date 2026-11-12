<%@ Page Language="C#" EnableViewState="false" EnableSessionState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
// Downloads the public part of a configured SLAPS certificate (SLAPS CA or recovery certificate).
protected void Page_Load(object sender, EventArgs e)
{
    var identity = PortalAuth.Require(Context);
    var sha = Request.QueryString["sha"];
    var pem = Request.QueryString["format"] == "pem";
    string fileName;
    var certificate = PortalCertificates.FindConfigured(sha, out fileName);
    if (certificate == null) throw new HttpException(404, "Certificate not found.");
    Vault.Audit(identity.Actor, "certificate-download-" + sha.ToUpperInvariant(), Guid.Empty, Guid.Empty);
    var body = pem ? Encoding.ASCII.GetBytes(PortalCertificates.Pem(certificate.RawData)) : certificate.RawData;
    if (pem) fileName = fileName.Substring(0, fileName.Length - 4) + ".pem";
    Response.Clear();
    Response.ContentType = pem ? "application/x-pem-file" : "application/pkix-cert";
    Response.AddHeader("Content-Disposition", "attachment; filename=\"" + fileName + "\"");
    Response.BinaryWrite(body);
    Context.ApplicationInstance.CompleteRequest();
}
</script>
