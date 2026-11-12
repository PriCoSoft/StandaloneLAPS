<%@ Page Language="C#" EnableSessionState="false" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
protected void Page_Load(object sender, EventArgs e)
{
    Response.ContentType = "application/json";
    Response.TrySkipIisCustomErrors = true;
    try
    {
        if (!Request.IsSecureConnection) { Response.StatusCode = 403; return; }
        var client = Vault.CertificateClient(Request);
        if (client == null) { Response.StatusCode = 403; return; }
        if (!Vault.PermitApiRequest(client.certificateSha256)) { Response.StatusCode = 429; return; }
        Guid device, rotation;
        if (!Guid.TryParseExact(Request.QueryString["device"], "D", out device) || device == Guid.Empty)
        { Response.StatusCode = 400; return; }
        var hasRotation = Guid.TryParseExact(Request.QueryString["rotation"], "D", out rotation) && rotation != Guid.Empty;
        var write = Request.HttpMethod == "PUT" || Request.HttpMethod == "POST";
        if (!Vault.CanAccess(client, device, write)) { Response.StatusCode = 403; return; }
        if (Request.HttpMethod == "PUT" && hasRotation)
        {
            if (Request.ContentLength > 65536) { Response.StatusCode = 413; return; }
            string body;
            using (var reader = new StreamReader(Request.InputStream)) body = reader.ReadToEnd();
            if (body.Length > 65536) { Response.StatusCode = 413; return; }
            var envelope = Vault.Json.Deserialize<Envelope>(body);
            if (!Vault.Valid(envelope, device, rotation)) { Response.StatusCode = 400; return; }
            Vault.Audit("certificate:" + client.certificateSha256, "backup-attempt", device, rotation);
            Response.StatusCode = Vault.Put(device, rotation, envelope) ? 204 : 409;
        }
        else if (Request.HttpMethod == "POST" && hasRotation && Request.QueryString["action"] == "applied")
        {
            Vault.Audit("certificate:" + client.certificateSha256, "applied-report", device, rotation);
            Response.StatusCode = Vault.Applied(device, rotation) ? 204 : 404;
        }
        else if (Request.HttpMethod == "GET" && hasRotation)
        {
            var record = Vault.Get(device, rotation);
            if (record == null) { Response.StatusCode = 404; return; }
            Vault.Audit("certificate:" + client.certificateSha256, "envelope-read", device, rotation);
            Response.Write(Vault.Json.Serialize(record.envelope));
        }
        else if (Request.HttpMethod == "GET" && string.IsNullOrEmpty(Request.QueryString["rotation"]))
        {
            int skip = 0, take = Vault.HistoryLimit;
            if ((Request.QueryString["skip"] != null && !int.TryParse(Request.QueryString["skip"], out skip)) ||
                (Request.QueryString["take"] != null && !int.TryParse(Request.QueryString["take"], out take)) || skip < 0 || take < 1 || take > Vault.MaxHistoryLimit)
            { Response.StatusCode = 400; return; }
            // Results are capped at the configured history limit (Vault.History).
            Vault.Audit("certificate:" + client.certificateSha256, "history-read", device, Guid.Empty);
            Response.Write(Vault.Json.Serialize(Vault.History(device, skip, take)));
        }
        else { Response.StatusCode = 400; }
    }
    catch (ArgumentException) { Response.StatusCode = 400; }
    catch (InvalidOperationException) { Response.StatusCode = 400; }
}
</script>
