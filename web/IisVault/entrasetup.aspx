<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
// Setup for the Microsoft Entra ID part of the Windows LAPS lookup (administrators only): certificate created on this
// server, upload of its public part, Graph application permission with admin consent, automatic renewal, test.
protected PortalIdentity Identity;
protected bool EntraMode, WebConfigCertificate;
protected string Csrf, Info, ErrorText, TenantId, ClientId;
protected EntraCredentialState State;
protected string E(object value) { return Server.HtmlEncode(Convert.ToString(value)); }
protected string Day(string stamp) { var value = EntraAppCredential.Parse(stamp); return value.HasValue ? PortalLayout.Utc(value) : "—"; }
protected string Portal(string blade) { return "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/" + blade + "/appId/" + Uri.EscapeDataString(ClientId ?? ""); }
protected void Page_Load(object sender, EventArgs e)
{
    Identity = PortalAuth.Require(Context);
    if (!Identity.IsAdmin) throw new HttpException(403, "Administrator access required.");
    EntraMode = PortalAuth.Mode == "Entra";
    if (Session["csrf"] == null) { var bytes = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes); Session["csrf"] = Convert.ToBase64String(bytes); }
    Csrf = (string)Session["csrf"];
    TenantId = WindowsLapsSettings.EntraTenantId; ClientId = WindowsLapsSettings.EntraClientId;
    WebConfigCertificate = WindowsLapsSettings.EntraCertificateThumbprint.Length > 0;
    State = EntraAppCredential.Load();
    if (Request.QueryString["download"] == "cer")
    {
        var raw = EntraAppCredential.PublicCertificate();
        if (raw == null) throw new HttpException(404, "No certificate.");
        Vault.AuditTarget(Identity.Actor, "entra-graph-certificate-download", EntraAppCredential.Load().currentThumbprint);
        Response.ContentType = "application/pkix-cert";
        Response.AddHeader("Content-Disposition", "attachment; filename=slaps-graph-access.cer");
        Response.BinaryWrite(raw);
        Response.End();
        return;
    }
    if (Request.HttpMethod == "POST")
    {
        if (Request.Form["csrf"] != Csrf) throw new HttpException(403, "Invalid request token.");
        try
        {
            switch (Request.Form["action"])
            {
                case "create":
                    if (EntraAppCredential.Configured && Request.Form["confirmReplace"] != "yes") { ErrorText = "A certificate exists already. Confirm the checkbox to replace it (the new one must be uploaded again)."; break; }
                    var created = EntraAppCredential.Create(Identity.Actor);
                    EntraLaps.ResetToken();
                    Info = "Certificate " + created.currentThumbprint + " created. Download it and upload it to the app registration (step 2).";
                    break;
                case "consent":
                    Guid tenant, client;
                    if (!Guid.TryParse(TenantId, out tenant) || !Guid.TryParse(ClientId, out client)) { ErrorText = "Tenant and client ID are not configured."; break; }
                    Vault.AuditTarget(Identity.Actor, "entra-admin-consent-started", client.ToString("D"));
                    // Redirect without rendering the page (the page would otherwise still render after CompleteRequest).
                    Response.Redirect(PortalAuth.AdminConsentUrl(tenant.ToString("D"), client.ToString("D")), false);
                    Response.SuppressContent = true;
                    Context.ApplicationInstance.CompleteRequest();
                    return;
                case "object-id":
                    Guid objectId;
                    var text = (Request.Form["objectId"] ?? "").Trim();
                    if (text.Length > 0 && !Guid.TryParse(text, out objectId)) { ErrorText = "The Object ID is a GUID (App registration → Overview → Object ID)."; break; }
                    var state = EntraAppCredential.Load();
                    state.objectId = text.Length == 0 ? null : Guid.Parse(text).ToString("D");
                    EntraAppCredential.Save(state);
                    Vault.AuditTarget(Identity.Actor, "entra-object-id-set", state.objectId ?? "(cleared)");
                    Info = text.Length == 0 ? "Automatic renewal is off." : "Object ID saved. The certificate is renewed automatically " + EntraAppCredential.RenewBeforeDays + " days before it expires.";
                    break;
                case "renew":
                    Info = EntraLaps.Renew(Identity.Actor);
                    break;
                case "test":
                    Info = EntraLaps.Test();
                    break;
                default: throw new HttpException(400, "Unsupported request.");
            }
        }
        catch (WindowsLapsException ex) { ErrorText = ex.Message; }
        catch (WindowsLapsNotFoundException) { ErrorText = "Microsoft Graph returned 404 (not found)."; }
        catch (HttpException) { throw; }
        catch (System.Threading.ThreadAbortException) { throw; }
        catch (Exception ex)
        {
            // Administrators only: show the technical reason (e.g. key storage or file permissions of the pool identity).
            var reference = Vault.LogError(ex, Request.AppRelativeCurrentExecutionFilePath + " action=" + Request.Form["action"]);
            ErrorText = "The action failed: " + ex.GetType().Name + ": " + ex.Message + (ex.InnerException == null ? "" : " (" + ex.InnerException.GetType().Name + ": " + ex.InnerException.Message + ")") +
                " Identity: " + WindowsLapsSettings.ProcessIdentity + ". Reference " + reference + " in App_Data\\Vault\\errors.log.";
        }
    }
    if (Request.HttpMethod == "POST" && Request.Headers["X-Slaps-Ajax"] == "1")
    {
        // copy.js: answer in place instead of reloading the page.
        Response.Clear(); Response.ContentType = "application/json";
        Response.Write(Vault.Json.Serialize(new { ok = ErrorText == null, message = ErrorText ?? Info }));
        Response.End();
    }
    State = EntraAppCredential.Load();
}
</script>
<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Entra setup · PriCoSoft SLAPS</title><%= PortalLayout.HeadLinks %></head>
<body>
<%= PortalLayout.TopBar(Identity, EntraMode) %>
<div class="shell">
<%= PortalLayout.Navigation("settings", true) %>
<main class="content">
<div class="breadcrumbs">SLAPS <span>/</span> <a href="settings.aspx">Settings</a> <span>/</span> Entra setup</div>
<div class="page-heading"><div><p class="eyebrow">WINDOWS LAPS · MICROSOFT ENTRA ID</p><h1>Entra lookup setup</h1><p class="subtitle">Lets SLAPS read Windows LAPS passwords that Entra-joined devices back up to Microsoft Entra ID (Microsoft Graph, read-only).</p></div><span class="role-label">Administrators only</span></div>
<% if (!string.IsNullOrEmpty(Info)) { %><p class="notice success wide"><%= E(Info) %></p><% } %>
<% if (!string.IsNullOrEmpty(ErrorText)) { %><p class="notice danger wide"><%= E(ErrorText) %></p><% } %>
<% if (!WindowsLapsSettings.EntraEnabled) { %><p class="notice wide">The Entra lookup is not switched on yet. You can prepare everything here; then set <code>WindowsLapsEntraEnabled</code> to <code>true</code> in web.config.</p><% } %>
<% if (WebConfigCertificate) { %><p class="notice wide">web.config names a certificate (<code>WindowsLapsEntraCertificateThumbprint</code>). It takes precedence; the certificate managed here is not used until that setting is cleared.</p><% } %>

<section class="form-card settings-card setup-step">
<div class="step-head"><span class="step-number <%= EntraAppCredential.Configured ? "done" : "" %>">1</span><h2 class="card-title">Certificate</h2></div>
<p class="helper">SLAPS signs in to Microsoft Graph as the app registration <span class="mono"><%= E(ClientId) %></span> with a certificate created on this server. The private key never leaves the server (stored in App_Data, protected with the site's machineKey); only the public part is uploaded to Entra ID.</p>
<% if (EntraAppCredential.Configured) { %>
<dl class="summary-list"><dt>Thumbprint</dt><dd class="mono"><%= E(State.currentThumbprint) %></dd><dt>Valid until</dt><dd><%= E(Day(State.currentNotAfter)) %></dd><dt>Created</dt><dd><%= E(Day(State.currentCreatedUtc)) %></dd></dl>
<div class="form-actions"><a class="button" href="entrasetup.aspx?download=cer">Download public certificate (.cer)</a></div>
<details class="replace"><summary>Replace certificate</summary><form method="post"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><label class="checkbox"><input type="checkbox" name="confirmReplace" value="yes" />Create a new certificate. The Entra lookup stops working until the new one is uploaded.</label><button class="button secondary" type="submit" name="action" value="create">Create new certificate</button></form></details>
<% } else { %>
<form method="post"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button" type="submit" name="action" value="create">Create certificate</button></form>
<% } %>
</section>

<section class="form-card settings-card setup-step">
<div class="step-head"><span class="step-number <%= State.consentResult == "granted" ? "done" : "" %>">2</span><h2 class="card-title">App registration: upload certificate and grant permission</h2></div>
<ol class="steps">
<li>Open <a href="<%= E(Portal("Credentials")) %>" target="_blank" rel="noopener">Certificates &amp; secrets</a> of the app registration → <em>Certificates</em> → <em>Upload certificate</em> → select the downloaded <code>.cer</code> file.</li>
<li>Open <a href="<%= E(Portal("CallAnAPI")) %>" target="_blank" rel="noopener">API permissions</a> → <em>Add a permission</em> → <em>Microsoft Graph</em> → <em>Application permissions</em> → <code>DeviceLocalCredential.Read.All</code> → <em>Add permissions</em>.</li>
<li>Grant admin consent (button below, or <em>Grant admin consent</em> on the API permissions page). This needs a Global Administrator or Privileged Role Administrator.</li>
</ol>
<form method="post"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button" type="submit" name="action" value="consent">Grant admin consent</button></form>
<p class="helper"><%= State.consentUtc == null ? "No consent recorded by SLAPS yet." : E("Last consent: " + (State.consentResult ?? "") + " · " + Day(State.consentUtc) + " by " + State.consentBy) %> Entra returns to <span class="mono">signin.aspx</span>, which is already a redirect URI of the SLAPS sign-in app. If the lookup uses a separate app registration, add that redirect URI there too.</p>
</section>

<section class="form-card settings-card setup-step">
<div class="step-head"><span class="step-number <%= State.objectId != null ? "done" : "" %>">3</span><h2 class="card-title">Automatic renewal</h2></div>
<p class="helper">The certificate is valid for <%= EntraAppCredential.ValidityDays %> days. <%= EntraAppCredential.RenewBeforeDays %> days before it expires, SLAPS creates a new one and adds it to the app registration itself (Microsoft Graph <em>addKey</em>, signed with the current certificate; no extra permission needed), switches over and removes the old one. For this it needs the <strong>Object ID</strong> of the app registration (<a href="<%= E(Portal("Overview")) %>" target="_blank" rel="noopener">Overview</a> → <em>Object ID</em>, not the client ID).</p>
<form method="post" class="inline-form"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><label class="field-label" for="objectId">Application Object ID</label><input class="text-input" id="objectId" name="objectId" value="<%= E(State.objectId) %>" placeholder="00000000-0000-0000-0000-000000000000" maxlength="40" /><div class="form-actions"><button class="button secondary" type="submit" name="action" value="object-id">Save</button></div></form>
<dl class="summary-list">
<dt>Next renewal</dt><dd><%= EntraAppCredential.Parse(State.currentNotAfter).HasValue ? E(PortalLayout.Utc(EntraAppCredential.Parse(State.currentNotAfter).Value.AddDays(-EntraAppCredential.RenewBeforeDays))) : "—" %><%= State.objectId == null ? " (off: Object ID missing)" : "" %></dd>
<dt>Last renewal</dt><dd><%= E(Day(State.lastRenewalUtc)) %></dd>
<% if (State.pending != null) { %><dt>Waiting for Entra</dt><dd class="mono"><%= E(State.pendingThumbprint) %> (added <%= E(Day(State.pendingCreatedUtc)) %>)</dd><% } %>
<% if (State.lastRenewalError != null) { %><dt>Last error</dt><dd class="error-text"><%= E(State.lastRenewalError) %></dd><% } %>
</dl>
<% if (EntraAppCredential.Configured && State.objectId != null) { %><form method="post"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button secondary" type="submit" name="action" value="renew">Renew now</button></form><% } %>
</section>

<section class="form-card settings-card setup-step">
<div class="step-head"><span class="step-number">4</span><h2 class="card-title">Test</h2></div>
<p class="helper">Requests a token and reads one entry of <span class="mono">deviceLocalCredentials</span> (no password). After uploading a certificate or granting consent, Entra may need a few minutes.</p>
<form method="post" data-ajax><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button" type="submit" name="action" value="test" data-busy="Testing…">Test connection</button><p class="ajax-result" hidden aria-live="polite"></p></form>
</section>
<p class="identity">Signed in as <%= E(Identity.DisplayName) %> · <%= E(Identity.Actor) %></p>
</main>
</div><%= PortalLayout.Scripts %></body></html>
