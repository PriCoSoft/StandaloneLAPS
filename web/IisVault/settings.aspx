<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Linq" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
protected PortalIdentity Identity;
protected bool EntraMode;
protected string Csrf, ErrorText, SavedText, AgentVersion, LapsTest, LapsTestError;
protected int Limit, FieldValue;
protected PortalSettings Current;
protected CertificateInfo[] Certificates = new CertificateInfo[0];
protected string E(object value) { return Server.HtmlEncode(Convert.ToString(value)); }
protected string Day(DateTime value) { return value == DateTime.MinValue ? "—" : value.ToString("yyyy-MM-dd HH:mm") + " UTC"; }
protected void Page_Load(object sender, EventArgs e)
{
    Identity = PortalAuth.Require(Context);
    EntraMode = PortalAuth.Mode == "Entra";
    if (Session["csrf"] == null) { var bytes = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes); Session["csrf"] = Convert.ToBase64String(bytes); }
    Csrf = (string)Session["csrf"];
    if (Request.HttpMethod == "POST")
    {
        if (!Identity.IsAdmin) throw new HttpException(403, "Administrator access required.");
        if (Request.Form["csrf"] != Csrf) throw new HttpException(403, "Invalid request token.");
        var action = Request.Form["action"];
        if (action == "test-ad" || action == "test-entra")
        {
            try { LapsTest = action == "test-ad" ? ActiveDirectoryLaps.Test() : EntraLaps.Test(); }
            catch (WindowsLapsException ex) { LapsTestError = ex.Message; }
            catch (WindowsLapsNotFoundException) { LapsTestError = "Microsoft Graph returned 404 (not found)."; }
            Vault.AuditTarget(Identity.Actor, "windows-laps-" + action + (LapsTestError == null ? "-ok" : "-failed"), "");
            if (Request.Headers["X-Slaps-Ajax"] == "1")
            {
                // copy.js: answer in place instead of reloading the page.
                Response.Clear(); Response.ContentType = "application/json";
                Response.Write(Vault.Json.Serialize(new { ok = LapsTestError == null, message = LapsTestError ?? LapsTest }));
                Response.End();
            }
        }
        else if (action != "history-limit") throw new HttpException(400, "Unsupported request.");
        else {
        int requested;
        var previous = Vault.HistoryLimit;
        if (!int.TryParse(Request.Form["historyLimit"], out requested) || requested < Vault.MinHistoryLimit || requested > Vault.MaxHistoryLimit)
            ErrorText = "Enter a number between " + Vault.MinHistoryLimit + " and " + Vault.MaxHistoryLimit + ".";
        else if (requested < previous && Request.Form["confirmTrim"] != "yes")
            ErrorText = "Lowering the limit permanently deletes older password versions. Confirm the checkbox to continue.";
        else
        {
            Vault.SetHistoryLimit(requested, Identity.Actor);
            SavedText = requested == previous ? "No change." : "History limit changed from " + previous + " to " + requested + " versions per device.";
        }
        }
    }
    Current = Vault.Settings();
    Limit = Current.historyLimit;
    int entered;
    FieldValue = ErrorText != null && int.TryParse(Request.Form["historyLimit"], out entered) ? entered : Limit;
    Certificates = PortalCertificates.All();
    var agent = Path.Combine(ClientPackages.AgentFilesDirectory ?? "", "StandaloneLaps.Agent.exe");
    AgentVersion = File.Exists(agent) ? FileVersionInfo.GetVersionInfo(agent).ProductVersion : "Agent package files missing (rerun the server installer)";
}
</script>
<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Settings · PriCoSoft SLAPS</title><%= PortalLayout.HeadLinks %></head>
<body>
<%= PortalLayout.TopBar(Identity, EntraMode) %>
<div class="shell">
<%= PortalLayout.Navigation("settings", Identity.IsAdmin) %>
<main class="content">
<div class="breadcrumbs">SLAPS <span>/</span> Settings</div>
<div class="page-heading"><div><p class="eyebrow">CONFIGURATION</p><h1>Settings</h1><p class="subtitle">Password history retention, SLAPS certificates and version information.</p></div><span class="role-label"><%= Identity.IsAdmin ? "Manage access" : "Read access" %></span></div>

<section class="form-card settings-card">
<h2 class="card-title">Password history</h2>
<p class="helper">Number of password versions kept per device. The newest versions are kept; the most recent version reported as applied is always kept as well.</p>
<% if (!string.IsNullOrEmpty(ErrorText)) { %><p class="notice danger"><%= E(ErrorText) %></p><% } %>
<% if (!string.IsNullOrEmpty(SavedText)) { %><p class="notice success"><%= E(SavedText) %></p><% } %>
<% if (Identity.IsAdmin) { %>
<form method="post">
<input type="hidden" name="csrf" value="<%= E(Csrf) %>" />
<label class="field-label" for="historyLimit">Versions per device (<%= Vault.MinHistoryLimit %>–<%= Vault.MaxHistoryLimit %>)</label>
<input class="text-input number-input" id="historyLimit" name="historyLimit" type="number" min="<%= Vault.MinHistoryLimit %>" max="<%= Vault.MaxHistoryLimit %>" value="<%= FieldValue %>" required />
<label class="checkbox"><input type="checkbox" name="confirmTrim" value="yes" />When lowering: permanently delete versions above the new limit on all devices.</label>
<div class="form-actions"><button class="button" type="submit" name="action" value="history-limit">Save</button></div>
</form>
<% } else { %>
<dl class="summary-list"><dt>Versions per device</dt><dd><%= Limit %></dd></dl>
<% } %>
<p class="helper"><%= Current.updatedUtc == null ? "Default value (" + Vault.DefaultHistoryLimit + "), not changed yet." : E("Last changed " + Vault.Timestamp(Current.updatedUtc).UtcDateTime.ToString("yyyy-MM-dd HH:mm") + " UTC by " + Current.updatedBy) %> Deleted devices keep their archive until they are restored.</p>
</section>

<section class="form-card settings-card">
<h2 class="card-title">Certificates</h2>
<p class="helper">Public certificates can be downloaded, e.g. to trust the SLAPS CA elsewhere or to configure agents manually. Private keys never leave the server through the portal.</p>
<% if (Certificates.Length == 0) { %><p class="notice danger">No SLAPS certificates are configured (IssuingCaSha256 / RecoveryCertificateSha256 in web.config). Rerun the server installer.</p><% } %>
<% foreach (var certificate in Certificates) { %>
<div class="certificate">
<div class="certificate-head"><h3><%= E(certificate.Role) %></h3><% if (!certificate.Installed) { %><span class="badge neutral"><span></span>Not installed</span><% } else if (certificate.Expired) { %><span class="badge warning"><span></span>Expired</span><% } else { %><span class="badge success"><span></span>Valid</span><% } %></div>
<p class="helper tight"><%= E(certificate.Purpose) %></p>
<dl>
<% if (certificate.Installed) { %>
<dt>Subject</dt><dd><%= E(certificate.Subject) %></dd>
<dt>Issuer</dt><dd><%= E(certificate.Issuer) %></dd>
<dt>Valid from</dt><dd><%= E(Day(certificate.NotBeforeUtc)) %></dd>
<dt>Valid until</dt><dd><%= E(Day(certificate.NotAfterUtc)) %></dd>
<dt>Key</dt><dd><%= E(certificate.KeyDescription) %></dd>
<dt>Private key</dt><dd><%= E(certificate.KeyStatus) %></dd>
<dt>Serial number</dt><dd class="mono"><%= E(certificate.SerialNumber) %></dd>
<dt>Thumbprint (SHA-1)</dt><dd class="mono fingerprint"><%= E(certificate.Thumbprint) %></dd>
<% } else { %>
<dt>Status</dt><dd><%= E(certificate.KeyStatus) %></dd>
<% } %>
<dt>SHA-256</dt><dd class="mono fingerprint"><%= E(certificate.Sha256) %></dd>
</dl>
<% if (certificate.Installed) { %><div class="form-actions"><a class="button secondary" href="certificate.aspx?sha=<%= E(certificate.Sha256) %>&amp;format=cer">Download .cer (DER)</a><a class="button secondary" href="certificate.aspx?sha=<%= E(certificate.Sha256) %>&amp;format=pem">Download .pem</a></div><% } %>
</div>
<% } %>
</section>

<section class="form-card settings-card" id="windows-laps">
<h2 class="card-title">Windows LAPS lookup</h2>
<p class="helper tight">Read-only lookup of passwords that Windows LAPS or legacy Microsoft LAPS stored in Active Directory or Microsoft Entra ID. Switched in web.config (<code>WindowsLaps*</code>); allowed for <strong><%= WindowsLapsSettings.ReaderAllowed ? "readers and administrators" : "administrators only" %></strong> (<code>WindowsLapsRequiredRole</code>).</p>
<% if (!string.IsNullOrEmpty(LapsTest)) { %><p class="notice success"><%= E(LapsTest) %></p><% } %>
<% if (!string.IsNullOrEmpty(LapsTestError)) { %><p class="notice danger"><%= E(LapsTestError) %></p><% } %>
<div class="certificate">
<div class="certificate-head"><h3>Active Directory</h3><span class="badge <%= WindowsLapsSettings.AdEnabled ? "success" : "neutral" %>"><span></span><%= WindowsLapsSettings.AdEnabled ? "On" : "Off" %></span></div>
<dl>
<dt>Domain controller</dt><dd><%= E(WindowsLapsSettings.AdServer.Length > 0 ? WindowsLapsSettings.AdServer : "Located automatically" + (WindowsLapsSettings.DnsDomain.Length > 0 ? " (domain " + WindowsLapsSettings.DnsDomain + ")" : " (this server is not domain-joined)")) %></dd>
<dt>Search base</dt><dd class="mono"><%= E(WindowsLapsSettings.AdSearchBase.Length > 0 ? WindowsLapsSettings.AdSearchBase : "Whole domain") %></dd>
<dt>Connection</dt><dd><%= WindowsLapsSettings.AdUseSsl ? "LDAPS (636)" : "LDAP 389, Kerberos signed and encrypted" %></dd>
<dt>Reads</dt><dd><%= E(string.Join(", ", new[] { WindowsLapsSettings.AdOptions.Legacy ? "legacy LAPS (ms-Mcs-AdmPwd)" : null, WindowsLapsSettings.AdOptions.Modern ? "Windows LAPS" + (WindowsLapsSettings.AdOptions.Decrypt ? " incl. encrypted (DPAPI-NG)" : " (clear text only)") : null, WindowsLapsSettings.AdOptions.Modern && WindowsLapsSettings.AdOptions.History ? "password history" : null }.Where(s => s != null))) %></dd>
<dt>Runs as</dt><dd><%= E(WindowsLapsSettings.NetworkIdentity) %></dd>
<dt>Expire now</dt><dd><%= WindowsLapsSettings.AdAllowExpire ? "On (administrators; needs <code>Set-LapsADResetPasswordPermission</code> / <code>Set-AdmPwdResetPasswordPermission</code>)" : "Off (<code>WindowsLapsAdAllowExpire</code>)" %></dd>
</dl>
<p class="helper tight">This identity needs the LAPS read permission on the OUs (<code>Set-LapsADReadPasswordPermission</code>, <code>Set-AdmPwdReadPasswordPermission</code>) and, for encrypted passwords, membership in the group of the LAPS policy <em>Configure authorized password decryptors</em>.</p>
<% if (Identity.IsAdmin && WindowsLapsSettings.AdEnabled) { %><form method="post" data-ajax><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button secondary" type="submit" name="action" value="test-ad" data-busy="Testing…">Test Active Directory connection</button><p class="ajax-result" hidden aria-live="polite"></p></form><% } %>
</div>
<div class="certificate">
<div class="certificate-head"><h3>Microsoft Entra ID</h3><span class="badge <%= WindowsLapsSettings.EntraEnabled ? "success" : "neutral" %>"><span></span><%= WindowsLapsSettings.EntraEnabled ? "On" : "Off" %></span></div>
<dl>
<dt>Tenant ID</dt><dd class="mono"><%= E(WindowsLapsSettings.EntraTenantId) %></dd>
<dt>Application (client) ID</dt><dd class="mono"><%= E(WindowsLapsSettings.EntraClientId) %></dd>
<dt>Credential</dt><dd><%= E(EntraLaps.CredentialSource) %></dd>
<% var entraState = EntraAppCredential.Load(); if (entraState.current != null) { %><dt>Certificate valid until</dt><dd><%= E(PortalLayout.Utc(EntraAppCredential.Parse(entraState.currentNotAfter))) %><%= entraState.objectId == null ? " · automatic renewal off (Object ID missing)" : " · renewed automatically" %></dd><% } %>
<% if (entraState.lastRenewalError != null) { %><dt>Renewal problem</dt><dd class="error-text"><%= E(entraState.lastRenewalError) %></dd><% } %>
<dt>Permission</dt><dd>Microsoft Graph <code>DeviceLocalCredential.Read.All</code> (application)<%= entraState.consentResult == null ? "" : E(" · consent " + entraState.consentResult) %></dd>
<dt>History</dt><dd><%= WindowsLapsSettings.EntraHistory ? "Older passwords are shown" : "Only the current password" %></dd>
<dt>Rotate via Intune</dt><dd><%= WindowsLapsSettings.EntraAllowRotate ? "On (administrators; needs <code>DeviceManagementManagedDevices.Read.All</code> and <code>DeviceManagementManagedDevices.PrivilegedOperations.All</code>)" : "Off (<code>WindowsLapsEntraAllowRotate</code>)" %></dd>
</dl>
<% if (Identity.IsAdmin) { %><div class="form-actions"><a class="button" href="entrasetup.aspx">Open Entra setup</a><% if (WindowsLapsSettings.EntraEnabled) { %><form method="post" data-ajax data-ajax-result="entra-test-result"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button secondary" type="submit" name="action" value="test-entra" data-busy="Testing…">Test Entra connection</button></form><% } %></div><p class="ajax-result" id="entra-test-result" hidden aria-live="polite"></p><% } %>
</div>
</section>

<section class="form-card settings-card">
<h2 class="card-title">About</h2>
<dl class="summary-list">
<dt>SLAPS portal version</dt><dd><%= E(AppVersion.Number) %></dd>
<dt>Agent in client packages</dt><dd><%= E(AgentVersion) %></dd>
<dt>Sign-in</dt><dd><%= EntraMode ? "Microsoft Entra ID (app roles SLAPS.Admin / SLAPS.Reader)" : E(PortalAuth.Mode) %></dd>
<dt>Password reveal in browser</dt><dd><%= string.Equals(Vault.Setting("EnableWebDecryption"), "true", StringComparison.OrdinalIgnoreCase) ? "Enabled" : "Disabled" %></dd>
<dt>Windows LAPS lookup</dt><dd><%= WindowsLapsSettings.Enabled ? E((WindowsLapsSettings.AdEnabled ? "Active Directory" : "") + (WindowsLapsSettings.AdEnabled && WindowsLapsSettings.EntraEnabled ? " + " : "") + (WindowsLapsSettings.EntraEnabled ? "Microsoft Entra ID" : "") + (WindowsLapsSettings.ReaderAllowed ? " (readers and administrators)" : " (administrators only)")) : "Disabled" %></dd>
<% if (Identity.IsAdmin) { %>
<dt>Public URL</dt><dd class="mono"><%= E(Vault.Setting("PublicBaseUrl")) %></dd>
<dt>Portal networks</dt><dd class="mono"><%= E(string.Join("; ", Vault.List(Vault.Setting("PortalAllowedNetworks")))) %></dd>
<dt>.NET runtime</dt><dd><%= E(Environment.Version) %></dd>
<% } %>
</dl>
<p class="helper">Settings in web.config are maintained by Install-SlapsServer.ps1; rerun it to change them.</p>
</section>
<p class="identity">Signed in as <%= E(Identity.DisplayName) %> · <%= E(Identity.Actor) %></p>
</main>
</div><%= PortalLayout.Scripts %></body></html>
