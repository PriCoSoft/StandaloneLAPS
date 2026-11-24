<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Linq" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
protected PortalIdentity Identity;
protected DeviceSummary Existing;
protected PackageResult Result;
protected string Csrf, ErrorText, NameValue, Platform = ClientPackages.Windows;
protected bool IsLinux { get { return Platform == ClientPackages.Linux; } }
protected bool EntraMode;
protected string E(object value) { return Server.HtmlEncode(Convert.ToString(value)); }
protected void Page_Load(object sender, EventArgs e)
{
    Identity = PortalAuth.Require(Context);
    if (!Identity.IsAdmin) throw new HttpException(403, "Administrator access required.");
    EntraMode = PortalAuth.Mode == "Entra";
    if (Session["csrf"] == null) { var bytes = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes); Session["csrf"] = Convert.ToBase64String(bytes); }
    Csrf = (string)Session["csrf"];
    Guid device;
    if (Guid.TryParseExact(Request.QueryString["device"], "D", out device))
    {
        Existing = Vault.Devices(false, "").FirstOrDefault(item => item.DeviceId == device.ToString("D"));
        if (Existing == null || !Existing.Managed) throw new HttpException(404, "Device not found or not managed by the portal.");
        NameValue = Existing.Name;
    }
    if (Request.HttpMethod != "POST") return;
    if (Request.Form["csrf"] != Csrf) throw new HttpException(403, "Invalid request token.");
    if (Existing == null) NameValue = (Request.Form["name"] ?? "").Trim();
    Platform = Request.Form["platform"] == ClientPackages.Linux ? ClientPackages.Linux : ClientPackages.Windows;
    try
    {
        Result = ClientPackages.Create(NameValue, Existing == null ? (Guid?)null : device, Identity.Actor, Platform);
    }
    catch (ArgumentException ex) { ErrorText = ex.Message; }
    catch (InvalidOperationException ex) { ErrorText = ex.Message; }
    catch (CryptographicException ex) { ErrorText = "The certificate could not be issued: " + ex.Message; }
}
</script>
<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Add client · PriCoSoft SLAPS</title><%= PortalLayout.HeadLinks %></head>
<body>
<%= PortalLayout.TopBar(Identity, EntraMode) %>
<div class="shell">
<%= PortalLayout.Navigation("add", true) %>
<main class="content">
<div class="breadcrumbs">SLAPS <span>/</span> <a href="Default.aspx">Devices</a> <span>/</span> <%= Existing == null ? "Add client" : "New certificate package" %></div>
<div class="page-heading"><div><p class="eyebrow">CLIENT DEPLOYMENT</p><h1><%= Existing == null ? "Add client" : "New certificate package" %></h1><p class="subtitle">The server issues an agent certificate from its SLAPS CA and builds an installation package with all settings predefined.</p></div></div>
<% if (Result == null) { %>
<section class="form-card">
<% if (!string.IsNullOrEmpty(ErrorText)) { %><p class="notice danger"><%= E(ErrorText) %></p><% } %>
<form method="post">
<input type="hidden" name="csrf" value="<%= E(Csrf) %>" />
<% if (Existing == null) { %>
<label class="field-label" for="name">Device name</label>
<input class="text-input" id="name" name="name" value="<%= E(NameValue) %>" maxlength="64" pattern="[A-Za-z0-9 ._\-]{1,64}" required autocomplete="off" placeholder="e.g. DMZ-WEB-01" />
<p class="helper">Use the server's computer name. Letters, digits, spaces, dots, dashes and underscores; up to 64 characters.</p>
<% } else { %>
<section class="notice"><h3><%= E(Existing.Name) %></h3><p>A new agent certificate replaces the current one immediately. The old package stops working; install the new package on this server. History and device ID stay unchanged.</p><p class="mono"><%= E(Existing.DeviceId) %></p></section>
<% } %>
<fieldset class="platform-choice"><legend class="field-label">Operating system</legend>
<label class="checkbox"><input type="radio" name="platform" value="windows" <%= IsLinux ? "" : "checked" %> /> Windows Server <span class="helper">service, password rules from local policy System &gt; LAPS</span></label>
<label class="checkbox"><input type="radio" name="platform" value="linux" <%= IsLinux ? "checked" : "" %> /> Linux (systemd) <span class="helper">.deb for Debian/Ubuntu, install.sh for other distributions; rules in /etc/slaps/agent.conf</span></label>
</fieldset>
<dl class="summary-list"><dt>Certificate</dt><dd>RSA 3072, Client Authentication, valid for 30 years, issued by the SLAPS CA</dd><dt>Agent</dt><dd>Windows: service (LocalSystem). Linux: systemd service slaps-agent (python3 + openssl), rotates root by default</dd><dt>Package</dt><dd>ZIP with installer, agent, PFX and recovery certificate; downloadable for 24 hours</dd></dl>
<div class="form-actions"><button class="button" type="submit"><%= Existing == null ? "Create client and package" : "Issue new certificate" %></button><a href="Default.aspx">Cancel</a></div>
</form>
</section>
<% } else { %>
<section class="form-card">
<h2 class="card-title">Package ready for <%= E(Result.Client.DisplayName) %></h2>
<div class="secret"><strong>PFX password · shown only once</strong><code><%= E(Result.Client.PfxPassword) %></code><p>Store it in your password manager now. The installer asks for it; it is not saved on the server.</p></div>
<div class="form-actions"><a class="button" href="package.aspx?id=<%= E(Result.Package.token) %>">Download <%= E(Result.Package.fileName) %></a><a href="Default.aspx?device=<%= E(Result.Client.DeviceId) %>&amp;tab=overview">Open device</a></div>
<dl class="summary-list"><dt>Device ID</dt><dd class="mono"><%= E(Result.Client.DeviceId) %></dd><dt>Certificate SHA-256</dt><dd class="mono fingerprint"><%= E(Result.Client.CertificateSha256) %></dd><dt>Valid until</dt><dd><%= E(Result.Client.NotAfterUtc.ToString("yyyy-MM-dd")) %> UTC</dd><dt>Download expires</dt><dd><%= E(Vault.Timestamp(Result.Package.expiresUtc).UtcDateTime.ToString("yyyy-MM-dd HH:mm")) %> UTC</dd></dl>
<h3 class="card-subtitle">Install on the server</h3>
<% if (IsLinux) { %>
<ol class="steps"><li>Copy the ZIP to the server and extract it, e.g. <span class="mono">python3 -m zipfile -e <%= E(Result.Package.fileName) %> .</span></li><li>In the extracted folder run <span class="mono">sudo sh install.sh</span> and enter the PFX password.</li><li>The installer installs the agent (.deb on Debian/Ubuntu), imports the certificate, tests the connection to this server and starts the <span class="mono">slaps-agent</span> service.</li><li>Delete the extracted folder and the ZIP afterwards.</li></ol>
<p class="helper">Password rules: <span class="mono">/etc/slaps/agent.conf</span> (default root, 14 characters, complexity 4, 30 days). Options: <span class="mono">--api-url … --no-start</span>. Remove with <span class="mono">--uninstall [--purge]</span>. Log: <span class="mono">journalctl -u slaps-agent</span>.</p>
<% } else { %>
<ol class="steps"><li>Copy the ZIP to the server and extract it.</li><li>Right-click <strong>Install.cmd</strong> &gt; <em>Run as administrator</em> and enter the PFX password.</li><li>The installer imports the certificate, installs and configures the service, tests the connection to this server and starts the agent.</li><li>Delete the extracted folder and the ZIP afterwards.</li></ol>
<p class="helper">Settings are predefined in slaps-settings.json. Optional overrides: <span class="mono">Install-SlapsAgent.ps1 -ApiUrl … -InstallDirectory … -NoStart</span>. Remove with <span class="mono">-Uninstall</span>.</p>
<% } %>
</section>
<% } %>
</main>
</div><%= PortalLayout.Scripts %></body></html>
