<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Linq" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
// Read-only lookup of Windows LAPS / legacy LAPS passwords in Active Directory and Microsoft Entra ID.
protected PortalIdentity Identity;
protected bool EntraMode, Searched;
protected string Csrf, Query, Source, Tab;
protected Guid Id;
protected List<WindowsLapsComputer> Results = new List<WindowsLapsComputer>();
protected List<string> Errors = new List<string>();
protected WindowsLapsComputer Selected;
protected WindowsLapsResult Revealed;
protected string RotateMessage;
protected string E(object value) { return Server.HtmlEncode(Convert.ToString(value)); }
protected string Url(WindowsLapsComputer computer, string tab)
{
    var url = "windowslaps.aspx?q=" + Server.UrlEncode(Query ?? "");
    if (computer != null) url += "&source=" + computer.Source + "&id=" + Server.UrlEncode(computer.Id) + "&tab=" + tab;
    return url;
}
protected string SourceName(string source) { return source == "entra" ? "Microsoft Entra ID" : "Active Directory"; }
// Which passwords a search hit has (AD: derived from the expiry attributes, which carry no secret).
protected string Kinds(WindowsLapsComputer computer)
{
    if (computer.Source == "entra") return "<span class=\"kind-badge entra\">Windows LAPS</span>";
    var html = "";
    if (computer.ExpiresUtc.HasValue) html += "<span class=\"kind-badge\">Windows LAPS</span>";
    if (computer.LegacyExpiresUtc.HasValue) html += "<span class=\"kind-badge legacy\">Legacy LAPS</span>";
    return html.Length == 0 ? "<span class=\"kind-badge\">Stored</span>" : html;
}
protected string Sort(DateTime? value) { return value.HasValue ? value.Value.ToString("o") : ""; }
protected bool Mixed { get { return Revealed != null && Revealed.Credentials.Any(c => c.Source == "ad-legacy" && c.IsCurrent) && Revealed.Credentials.Any(c => c.Source == "ad" && c.IsCurrent); } }
protected IEnumerable<WindowsLapsCredential> Shown()
{
    if (Revealed == null) return new WindowsLapsCredential[0];
    return Revealed.Credentials.Where(c => Tab == "history" ? c.IsHistory : !c.IsHistory);
}
protected string Card(WindowsLapsCredential credential, int index)
{
    var meta = "<span>" + E(WindowsLapsFormat.SourceLabel(credential.Source)) + (credential.Encrypted ? " · encrypted in AD" : "") + "</span>";
    if (credential.UpdatedUtc.HasValue) meta += "<span>Set " + E(PortalLayout.Utc(credential.UpdatedUtc)) + "</span>";
    if (credential.ExpiresUtc.HasValue) meta += "<span>" + (credential.Source == "entra" ? "Next rotation " : "Expires ") + E(PortalLayout.Utc(credential.ExpiresUtc)) + "</span>";
    if (credential.Source == "ad-legacy") meta += "<span>Account: as set in the legacy LAPS policy (default: built-in Administrator)</span>";
    if (credential.Error != null)
        return "<div class=\"credential error\"><strong>" + E(WindowsLapsFormat.Title(credential)) + "</strong> could not be read: " + E(credential.Error) + "<div class=\"credential-meta\">" + meta + "</div></div>";
    var account = credential.Account;
    if (credential.Source != "ad-legacy" && !string.IsNullOrEmpty(account) && account.IndexOf('\\') < 0 && Selected != null && !string.IsNullOrEmpty(Selected.Name))
        account = Selected.Name + "\\" + account;
    return PortalLayout.Credential("laps-" + index, WindowsLapsFormat.Title(credential), null, account, credential.Password, meta);
}
protected void Page_Load(object sender, EventArgs e)
{
    Identity = PortalAuth.Require(Context);
    EntraMode = PortalAuth.Mode == "Entra";
    if (!WindowsLapsSettings.Enabled) throw new HttpException(404, "Windows LAPS lookup is not enabled.");
    if (!WindowsLapsSettings.Allowed(Identity)) throw new HttpException(403, "Administrator access required.");
    if (Session["csrf"] == null) { var bytes = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes); Session["csrf"] = Convert.ToBase64String(bytes); }
    Csrf = (string)Session["csrf"];
    Query = (Request.QueryString["q"] ?? "").Trim(); if (Query.Length > 128) Query = Query.Substring(0, 128);
    Source = Request.QueryString["source"] == "entra" ? "entra" : Request.QueryString["source"] == "ad" ? "ad" : null;
    Tab = Request.QueryString["tab"] == "history" ? "history" : Request.QueryString["tab"] == "details" ? "details" : "password";
    Guid.TryParseExact(Request.QueryString["id"] ?? "", "D", out Id);
    if (Source == "ad" && !WindowsLapsSettings.AdEnabled || Source == "entra" && !WindowsLapsSettings.EntraEnabled) Source = null;

    if (Query.Length > 0)
    {
        Searched = true;
        if (!WindowsLapsFormat.ValidQuery(Query)) Errors.Add("Enter a computer name, DNS name or Entra device ID. Letters, digits, '-', '.', '_' are allowed; '*' only at the end (at least two characters before it).");
        else
        {
            Vault.AuditTarget(Identity.Actor, "windows-laps-search", Query);
            if (WindowsLapsSettings.AdEnabled)
                try { Results.AddRange(ActiveDirectoryLaps.Search(Query)); }
                catch (WindowsLapsException ex) { Errors.Add("Active Directory: " + ex.Message); }
            if (WindowsLapsSettings.EntraEnabled)
                try { Results.AddRange(EntraLaps.Search(Query)); }
                catch (WindowsLapsException ex) { Errors.Add("Microsoft Entra ID: " + ex.Message); }
        }
    }

    if (Source != null && Id != Guid.Empty && Request.HttpMethod == "POST" && Request.Form["action"] == "expire")
    {
        // "Expire now" (AD) / "Rotate now" (Intune): administrators only, switched on separately, audited.
        if (Request.Form["csrf"] != Csrf) throw new HttpException(403, "Invalid request token.");
        if (!WindowsLapsSettings.CanRotate(Identity, Source)) throw new HttpException(403, "Not allowed.");
        string message = null, failure = null;
        try { message = Source == "ad" ? ActiveDirectoryLaps.Expire(Id) : EntraLaps.Rotate(Id); }
        catch (WindowsLapsException ex) { failure = ex.Message; }
        catch (WindowsLapsNotFoundException) { failure = "Microsoft Graph returned 404 (not found)."; }
        Vault.AuditTarget(Identity.Actor, (Source == "ad" ? "windows-laps-expire-ad" : "windows-laps-rotate-entra") + (failure == null ? "" : "-failed"), Id.ToString("D"));
        if (Request.Headers["X-Slaps-Ajax"] == "1")
        {
            Response.Clear(); Response.ContentType = "application/json";
            Response.Write(Vault.Json.Serialize(new { ok = failure == null, message = failure ?? message }));
            Response.End();
        }
        if (failure != null) Errors.Add(failure); else RotateMessage = message;
    }
    if (Source != null && Id != Guid.Empty)
    {
        var reveal = Request.HttpMethod == "POST" && Request.Form["action"] != "expire";
        if (reveal && (Request.Form["csrf"] != Csrf || Request.Form["action"] != "reveal")) throw new HttpException(403, "Invalid request token.");
        try
        {
            if (Source == "ad")
            {
                WindowsLapsResult credentials;
                if (reveal) Vault.AuditTarget(Identity.Actor, "windows-laps-reveal-ad", Id.ToString("D"));
                Selected = ActiveDirectoryLaps.Find(Id, out credentials, reveal);
                Revealed = credentials;
            }
            else if (reveal)
            {
                Vault.AuditTarget(Identity.Actor, "windows-laps-reveal-entra", Id.ToString("D"));
                WindowsLapsComputer computer;
                Revealed = EntraLaps.Read(Id, out computer);
                Selected = computer;
            }
            else Selected = EntraLaps.Find(Id);
            if (Selected == null) { Errors.Add("The selected computer was not found."); Revealed = null; }
            else if (reveal) Vault.AuditTarget(Identity.Actor, "windows-laps-revealed-" + Source, Id.ToString("D") + " " + Selected.Name);
        }
        catch (WindowsLapsException ex) { Errors.Add(SourceName(Source) + ": " + ex.Message); }
        catch (WindowsLapsNotFoundException) { Errors.Add("The selected device was not found in Microsoft Entra ID."); }
    }
}
</script>
<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Windows LAPS · PriCoSoft SLAPS</title><%= PortalLayout.HeadLinks %></head>
<body>
<%= PortalLayout.TopBar(Identity, EntraMode) %>
<div class="shell">
<%= PortalLayout.Navigation("windowslaps", Identity.IsAdmin) %>
<main class="content <%= Selected != null ? "with-drawer" : "" %>">
<div class="breadcrumbs">SLAPS <span>/</span> Windows LAPS</div>
<div class="page-heading"><div><p class="eyebrow">DIRECTORY LOOKUP · READ-ONLY</p><h1>Windows LAPS</h1><p class="subtitle">Find a domain-joined or Entra-joined computer and show the password that Windows LAPS or legacy Microsoft LAPS stored for it.</p></div><span class="role-label"><%= Identity.IsAdmin ? "Manage access" : "Read access" %></span></div>
<div class="source-chips"><span class="chip <%= WindowsLapsSettings.AdEnabled ? "on" : "" %>">Active Directory: <%= WindowsLapsSettings.AdEnabled ? "on" : "off" %></span><span class="chip <%= WindowsLapsSettings.EntraEnabled ? "on" : "" %>">Microsoft Entra ID: <%= WindowsLapsSettings.EntraEnabled ? "on" : "off" %></span></div>
<div class="list-card">
<form class="search-panel" method="get"><label class="field-label" for="laps-query">Computer</label><div class="search-row"><label class="search-box wide"><span aria-hidden="true">⌕</span><input id="laps-query" type="search" name="q" value="<%= E(Query) %>" placeholder="e.g. SRV-APP01, srv-app01.corp.example or SRV-*" maxlength="128" autofocus /></label><button class="button" type="submit">Search</button><% if (Searched) { %><a class="text-link" href="windowslaps.aspx">Clear</a><span class="results"><%= Results.Count %> <%= Results.Count == 1 ? "computer" : "computers" %></span><% } %></div>
<p class="search-hint">Name, DNS name or Entra device ID. End with <code>*</code> to search by prefix. Only computers with a stored LAPS password are listed (max. <%= ActiveDirectoryLaps.MaxResults %> per directory).</p></form>
<% foreach (var error in Errors) { %><p class="notice danger inset"><%= E(error) %></p><% } %>
<% if (Results.Count > 0) { %>
<div class="table-scroll"><table class="device-table sortable" data-table-key="windowslaps"><thead><tr><th data-sort="text">Computer</th><th data-sort="text">Description</th><th data-sort="text">Directory</th><th data-sort="text">Stored passwords</th><th data-sort="text">Password expires (UTC)</th><th class="no-sort"><span class="sr-only">Open</span></th></tr></thead><tbody>
<% foreach (var computer in Results) { var link = Url(computer, "password"); var expires = computer.ExpiresUtc ?? computer.LegacyExpiresUtc; %><tr class="<%= Selected != null && Selected.Source == computer.Source && Selected.Id == computer.Id ? "selected-row" : "" %>"><td><a class="device-link" href="<%= E(link) %>"><span class="device-icon" aria-hidden="true"></span><span><strong><%= E(computer.Name) %></strong><small><%= E(computer.DnsName ?? computer.OperatingSystem ?? computer.Id) %></small></span></a></td><td class="description-cell"><%= E(computer.Description ?? "") %></td><td><span class="source-badge <%= computer.Source %>"><%= E(SourceName(computer.Source)) %></span></td><td class="kinds-cell"><%= Kinds(computer) %></td><td class="date-cell" data-sort-value="<%= E(Sort(expires)) %>"><%= E(expires.HasValue ? PortalLayout.Utc(expires) : "—") %></td><td><a class="row-open" aria-label="<%= E("Open " + computer.Name) %>" href="<%= E(link) %>">›</a></td></tr><% } %>
</tbody></table></div>
<% } else if (Searched && Errors.Count == 0) { %><div class="empty-state compact"><span class="empty-icon">⌕</span><h2>No computer with a LAPS password found</h2><p>Check the name, search by prefix with * at the end, or check that this server may read the LAPS attributes of that OU.</p></div>
<% } else if (!Searched) { %><div class="empty-state compact"><span class="empty-icon">⌕</span><h2>Search for a computer</h2><p>Passwords are read live from the directory and never stored by SLAPS.</p></div><% } %>
<div class="list-footer"><span>Read-only · every search and reveal is audited</span><span><%= WindowsLapsSettings.ReaderAllowed ? "Readers and administrators" : "Administrators only" %></span></div></div>
<p class="identity">Signed in as <%= E(Identity.DisplayName) %> · <%= E(Identity.Actor) %></p>
</main>
<% if (Selected != null) { %>
<a class="drawer-backdrop" href="<%= E(Url(null, "")) %>" aria-label="Close computer details"></a>
<aside class="drawer" aria-labelledby="computer-title"><div class="drawer-top"><div class="drawer-breadcrumb">Windows LAPS <span>/</span> <%= E(Selected.Name) %></div><a class="close-button" href="<%= E(Url(null, "")) %>" aria-label="Close computer details">×</a></div>
<div class="drawer-heading"><span class="device-icon large" aria-hidden="true"></span><div><h2 id="computer-title"><%= E(Selected.Name) %></h2><p><%= E(SourceName(Selected.Source)) %><%= string.IsNullOrEmpty(Selected.OperatingSystem) ? "" : " · " + E(Selected.OperatingSystem) %></p><% if (!string.IsNullOrEmpty(Selected.Description)) { %><p class="drawer-description"><%= E(Selected.Description) %></p><% } %></div></div>
<nav class="tabs" aria-label="Computer sections"><a class="<%= Tab == "password" ? "active" : "" %>" href="<%= E(Url(Selected, "password")) %>">Password</a><a class="<%= Tab == "history" ? "active" : "" %>" href="<%= E(Url(Selected, "history")) %>">History</a><a class="<%= Tab == "details" ? "active" : "" %>" href="<%= E(Url(Selected, "details")) %>">Details</a></nav>
<div class="drawer-body">
<% if (Tab == "details") { %>
<section class="detail-section"><h3>Directory object</h3><dl><dt>Name</dt><dd><%= E(Selected.Name) %></dd>
<% if (!string.IsNullOrEmpty(Selected.Description)) { %><dt>Description</dt><dd><%= E(Selected.Description) %></dd><% } %>
<% if (!string.IsNullOrEmpty(Selected.DnsName)) { %><dt>DNS name</dt><dd><%= E(Selected.DnsName) %></dd><% } %>
<% if (!string.IsNullOrEmpty(Selected.DistinguishedName)) { %><dt>Distinguished name</dt><dd class="mono"><%= E(Selected.DistinguishedName) %></dd><% } %>
<dt><%= Selected.Source == "entra" ? "Entra device ID" : "Object GUID" %></dt><dd class="mono"><%= E(Selected.Id) %></dd>
<% if (Selected.ExpiresUtc.HasValue) { %><dt><%= Selected.Source == "entra" ? "Next rotation" : "Windows LAPS expiry" %></dt><dd><%= E(PortalLayout.Utc(Selected.ExpiresUtc)) %></dd><% } %>
<% if (Selected.LegacyExpiresUtc.HasValue) { %><dt>Legacy LAPS expiry</dt><dd><%= E(PortalLayout.Utc(Selected.LegacyExpiresUtc)) %></dd><% } %>
<% if (Selected.LastBackupUtc.HasValue) { %><dt>Last backup</dt><dd><%= E(PortalLayout.Utc(Selected.LastBackupUtc)) %></dd><% } %>
</dl></section>
<p class="helper">SLAPS only reads these values. Rotate or reset passwords with the Windows LAPS tools (Reset-LapsPassword, Intune, Entra admin center).</p>
<% } else { %>
<% if (Revealed == null) { %>
<section class="current-card"><h3><%= Tab == "history" ? "Previous passwords" : "Current password" %></h3><p><%= Tab == "history" ? "Older passwords kept by Windows LAPS (password history). They are read and decrypted only when you ask for them." : "The password is read live from " + E(SourceName(Selected.Source)) + " and decrypted on this server when needed." %></p>
<form method="post" action="<%= E(Url(Selected, Tab)) %>"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button large" type="submit" name="action" value="reveal"><%= Tab == "history" ? "Show password history" : "Show password" %></button></form></section>
<% if (Tab == "password") { %><% if (WindowsLapsSettings.CanRotate(Identity, Selected.Source)) { %>
<section class="current-card rotate-card"><h3>Change the password soon</h3>
<p><%= Selected.Source == "ad" ? "Used the password? Set its expiry to now: the computer creates a new password at its next LAPS cycle. Until then the current password keeps working." : "Used the password? Ask Intune to rotate it: the device sets a new password at its next check-in and backs it up to Entra ID." %></p>
<form method="post" action="<%= E(Url(Selected, "password")) %>" data-ajax><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button secondary" type="submit" name="action" value="expire" data-busy="Requesting…"><%= Selected.Source == "ad" ? "Expire password now" : "Rotate password now (Intune)" %></button><p class="ajax-result <%= RotateMessage == null ? "" : "notice success" %>" <%= RotateMessage == null ? "hidden" : "" %> aria-live="polite"><%= E(RotateMessage) %></p></form></section>
<% } %><% } %>
<% } else { var index = 0; var shown = Shown().ToList(); %>
<% foreach (var error in Revealed.Errors) { %><p class="notice danger"><%= E(error) %></p><% } %>
<% if (Mixed && Tab == "password") { %><p class="notice">This computer has both a <strong>Windows LAPS</strong> and a <strong>legacy LAPS</strong> password (mixed operation, e.g. during migration). The one that changed last is active on the device; compare the dates below.</p><% } %>
<% if (shown.Count == 0) { %><div class="empty-panel"><h3><%= Tab == "history" ? "No password history" : "No password found" %></h3><p><%= Tab == "history" ? "Windows LAPS keeps history only for encrypted passwords and when PasswordHistorySize is set." : "No LAPS password is stored for this computer, or this server's identity cannot read it." %></p></div><% } %>
<div class="<%= Tab == "history" ? "history-credentials" : "" %>"><% foreach (var credential in shown) { %><%= Card(credential, index++) %><% } %></div>
<p class="helper">Close this page after use. Every reveal is audited.</p>
<% if (Tab == "password") { %><% if (WindowsLapsSettings.CanRotate(Identity, Selected.Source)) { %>
<section class="current-card rotate-card"><h3>Change the password soon</h3>
<p><%= Selected.Source == "ad" ? "Used the password? Set its expiry to now: the computer creates a new password at its next LAPS cycle. Until then the current password keeps working." : "Used the password? Ask Intune to rotate it: the device sets a new password at its next check-in and backs it up to Entra ID." %></p>
<form method="post" action="<%= E(Url(Selected, "password")) %>" data-ajax><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button secondary" type="submit" name="action" value="expire" data-busy="Requesting…"><%= Selected.Source == "ad" ? "Expire password now" : "Rotate password now (Intune)" %></button><p class="ajax-result <%= RotateMessage == null ? "" : "notice success" %>" <%= RotateMessage == null ? "hidden" : "" %> aria-live="polite"><%= E(RotateMessage) %></p></form></section>
<% } %><% } %>
<% } %>
<% } %>
</div><footer class="drawer-footer">Read-only directory lookup · Access is audited</footer></aside>
<% } %>
</div><%= PortalLayout.Scripts %></body></html>
