<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Linq" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
protected Guid Device, Rotation;
protected bool IsAdmin, ShowDeleted, ConfirmDelete, EntraMode, WebDecryption;
protected string Actor, ActorName, Secret, Account, Message, Csrf, Query, Tab;
protected DeviceSummary[] Devices = new DeviceSummary[0];
protected DeviceSummary Selected;
protected PortalIdentity Identity;
protected int Limit;
protected HistoryEntry[] Entries = new HistoryEntry[0];
protected HistoryEntry Latest, LastApplied;
protected StoredRecord SelectedRecord;
protected string E(object value) { return Server.HtmlEncode(Convert.ToString(value)); }
protected string DateLabel(string value) { return string.IsNullOrEmpty(value) ? "—" : Vault.Timestamp(value).UtcDateTime.ToString("dd MMM yyyy, HH:mm", System.Globalization.CultureInfo.GetCultureInfo("en-US")); }
protected string Status(DeviceSummary value) { return value.Deleted ? "Deleted" : value.Versions == 0 ? "Awaiting backup" : value.Unconfirmed ? "Unconfirmed" : "Reported applied"; }
protected string Url(Guid device, string tab, Guid rotation, bool confirm)
{
    var url = "?q=" + Server.UrlEncode(Query ?? "");
    if (ShowDeleted) url += "&view=deleted";
    if (device != Guid.Empty) url += "&device=" + device.ToString("D") + "&tab=" + tab;
    if (rotation != Guid.Empty) url += "&rotation=" + rotation.ToString("D");
    if (confirm) url += "&confirm=delete";
    return url;
}
// Revealed credential with copy buttons, or nothing when this version was not revealed in this request.
protected string Revealed(Guid rotation)
{
    if (Secret == null || rotation != Rotation) return "";
    return PortalLayout.Credential("slaps-" + rotation.ToString("N").Substring(0, 8), null, null, Account, Secret,
        "<span>Version " + E(rotation) + "</span><span>Close this page after use · copying is not audited, revealing is</span>");
}
protected void Page_Load(object sender, EventArgs e)
{
    var identity = Identity = PortalAuth.Require(Context);
    Limit = Vault.HistoryLimit;
    Actor = identity.Actor; ActorName = identity.DisplayName; IsAdmin = identity.IsAdmin;
    EntraMode = PortalAuth.Mode == "Entra";
    WebDecryption = string.Equals(Vault.Setting("EnableWebDecryption"), "true", StringComparison.OrdinalIgnoreCase);
    ShowDeleted = Request.QueryString["view"] == "deleted";
    if (ShowDeleted && !IsAdmin) throw new HttpException(403, "Administrator access required.");
    Query = (Request.QueryString["q"] ?? "").Trim(); if (Query.Length > 200) Query = Query.Substring(0, 200);
    // "overview" is the pre-1.6 name of the first tab; old links keep working.
    var tab = Request.QueryString["tab"];
    Tab = tab == "history" ? "history" : tab == "details" ? "details" : "password";
    ConfirmDelete = Request.QueryString["confirm"] == "delete" && IsAdmin && !ShowDeleted;
    if (Session["csrf"] == null) { var bytes = new byte[32]; using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(bytes); Session["csrf"] = Convert.ToBase64String(bytes); }
    Csrf = (string)Session["csrf"];
    Guid.TryParseExact(Request.QueryString["device"], "D", out Device);
    Guid.TryParseExact(Request.QueryString["rotation"], "D", out Rotation);
    var all = Vault.Devices(ShowDeleted, "");
    Devices = Vault.FilterDevices(all, ShowDeleted, Query);
    Selected = all.FirstOrDefault(item => item.DeviceId == Device.ToString("D"));
    if (Device != Guid.Empty && Selected == null) throw new HttpException(404, "Device not found.");
    if (Request.HttpMethod == "POST")
    {
        if (Request.Form["csrf"] != Csrf) throw new HttpException(403, "Invalid request token.");
        if (Selected == null) throw new HttpException(400, "Select a device.");
        var action = Request.Form["action"];
        if (action == "delete" || action == "restore")
        {
            if (!IsAdmin) throw new HttpException(403, "Administrator access required.");
            if (action == "delete")
            {
                if (ShowDeleted || !string.Equals(Request.Form["confirmName"], Selected.Name, StringComparison.Ordinal)) throw new HttpException(400, "Enter the exact device name to confirm deletion.");
                Vault.ArchiveDevice(Device, Actor);
            }
            else
            {
                if (!ShowDeleted || Request.Form["confirmRestore"] != "yes") throw new HttpException(400, "Confirm restoring agent access.");
                Vault.RestoreDevice(Device, Actor);
            }
            Response.Redirect(Url(Guid.Empty, "password", Guid.Empty, false), false);
            Response.SuppressContent = true; Context.ApplicationInstance.CompleteRequest(); return;
        }
        if (action != "reveal" || ShowDeleted || Rotation == Guid.Empty) throw new HttpException(400, "Select a password version.");
        SelectedRecord = Vault.Get(Device, Rotation);
        if (SelectedRecord == null) throw new HttpException(404, "Version not found.");
        if (!WebDecryption) Message = "Web decryption is disabled. Download the encrypted envelope and use offline recovery.";
        else
        {
            Vault.Audit(Actor, "password-reveal-attempt", Device, Rotation);
            var payload = Vault.Reveal(SelectedRecord.envelope);
            Secret = payload.password; Account = payload.computerName + "\\" + payload.accountName;
        }
    }
    if (Selected != null && !ShowDeleted)
    {
        Vault.Audit(Actor, "portal-history", Device, Guid.Empty);
        Entries = Vault.History(Device, 0, Limit);
        Latest = Entries.FirstOrDefault();
        LastApplied = Entries.FirstOrDefault(entry => entry.appliedReportedUtc != null);
        if (Rotation != Guid.Empty && SelectedRecord == null) SelectedRecord = Vault.Get(Device, Rotation);
    }
}
</script>
<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Devices · PriCoSoft SLAPS</title><%= PortalLayout.HeadLinks %></head>
<body>
<%= PortalLayout.TopBar(Identity, EntraMode) %>
<div class="shell">
<%= PortalLayout.Navigation(ShowDeleted ? "deleted" : "devices", IsAdmin) %>
<main class="content <%= Selected != null ? "with-drawer" : "" %>">
<div class="breadcrumbs">SLAPS <span>/</span> <%= ShowDeleted ? "Deleted devices" : "Devices" %></div>
<div class="page-heading"><div><p class="eyebrow">ADMINISTRATOR RECOVERY</p><h1><%= ShowDeleted ? "Deleted devices" : "Devices" %><span class="count"><%= Devices.Length %></span></h1><p class="subtitle"><%= ShowDeleted ? "Restore an archived device and its configured agent access." : "Select a device to see its current local administrator password." %></p></div><% if (IsAdmin && !ShowDeleted) { %><a class="button" href="addclient.aspx">Add client</a><% } else { %><span class="role-label"><%= IsAdmin ? "Manage access" : "Read access" %></span><% } %></div>
<div class="list-card">
<form class="search-toolbar" method="get"><% if (ShowDeleted) { %><input type="hidden" name="view" value="deleted" /><% } %><label class="search-box"><span aria-hidden="true">⌕</span><input type="search" name="q" value="<%= E(Query) %>" placeholder="Search by device name or ID" aria-label="Search devices" maxlength="200" /></label><button class="button secondary" type="submit">Search</button><% if (!string.IsNullOrEmpty(Query)) { %><a class="text-link" href="<%= ShowDeleted ? "?view=deleted" : "?" %>">Clear</a><% } %><span class="results"><%= Devices.Length %> <%= Devices.Length == 1 ? "device" : "devices" %></span></form>
<div class="table-scroll"><table class="device-table sortable" data-table-key="devices"><thead><tr><th data-sort="text">Device name</th><th data-sort="text">Last backup (UTC)</th><th data-sort="text">Status</th><th class="number" data-sort="number">Versions</th><th class="no-sort"><span class="sr-only">Details</span></th></tr></thead><tbody>
<% foreach (var device in Devices) { %><tr class="<%= Selected != null && Selected.DeviceId == device.DeviceId ? "selected-row" : "" %>"><td><a class="device-link" href="<%= E(Url(Guid.Parse(device.DeviceId), "password", Guid.Empty, false)) %>"><span class="device-icon" aria-hidden="true"></span><span><strong><%= E(device.Name) %></strong><small><%= E(device.DeviceId) %></small></span></a></td><td class="date-cell" data-sort-value="<%= E(device.LastBackupUtc ?? "") %>"><%= E(DateLabel(device.LastBackupUtc)) %></td><td><span class="badge <%= device.Deleted ? "neutral" : device.Unconfirmed ? "warning" : device.Versions == 0 ? "neutral" : "success" %>"><span></span><%= E(Status(device)) %></span></td><td class="number" data-sort-value="<%= device.Versions %>"><%= device.Versions %><span class="muted"> / <%= Limit %></span></td><td><a class="row-open" aria-label="<%= E("Open " + device.Name) %>" href="<%= E(Url(Guid.Parse(device.DeviceId), "password", Guid.Empty, false)) %>">›</a></td></tr><% } %>
</tbody></table></div>
<% if (Devices.Length == 0) { %><div class="empty-state"><span class="empty-icon">⌕</span><h2><%= string.IsNullOrEmpty(Query) ? "No devices here yet" : "No matching devices" %></h2><p><%= string.IsNullOrEmpty(Query) ? "Configured agents will appear here. Deleted devices can be restored by an administrator." : "Try a different device name or part of its ID." %></p></div><% } %>
<div class="list-footer"><span><%= string.IsNullOrEmpty(Query) ? "All configured devices" : "Filtered results" %></span><span>History is limited to <%= Limit %> versions</span></div></div>
<p class="identity">Signed in as <%= E(ActorName) %> · <%= E(Actor) %></p>
</main>
<% if (Selected != null) { %>
<a class="drawer-backdrop" href="<%= E(Url(Guid.Empty, "password", Guid.Empty, false)) %>" aria-label="Close device details"></a>
<aside class="drawer" aria-labelledby="device-title"><div class="drawer-top"><div class="drawer-breadcrumb">Devices <span>/</span> <%= E(Selected.Name) %></div><a class="close-button" href="<%= E(Url(Guid.Empty, "password", Guid.Empty, false)) %>" aria-label="Close device details">×</a></div>
<div class="drawer-heading"><span class="device-icon large" aria-hidden="true"></span><div><h2 id="device-title"><%= E(Selected.Name) %></h2><p>Standalone Windows device</p></div></div>
<div class="drawer-actions"><% if (IsAdmin && !ShowDeleted) { %><span class="drawer-links"><% if (Selected.Managed) { %><a href="addclient.aspx?device=<%= E(Device) %>">New certificate package</a><% } %><a class="delete-link" href="<%= E(Url(Device, "details", Guid.Empty, true)) %>">Delete device</a></span><% } %><span class="badge <%= ShowDeleted ? "neutral" : Selected.Unconfirmed ? "warning" : Selected.Versions == 0 ? "neutral" : "success" %>"><span></span><%= E(Status(Selected)) %></span></div>
<% if (!ShowDeleted) { %><nav class="tabs" aria-label="Device sections"><a class="<%= Tab == "password" ? "active" : "" %>" href="<%= E(Url(Device, "password", Guid.Empty, false)) %>" <%= Tab == "password" ? "aria-current=\"page\"" : "" %>>Password</a><a class="<%= Tab == "history" ? "active" : "" %>" href="<%= E(Url(Device, "history", Guid.Empty, false)) %>" <%= Tab == "history" ? "aria-current=\"page\"" : "" %>>History <span><%= Entries.Length %></span></a><a class="<%= Tab == "details" ? "active" : "" %>" href="<%= E(Url(Device, "details", Guid.Empty, false)) %>" <%= Tab == "details" ? "aria-current=\"page\"" : "" %>>Details</a></nav><% } %>
<div class="drawer-body">
<% if (ConfirmDelete) { %><section class="notice danger"><h3>Delete this device?</h3><p>The device will disappear from the active list and its agent will be blocked. Encrypted history is archived and can be restored by an administrator.</p><form method="post"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><label class="field-label" for="confirmName">Type <strong><%= E(Selected.Name) %></strong> to confirm</label><input class="text-input" id="confirmName" name="confirmName" autocomplete="off" required /><div class="form-actions"><button class="button destructive" type="submit" name="action" value="delete">Delete device</button><a href="<%= E(Url(Device, "details", Guid.Empty, false)) %>">Cancel</a></div></form></section><% } %>
<% if (ShowDeleted) { %><section class="notice"><h3>This device is deleted</h3><p>Its encrypted records are archived. Restore it to view history and allow its configured agent certificates to upload again.</p><form method="post"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><label class="checkbox"><input type="checkbox" name="confirmRestore" value="yes" required />Restore this device and its configured agent access.</label><button class="button" type="submit" name="action" value="restore">Restore device</button></form></section>
<% } else if (Tab == "password") { %>
<% if (Latest == null) { %><div class="empty-panel"><h3>No password yet</h3><p>The first successful agent backup will appear here.</p></div>
<% } else { %>
<section class="current-card"><h3>Current local administrator password</h3>
<div class="meta"><span>Backed up <%= E(DateLabel(Latest.createdUtc)) %> UTC</span><span class="badge <%= Latest.appliedReportedUtc == null ? "warning" : "success" %>"><span></span><%= Latest.appliedReportedUtc == null ? "Not confirmed yet" : "Applied on the device" %></span></div>
<% if (Latest.appliedReportedUtc == null) { %><p>The agent has not confirmed this newest version yet (rotation in progress or interrupted). If it does not work, use the last confirmed password below.</p><% } %>
<% if (!WebDecryption) { %><p class="notice">Web decryption is disabled. Download the encrypted envelope and use offline recovery.</p><a class="button secondary" href="download.aspx?device=<%= E(Device) %>&amp;rotation=<%= E(Latest.rotationId) %>">Download encrypted envelope</a>
<% } else if (Secret == null || Rotation != Latest.rotationId) { %><form method="post" action="<%= E(Url(Device, "password", Latest.rotationId, false)) %>"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button large" name="action" value="reveal" type="submit">Show password</button></form>
<% } %>
<%= Revealed(Latest.rotationId) %>
</section>
<% if (Latest.appliedReportedUtc == null && LastApplied != null) { %>
<section class="current-card"><h3>Last confirmed password</h3><div class="meta"><span>Backed up <%= E(DateLabel(LastApplied.createdUtc)) %> UTC</span><span class="badge success"><span></span>Applied on the device</span></div>
<% if (WebDecryption && (Secret == null || Rotation != LastApplied.rotationId)) { %><form method="post" action="<%= E(Url(Device, "password", LastApplied.rotationId, false)) %>"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button secondary" name="action" value="reveal" type="submit">Show password</button></form><% } %>
<%= Revealed(LastApplied.rotationId) %>
</section>
<% } %>
<% if (!string.IsNullOrEmpty(Message)) { %><p class="notice"><%= E(Message) %></p><% } %>
<p class="helper">Older versions are in the <a href="<%= E(Url(Device, "history", Guid.Empty, false)) %>">History</a> tab. Every reveal is audited.</p>
<% } %>
<% } else if (Tab == "history") { %>
<div class="section-heading"><h3>Password history</h3><span class="muted"><%= Entries.Length %> / <%= Limit %> versions</span></div><p class="helper">Newest first. Select a version to reveal or download it. An unconfirmed candidate may already be active after an interrupted rotation.</p>
<div class="history-list"><% foreach (var entry in Entries) { %><a class="history-item <%= Rotation == entry.rotationId ? "chosen" : "" %>" href="<%= E(Url(Device, "history", entry.rotationId, false)) %>"><span class="history-marker <%= entry.appliedReportedUtc == null ? "pending" : "" %>"></span><span class="history-content"><strong><%= E(DateLabel(entry.createdUtc)) %> UTC</strong><% if (Latest != null && entry.rotationId == Latest.rotationId) { %><span class="badge neutral">Newest</span><% } %><span class="badge <%= entry.appliedReportedUtc == null ? "warning" : "success" %>"><%= entry.appliedReportedUtc == null ? "Unconfirmed" : "Reported applied" %></span><small><%= E(entry.rotationId) %></small></span><span class="history-chevron">›</span></a><% } %></div>
<% if (Entries.Length == 0) { %><div class="empty-panel"><h3>No password versions yet</h3><p>The first successful agent backup will appear here.</p></div><% } %>
<% if (SelectedRecord != null) { %><section class="recovery-card"><h3>Selected version</h3><p class="mono"><%= E(Rotation) %></p><dl><dt>Recovery certificate SHA-256</dt><dd class="mono fingerprint"><%= E(SelectedRecord.envelope.recipientSha256) %></dd></dl><div class="form-actions"><% if (WebDecryption && Secret == null) { %><form method="post" action="<%= E(Url(Device, "history", Rotation, false)) %>"><input type="hidden" name="csrf" value="<%= E(Csrf) %>" /><button class="button" name="action" value="reveal" type="submit">Show password</button></form><% } %><a class="button secondary" href="download.aspx?device=<%= E(Device) %>&amp;rotation=<%= E(Rotation) %>">Download encrypted envelope</a></div><% if (!string.IsNullOrEmpty(Message)) { %><p class="notice"><%= E(Message) %></p><% } %><%= Revealed(Rotation) %></section><% } %>
<% } else { %>
<section class="detail-section"><h3>Device information</h3><dl><dt>Device name</dt><dd><%= E(Selected.Name) %></dd><dt>Device ID</dt><dd class="mono"><%= E(Device) %></dd><dt>Last backup</dt><dd><%= E(DateLabel(Selected.LastBackupUtc)) %> <%= Selected.LastBackupUtc == null ? "" : "UTC" %></dd><dt>Last applied report</dt><dd><%= E(DateLabel(Selected.LastAppliedUtc)) %> <%= Selected.LastAppliedUtc == null ? "" : "UTC" %></dd><dt>Retained versions</dt><dd><%= Entries.Length %> of <%= Limit %></dd></dl></section>
<section class="detail-section"><h3>Protection</h3><dl><dt>Password encryption</dt><dd>AES-256-GCM</dd><dt>Recovery key protection</dt><dd>RSA-OAEP-SHA256</dd><dt>Agent certificate SHA-256</dt><dd class="mono fingerprint"><%= E(Selected.CertificateSha256) %></dd><dt>Storage</dt><dd>App_Data / Vault</dd></dl><p class="helper">The recovery private key is required to decrypt passwords. It is not stored with these records.</p></section>
<% } %>
</div><footer class="drawer-footer">Encrypted recovery · Access is audited</footer></aside>
<% } %>
</div><%= PortalLayout.Scripts %></body></html>
