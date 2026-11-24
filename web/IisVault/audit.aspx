<%@ Page Language="C#" EnableViewState="false" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Linq" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="StandaloneLapsWeb" %>
<script runat="server">
// Audit log viewer (administrators): App_Data\Vault\audit.jsonl, newest first, filter, paging and CSV export.
protected PortalIdentity Identity;
protected bool EntraMode, More;
protected string Query, Category, From, To;
protected int PageNumber;
protected List<AuditEntry> Entries = new List<AuditEntry>();
protected Dictionary<string, string> Names = new Dictionary<string, string>();
protected string E(object value) { return Server.HtmlEncode(Convert.ToString(value)); }
protected string Link(int page, string format)
{
    var parts = new List<string>();
    if (!string.IsNullOrEmpty(Query)) parts.Add("q=" + Server.UrlEncode(Query));
    if (!string.IsNullOrEmpty(Category)) parts.Add("category=" + Server.UrlEncode(Category));
    if (!string.IsNullOrEmpty(From)) parts.Add("from=" + Server.UrlEncode(From));
    if (!string.IsNullOrEmpty(To)) parts.Add("to=" + Server.UrlEncode(To));
    if (page > 1) parts.Add("page=" + page);
    if (format != null) parts.Add("format=" + format);
    return "audit.aspx" + (parts.Count == 0 ? "" : "?" + string.Join("&", parts));
}
protected string ActorName(string actor) { string name; return actor != null && Names.TryGetValue(actor, out name) ? name : null; }
protected void Page_Load(object sender, EventArgs e)
{
    Identity = PortalAuth.Require(Context);
    if (!Identity.IsAdmin) throw new HttpException(403, "Administrator access required.");
    EntraMode = PortalAuth.Mode == "Entra";
    Query = (Request.QueryString["q"] ?? "").Trim();
    if (Query.Length > 128) Query = Query.Substring(0, 128);
    Category = AuditFormat.NormalizeCategory(Request.QueryString["category"]);
    var from = AuditFormat.ParseDay(Request.QueryString["from"], false);
    var to = AuditFormat.ParseDay(Request.QueryString["to"], true);
    From = from.HasValue ? Request.QueryString["from"].Trim() : "";
    To = to.HasValue ? Request.QueryString["to"].Trim() : "";
    int page;
    PageNumber = int.TryParse(Request.QueryString["page"], out page) && page > 1 && page <= 10000 ? page : 1;
    var filter = new AuditFilter { Text = Query, Category = Category, FromUtc = from, ToUtc = to };
    if (Request.QueryString["format"] == "csv")
    {
        bool truncated;
        var all = Vault.ReadAudit(filter, 0, AuditFormat.ExportLimit, out truncated, out Names);
        Vault.AuditTarget(Identity.Actor, "audit-exported", all.Count + " entries" + (Query.Length > 0 || Category.Length > 0 || From.Length > 0 || To.Length > 0 ? ", filtered" : ""));
        Response.Clear();
        Response.ContentType = "text/csv";
        Response.ContentEncoding = new UTF8Encoding(true);
        Response.AddHeader("Content-Disposition", "attachment; filename=\"slaps-audit-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm") + ".csv\"");
        Response.Write(AuditFormat.Csv(all, Names));
        Response.End();
        return;
    }
    Entries = Vault.ReadAudit(filter, (PageNumber - 1) * AuditFormat.PageSize, AuditFormat.PageSize, out More, out Names);
}
</script>
<!doctype html>
<html lang="en"><head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>Audit log · PriCoSoft SLAPS</title><%= PortalLayout.HeadLinks %></head>
<body>
<%= PortalLayout.TopBar(Identity, EntraMode) %>
<div class="shell">
<%= PortalLayout.Navigation("audit", Identity.IsAdmin) %>
<main class="content">
<div class="breadcrumbs">SLAPS <span>/</span> Audit log</div>
<div class="page-heading"><div><p class="eyebrow">ADMINISTRATION · READ-ONLY</p><h1>Audit log</h1><p class="subtitle">Who revealed which password, signed in, changed settings or managed devices. Newest first; times in UTC.</p></div><span class="role-label">Manage access</span></div>
<div class="list-card">
<form class="search-panel" method="get">
<div class="filter-row">
<label class="filter-field grow"><span class="field-label">Search</span><span class="search-box wide"><span aria-hidden="true">&#8981;</span><input type="search" name="q" value="<%= E(Query) %>" placeholder="User, device, computer, action…" maxlength="128" /></span></label>
<label class="filter-field"><span class="field-label">Events</span><select class="select-input" name="category"><% foreach (var option in AuditFormat.Categories) { %><option value="<%= E(option.Key) %>"<%= option.Key == Category ? " selected" : "" %>><%= E(option.Value) %></option><% } %></select></label>
<label class="filter-field"><span class="field-label">From</span><input class="text-input date-input" type="date" name="from" value="<%= E(From) %>" /></label>
<label class="filter-field"><span class="field-label">To</span><input class="text-input date-input" type="date" name="to" value="<%= E(To) %>" /></label>
<div class="filter-actions"><button class="button" type="submit">Filter</button><a class="text-link" href="audit.aspx">Clear</a></div>
</div>
<p class="search-hint">Text matches user names, IDs, devices, computers and actions. Export downloads up to <%= AuditFormat.ExportLimit %> matching entries as CSV; exports are audited.</p>
</form>
<% if (Entries.Count == 0) { %><div class="empty-state compact"><span class="empty-icon">&#9783;</span><h2>No audit entries</h2><p><%= Query.Length > 0 || Category.Length > 0 || From.Length > 0 || To.Length > 0 ? "Nothing matches this filter." : "Nothing has been recorded yet." %></p></div>
<% } else { %>
<div class="table-scroll"><table class="device-table audit-table sortable" data-table-key="audit"><thead><tr><th data-sort="text">Time (UTC)</th><th data-sort="text">User / client</th><th data-sort="text">Event</th><th data-sort="text">Target</th></tr></thead><tbody>
<% foreach (var entry in Entries) { var name = ActorName(entry.Actor); var failure = AuditFormat.IsFailure(entry.Action); %><tr>
<td class="date-cell" data-sort-value="<%= E(entry.Utc.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss")) %>"><%= E(entry.Utc.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss")) %></td>
<td><% if (name != null) { %><strong class="audit-name"><%= E(name) %></strong><% } %><small class="audit-sub mono"><%= E(entry.Actor) %></small></td>
<td><span class="audit-event<%= failure ? " failed" : "" %>"><%= E(AuditFormat.Label(entry.Action)) %></span><small class="audit-sub"><%= E(AuditFormat.CategoryLabel(entry.Action)) %> · <code><%= E(entry.Action) %></code></small></td>
<td><% if (entry.DeviceId != null) { %><a href="Default.aspx?device=<%= E(entry.DeviceId) %>"><%= E(entry.DeviceName ?? entry.DeviceId) %></a><% } %><% if (!string.IsNullOrEmpty(entry.Target)) { %><span class="audit-target"><%= E(entry.Target) %></span><% } %><% if (entry.RotationId != null) { %><small class="audit-sub mono">Version <%= E(entry.RotationId) %></small><% } %><% if (entry.DeviceId == null && string.IsNullOrEmpty(entry.Target)) { %><span class="muted">—</span><% } %></td>
</tr><% } %>
</tbody></table></div>
<% } %>
<div class="list-footer"><span>Page <%= PageNumber %> · <%= Entries.Count %> <%= Entries.Count == 1 ? "entry" : "entries" %> on this page</span><span class="pager"><% if (PageNumber > 1) { %><a href="<%= E(Link(PageNumber - 1, null)) %>">‹ Newer</a><% } %><% if (More) { %><a href="<%= E(Link(PageNumber + 1, null)) %>">Older ›</a><% } %><a href="<%= E(Link(1, "csv")) %>">Export CSV</a></span></div>
</div>
<p class="helper">Stored in <code>App_Data\Vault\audit.jsonl</code> (ordinary protected storage, not tamper-evident). Copying a password to the clipboard is not audited, revealing it is.</p>
<p class="identity">Signed in as <%= E(Identity.DisplayName) %> · <%= E(Identity.Actor) %></p>
</main>
</div><%= PortalLayout.Scripts %></body></html>
