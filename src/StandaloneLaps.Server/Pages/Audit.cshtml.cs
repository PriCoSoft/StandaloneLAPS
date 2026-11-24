using System.Globalization;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using StandaloneLapsWeb;

namespace StandaloneLaps.Server.Pages;

// Audit log viewer (administrators, see Program.cs): table slaps_audit, newest first, filter, paging and CSV export.
public sealed class AuditModel : PortalPage
{
    public AuditModel(VaultStore store, ServerOptions options) : base(store, options) { }

    public override string Active => "audit";
    public string Query = "", Category = "", From = "", To = "";
    public int PageNumber = 1;
    public bool More;
    public List<AuditEntry> Entries = new();
    public Dictionary<string, string> Names = new();

    public bool Filtered => Query.Length > 0 || Category.Length > 0 || From.Length > 0 || To.Length > 0;

    public string ActorName(string actor) => actor != null && Names.TryGetValue(actor, out var name) ? name : null;

    public string Link(int page, string format)
    {
        var parts = new List<string>();
        if (Query.Length > 0) parts.Add("q=" + Uri.EscapeDataString(Query));
        if (Category.Length > 0) parts.Add("category=" + Uri.EscapeDataString(Category));
        if (From.Length > 0) parts.Add("from=" + From);
        if (To.Length > 0) parts.Add("to=" + To);
        if (page > 1) parts.Add("page=" + page.ToString(CultureInfo.InvariantCulture));
        if (format != null) parts.Add("format=" + format);
        return "audit" + (parts.Count == 0 ? "" : "?" + string.Join("&", parts));
    }

    public IActionResult OnGet(string q, string category, string from, string to, string page, string format)
    {
        Query = (q ?? "").Trim();
        if (Query.Length > 128) Query = Query[..128];
        Category = AuditFormat.NormalizeCategory(category);
        var fromUtc = AuditFormat.ParseDay(from, false);
        var toUtc = AuditFormat.ParseDay(to, true);
        From = fromUtc.HasValue ? from.Trim() : "";
        To = toUtc.HasValue ? to.Trim() : "";
        PageNumber = int.TryParse(page, NumberStyles.None, CultureInfo.InvariantCulture, out var number) && number > 1 && number <= 10000 ? number : 1;
        var filter = new AuditFilter { Text = Query, Category = Category, FromUtc = fromUtc, ToUtc = toUtc };
        if (format == "csv")
        {
            var all = Store.AuditEntries(filter, 0, AuditFormat.ExportLimit, out _, out Names);
            Store.Audit(Identity.Actor, "audit-exported:" + all.Count + " entries" + (Filtered ? ", filtered" : ""), Guid.Empty, Guid.Empty);
            var bytes = Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(AuditFormat.Csv(all, Names))).ToArray();
            return File(bytes, "text/csv", "slaps-audit-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmm", CultureInfo.InvariantCulture) + ".csv");
        }
        Entries = Store.AuditEntries(filter, (PageNumber - 1) * AuditFormat.PageSize, AuditFormat.PageSize, out More, out Names);
        return Page();
    }
}
