using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;
using StandaloneLapsWeb;

namespace StandaloneLaps.Server.Pages;

// Read-only lookup of Windows LAPS / legacy LAPS passwords in Active Directory and Microsoft Entra ID.
public sealed class WindowsLapsModel : PortalPage
{
    private readonly WindowsLapsService laps;

    public WindowsLapsModel(VaultStore store, ServerOptions options, WindowsLapsService laps) : base(store, options)
    {
        this.laps = laps;
    }

    public override string Active => "windowslaps";
    public WindowsLapsOptions Laps => Options.WindowsLaps;
    public string Query = "", Source, Tab = "password";
    public Guid Id;
    public bool Searched;
    public List<WindowsLapsComputer> Results = new();
    public List<string> Errors = new();
    public WindowsLapsComputer Selected;
    public WindowsLapsResult Revealed;

    public static string SourceName(string source) => source == "entra" ? "Microsoft Entra ID" : "Active Directory";

    // Which passwords a search hit has (AD: derived from the expiry attributes, which carry no secret).
    public static IHtmlContent Kinds(WindowsLapsComputer computer)
    {
        if (computer.Source == "entra") return new HtmlString("<span class=\"kind-badge entra\">Windows LAPS</span>");
        var html = (computer.ExpiresUtc.HasValue ? "<span class=\"kind-badge\">Windows LAPS</span>" : "") + (computer.LegacyExpiresUtc.HasValue ? "<span class=\"kind-badge legacy\">Legacy LAPS</span>" : "");
        return new HtmlString(html.Length == 0 ? "<span class=\"kind-badge\">Stored</span>" : html);
    }

    public static string Sort(DateTime? value) => value?.ToString("o") ?? "";

    public bool Mixed => Revealed != null && Revealed.Credentials.Any(c => c.Source == "ad-legacy" && c.IsCurrent) && Revealed.Credentials.Any(c => c.Source == "ad" && c.IsCurrent);

    public string Url(WindowsLapsComputer computer, string tab)
    {
        var url = "windowslaps?q=" + Uri.EscapeDataString(Query ?? "");
        if (computer != null) url += "&source=" + computer.Source + "&id=" + Uri.EscapeDataString(computer.Id) + "&tab=" + tab;
        return url;
    }

    public IEnumerable<WindowsLapsCredential> Shown() =>
        Revealed == null ? Array.Empty<WindowsLapsCredential>() : Revealed.Credentials.Where(c => Tab == "history" ? c.IsHistory : !c.IsHistory);

    public IHtmlContent Card(WindowsLapsCredential credential, int index)
    {
        var meta = new List<string> { WindowsLapsFormat.SourceLabel(credential.Source) + (credential.Encrypted ? " · encrypted in AD" : "") };
        if (credential.UpdatedUtc.HasValue) meta.Add("Set " + CredentialHtml.Utc(credential.UpdatedUtc));
        if (credential.ExpiresUtc.HasValue) meta.Add((credential.Source == "entra" ? "Next rotation " : "Expires ") + CredentialHtml.Utc(credential.ExpiresUtc));
        if (credential.Source == "ad-legacy") meta.Add("Account: as set in the legacy LAPS policy (default: built-in Administrator)");
        if (credential.Error != null)
        {
            var e = System.Text.Encodings.Web.HtmlEncoder.Default;
            return new HtmlString("<div class=\"credential error\"><strong>" + e.Encode(WindowsLapsFormat.Title(credential)) + "</strong> could not be read: " + e.Encode(credential.Error) +
                "<div class=\"credential-meta\">" + string.Concat(meta.Select(m => "<span>" + e.Encode(m) + "</span>")) + "</div></div>");
        }
        var account = credential.Account;
        if (credential.Source != "ad-legacy" && !string.IsNullOrEmpty(account) && !account.Contains('\\') && !string.IsNullOrEmpty(Selected?.Name)) account = Selected.Name + "\\" + account;
        return CredentialHtml.Render("laps-" + index, WindowsLapsFormat.Title(credential), account, credential.Password, meta);
    }

    private async Task<IActionResult> Load(bool reveal)
    {
        if (!Laps.Enabled) return NotFound();
        var identity = Identity;
        if (!Laps.Allowed(identity)) return Forbid();
        Query = Request.Query["q"].ToString().Trim();
        if (Query.Length > 128) Query = Query[..128];
        Source = Request.Query["source"] == "entra" && Laps.EntraEnabled ? "entra" : Request.Query["source"] == "ad" && Laps.AdEnabled ? "ad" : null;
        Tab = Request.Query["tab"] == "history" ? "history" : Request.Query["tab"] == "details" ? "details" : "password";
        Guid.TryParseExact(Request.Query["id"], "D", out Id);

        if (Query.Length > 0)
        {
            Searched = true;
            if (!WindowsLapsFormat.ValidQuery(Query)) Errors.Add("Enter a computer name, DNS name or Entra device ID. Letters, digits, '-', '.', '_' are allowed; '*' only at the end (at least two characters before it).");
            else
            {
                Store.Audit(identity.Actor, "windows-laps-search:" + Query, Guid.Empty, Guid.Empty);
                if (Laps.AdEnabled)
                    try { Results.AddRange(await Task.Run(() => laps.SearchAd(Query))); }
                    catch (WindowsLapsException ex) { Errors.Add("Active Directory: " + ex.Message); }
                if (Laps.EntraEnabled)
                    try { Results.AddRange(await laps.SearchEntra(Query)); }
                    catch (WindowsLapsException ex) { Errors.Add("Microsoft Entra ID: " + ex.Message); }
            }
        }

        if (Source != null && Id != Guid.Empty)
        {
            try
            {
                if (reveal) Store.Audit(identity.Actor, "windows-laps-reveal-" + Source + ":" + Id.ToString("D"), Guid.Empty, Guid.Empty);
                if (Source == "ad") (Selected, Revealed) = await Task.Run(() => laps.ReadAd(Id, reveal));
                else if (reveal) (Selected, Revealed) = await laps.ReadEntra(Id);
                else Selected = await laps.FindEntra(Id);
                if (Selected == null) { Errors.Add("The selected computer was not found."); Revealed = null; }
                else if (reveal) Store.Audit(identity.Actor, "windows-laps-revealed-" + Source + ":" + Id.ToString("D") + " " + Selected.Name, Guid.Empty, Guid.Empty);
            }
            catch (WindowsLapsException ex) { Errors.Add(SourceName(Source) + ": " + ex.Message); }
        }
        return Page();
    }

    public Task<IActionResult> OnGet() => Load(false);

    public Task<IActionResult> OnPost(string action) => action == "reveal" ? Load(true) : Task.FromResult<IActionResult>(BadRequest());
}
