using System.Security.Cryptography;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Mvc;

namespace StandaloneLaps.Server.Pages;

public sealed class IndexModel : PortalPage
{
    private readonly KeyVault keys;

    public IndexModel(VaultStore store, ServerOptions options, KeyVault keys) : base(store, options)
    {
        this.keys = keys;
    }

    public override string Active => ShowDeleted ? "deleted" : "devices";
    public Guid Device, Rotation;
    public bool ShowDeleted, ConfirmDelete;
    public string Query = "", Tab = "password", Secret, Account, Message;
    public DeviceSummary[] Devices = Array.Empty<DeviceSummary>();
    public DeviceSummary Selected;
    public HistoryEntry[] Entries = Array.Empty<HistoryEntry>();
    public HistoryEntry Latest, LastApplied;
    public StoredRecord SelectedRecord;

    // Revealed credential with copy buttons, or nothing when this version was not revealed in this request.
    public IHtmlContent Revealed(Guid rotation) => Secret == null || rotation != Rotation ? HtmlString.Empty
        : CredentialHtml.Render("slaps-" + rotation.ToString("N")[..8], null, Account, Secret, new[] { "Version " + rotation.ToString("D"), "Close this page after use · copying is not audited, revealing is" });

    public static string Status(DeviceSummary value) => value.Deleted ? "Deleted" : value.Versions == 0 ? "Awaiting backup" : value.Unconfirmed ? "Unconfirmed" : "Reported applied";

    public string DeviceUrl(Guid device, string tab, Guid rotation, bool confirm)
    {
        var url = "./?q=" + Uri.EscapeDataString(Query ?? "");
        if (ShowDeleted) url += "&view=deleted";
        if (device != Guid.Empty) url += "&device=" + device.ToString("D") + "&tab=" + tab;
        if (rotation != Guid.Empty) url += "&rotation=" + rotation.ToString("D");
        if (confirm) url += "&confirm=delete";
        return url;
    }

    private IActionResult Load()
    {
        var identity = Identity;
        ShowDeleted = Request.Query["view"] == "deleted";
        if (ShowDeleted && !identity.IsAdmin) return Forbid();
        Query = Request.Query["q"].ToString().Trim();
        if (Query.Length > 200) Query = Query[..200];
        // "overview" is the pre-1.6 name of the first tab; old links keep working.
        Tab = Request.Query["tab"] == "history" ? "history" : Request.Query["tab"] == "details" ? "details" : "password";
        ConfirmDelete = Request.Query["confirm"] == "delete" && identity.IsAdmin && !ShowDeleted;
        Guid.TryParseExact(Request.Query["device"], "D", out Device);
        Guid.TryParseExact(Request.Query["rotation"], "D", out Rotation);
        var all = Store.Devices(ShowDeleted, "");
        Devices = Store.Devices(ShowDeleted, Query);
        Selected = all.FirstOrDefault(d => d.DeviceId == Device.ToString("D"));
        if (Device != Guid.Empty && Selected == null) return NotFound();
        return null;
    }

    private void LoadHistory()
    {
        if (Selected == null || ShowDeleted) return;
        Store.Audit(Identity.Actor, "portal-history", Device, Guid.Empty);
        Entries = Store.History(Device, 0, Limit);
        Latest = Entries.FirstOrDefault();
        LastApplied = Entries.FirstOrDefault(e => e.appliedReportedUtc != null);
        if (Rotation != Guid.Empty) SelectedRecord = Store.Get(Device, Rotation);
    }

    public IActionResult OnGet()
    {
        var result = Load();
        if (result != null) return result;
        LoadHistory();
        return Page();
    }

    public IActionResult OnPost(string action, string confirmName, string confirmRestore)
    {
        var result = Load();
        if (result != null) return result;
        if (Selected == null) return BadRequest("Select a device.");
        var identity = Identity;
        if (action is "delete" or "restore")
        {
            if (!identity.IsAdmin) return Forbid();
            if (action == "delete")
            {
                if (ShowDeleted || !string.Equals(confirmName, Selected.Name, StringComparison.Ordinal)) return BadRequest("Enter the exact device name to confirm deletion.");
                Store.SetDeleted(Device, true, identity.Actor);
            }
            else
            {
                if (!ShowDeleted || confirmRestore != "yes") return BadRequest("Confirm restoring agent access.");
                try { Store.SetDeleted(Device, false, identity.Actor); }
                catch (InvalidOperationException ex) { return BadRequest(ex.Message); }
            }
            return Redirect(DeviceUrl(Guid.Empty, "password", Guid.Empty, false));
        }
        if (action != "reveal" || ShowDeleted || Rotation == Guid.Empty) return BadRequest("Select a password version.");
        LoadHistory();
        if (SelectedRecord == null) return NotFound();
        if (!Options.EnableWebDecryption) Message = "Web decryption is disabled. Download the encrypted envelope and use offline recovery.";
        else
        {
            Store.Audit(identity.Actor, "password-reveal-attempt", Device, Rotation);
            try
            {
                var payload = keys.Reveal(SelectedRecord.Envelope);
                Secret = payload.password;
                Account = payload.computerName + "\\" + payload.accountName;
                Store.Audit(identity.Actor, "password-revealed", Device, Rotation);
            }
            catch (CryptographicException ex) { Message = "The password could not be decrypted: " + ex.Message; }
        }
        return Page();
    }
}
