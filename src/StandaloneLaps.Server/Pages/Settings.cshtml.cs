using Microsoft.AspNetCore.Mvc;

namespace StandaloneLaps.Server.Pages;

public sealed class SettingsModel : PortalPage
{
    private readonly KeyVault keys;
    private readonly ClientPackages packages;

    public SettingsModel(VaultStore store, ServerOptions options, KeyVault keys, ClientPackages packages) : base(store, options)
    {
        this.keys = keys;
        this.packages = packages;
    }

    public override string Active => "settings";
    public string ErrorText, SavedText;
    public int FieldValue;
    public PortalSettings Current;
    public CertificateInfo[] Certificates = Array.Empty<CertificateInfo>();
    public string AgentVersion => packages.AgentVersion;

    private void Load(string entered)
    {
        Current = Store.Settings();
        FieldValue = ErrorText != null && int.TryParse(entered, out var value) ? value : Current.HistoryLimit;
        Certificates = keys.Describe();
    }

    public void OnGet() => Load(null);

    public IActionResult OnPost(string action, string historyLimit, string confirmTrim)
    {
        if (!Identity.IsAdmin) return Forbid();
        if (action != "history-limit") return BadRequest("Unsupported request.");
        var previous = Store.HistoryLimit;
        if (!int.TryParse(historyLimit, out var requested) || requested < ServerOptions.MinHistoryLimit || requested > ServerOptions.MaxHistoryLimit)
            ErrorText = $"Enter a number between {ServerOptions.MinHistoryLimit} and {ServerOptions.MaxHistoryLimit}.";
        else if (requested < previous && confirmTrim != "yes")
            ErrorText = "Lowering the limit permanently deletes older password versions. Confirm the checkbox to continue.";
        else
        {
            Store.SetHistoryLimit(requested, Identity.Actor);
            SavedText = requested == previous ? "No change." : $"History limit changed from {previous} to {requested} versions per device.";
        }
        Load(historyLimit);
        return Page();
    }
}
