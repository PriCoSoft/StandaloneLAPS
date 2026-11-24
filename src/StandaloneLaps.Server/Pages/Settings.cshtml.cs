using Microsoft.AspNetCore.Mvc;

namespace StandaloneLaps.Server.Pages;

public sealed class SettingsModel : PortalPage
{
    private readonly KeyVault keys;
    private readonly ClientPackages packages;

    private readonly WindowsLapsService laps;

    public SettingsModel(VaultStore store, ServerOptions options, KeyVault keys, ClientPackages packages, WindowsLapsService laps) : base(store, options)
    {
        this.keys = keys;
        this.packages = packages;
        this.laps = laps;
    }

    public string LapsTest, LapsTestError;

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

    public async Task<IActionResult> OnPost(string action, string historyLimit, string confirmTrim)
    {
        if (!Identity.IsAdmin) return Forbid();
        if (action is "test-ad" or "test-entra")
        {
            try { LapsTest = action == "test-ad" ? await Task.Run(laps.TestAd) : await laps.TestEntra(); }
            catch (WindowsLapsException ex) { LapsTestError = ex.Message; }
            Store.Audit(Identity.Actor, "windows-laps-" + action + (LapsTestError == null ? "-ok" : "-failed"), Guid.Empty, Guid.Empty);
            Load(null);
            return Page();
        }
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
