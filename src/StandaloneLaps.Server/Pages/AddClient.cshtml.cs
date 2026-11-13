using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;

namespace StandaloneLaps.Server.Pages;

public sealed class AddClientModel : PortalPage
{
    private readonly ClientPackages packages;

    public AddClientModel(VaultStore store, ServerOptions options, ClientPackages packages) : base(store, options)
    {
        this.packages = packages;
    }

    public override string Active => "add";
    public AgentClient Existing;
    public PackageResult Result;
    public string ErrorText, NameValue, Platform = ClientPackages.Windows;
    public bool IsLinux => Platform == ClientPackages.Linux;
    public string MissingWindows, MissingLinux;

    private IActionResult Load()
    {
        MissingWindows = packages.MissingFiles(ClientPackages.Windows);
        MissingLinux = packages.MissingFiles(ClientPackages.Linux);
        if (Guid.TryParseExact(Request.Query["device"], "D", out var device))
        {
            Existing = Store.Client(device);
            if (Existing == null || Existing.Deleted) return NotFound();
            NameValue = Existing.DisplayName;
            Platform = Existing.Platform == ClientPackages.Linux ? ClientPackages.Linux : ClientPackages.Windows;
        }
        return null;
    }

    public IActionResult OnGet() => Load() ?? Page();

    public IActionResult OnPost(string name, string platform)
    {
        var result = Load();
        if (result != null) return result;
        if (Existing == null) NameValue = (name ?? "").Trim();
        Platform = platform == ClientPackages.Linux ? ClientPackages.Linux : ClientPackages.Windows;
        try
        {
            Result = packages.Create(NameValue, Existing == null ? null : Guid.Parse(Existing.DeviceId), Identity.Actor, Platform);
        }
        catch (ArgumentException ex) { ErrorText = ex.Message; }
        catch (InvalidOperationException ex) { ErrorText = ex.Message; }
        catch (CryptographicException ex) { ErrorText = "The certificate could not be issued: " + ex.Message; }
        return Page();
    }
}
