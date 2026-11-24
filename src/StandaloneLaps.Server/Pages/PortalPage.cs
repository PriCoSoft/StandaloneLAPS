using System.Globalization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace StandaloneLaps.Server.Pages;

// Shared state for all portal pages (identity, navigation, history limit).
public abstract class PortalPage : PageModel
{
    protected PortalPage(VaultStore store, ServerOptions options)
    {
        Store = store;
        Options = options;
    }

    public VaultStore Store { get; }
    public ServerOptions Options { get; }
    public PortalUser Identity => PortalAuth.User(User, Options);
    public int Limit => Store.HistoryLimit;
    public abstract string Active { get; }

    public static string DateLabel(string value) => string.IsNullOrEmpty(value) ? "—" : Wire.Timestamp(value).UtcDateTime.ToString("dd MMM yyyy, HH:mm", CultureInfo.InvariantCulture);
    public static string Day(DateTime value) => value == DateTime.MinValue ? "—" : value.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture) + " UTC";
}
