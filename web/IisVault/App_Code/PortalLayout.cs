using System.Text;
using System.Web;

namespace StandaloneLapsWeb
{
    // Shared page chrome: head links (icon), top bar and navigation, so every page shows the same menu and version.
    public static class PortalLayout
    {
        public const string HeadLinks = "<link rel=\"icon\" href=\"icon.svg\" type=\"image/svg+xml\" /><link rel=\"alternate icon\" href=\"favicon.ico\" sizes=\"16x16 32x32 48x48\" /><link rel=\"apple-touch-icon\" href=\"icon-180.png\" /><link rel=\"stylesheet\" href=\"style.css\" />";

        public static string Brand(string href)
        {
            return "<a class=\"brand\" href=\"" + href + "\"><img class=\"brand-icon\" src=\"icon.svg\" alt=\"\" width=\"32\" height=\"32\" /><span>PriCoSoft <strong>SLAPS</strong></span></a>";
        }

        public static string TopBar(PortalIdentity identity, bool entraMode)
        {
            var html = new StringBuilder();
            html.Append("<header class=\"topbar\">").Append(Brand("Default.aspx"));
            html.Append("<span class=\"topbar-context\">Standalone password management</span>");
            html.Append("<span class=\"profile\"><span class=\"avatar\">").Append(identity.IsAdmin ? "A" : "R").Append("</span>");
            html.Append("<span class=\"profile-text\">").Append(HttpUtility.HtmlEncode(identity.DisplayName)).Append("<small>").Append(identity.IsAdmin ? "Administrator" : "Reader").Append("</small></span>");
            if (entraMode) html.Append("<a class=\"signout\" href=\"signout.aspx\">Sign out</a>");
            html.Append("</span></header>");
            return html.ToString();
        }

        // active: devices, add, deleted, settings
        public static string Navigation(string active, bool isAdmin)
        {
            var html = new StringBuilder("<aside class=\"navigation\"><p class=\"nav-label\">MANAGE</p>");
            // Icons as HTML entities so the source stays ASCII.
            Item(html, "Default.aspx", "&#9636;", "Devices", active == "devices");
            if (isAdmin)
            {
                Item(html, "addclient.aspx", "&#65291;", "Add client", active == "add");
                Item(html, "Default.aspx?view=deleted", "&#8634;", "Deleted devices", active == "deleted");
            }
            Item(html, "settings.aspx", "&#9881;", "Settings", active == "settings");
            html.Append("<div class=\"nav-bottom\"><span class=\"security-dot\"></span>Encrypted vault<small>")
                .Append(Vault.HistoryLimit).Append(" versions per device</small><small class=\"version\">Version ")
                .Append(AppVersion.Number).Append("</small></div></aside>");
            return html.ToString();
        }

        private static void Item(StringBuilder html, string href, string icon, string label, bool active)
        {
            html.Append("<a class=\"nav-item").Append(active ? " active" : "").Append("\" href=\"").Append(href).Append("\"")
                .Append(active ? " aria-current=\"page\"" : "").Append("><span class=\"nav-icon\">").Append(icon).Append("</span>").Append(label).Append("</a>");
        }
    }
}
