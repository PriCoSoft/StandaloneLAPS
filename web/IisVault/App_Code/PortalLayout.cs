using System;
using System.Globalization;
using System.Text;
using System.Web;

namespace StandaloneLapsWeb
{
    // Shared page chrome: head links (icon), top bar and navigation, so every page shows the same menu and version.
    public static class PortalLayout
    {
        public const string HeadLinks = "<link rel=\"icon\" href=\"icon.svg\" type=\"image/svg+xml\" /><link rel=\"alternate icon\" href=\"favicon.ico\" sizes=\"16x16 32x32 48x48\" /><link rel=\"apple-touch-icon\" href=\"icon-180.png\" /><link rel=\"stylesheet\" href=\"style.css\" />";

        // Copy / show buttons for revealed credentials (same origin, allowed by the CSP).
        public const string Scripts = "<script src=\"copy.js\"></script>";

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

        // active: devices, windowslaps, add, deleted, audit, settings
        public static string Navigation(string active, bool isAdmin)
        {
            var html = new StringBuilder("<aside class=\"navigation\"><p class=\"nav-label\">MANAGE</p>");
            // Icons as HTML entities so the source stays ASCII.
            Item(html, "Default.aspx", "&#9636;", "Devices", active == "devices");
            if (WindowsLapsSettings.Enabled && (isAdmin || WindowsLapsSettings.ReaderAllowed))
                Item(html, "windowslaps.aspx", "&#9919;", "Windows LAPS", active == "windowslaps");
            if (isAdmin)
            {
                Item(html, "addclient.aspx", "&#65291;", "Add client", active == "add");
                Item(html, "Default.aspx?view=deleted", "&#8634;", "Deleted devices", active == "deleted");
                Item(html, "audit.aspx", "&#9783;", "Audit log", active == "audit");
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

        public static string Utc(DateTime? value)
        {
            return value.HasValue ? value.Value.ToString("dd MMM yyyy, HH:mm", CultureInfo.GetCultureInfo("en-US")) + " UTC" : "—";
        }

        // Username/password block with copy buttons. The password is masked by copy.js (blur) until "Show";
        // without JavaScript it stays readable and the buttons stay hidden.
        public static string Credential(string id, string title, string badge, string account, string password, string meta)
        {
            var e = new Func<string, string>(HttpUtility.HtmlEncode);
            var html = new StringBuilder("<div class=\"credential\">");
            if (!string.IsNullOrEmpty(title) || !string.IsNullOrEmpty(badge))
                html.Append("<div class=\"credential-head\"><h4>").Append(e(title ?? "")).Append("</h4>").Append(badge ?? "").Append("</div>");
            if (!string.IsNullOrEmpty(account))
                html.Append("<div class=\"credential-row\"><span class=\"credential-label\">Username</span><code class=\"credential-value small\" id=\"").Append(id).Append("-u\">")
                    .Append(e(account)).Append("</code><button type=\"button\" class=\"copy-button\" data-copy=\"").Append(id).Append("-u\" hidden>Copy</button></div>");
            html.Append("<div class=\"credential-row\"><span class=\"credential-label\">Password</span><code class=\"credential-value\" data-secret id=\"").Append(id).Append("-p\">")
                .Append(e(password ?? "")).Append("</code><button type=\"button\" class=\"copy-button\" data-toggle=\"").Append(id).Append("-p\" aria-pressed=\"false\" hidden>Show</button>")
                .Append("<button type=\"button\" class=\"copy-button\" data-copy=\"").Append(id).Append("-p\" hidden>Copy</button></div>");
            if (!string.IsNullOrEmpty(meta)) html.Append("<div class=\"credential-meta\">").Append(meta).Append("</div>");
            return html.Append("</div>").ToString();
        }
    }
}
