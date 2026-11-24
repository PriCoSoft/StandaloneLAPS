using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Html;

namespace StandaloneLaps.Server.Pages;

// Same markup as PortalLayout.Credential in the IIS portal: username/password with copy buttons (copy.js).
public static class CredentialHtml
{
    public static IHtmlContent Render(string id, string title, string account, string password, IEnumerable<string> meta)
    {
        var e = HtmlEncoder.Default;
        var html = new StringBuilder("<div class=\"credential\">");
        if (!string.IsNullOrEmpty(title)) html.Append("<div class=\"credential-head\"><h4>").Append(e.Encode(title)).Append("</h4></div>");
        if (!string.IsNullOrEmpty(account))
            html.Append("<div class=\"credential-row\"><span class=\"credential-label\">Username</span><code class=\"credential-value small\" id=\"").Append(id).Append("-u\">")
                .Append(e.Encode(account)).Append("</code><button type=\"button\" class=\"copy-button\" data-copy=\"").Append(id).Append("-u\" hidden>Copy</button></div>");
        html.Append("<div class=\"credential-row\"><span class=\"credential-label\">Password</span><code class=\"credential-value\" data-secret id=\"").Append(id).Append("-p\">")
            .Append(e.Encode(password ?? "")).Append("</code><button type=\"button\" class=\"copy-button\" data-toggle=\"").Append(id).Append("-p\" aria-pressed=\"false\" hidden>Show</button>")
            .Append("<button type=\"button\" class=\"copy-button\" data-copy=\"").Append(id).Append("-p\" hidden>Copy</button></div>");
        var items = (meta ?? Array.Empty<string>()).Where(m => !string.IsNullOrEmpty(m)).ToArray();
        if (items.Length > 0) html.Append("<div class=\"credential-meta\">").Append(string.Concat(items.Select(m => "<span>" + e.Encode(m) + "</span>"))).Append("</div>");
        return new HtmlString(html.Append("</div>").ToString());
    }

    public static string Utc(DateTime? value) => value.HasValue ? value.Value.ToString("dd MMM yyyy, HH:mm", CultureInfo.InvariantCulture) + " UTC" : "—";
}
