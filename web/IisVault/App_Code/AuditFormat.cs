using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace StandaloneLapsWeb
{
    // One audit entry as shown on the audit page (IIS: App_Data\Vault\audit.jsonl, container: table slaps_audit).
    public sealed class AuditEntry
    {
        public DateTimeOffset Utc { get; set; }
        public string Actor { get; set; }
        public string Action { get; set; }
        public string Target { get; set; }
        public string DeviceId { get; set; }
        public string RotationId { get; set; }
        public string DeviceName { get; set; }
    }

    public sealed class AuditFilter
    {
        public string Text { get; set; }
        public string Category { get; set; }
        public DateTime? FromUtc { get; set; }   // inclusive
        public DateTime? ToUtc { get; set; }     // exclusive
    }

    // Shared by the IIS portal and the container server (linked source, C# 5): categories, labels, filtering, CSV.
    public static class AuditFormat
    {
        public const int PageSize = 100, ExportLimit = 10000;

        public static readonly KeyValuePair<string, string>[] Categories =
        {
            new KeyValuePair<string, string>("", "All events"),
            new KeyValuePair<string, string>("access", "Password access"),
            new KeyValuePair<string, string>("windows-laps", "Windows LAPS / Entra"),
            new KeyValuePair<string, string>("admin", "Administration"),
            new KeyValuePair<string, string>("sign-in", "Sign-in"),
            new KeyValuePair<string, string>("agent", "Agents"),
            new KeyValuePair<string, string>("failed", "Failures and denials")
        };

        public static string NormalizeCategory(string value)
        {
            value = (value ?? "").Trim().ToLowerInvariant();
            return Categories.Any(c => c.Key == value) ? value : "";
        }

        // Container entries keep the target in the action ("windows-laps-search:SRV01"); IIS has a separate field.
        // IIS sign-in denials also use "action: reason".
        public static void SplitTarget(string raw, out string action, out string target)
        {
            raw = raw ?? "";
            var colon = raw.IndexOf(':');
            if (colon <= 0) { action = raw; target = null; return; }
            action = raw.Substring(0, colon);
            target = raw.Substring(colon + 1).Trim();
        }

        public static bool IsFailure(string action)
        {
            return action.Contains("-failed") || action.Contains("denied") || action.EndsWith("-no-role", StringComparison.Ordinal);
        }

        public static bool InCategory(string category, string action)
        {
            action = action ?? "";
            switch (category ?? "")
            {
                case "": return true;
                case "failed": return IsFailure(action);
                case "access":
                    return action.StartsWith("password-reveal", StringComparison.Ordinal) || action == "portal-history" || action == "portal-download" || action == "envelope-download"
                        || action.StartsWith("windows-laps-reveal", StringComparison.Ordinal);
                case "windows-laps": return action.StartsWith("windows-laps-", StringComparison.Ordinal) || action.StartsWith("entra-", StringComparison.Ordinal);
                case "sign-in": return action.StartsWith("portal-sign-", StringComparison.Ordinal);
                case "agent": return action == "backup-attempt" || action == "applied-report" || action == "envelope-read" || action == "history-read";
                case "admin":
                    return action.StartsWith("client-", StringComparison.Ordinal) || action.StartsWith("device-", StringComparison.Ordinal) || action.StartsWith("settings-", StringComparison.Ordinal)
                        || action.StartsWith("key-", StringComparison.Ordinal) || action.StartsWith("certificate-download", StringComparison.Ordinal) || action.StartsWith("trim-history", StringComparison.Ordinal)
                        || action.StartsWith("entra-", StringComparison.Ordinal) || action.StartsWith("windows-laps-expire", StringComparison.Ordinal)
                        || action.StartsWith("windows-laps-rotate", StringComparison.Ordinal) || action.StartsWith("windows-laps-test", StringComparison.Ordinal) || action.StartsWith("audit-", StringComparison.Ordinal);
                default: return false;
            }
        }

        public static string CategoryLabel(string action)
        {
            foreach (var category in new[] { "access", "agent", "sign-in", "admin", "windows-laps" })
                if (InCategory(category, action)) return Categories.First(c => c.Key == category).Value;
            return "Other";
        }

        private static readonly Dictionary<string, string> Labels = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            { "password-reveal-attempt", "Password reveal requested" },
            { "password-revealed", "Password revealed" },
            { "portal-history", "Password history opened" },
            { "portal-download", "Encrypted envelope downloaded" },
            { "envelope-download", "Encrypted envelope downloaded" },
            { "client-package-download", "Client package downloaded" },
            { "client-added", "Client added" },
            { "client-imported", "Client imported" },
            { "client-certificate-replaced", "Client certificate replaced" },
            { "device-delete", "Device deleted" },
            { "device-restore", "Device restored" },
            { "backup-attempt", "Agent uploaded a password" },
            { "applied-report", "Agent reported password applied" },
            { "envelope-read", "Agent read its password" },
            { "history-read", "Agent read its history" },
            { "portal-sign-in-admin", "Signed in (administrator)" },
            { "portal-sign-in-reader", "Signed in (reader)" },
            { "portal-sign-in-no-role", "Sign-in without SLAPS role" },
            { "portal-sign-in-denied", "Sign-in denied" },
            { "portal-sign-out", "Signed out" },
            { "windows-laps-search", "Windows LAPS search" },
            { "windows-laps-reveal-ad", "Windows LAPS password requested (AD)" },
            { "windows-laps-reveal-entra", "Windows LAPS password requested (Entra)" },
            { "windows-laps-revealed-ad", "Windows LAPS password shown (AD)" },
            { "windows-laps-revealed-entra", "Windows LAPS password shown (Entra)" },
            { "windows-laps-expire-ad", "Windows LAPS password expired (AD)" },
            { "windows-laps-expire-ad-failed", "Windows LAPS expire failed (AD)" },
            { "windows-laps-rotate-entra", "Intune password rotation requested" },
            { "windows-laps-rotate-entra-failed", "Intune password rotation failed" },
            { "windows-laps-test-ad-ok", "AD connection test succeeded" },
            { "windows-laps-test-ad-failed", "AD connection test failed" },
            { "windows-laps-test-entra-ok", "Entra connection test succeeded" },
            { "windows-laps-test-entra-failed", "Entra connection test failed" },
            { "entra-admin-consent-started", "Entra admin consent started" },
            { "entra-admin-consent-granted", "Entra admin consent granted" },
            { "entra-admin-consent-failed", "Entra admin consent failed" },
            { "entra-object-id-set", "Entra application object ID set" },
            { "entra-graph-certificate-download", "Entra certificate downloaded" },
            { "audit-exported", "Audit log exported" }
        };

        // Readable label; unknown actions fall back to the raw name with spaces.
        public static string Label(string action)
        {
            action = action ?? "";
            string label;
            if (Labels.TryGetValue(action, out label)) return label;
            if (action.StartsWith("entra-graph-certificate-", StringComparison.Ordinal)) return "Entra certificate " + action.Substring(24).Split('-')[0];
            if (action.StartsWith("settings-history-limit-", StringComparison.Ordinal)) return "History limit changed (" + action.Substring(23).Replace("-to-", " to ") + ")";
            if (action.StartsWith("trim-history-to-", StringComparison.Ordinal)) return "History trimmed to " + action.Substring(16) + " versions";
            if (action.StartsWith("certificate-download-", StringComparison.Ordinal)) return "Certificate downloaded";
            if (action.StartsWith("key-", StringComparison.Ordinal)) return "Key " + action.Substring(4).Replace('-', ' ');
            if (action.Length == 0) return "—";
            var text = action.Replace('-', ' ');
            return char.ToUpperInvariant(text[0]) + text.Substring(1);
        }

        public static bool Matches(AuditEntry entry, AuditFilter filter, IDictionary<string, string> names)
        {
            if (filter == null) return true;
            if (filter.FromUtc.HasValue && entry.Utc.UtcDateTime < filter.FromUtc.Value) return false;
            if (filter.ToUtc.HasValue && entry.Utc.UtcDateTime >= filter.ToUtc.Value) return false;
            if (!InCategory(filter.Category, entry.Action)) return false;
            if (string.IsNullOrWhiteSpace(filter.Text)) return true;
            var text = filter.Text.Trim();
            string name;
            var actorName = names != null && entry.Actor != null && names.TryGetValue(entry.Actor, out name) ? name : null;
            return new[] { entry.Actor, actorName, entry.Action, Label(entry.Action), entry.Target, entry.DeviceId, entry.DeviceName, entry.RotationId }
                .Any(value => value != null && value.IndexOf(text, StringComparison.OrdinalIgnoreCase) >= 0);
        }

        // Actor -> display name from the sign-in entries (newest wins: callers pass entries oldest first).
        public static void CollectName(IDictionary<string, string> names, AuditEntry entry)
        {
            if (entry.Actor != null && entry.Action != null && entry.Action.StartsWith("portal-sign-in-", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(entry.Target))
                names[entry.Actor] = entry.Target.Trim();
        }

        // yyyy-MM-dd from a date input; the "to" date is inclusive, so the exclusive bound is the next day.
        public static DateTime? ParseDay(string value, bool endOfDay)
        {
            DateTime day;
            if (!DateTime.TryParseExact((value ?? "").Trim(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out day)) return null;
            day = DateTime.SpecifyKind(day, DateTimeKind.Utc);
            return endOfDay ? day.AddDays(1) : day;
        }

        public static string Csv(IEnumerable<AuditEntry> entries, IDictionary<string, string> names)
        {
            var csv = new StringBuilder("utc,actor,actor_name,action,description,target,device_id,device_name,rotation_id\r\n");
            foreach (var entry in entries)
            {
                string name;
                var actorName = names != null && entry.Actor != null && names.TryGetValue(entry.Actor, out name) ? name : "";
                csv.Append(string.Join(",", new[] { entry.Utc.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture), entry.Actor, actorName, entry.Action, Label(entry.Action), entry.Target, entry.DeviceId, entry.DeviceName, entry.RotationId }.Select(CsvField))).Append("\r\n");
            }
            return csv.ToString();
        }

        // Quoted; a leading = + - @ is neutralised so a spreadsheet does not evaluate it (CSV injection).
        public static string CsvField(string value)
        {
            value = value ?? "";
            if (value.Length > 0 && "=+-@\t\r".IndexOf(value[0]) >= 0) value = "'" + value;
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }
    }
}
