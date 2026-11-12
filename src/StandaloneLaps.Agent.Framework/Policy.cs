using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.Win32;

namespace StandaloneLaps.FrameworkAgent
{
    public sealed class AgentPolicy
    {
        public const string SettingsPath = @"SOFTWARE\PriCoSoft\SLAPS";
        public const string LapsPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS";
        public string DeviceId, ClientCertificateSha256, RecoveryCertificatePath, RecoveryCertificateSha256, AccountName;
        public Uri ApiUrl;
        public int AgeDays, Length, Complexity;
        // Native Windows LAPS post-authentication settings: grace period in hours (0 = disabled) and action (1, 3, 5, 11).
        public int PostAuthenticationResetDelayHours, PostAuthenticationActions;
        public const int ActionReset = 1, ActionResetLogoff = 3, ActionResetReboot = 5, ActionResetLogoffTerminate = 11;

        public static AgentPolicy Read()
        {
            using (var registry = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            {
                var settings = Values(registry, SettingsPath);
                if (Number(settings, "Enabled", 0) == 0) return null;
                foreach (var path in new[] { @"SOFTWARE\Microsoft\Policies\LAPS", @"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" })
                    if (Number(Values(registry, path), "BackupDirectory", 0) != 0) throw new InvalidOperationException("Competing native LAPS backup is enabled.");
                if (Number(Values(registry, @"SOFTWARE\Policies\Microsoft Services\AdmPwd"), "AdmPwdEnabled", 0) != 0)
                    throw new InvalidOperationException("Legacy LAPS is enabled.");
                return FromValues(settings, Values(registry, LapsPath));
            }
        }
        private static IDictionary<string, object> Values(RegistryKey root, string path)
        {
            using (var key = root.OpenSubKey(path)) return key == null ? new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
                : key.GetValueNames().ToDictionary(name => name, name => key.GetValue(name, null, RegistryValueOptions.DoNotExpandEnvironmentNames), StringComparer.OrdinalIgnoreCase);
        }
        private static int Number(IDictionary<string, object> values, string name, int fallback)
        {
            object value;
            if (!values.TryGetValue(name, out value)) return fallback;
            if (!(value is int)) throw new InvalidDataException(name + " must be REG_DWORD.");
            return (int)value;
        }
        private static string Text(IDictionary<string, object> values, string name, bool required)
        {
            object value;
            if (!values.TryGetValue(name, out value)) { if (!required) return null; throw new InvalidDataException(name + " is required."); }
            var text = value as string;
            if (text == null || (required && string.IsNullOrWhiteSpace(text))) throw new InvalidDataException(name + " must be a nonempty REG_SZ.");
            return text.Trim();
        }
        public static AgentPolicy FromValues(IDictionary<string, object> settings, IDictionary<string, object> values)
        {
            var enabled = Number(settings, "Enabled", 0);
            if (enabled == 0) return null;
            if (enabled != 1) throw new InvalidDataException("Enabled must be 0 or 1.");
            if (Number(values, "BackupDirectory", 0) != 0) throw new InvalidOperationException("Native BackupDirectory must be Disabled (0).");
            if (Number(values, "AutomaticAccountManagementEnabled", 0) != 0)
                throw new InvalidOperationException("Automatic account management is unsupported.");
            var policy = new AgentPolicy { AgeDays = Number(values, "PasswordAgeDays", 30), Length = Number(values, "PasswordLength", 14),
                Complexity = Number(values, "PasswordComplexity", 4), AccountName = Text(values, "AdministratorAccountName", false) };
            // Same defaults as Windows LAPS: 24 hours and "reset password and sign out"; unsupported values fall back to the default.
            var delay = Number(values, "PostAuthenticationResetDelay", 24);
            policy.PostAuthenticationResetDelayHours = delay < 0 || delay > 24 ? 24 : delay;
            var actions = Number(values, "PostAuthenticationActions", ActionResetLogoff);
            policy.PostAuthenticationActions = actions == ActionReset || actions == ActionResetLogoff || actions == ActionResetReboot || actions == ActionResetLogoffTerminate ? actions : ActionResetLogoff;
            if (policy.AgeDays < 1 || policy.AgeDays > 365 || policy.Length < 8 || policy.Length > 64 || policy.Complexity < 1 || policy.Complexity > 4)
                throw new InvalidDataException("Unsupported LAPS password settings.");
            if (policy.AccountName != null && policy.AccountName.IndexOfAny(new[] { '\\', '/', '@' }) >= 0) throw new InvalidDataException("Only local accounts are supported.");
            Guid id;
            if (!Guid.TryParseExact(Text(settings, "DeviceId", true), "D", out id) || id == Guid.Empty) throw new InvalidDataException("DeviceId must be a unique GUID.");
            policy.DeviceId = id.ToString("D");
            policy.ApiUrl = new Uri(Text(settings, "ApiUrl", true), UriKind.Absolute);
            if (policy.ApiUrl.Scheme != "https" || !policy.ApiUrl.AbsolutePath.EndsWith("/", StringComparison.Ordinal) || policy.ApiUrl.Query.Length != 0 ||
                policy.ApiUrl.Fragment.Length != 0 || policy.ApiUrl.UserInfo.Length != 0) throw new InvalidDataException("ApiUrl must be an HTTPS application URL ending in '/'.");
            policy.ClientCertificateSha256 = Text(settings, "ClientCertificateSha256", true).ToUpperInvariant();
            policy.RecoveryCertificateSha256 = Text(settings, "RecoveryCertificateSha256", true).ToUpperInvariant();
            foreach (var hash in new[] { policy.ClientCertificateSha256, policy.RecoveryCertificateSha256 })
                if (hash.Length != 64 || !hash.All(Uri.IsHexDigit)) throw new InvalidDataException("Certificate SHA-256 must contain 64 hexadecimal characters.");
            policy.RecoveryCertificatePath = Text(settings, "RecoveryCertificatePath", true);
            if (!Path.IsPathRooted(policy.RecoveryCertificatePath) || policy.RecoveryCertificatePath.Length < 3 || policy.RecoveryCertificatePath[1] != ':' ||
                policy.RecoveryCertificatePath[2] != '\\') throw new InvalidDataException("Recovery certificate requires a local absolute drive path.");
            return policy;
        }
    }
}
