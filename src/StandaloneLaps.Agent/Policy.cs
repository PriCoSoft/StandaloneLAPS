using Microsoft.Win32;
using System.Text.Json;

namespace StandaloneLaps.Agent;

public sealed record AgentSettings
{
    public bool Enabled { get; init; }
    public string DeviceId { get; init; } = "";
    public string ApiUrl { get; init; } = "";
    public string ClientCertificateSha256 { get; init; } = "";
    public string RecoveryCertificatePath { get; init; } = "";
    public string RecoveryCertificateSha256 { get; init; } = "";
}

public sealed record Policy(string DeviceId, Uri ApiUrl, string ClientCertificateSha256,
    string RecoveryCertificatePath, string RecoveryCertificateSha256, int AgeDays, int Length,
    int Complexity, string? AccountName)
{
    public const string NativePolicyPath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS";

    public static Policy? Read()
    {
        var settings = JsonSerializer.Deserialize<AgentSettings>(File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "agentsettings.json")))
            ?? throw new InvalidDataException("Missing agent settings.");
        if (!settings.Enabled) return null;
        using var registry = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
        using var policy = registry.OpenSubKey(NativePolicyPath);
        foreach (var keyPath in new[] { @"SOFTWARE\Microsoft\Policies\LAPS", @"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" })
        {
            using var other = registry.OpenSubKey(keyPath);
            if (other?.GetValue("BackupDirectory") is int backup && backup != 0)
                throw new InvalidOperationException("Another native LAPS policy is enabled.");
        }
        using var legacy = registry.OpenSubKey(@"SOFTWARE\Policies\Microsoft Services\AdmPwd");
        if (legacy?.GetValue("AdmPwdEnabled") is int legacyEnabled && legacyEnabled != 0)
            throw new InvalidOperationException("Legacy LAPS is enabled.");
        var values = policy?.GetValueNames().ToDictionary(name => name, name => policy.GetValue(name), StringComparer.OrdinalIgnoreCase)
            ?? new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        return FromValues(settings, values);
    }

    // Pure mapping lets tests verify native policy behavior without changing the live registry.
    public static Policy FromValues(AgentSettings settings, IReadOnlyDictionary<string, object?> values)
    {
        int Number(string name, int fallback) => values.TryGetValue(name, out var value)
            ? value is int number ? number : throw new InvalidDataException($"LAPS setting {name} must be DWORD.") : fallback;
        if (Number("BackupDirectory", 0) != 0) throw new InvalidOperationException("Native BackupDirectory must be Disabled (0) for the standalone API.");
        if (Number("AutomaticAccountManagementEnabled", 0) != 0 || Number("PostAuthenticationActions", 0) != 0)
            throw new InvalidOperationException("Automatic account management and post-authentication actions are not implemented by this agent.");
        var age = Number("PasswordAgeDays", 30);
        var length = Number("PasswordLength", 14);
        var complexity = Number("PasswordComplexity", 4);
        if (age is < 1 or > 365 || length is < 8 or > 64 || complexity is < 1 or > 4)
            throw new InvalidOperationException("Unsupported LAPS settings; complexity modes 1-4 are supported.");
        var account = values.TryGetValue("AdministratorAccountName", out var name) ? name as string : null;
        if (name is not null && name is not string) throw new InvalidDataException("AdministratorAccountName must be REG_SZ.");
        if (account?.IndexOfAny(['\\', '/', '@']) >= 0) throw new InvalidDataException("Only local account names are supported.");
        if (!Guid.TryParseExact(settings.DeviceId, "D", out var device) || device == Guid.Empty) throw new InvalidDataException("DeviceId must be a unique GUID.");
        var uri = new Uri(settings.ApiUrl, UriKind.Absolute);
        if (uri.Scheme != "https" || !uri.AbsolutePath.EndsWith('/') || uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.UserInfo.Length != 0)
            throw new InvalidDataException("ApiUrl must be an HTTPS application base URL ending in '/'.");
        static bool Hash(string value) => value.Length == 64 && value.All(Uri.IsHexDigit);
        if (!Hash(settings.ClientCertificateSha256) || !Hash(settings.RecoveryCertificateSha256)) throw new InvalidDataException("SHA-256 fingerprints must contain 64 hexadecimal characters.");
        if (!Path.IsPathFullyQualified(settings.RecoveryCertificatePath) || settings.RecoveryCertificatePath.StartsWith(@"\\", StringComparison.Ordinal))
            throw new InvalidDataException("Recovery certificate must use a local absolute path.");
        return new Policy(device.ToString("D"), uri, settings.ClientCertificateSha256.ToUpperInvariant(), settings.RecoveryCertificatePath,
            settings.RecoveryCertificateSha256.ToUpperInvariant(), age, length, complexity, string.IsNullOrWhiteSpace(account) ? null : account);
    }
}
