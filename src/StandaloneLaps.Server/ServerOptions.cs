using System.Net;

namespace StandaloneLaps.Server;

// All settings come from the "Slaps" configuration section (environment variables Slaps__Name, appsettings.json).
// Secrets can be given as <Name>File (path to a file, e.g. a Docker secret) instead of the value itself.
public sealed class ServerOptions
{
    public const int DefaultHistoryLimit = 20, MinHistoryLimit = 2, MaxHistoryLimit = 100;

    public string PublicUrl { get; init; }
    public string AgentApiUrl { get; init; }
    public int PortalPort { get; init; } = 8443;
    public int AgentPort { get; init; } = 8444;
    public int PortalHttpPort { get; init; }
    public string DataDirectory { get; init; } = "/data";
    public string AgentPackageDirectory { get; init; } = "/app/agent-package";
    public string DatabaseProvider { get; init; } = "sqlite";
    public string ConnectionString { get; init; }
    public string MasterKey { get; init; }
    public string TlsCertificatePath { get; init; }
    public string TlsKeyPath { get; init; }
    public string TlsPfxPath { get; init; }
    public string TlsPfxPassword { get; init; }
    public string[] TlsDnsNames { get; init; } = Array.Empty<string>();
    public IPNetwork[] PortalAllowedNetworks { get; init; } = Array.Empty<IPNetwork>();
    public IPNetwork[] ForwardedHeadersNetworks { get; init; } = Array.Empty<IPNetwork>();
    public bool EnableWebDecryption { get; init; } = true;
    public string AuthMode { get; init; } = "Oidc";
    public string OidcAuthority { get; init; }
    public string OidcClientId { get; init; }
    public string OidcClientSecret { get; init; }
    public string OidcRoleClaim { get; init; } = "roles";
    public string OidcNameClaim { get; init; } = "name";
    public string OidcIdClaim { get; init; } = "oid";
    public string AdminRole { get; init; } = "SLAPS.Admin";
    public string ReaderRole { get; init; } = "SLAPS.Reader";
    public string ServerName { get; init; }
    public WindowsLapsOptions WindowsLaps { get; init; } = new();

    public const string PrivateNetworks = "10.0.0.0/8;172.16.0.0/12;192.168.0.0/16;127.0.0.0/8;::1/128;fc00::/7";

    public bool IsPostgres => string.Equals(DatabaseProvider, "postgresql", StringComparison.OrdinalIgnoreCase) || string.Equals(DatabaseProvider, "postgres", StringComparison.OrdinalIgnoreCase);
    public bool DevelopmentAuth => string.Equals(AuthMode, "Development", StringComparison.OrdinalIgnoreCase);

    public string HostName => ServerName ?? (Uri.TryCreate(PublicUrl, UriKind.Absolute, out var uri) ? uri.Host : Environment.MachineName.ToLowerInvariant());

    public static ServerOptions Load(IConfiguration configuration)
    {
        var section = configuration.GetSection("Slaps");
        string Value(string name) { var value = section[name]; return string.IsNullOrWhiteSpace(value) ? null : value.Trim(); }
        string Secret(string name, string environment = null)
        {
            var value = Value(name) ?? (environment == null ? null : Environment.GetEnvironmentVariable(environment));
            if (value != null) return value;
            var file = Value(name + "File") ?? (environment == null ? null : Environment.GetEnvironmentVariable(environment + "_FILE"));
            return file == null ? null : File.ReadAllText(file).Trim();
        }
        int Number(string name, int fallback) => Value(name) is { } text ? int.Parse(text, System.Globalization.CultureInfo.InvariantCulture) : fallback;
        bool Flag(string name, bool fallback) => Value(name) is { } text ? bool.Parse(text) : fallback;
        string[] List(string name, string fallback = "") => (Value(name) ?? fallback).Split(new[] { ';', ',' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        var dataDirectory = Value("DataDirectory") ?? "/data";
        var options = new ServerOptions
        {
            PublicUrl = BaseUrl(Value("PublicUrl"), "PublicUrl"),
            AgentApiUrl = BaseUrl(Value("AgentApiUrl"), "AgentApiUrl"),
            PortalPort = Number("PortalPort", 8443),
            AgentPort = Number("AgentPort", 8444),
            PortalHttpPort = Number("PortalHttpPort", 0),
            DataDirectory = dataDirectory,
            AgentPackageDirectory = Value("AgentPackageDirectory") ?? "/app/agent-package",
            DatabaseProvider = Value("DatabaseProvider") ?? "sqlite",
            ConnectionString = Secret("ConnectionString") ?? "Data Source=" + Path.Combine(dataDirectory, "slaps.db"),
            MasterKey = Secret("MasterKey", "SLAPS_MASTER_KEY"),
            TlsCertificatePath = Value("TlsCertificatePath"),
            TlsKeyPath = Value("TlsKeyPath"),
            TlsPfxPath = Value("TlsPfxPath"),
            TlsPfxPassword = Secret("TlsPfxPassword"),
            TlsDnsNames = List("TlsDnsNames"),
            PortalAllowedNetworks = List("PortalAllowedNetworks", PrivateNetworks).Select(IPNetwork.Parse).ToArray(),
            ForwardedHeadersNetworks = List("ForwardedHeadersNetworks").Select(IPNetwork.Parse).ToArray(),
            EnableWebDecryption = Flag("EnableWebDecryption", true),
            AuthMode = Value("AuthMode") ?? "Oidc",
            OidcAuthority = Value("OidcAuthority"),
            OidcClientId = Value("OidcClientId"),
            OidcClientSecret = Secret("OidcClientSecret"),
            OidcRoleClaim = Value("OidcRoleClaim") ?? "roles",
            OidcNameClaim = Value("OidcNameClaim") ?? "name",
            OidcIdClaim = Value("OidcIdClaim") ?? "oid",
            AdminRole = Value("AdminRole") ?? "SLAPS.Admin",
            ReaderRole = Value("ReaderRole") ?? "SLAPS.Reader",
            ServerName = Value("ServerName"),
            WindowsLaps = new WindowsLapsOptions
            {
                ReaderAllowed = RequiredRoleIsReader(Value("WindowsLapsRequiredRole")),
                AdEnabled = Flag("WindowsLapsAdEnabled", false),
                AdServer = Value("WindowsLapsAdServer"),
                AdUseSsl = Flag("WindowsLapsAdUseSsl", true),
                AdPort = Number("WindowsLapsAdPort", 0),
                AdSearchBase = Value("WindowsLapsAdSearchBase"),
                AdUsername = Value("WindowsLapsAdUsername"),
                AdPassword = Secret("WindowsLapsAdPassword"),
                AdCaDirectory = Value("WindowsLapsAdCaDirectory"),
                AdLegacy = Flag("WindowsLapsAdLegacy", true),
                AdModern = Flag("WindowsLapsAdModern", true),
                AdDecrypt = Flag("WindowsLapsAdDecrypt", true),
                AdHistory = Flag("WindowsLapsAdHistory", true),
                AdAllowExpire = Flag("WindowsLapsAdAllowExpire", false),
                EntraAllowRotate = Flag("WindowsLapsEntraAllowRotate", false),
                DecryptMode = Value("WindowsLapsAdDecryptMode") ?? "auto",
                DecryptServer = Value("WindowsLapsAdDecryptServer"),
                DecryptAuth = Value("WindowsLapsAdDecryptAuth") ?? "negotiate",
                Python = Value("WindowsLapsPython") ?? "python3",
                DpapiScript = Value("WindowsLapsDpapiScript") ?? Path.Combine(AppContext.BaseDirectory, "dpapi", "slaps_dpapi_ng.py"),
                EntraEnabled = Flag("WindowsLapsEntraEnabled", false),
                EntraTenantId = Value("WindowsLapsEntraTenantId") ?? TenantFromAuthority(Value("OidcAuthority")),
                EntraClientId = Value("WindowsLapsEntraClientId") ?? Value("OidcClientId"),
                EntraClientSecret = Secret("WindowsLapsEntraClientSecret"),
                EntraCertificatePath = Value("WindowsLapsEntraCertificatePath"),
                EntraCertificatePassword = Secret("WindowsLapsEntraCertificatePassword"),
                EntraHistory = Flag("WindowsLapsEntraHistory", true)
            }
        };
        options.WindowsLaps.Validate();
        if (options.PortalPort == options.AgentPort) throw new InvalidOperationException("Slaps:PortalPort and Slaps:AgentPort must differ: the agent port requires client certificates.");
        if (!options.IsPostgres && !string.Equals(options.DatabaseProvider, "sqlite", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Slaps:DatabaseProvider must be sqlite or postgresql.");
        return options;
    }

    public void ValidateForServe(bool development)
    {
        if (string.IsNullOrEmpty(MasterKey) || MasterKey.Length < 32)
            throw new InvalidOperationException("Set SLAPS_MASTER_KEY (or SLAPS_MASTER_KEY_FILE) to a random secret of at least 32 characters. It protects the CA and recovery keys; keep a copy offline.");
        if (DevelopmentAuth && !development) throw new InvalidOperationException("Slaps:AuthMode=Development is only allowed with ASPNETCORE_ENVIRONMENT=Development.");
        if (!DevelopmentAuth && (string.IsNullOrEmpty(OidcAuthority) || string.IsNullOrEmpty(OidcClientId)))
            throw new InvalidOperationException("Set Slaps__OidcAuthority (e.g. https://login.microsoftonline.com/<tenant-id>/v2.0) and Slaps__OidcClientId.");
        if (PublicUrl == null) throw new InvalidOperationException("Set Slaps__PublicUrl to the portal URL, e.g. https://slaps.example.com:8443/.");
        if (AgentApiUrl == null) throw new InvalidOperationException("Set Slaps__AgentApiUrl to the agent API URL written into client packages, e.g. https://slaps.example.com:8444/.");
    }

    // Reader (default since 1.6.5, same as SLAPS passwords) or Admin. A typo must not silently widen or narrow access.
    private static bool RequiredRoleIsReader(string value)
    {
        if (value == null || string.Equals(value, "Reader", StringComparison.OrdinalIgnoreCase)) return true;
        if (string.Equals(value, "Admin", StringComparison.OrdinalIgnoreCase)) return false;
        throw new InvalidOperationException("Slaps:WindowsLapsRequiredRole must be Reader or Admin.");
    }

    private static string TenantFromAuthority(string authority)
    {
        if (!Uri.TryCreate(authority, UriKind.Absolute, out var uri)) return null;
        var first = uri.AbsolutePath.Trim('/').Split('/')[0];
        return Guid.TryParse(first, out var tenant) ? tenant.ToString("D") : null;
    }

    private static string BaseUrl(string value, string name)
    {
        if (value == null) return null;
        if (!Uri.TryCreate(value, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps || uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.UserInfo.Length != 0)
            throw new InvalidOperationException("Slaps:" + name + " must be an HTTPS URL without query, e.g. https://slaps.example.com:8443/.");
        var text = uri.AbsoluteUri;
        return text.EndsWith('/') ? text : text + "/";
    }
}
