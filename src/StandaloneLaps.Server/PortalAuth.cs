using System.Net;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace StandaloneLaps.Server;

public sealed class PortalUser
{
    public string Actor { get; init; }
    public string DisplayName { get; init; }
    public bool IsAdmin { get; init; }
    public bool IsReader { get; init; }
}

// Portal sign-in: OpenID Connect (Microsoft Entra ID or any OIDC provider) with app roles SLAPS.Admin / SLAPS.Reader.
// The agent port never uses this; it accepts only pinned client certificates.
public static class PortalAuth
{
    public const string AdminPolicy = "SlapsAdmin", ReaderPolicy = "SlapsReader", DevelopmentScheme = "SlapsDevelopment";

    public static void Add(IServiceCollection services, ServerOptions options)
    {
        if (options.DevelopmentAuth)
        {
            services.AddAuthentication(DevelopmentScheme).AddScheme<AuthenticationSchemeOptions, DevelopmentHandler>(DevelopmentScheme, null);
        }
        else
        {
            services.AddAuthentication(o =>
            {
                o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(o =>
            {
                o.Cookie.Name = "slaps_auth";
                o.Cookie.HttpOnly = true;
                o.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                o.Cookie.SameSite = SameSiteMode.Lax;
                o.ExpireTimeSpan = TimeSpan.FromHours(8);
                o.SlidingExpiration = false;
                o.AccessDeniedPath = "/denied";
            })
            .AddOpenIdConnect(o =>
            {
                o.Authority = options.OidcAuthority;
                o.ClientId = options.OidcClientId;
                o.MapInboundClaims = false;
                o.SaveTokens = false;
                o.GetClaimsFromUserInfoEndpoint = false;
                o.CallbackPath = "/signin-oidc";
                o.SignedOutCallbackPath = "/signout-callback-oidc";
                o.Scope.Clear();
                o.Scope.Add("openid");
                o.Scope.Add("profile");
                if (string.IsNullOrEmpty(options.OidcClientSecret))
                {
                    // Like the IIS portal: ID token via form_post, no client secret (Entra: enable "ID tokens").
                    o.ResponseType = OpenIdConnectResponseType.IdToken;
                    o.ResponseMode = OpenIdConnectResponseMode.FormPost;
                }
                else
                {
                    o.ClientSecret = options.OidcClientSecret;
                    o.ResponseType = OpenIdConnectResponseType.Code;
                    o.UsePkce = true;
                }
                o.TokenValidationParameters.NameClaimType = options.OidcNameClaim;
                o.TokenValidationParameters.RoleClaimType = options.OidcRoleClaim;
                o.CorrelationCookie.SecurePolicy = CookieSecurePolicy.Always;
                o.NonceCookie.SecurePolicy = CookieSecurePolicy.Always;
            });
        }
        services.AddAuthorization(o =>
        {
            o.AddPolicy(ReaderPolicy, p => p.RequireAuthenticatedUser().RequireAssertion(c => User(c.User, options).IsReader));
            o.AddPolicy(AdminPolicy, p => p.RequireAuthenticatedUser().RequireAssertion(c => User(c.User, options).IsAdmin));
        });
    }

    public static PortalUser User(ClaimsPrincipal principal, ServerOptions options)
    {
        if (principal?.Identity?.IsAuthenticated != true) return new PortalUser { Actor = "anonymous", DisplayName = "Anonymous" };
        string Claim(string type) => principal.FindFirst(type)?.Value;
        var roles = principal.FindAll(options.OidcRoleClaim).Select(c => c.Value).ToArray();
        var admin = roles.Contains(options.AdminRole, StringComparer.Ordinal);
        var id = Claim(options.OidcIdClaim) ?? Claim("oid") ?? Claim("sub") ?? "unknown";
        var name = Claim(options.OidcNameClaim) ?? Claim("name") ?? Claim("preferred_username") ?? Claim("email") ?? id;
        var prefix = principal.Identity.AuthenticationType == DevelopmentScheme ? "dev:" : "oidc:";
        return new PortalUser { Actor = prefix + id, DisplayName = name, IsAdmin = admin, IsReader = admin || roles.Contains(options.ReaderRole, StringComparer.Ordinal) };
    }

    // Development only (ASPNETCORE_ENVIRONMENT=Development): loopback requests are signed in as a local administrator.
    private sealed class DevelopmentHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly ServerOptions server;

        public DevelopmentHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ServerOptions server) : base(options, logger, encoder)
        {
            this.server = server;
        }

        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var remote = Context.Connection.RemoteIpAddress;
            if (remote == null || !IPAddress.IsLoopback(remote)) return Task.FromResult(AuthenticateResult.Fail("Development sign-in is loopback-only."));
            var role = Request.Headers["X-Slaps-Development-Role"].ToString() == "reader" ? server.ReaderRole : server.AdminRole;
            var identity = new ClaimsIdentity(new[] { new Claim("sub", "local"), new Claim("name", "Local developer"), new Claim(server.OidcRoleClaim, role) }, DevelopmentScheme, "name", server.OidcRoleClaim);
            return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), DevelopmentScheme)));
        }
    }
}
