using System.Net;
using System.Security.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.Extensions.FileProviders;
using StandaloneLaps.Server;
using StandaloneLapsWeb;

return await ServerProgram.Run(args);

namespace StandaloneLaps.Server
{
    public static class ServerProgram
    {
        public static async Task<int> Run(string[] args)
        {
            var command = args.Length > 0 && !args[0].StartsWith('-') ? args[0].ToLowerInvariant() : "serve";
            var rest = args.Length > 0 && !args[0].StartsWith('-') ? args.Skip(1).ToArray() : args;
            try
            {
                switch (command)
                {
                    case "serve":
                        var app = Build(rest);
                        await app.RunAsync();
                        return 0;
                    case "health": return await Tools.Health(rest);
                    case "export-recovery-key": return Tools.ExportKey(rest, KeyVault.RecoveryKey);
                    case "export-ca-key": return Tools.ExportKey(rest, KeyVault.CaKey);
                    case "import-keys": return Tools.ImportKeys(rest);
                    case "import-iis-vault": return Tools.ImportIisVault(rest);
                    case "version": Console.WriteLine("SLAPS container server " + AppVersion.Number); return 0;
                    default:
                        Console.Error.WriteLine("Commands: serve | health | version | export-recovery-key <file.pfx> | export-ca-key <file.pfx> | import-keys --ca <pfx> --recovery <pfx> [--previous-recovery <pfx>] | import-iis-vault <App_Data directory>");
                        return 2;
                }
            }
            catch (InvalidOperationException ex)
            {
                // Configuration and key errors: one clear line instead of a stack trace.
                Console.Error.WriteLine("SLAPS: " + ex.Message);
                return 1;
            }
        }

        // Builds the web application; tests call this with in-memory configuration.
        public static WebApplication Build(string[] args, IDictionary<string, string> overrides = null)
        {
            var builder = WebApplication.CreateBuilder(new WebApplicationOptions
            {
                Args = args, ContentRootPath = AppContext.BaseDirectory, ApplicationName = typeof(ServerProgram).Assembly.GetName().Name
            });
            if (overrides != null) builder.Configuration.AddInMemoryCollection(overrides);
            var options = ServerOptions.Load(builder.Configuration);
            options.ValidateForServe(builder.Environment.IsDevelopment());

            var store = new VaultStore(options);
            store.Initialize();
            var keys = new KeyVault(store, options);
            keys.Initialize();

            builder.Services.AddSingleton(options);
            builder.Services.AddSingleton(store);
            builder.Services.AddSingleton(keys);
            builder.Services.AddSingleton<ClientPackages>();
            builder.Services.AddSingleton<AgentApi>();
            builder.Services.AddSingleton(new WindowsLapsService(options, null, store, keys));
            // Session cookies and antiforgery tokens are protected with in-memory keys: a restart signs everybody out,
            // and nothing in the data volume can be used to forge a portal session.
            builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
            PortalAuth.Add(builder.Services, options);
            builder.Services.AddRazorPages(o =>
            {
                o.Conventions.AuthorizeFolder("/", PortalAuth.ReaderPolicy);
                o.Conventions.AuthorizePage("/AddClient", PortalAuth.AdminPolicy);
                o.Conventions.AuthorizePage("/EntraSetup", PortalAuth.AdminPolicy);
                o.Conventions.AllowAnonymousToPage("/Denied");
            }).ConfigureApplicationPartManager(manager =>
            {
                // Also when another entry assembly hosts the server (integration tests).
                var assembly = typeof(ServerProgram).Assembly;
                if (!manager.ApplicationParts.OfType<Microsoft.AspNetCore.Mvc.ApplicationParts.AssemblyPart>().Any(p => p.Assembly == assembly))
                    foreach (var part in new Microsoft.AspNetCore.Mvc.ApplicationParts.CompiledRazorAssemblyApplicationPartFactory().GetApplicationParts(assembly)) manager.ApplicationParts.Add(part);
            });
            builder.Services.Configure<ForwardedHeadersOptions>(o =>
            {
                o.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedHost;
                o.KnownIPNetworks.Clear();
                o.KnownProxies.Clear();
                foreach (var network in options.ForwardedHeadersNetworks) o.KnownIPNetworks.Add(network);
            });

            builder.WebHost.ConfigureKestrel(kestrel =>
            {
                kestrel.AddServerHeader = false;
                kestrel.Limits.MaxRequestBodySize = 131072;
                kestrel.ListenAnyIP(options.PortalPort, listen =>
                {
                    listen.Protocols = HttpProtocols.Http1AndHttp2;
                    listen.UseHttps(new HttpsConnectionAdapterOptions
                    {
                        ServerCertificate = keys.Tls, ServerCertificateChain = keys.TlsChain, SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        ClientCertificateMode = ClientCertificateMode.NoCertificate
                    });
                });
                // Agent port: the TLS handshake requires a client certificate from the SLAPS CA, so browsers never
                // see a certificate prompt on the portal and unauthenticated clients cannot reach the API code.
                kestrel.ListenAnyIP(options.AgentPort, listen =>
                {
                    listen.Protocols = HttpProtocols.Http1;
                    listen.UseHttps(new HttpsConnectionAdapterOptions
                    {
                        ServerCertificate = keys.Tls, ServerCertificateChain = keys.TlsChain, SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        ClientCertificateMode = ClientCertificateMode.RequireCertificate, CheckCertificateRevocation = false,
                        ClientCertificateValidation = (certificate, _, _) => keys.IsAgentCertificate(certificate)
                    });
                });
                if (options.PortalHttpPort > 0) kestrel.ListenAnyIP(options.PortalHttpPort, listen => listen.Protocols = HttpProtocols.Http1AndHttp2);
            });

            var app = builder.Build();
            app.Logger.LogInformation("SLAPS container server {Version}: portal https port {Portal}, agent port {Agent}, database {Database}, TLS: {Tls}",
                AppVersion.Number, options.PortalPort, options.AgentPort, options.IsPostgres ? "PostgreSQL" : "SQLite", keys.TlsSource);
            if (options.DevelopmentAuth) app.Logger.LogWarning("Development sign-in is enabled: every loopback request is an administrator. Never use this in production.");

            // 1. Agent port: only the agent API.
            app.Use(async (context, next) =>
            {
                var isApi = string.Equals(context.Request.Path.Value, "/api.aspx", StringComparison.OrdinalIgnoreCase);
                if (context.Connection.LocalPort == options.AgentPort)
                {
                    if (isApi) await context.RequestServices.GetRequiredService<AgentApi>().Handle(context);
                    else context.Response.StatusCode = 404;
                    return;
                }
                if (isApi) { context.Response.StatusCode = 404; return; }
                await next();
            });
            // 2. Portal: optional reverse proxy, source network filter, security headers.
            if (options.ForwardedHeadersNetworks.Length > 0) app.UseForwardedHeaders();
            app.Use(async (context, next) =>
            {
                var remote = context.Connection.RemoteIpAddress;
                if (remote != null && remote.IsIPv4MappedToIPv6) remote = remote.MapToIPv4();
                var health = context.Request.Path == "/healthz";
                if (remote == null || !(options.PortalAllowedNetworks.Any(n => n.Contains(remote)) || (health && IPAddress.IsLoopback(remote))))
                {
                    context.Response.StatusCode = 403;
                    await context.Response.WriteAsync("The SLAPS portal is not available from this network.");
                    return;
                }
                if (context.Connection.LocalPort == options.PortalHttpPort && options.PortalHttpPort > 0 && !context.Request.IsHttps)
                {
                    context.Response.StatusCode = 400;
                    await context.Response.WriteAsync("Plain HTTP is only accepted from the configured reverse proxy with X-Forwarded-Proto: https.");
                    return;
                }
                var headers = context.Response.Headers;
                headers["X-Content-Type-Options"] = "nosniff";
                headers["Referrer-Policy"] = "no-referrer";
                headers["X-Frame-Options"] = "DENY";
                headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self' " + FormActionSources(options);
                headers["Strict-Transport-Security"] = "max-age=31536000";
                await next();
            });
            app.MapGet("/healthz", () => Results.Text("ok"));
            app.UseStaticFiles(new StaticFileOptions { FileProvider = new PhysicalFileProvider(Path.Combine(AppContext.BaseDirectory, "assets")) });
            app.UseAuthentication();
            app.UseAuthorization();
            app.Use(async (context, next) =>
            {
                context.Response.Headers.CacheControl = "no-cache, no-store";
                context.Response.Headers.Pragma = "no-cache";
                await next();
            });
            PortalEndpoints.Map(app);
            app.MapRazorPages();
            return app;
        }

        // Sign-in provider plus the Entra admin consent of the Windows LAPS setup (form POST redirected to Microsoft).
        private static string FormActionSources(ServerOptions options)
        {
            var sources = new List<string> { "https://login.microsoftonline.com" };
            if (Uri.TryCreate(options.OidcAuthority, UriKind.Absolute, out var authority)) sources.Add(authority.GetLeftPart(UriPartial.Authority));
            return string.Join(" ", sources.Distinct(StringComparer.OrdinalIgnoreCase));
        }
    }
}
