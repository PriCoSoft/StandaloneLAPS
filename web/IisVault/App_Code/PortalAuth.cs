using System;
using System.Collections;
using System.Collections.Generic;
using System.Configuration;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using System.Web.Script.Serialization;
using System.Web.Security;

namespace StandaloneLapsWeb
{
    public sealed class PortalIdentity
    {
        public string Actor { get; set; }
        public string DisplayName { get; set; }
        public string Role { get; set; }
        public bool IsAdmin { get { return Role == "admin"; } }
    }

    public class TokenValidationException : Exception
    {
        public TokenValidationException(string message) : base(message) { }
    }

    public sealed class SigningKeyNotFoundException : TokenValidationException
    {
        public SigningKeyNotFoundException() : base("The token signing key is unknown.") { }
    }

    // Portal authentication: Microsoft Entra ID sign-in (OpenID Connect, ID token via form_post) for the
    // internal admin portal, or pinned reader/admin client certificates as a break-glass mode.
    // The agent API (api.aspx) never uses this class; it stays certificate-only.
    public static class PortalAuth
    {
        public const string AdminRole = "SLAPS.Admin";
        public const string ReaderRole = "SLAPS.Reader";
        public const string SessionCookie = "slaps_auth";
        public const string SignInCookie = "slaps_signin";
        private const string SessionPurpose = "StandaloneLaps.PortalSession.v1";
        private const string SignInPurpose = "StandaloneLaps.SignIn.v1";
        private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(8);
        private static readonly Regex ReturnUrlPattern = new Regex(@"^[A-Za-z]+\.aspx(\?[A-Za-z0-9_\-=&.%+]*)?$", RegexOptions.CultureInvariant);

        public static string Mode { get { return Vault.Setting("PortalAuthMode"); } }

        public static string TenantId { get { return RequiredGuid("EntraTenantId"); } }
        public static string ClientId { get { return RequiredGuid("EntraClientId"); } }

        public static string PublicBaseUrl
        {
            get
            {
                Uri uri;
                var value = Vault.Setting("PublicBaseUrl");
                if (!Uri.TryCreate(value, UriKind.Absolute, out uri) || uri.Scheme != Uri.UriSchemeHttps || !uri.AbsolutePath.EndsWith("/", StringComparison.Ordinal) ||
                    uri.Query.Length != 0 || uri.Fragment.Length != 0 || uri.UserInfo.Length != 0)
                    throw new ConfigurationErrorsException("PublicBaseUrl must be the HTTPS site URL ending in '/'.");
                return uri.AbsoluteUri;
            }
        }

        public static string RedirectUri { get { return PublicBaseUrl + "signin.aspx"; } }

        private static string RequiredGuid(string setting)
        {
            Guid value;
            if (!Guid.TryParse(Vault.Setting(setting), out value) || value == Guid.Empty) throw new ConfigurationErrorsException(setting + " must be configured.");
            return value.ToString("D");
        }

        // ---- Network restriction for everything except the agent API -------------------------------

        public static bool IsInternal(HttpRequest request)
        {
            return NetworkAllowed(request.UserHostAddress, Vault.List(Vault.Setting("PortalAllowedNetworks")));
        }

        public static bool NetworkAllowed(string remote, IEnumerable<string> networks)
        {
            IPAddress address;
            if (!IPAddress.TryParse(remote ?? "", out address)) return false;
            return networks.Any(network => InNetwork(address, network));
        }

        public static bool ValidNetwork(string cidr)
        {
            IPAddress network; int bits;
            return ParseNetwork(cidr, out network, out bits);
        }

        public static bool InNetwork(IPAddress address, string cidr)
        {
            IPAddress network; int bits;
            if (address == null || !ParseNetwork(cidr, out network, out bits)) return false;
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            var candidate = address.GetAddressBytes();
            var prefix = network.GetAddressBytes();
            if (candidate.Length != prefix.Length) return false;
            for (var i = 0; i < candidate.Length && bits > 0; i++, bits -= 8)
            {
                var mask = bits >= 8 ? (byte)0xFF : (byte)(0xFF << (8 - bits));
                if ((candidate[i] & mask) != (prefix[i] & mask)) return false;
            }
            return true;
        }

        private static bool ParseNetwork(string cidr, out IPAddress network, out int bits)
        {
            network = null; bits = -1;
            var parts = (cidr ?? "").Trim().Split('/');
            if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out network) ||
                !int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out bits)) return false;
            if (network.IsIPv4MappedToIPv6) network = network.MapToIPv4();
            return bits >= 0 && bits <= network.GetAddressBytes().Length * 8;
        }

        // ---- Identity -------------------------------------------------------------------------------

        // PREVIEW-AUTH-BEGIN
        public static PortalIdentity Current(HttpRequest request)
        {
            if (!request.IsSecureConnection || !IsInternal(request)) return null;
            if (Mode == "Certificate")
            {
                var client = Vault.CertificateClient(request);
                if (client == null || (client.role != "reader" && client.role != "admin")) return null;
                return new PortalIdentity { Actor = "certificate:" + client.certificateSha256, DisplayName = "Certificate " + client.certificateSha256.Substring(0, 12), Role = client.role };
            }
            return Mode == "Entra" ? ReadSession(request, DateTime.UtcNow) : null;
        }
        // PREVIEW-AUTH-END

        public static PortalIdentity Require(HttpContext context)
        {
            var identity = Current(context.Request);
            if (identity != null) return identity;
            var request = context.Request;
            if (Mode == "Entra" && request.HttpMethod == "GET" && request.IsSecureConnection && IsInternal(request))
            {
                var target = request.AppRelativeCurrentExecutionFilePath.TrimStart('~', '/') + request.Url.Query;
                context.Response.Redirect("~/signin.aspx?returnUrl=" + HttpUtility.UrlEncode(SafeReturnUrl(target)), true);
            }
            throw new HttpException(403, "Portal access denied.");
        }

        public static string SafeReturnUrl(string value)
        {
            return !string.IsNullOrEmpty(value) && value.Length <= 300 && ReturnUrlPattern.IsMatch(value) ? value : "Default.aspx";
        }

        public static void StartSession(HttpResponse response, PortalIdentity identity, DateTime utcNow)
        {
            var data = new Dictionary<string, string>
            {
                { "a", identity.Actor }, { "n", identity.DisplayName }, { "r", identity.Role },
                { "e", utcNow.Add(SessionLifetime).Ticks.ToString(CultureInfo.InvariantCulture) }
            };
            response.Cookies.Add(new HttpCookie(SessionCookie, Protect(Vault.Json.Serialize(data), SessionPurpose))
                { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = CookiePath });
        }

        public static void EndSession(HttpResponse response)
        {
            response.Cookies.Add(new HttpCookie(SessionCookie, "") { HttpOnly = true, Secure = true, SameSite = SameSiteMode.Lax, Path = CookiePath, Expires = DateTime.UtcNow.AddDays(-1) });
        }

        private static PortalIdentity ReadSession(HttpRequest request, DateTime utcNow)
        {
            var cookie = request.Cookies[SessionCookie];
            if (cookie == null || string.IsNullOrEmpty(cookie.Value)) return null;
            var data = ReadProtected(cookie.Value, SessionPurpose);
            if (data == null || !Fresh(data, utcNow)) return null;
            string actor, name, role;
            if (!data.TryGetValue("a", out actor) || !data.TryGetValue("n", out name) || !data.TryGetValue("r", out role) ||
                !actor.StartsWith("entra:", StringComparison.Ordinal) || (role != "admin" && role != "reader")) return null;
            return new PortalIdentity { Actor = actor, DisplayName = name, Role = role };
        }

        // ---- Entra sign-in --------------------------------------------------------------------------

        public static string BeginSignIn(HttpResponse response, string returnUrl)
        {
            var state = RandomToken();
            var nonce = RandomToken();
            var data = new Dictionary<string, string>
            {
                { "s", state }, { "n", nonce }, { "u", SafeReturnUrl(returnUrl) },
                { "e", DateTime.UtcNow.AddMinutes(10).Ticks.ToString(CultureInfo.InvariantCulture) }
            };
            // Entra returns the ID token as a cross-site form POST. The short-lived sign-in cookie therefore needs
            // SameSite=None; it is written as a raw header so this does not depend on the installed .NET patch level.
            response.AppendHeader("Set-Cookie", SignInCookie + "=" + Protect(Vault.Json.Serialize(data), SignInPurpose) +
                "; path=" + CookiePath + "; max-age=600; secure; httponly; samesite=none");
            return "https://login.microsoftonline.com/" + TenantId + "/oauth2/v2.0/authorize?client_id=" + ClientId +
                "&response_type=id_token&response_mode=form_post&scope=" + Uri.EscapeDataString("openid profile") +
                "&redirect_uri=" + Uri.EscapeDataString(RedirectUri) + "&state=" + state + "&nonce=" + nonce;
        }

        public static PortalIdentity CompleteSignIn(HttpContext context, out string returnUrl)
        {
            returnUrl = "Default.aspx";
            var request = context.Request;
            context.Response.AppendHeader("Set-Cookie", SignInCookie + "=; path=" + CookiePath + "; max-age=0; secure; httponly; samesite=none");
            var cookie = request.Cookies[SignInCookie];
            var data = cookie == null ? null : ReadProtected(cookie.Value, SignInPurpose);
            if (data == null || !Fresh(data, DateTime.UtcNow)) throw new TokenValidationException("The sign-in attempt expired. Please sign in again.");
            string state, nonce, target;
            if (!data.TryGetValue("s", out state) || !data.TryGetValue("n", out nonce) || !data.TryGetValue("u", out target) || !FixedTimeEquals(state, request.Form["state"]))
                throw new TokenValidationException("The sign-in response does not belong to this browser session.");
            if (!string.IsNullOrEmpty(request.Form["error"]))
                throw new TokenValidationException("Microsoft Entra ID did not sign you in (" + Truncate(request.Form["error"], 60) + ").");
            var token = request.Form["id_token"];
            PortalIdentity identity;
            try { identity = EntraTokenValidator.Validate(token, EntraSigningKeys.Get(TenantId, false), TenantId, ClientId, nonce, DateTime.UtcNow); }
            catch (SigningKeyNotFoundException) { identity = EntraTokenValidator.Validate(token, EntraSigningKeys.Get(TenantId, true), TenantId, ClientId, nonce, DateTime.UtcNow); }
            returnUrl = SafeReturnUrl(target);
            return identity;
        }

        public static string SignOutUrl { get { return "https://login.microsoftonline.com/" + TenantId + "/oauth2/v2.0/logout"; } }

        // ---- Admin consent for the Graph (Windows LAPS) application permission ------------------------
        // Entra returns to signin.aspx (already registered as redirect URI) with admin_consent/error and our state.

        private const string ConsentPurpose = "StandaloneLaps.AdminConsent.v1";

        public static string AdminConsentUrl(string tenantId, string clientId)
        {
            var data = new Dictionary<string, string> { { "c", "consent" }, { "e", DateTime.UtcNow.AddMinutes(15).Ticks.ToString(CultureInfo.InvariantCulture) } };
            return "https://login.microsoftonline.com/" + tenantId + "/v2.0/adminconsent?client_id=" + Uri.EscapeDataString(clientId) +
                "&scope=" + Uri.EscapeDataString("https://graph.microsoft.com/.default") + "&redirect_uri=" + Uri.EscapeDataString(RedirectUri) +
                "&state=" + Protect(Vault.Json.Serialize(data), ConsentPurpose);
        }

        public static bool ValidConsentState(string state)
        {
            if (string.IsNullOrEmpty(state) || state.Length > 2000) return false;
            var data = ReadProtected(state, ConsentPurpose);
            string kind;
            return data != null && Fresh(data, DateTime.UtcNow) && data.TryGetValue("c", out kind) && kind == "consent";
        }

        // ---- Helpers --------------------------------------------------------------------------------

        private static string CookiePath { get { var path = HttpRuntime.AppDomainAppVirtualPath; return string.IsNullOrEmpty(path) ? "/" : path; } }

        private static bool Fresh(IDictionary<string, string> data, DateTime utcNow)
        {
            string value; long ticks;
            return data.TryGetValue("e", out value) && long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out ticks) && ticks > utcNow.Ticks;
        }

        private static string Protect(string json, string purpose)
        {
            return EntraTokenValidator.Base64UrlEncode(MachineKey.Protect(Encoding.UTF8.GetBytes(json), purpose));
        }

        private static Dictionary<string, string> ReadProtected(string value, string purpose)
        {
            try
            {
                var bytes = MachineKey.Unprotect(EntraTokenValidator.Base64UrlDecode(value), purpose);
                return bytes == null ? null : Vault.Json.Deserialize<Dictionary<string, string>>(Encoding.UTF8.GetString(bytes));
            }
            catch (CryptographicException) { return null; }
            catch (FormatException) { return null; }
            catch (ArgumentException) { return null; }
            catch (InvalidOperationException) { return null; }
        }

        private static string RandomToken()
        {
            var bytes = new byte[32];
            using (var random = RandomNumberGenerator.Create()) random.GetBytes(bytes);
            return EntraTokenValidator.Base64UrlEncode(bytes);
        }

        public static bool FixedTimeEquals(string left, string right)
        {
            if (left == null || right == null || left.Length != right.Length) return false;
            var difference = 0;
            for (var i = 0; i < left.Length; i++) difference |= left[i] ^ right[i];
            return difference == 0;
        }

        private static string Truncate(string value, int length) { return value.Length <= length ? value : value.Substring(0, length); }
    }

    // Validates an Entra ID v2.0 ID token (RS256) against the tenant's published signing keys.
    public static class EntraTokenValidator
    {
        private const int ClockSkewSeconds = 300;

        public static PortalIdentity Validate(string token, string signingKeysJson, string tenantId, string clientId, string expectedNonce, DateTime utcNow)
        {
            if (string.IsNullOrEmpty(token) || token.Length > 20000) throw new TokenValidationException("The sign-in response contains no ID token.");
            var parts = token.Split('.');
            if (parts.Length != 3) throw new TokenValidationException("The ID token is malformed.");
            Dictionary<string, object> header, claims;
            byte[] signature;
            try
            {
                header = JsonObject(Base64UrlDecode(parts[0]));
                claims = JsonObject(Base64UrlDecode(parts[1]));
                signature = Base64UrlDecode(parts[2]);
            }
            catch (FormatException) { throw new TokenValidationException("The ID token is malformed."); }
            if (Text(header, "alg") != "RS256") throw new TokenValidationException("The ID token uses an unsupported signature algorithm.");
            var keyId = Text(header, "kid");
            if (string.IsNullOrEmpty(keyId)) throw new TokenValidationException("The ID token has no signing key ID.");
            using (var rsa = SigningKey(signingKeysJson, keyId))
                if (!rsa.VerifyData(Encoding.ASCII.GetBytes(parts[0] + "." + parts[1]), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
                    throw new TokenValidationException("The ID token signature is invalid.");

            tenantId = Guid.Parse(tenantId).ToString("D");
            clientId = Guid.Parse(clientId).ToString("D");
            if (Text(claims, "iss") != "https://login.microsoftonline.com/" + tenantId + "/v2.0") throw new TokenValidationException("The ID token was issued by an unexpected authority.");
            if (!string.Equals(Text(claims, "aud"), clientId, StringComparison.OrdinalIgnoreCase)) throw new TokenValidationException("The ID token was issued for a different application.");
            if (!string.Equals(Text(claims, "tid"), tenantId, StringComparison.OrdinalIgnoreCase)) throw new TokenValidationException("The ID token belongs to a different tenant.");
            var now = (long)(utcNow - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            if (Number(claims, "exp", true) + ClockSkewSeconds < now) throw new TokenValidationException("The ID token has expired. Please sign in again.");
            if (claims.ContainsKey("nbf") && Number(claims, "nbf", true) - ClockSkewSeconds > now) throw new TokenValidationException("The ID token is not valid yet. Check the server clock.");
            if (Number(claims, "iat", true) - ClockSkewSeconds > now) throw new TokenValidationException("The ID token is not valid yet. Check the server clock.");
            if (string.IsNullOrEmpty(expectedNonce) || !PortalAuth.FixedTimeEquals(Text(claims, "nonce"), expectedNonce)) throw new TokenValidationException("The ID token does not match this sign-in attempt.");
            Guid objectId;
            if (!Guid.TryParseExact(Text(claims, "oid") ?? "", "D", out objectId)) throw new TokenValidationException("The ID token contains no user object ID.");
            var roles = claims.ContainsKey("roles") && claims["roles"] is IEnumerable && !(claims["roles"] is string)
                ? ((IEnumerable)claims["roles"]).OfType<string>().ToArray() : new string[0];
            string role;
            if (roles.Contains(PortalAuth.AdminRole)) role = "admin";
            else if (roles.Contains(PortalAuth.ReaderRole)) role = "reader";
            else throw new TokenValidationException("Your account has no SLAPS role. Ask an administrator to assign SLAPS.Admin or SLAPS.Reader in the Entra enterprise application.");
            var name = Text(claims, "name") ?? Text(claims, "preferred_username") ?? objectId.ToString("D");
            if (name.Length > 128) name = name.Substring(0, 128);
            return new PortalIdentity { Actor = "entra:" + objectId.ToString("D"), DisplayName = name, Role = role };
        }

        private static RSA SigningKey(string signingKeysJson, string keyId)
        {
            Dictionary<string, object> document;
            try { document = JsonObject(Encoding.UTF8.GetBytes(signingKeysJson ?? "")); }
            catch (ArgumentException) { throw new TokenValidationException("The Entra signing key document is invalid."); }
            var keys = document.ContainsKey("keys") ? document["keys"] as IEnumerable : null;
            if (keys == null) throw new TokenValidationException("The Entra signing key document is invalid.");
            foreach (var entry in keys.OfType<Dictionary<string, object>>())
            {
                if (Text(entry, "kid") != keyId || Text(entry, "kty") != "RSA") continue;
                var use = Text(entry, "use");
                if (use != null && use != "sig") continue;
                var parameters = new RSAParameters { Modulus = Base64UrlDecode(Text(entry, "n") ?? ""), Exponent = Base64UrlDecode(Text(entry, "e") ?? "") };
                if (parameters.Modulus.Length < 256 || parameters.Exponent.Length == 0) throw new TokenValidationException("The Entra signing key is too weak.");
                var rsa = new RSACng();
                rsa.ImportParameters(parameters);
                return rsa;
            }
            throw new SigningKeyNotFoundException();
        }

        private static Dictionary<string, object> JsonObject(byte[] utf8)
        {
            var value = new JavaScriptSerializer { MaxJsonLength = 1048576, RecursionLimit = 16 }.DeserializeObject(Encoding.UTF8.GetString(utf8)) as Dictionary<string, object>;
            if (value == null) throw new FormatException("JSON object expected.");
            return value;
        }

        private static string Text(IDictionary<string, object> values, string name)
        {
            object value;
            return values.TryGetValue(name, out value) ? value as string : null;
        }

        private static long Number(IDictionary<string, object> values, string name, bool required)
        {
            object value;
            if (!values.TryGetValue(name, out value) || value == null || value is string || value is bool)
            {
                if (required) throw new TokenValidationException("The ID token has no valid '" + name + "' claim.");
                return 0;
            }
            try { return Convert.ToInt64(value, CultureInfo.InvariantCulture); }
            catch (Exception) { throw new TokenValidationException("The ID token has no valid '" + name + "' claim."); }
        }

        public static byte[] Base64UrlDecode(string value)
        {
            var text = (value ?? "").Replace('-', '+').Replace('_', '/');
            switch (text.Length % 4) { case 2: text += "=="; break; case 3: text += "="; break; case 1: throw new FormatException("Invalid base64url text."); }
            return Convert.FromBase64String(text);
        }

        public static string Base64UrlEncode(byte[] value)
        {
            return Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }

    // Caches the tenant signing keys; refreshes daily and, rate-limited, when an unknown key ID appears.
    public static class EntraSigningKeys
    {
        private static readonly object Gate = new object();
        private static string cached;
        private static DateTime fetchedUtc, forcedUtc;

        public static string Get(string tenantId, bool forceRefresh)
        {
            lock (Gate)
            {
                var now = DateTime.UtcNow;
                if (cached != null && !forceRefresh && now - fetchedUtc < TimeSpan.FromHours(24)) return cached;
                if (cached != null && forceRefresh && now - forcedUtc < TimeSpan.FromMinutes(5)) return cached;
                if (forceRefresh) forcedUtc = now;
                cached = Download("https://login.microsoftonline.com/" + tenantId + "/discovery/v2.0/keys");
                fetchedUtc = now;
                return cached;
            }
        }

        private static string Download(string url)
        {
            var request = (HttpWebRequest)WebRequest.Create(url);
            request.Method = "GET"; request.Timeout = 15000; request.ReadWriteTimeout = 15000; request.AllowAutoRedirect = false;
            var proxy = Vault.Setting("OutboundProxyUrl");
            if (!string.IsNullOrWhiteSpace(proxy)) request.Proxy = new WebProxy(new Uri(proxy, UriKind.Absolute));
            try
            {
                using (var response = (HttpWebResponse)request.GetResponse())
                using (var reader = new StreamReader(response.GetResponseStream(), Encoding.UTF8))
                {
                    var buffer = new char[1048577]; var used = 0; int read;
                    while (used < buffer.Length && (read = reader.Read(buffer, used, buffer.Length - used)) > 0) used += read;
                    if (used > 1048576) throw new TokenValidationException("The Entra signing key document is too large.");
                    return new string(buffer, 0, used);
                }
            }
            catch (WebException) { throw new TokenValidationException("The server cannot reach login.microsoftonline.com to download the Entra signing keys. Check outbound HTTPS or OutboundProxyUrl."); }
        }
    }
}
