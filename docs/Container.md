# SLAPS container server (Docker)

The container server is an alternative to the IIS backend. It runs on any Docker host (Linux or Windows with
Linux containers) and offers the same functions: agent API, internal portal with OpenID Connect sign-in
(Microsoft Entra ID or another provider), password history and reveal, **Add client** with certificate packages
for Windows and Linux, delete/restore and retention. Existing agents work unchanged: the agent API has the same
path (`api.aspx`), parameters, status codes and JSON as the IIS backend.

Storage: **SQLite** (default, one file in the data volume) or **PostgreSQL**.

## Architecture

```text
Managed server (agent)                          Docker host
 StandaloneLapsAgent / slaps-agent ── TLS, client certificate ──> :8444  agent API only (api.aspx)
                                                                          handshake requires a certificate from the SLAPS CA,
                                                                          every request checks the SHA-256 pin of the device
Admin workstation ── browser ─────────────────────────────────> :8443  portal (no client certificate prompt)
                                                                          source networks filtered, OIDC sign-in, app roles
                                         container "slaps" (non-root, .NET 10)
                                          /data  SQLite database (or PostgreSQL service)
                                          SLAPS_MASTER_KEY (Docker secret)
```

Two ports keep the portal and the agent API apart: the agent port only completes the TLS handshake with a
certificate from the server's own SLAPS CA, so browsers never see a certificate prompt and unauthenticated
clients never reach application code. Open 8444 from the managed servers and 8443 only from admin networks.

## How passwords are protected

Passwords are not hashed ("salted"): LAPS has to give an administrator the actual password back, and a hash
cannot be reversed. Instead every password version is **encrypted on the managed server** before it is sent:

- a fresh AES-256-GCM key per version, wrapped with the **recovery certificate** (RSA 4096, RSA-OAEP-SHA256),
- the server stores only this encrypted envelope (same format as the IIS backend),
- the private keys of the recovery certificate and of the SLAPS CA are stored in the database as PKCS#12
  (PBES2/AES-256), encrypted with the **master key** that the container receives as a Docker secret.

A copy of the database or volume alone therefore reveals no passwords and cannot issue agent certificates.
Device names, timestamps and the audit log are stored unencrypted. Portal sessions use in-memory keys:
a restart signs everybody out, and nothing in the volume can be used to forge a session.

Whoever controls the running container (or has the master key plus the database) can decrypt passwords,
exactly like an administrator of the IIS server in the IIS variant. Keep the master key offline as well:
**without it the database cannot be used.**

## Prebuilt image and automatic updates

Every release is also published as a ready-made image (linux/amd64 and linux/arm64) in the GitHub Container
Registry. It is built by GitHub Actions from the signed container package of the release, so it contains the same
server and the same signed agent files.

| Tag | Follows |
|---|---|
| `ghcr.io/pricosoft/standalonelaps:1.6.2` | exactly this release (manual updates) |
| `ghcr.io/pricosoft/standalonelaps:1.6` | all 1.6.x patch releases (recommended for automatic updates) |
| `ghcr.io/pricosoft/standalonelaps:1` | all 1.x releases |
| `ghcr.io/pricosoft/standalonelaps:latest` | every release |

Use `compose.image.yaml` instead of `compose.yaml` (same settings, no `build:`). Update with
`docker compose -f compose.image.yaml pull && docker compose -f compose.image.yaml up -d`, or let an updater
(e.g. Watchtower) watch the container. The data volume, the master key secret and the settings are kept; the
database schema is upgraded on start. As with every update, back up the `/data` volume first (for SQLite) or the
PostgreSQL database.

## Quick start (release package)

Download `StandaloneLaps-Container-<version>-<timestamp>.zip` from the
[GitHub releases](../../../releases) and extract it on the Docker host. It contains the published server, the
signed Windows/Linux agent files for client packages, a `Dockerfile`, `compose.yaml` and `compose.postgres.yaml`.

1. Create the master key (keep a copy offline):

   ```bash
   mkdir secrets
   openssl rand -base64 48 > secrets/slaps_master_key.txt
   sudo chown 1654 secrets/slaps_master_key.txt && sudo chmod 0400 secrets/slaps_master_key.txt
   ```

2. Register the app in Microsoft Entra ID (see below) and edit `compose.yaml`: `Slaps__PublicUrl`,
   `Slaps__AgentApiUrl`, `Slaps__OidcAuthority`, `Slaps__OidcClientId`, `Slaps__PortalAllowedNetworks`.
3. TLS (recommended): put `tls.crt` (certificate plus intermediates, PEM) and `tls.key` into `./certs`, uncomment
   the certificate lines and the `./certs` volume. Use a certificate the managed servers already trust.
4. Start: `docker compose up -d --build`, then `docker compose logs -f slaps`.
5. Open `https://<host>:8443/` from an admin network, sign in with the role `SLAPS.Admin`, open **Add client**.
   On the managed server, run `Install.cmd` (Windows) or `sudo sh install.sh` (Linux). The installer's connectivity
   test must report GET 200 / PUT 400.

From source: copy the agent files into `container/agent-package/` (see the README there), then
`docker compose -f container/compose.yaml up -d --build` from the repository root.

## Microsoft Entra ID app registration

Same as for the IIS portal, with a different redirect URI:

- Redirect URI (platform *Web*): `https://<host>:8443/signin-oidc`
- *Authentication*: enable **ID tokens** (no client secret needed). Alternatively create a client secret and set
  `Slaps__OidcClientSecretFile`; the server then uses the authorization code flow with PKCE.
- App roles `SLAPS.Admin` and `SLAPS.Reader`, enterprise application with *Assignment required = Yes*.
- `Slaps__OidcAuthority`: `https://login.microsoftonline.com/<tenant-id>/v2.0`, `Slaps__OidcClientId`: application ID.

Other OpenID Connect providers (Keycloak, Authentik, ...) work as well: set `Slaps__OidcRoleClaim`,
`Slaps__AdminRole`, `Slaps__ReaderRole`, `Slaps__OidcIdClaim` (default `oid`, falls back to `sub`) and
`Slaps__OidcNameClaim` to match the provider's ID token. Users without one of the roles get "Access denied".

## TLS certificate

| Option | Settings |
|---|---|
| PEM files (recommended) | `Slaps__TlsCertificatePath`, `Slaps__TlsKeyPath` (unencrypted key); intermediates after the first certificate are sent |
| PFX | `Slaps__TlsPfxPath`, `Slaps__TlsPfxPasswordFile` |
| None | The server generates a **self-signed end-entity certificate** for the host names of `PublicUrl`, `AgentApiUrl` and `TlsDnsNames` (renewed automatically 60 days before expiry; agents must then trust the new one). Download it on **Settings > Certificates** and import it on every managed server: Windows `certutil -addstore Root SLAPS-TLS.cer`, Linux `CaFile=/etc/slaps/slaps-tls.pem` in `agent.conf`. It is not a CA, so trusting it trusts only this server. |

## Configuration reference

All settings are environment variables `Slaps__<Name>`. Secrets can also be given as `Slaps__<Name>File`.

| Setting | Default | Meaning |
|---|---|---|
| `SLAPS_MASTER_KEY` / `SLAPS_MASTER_KEY_FILE` | — (required) | At least 32 characters; encrypts the CA, recovery and generated TLS keys |
| `PublicUrl` | — (required) | Portal URL, e.g. `https://slaps.example.com:8443/` |
| `AgentApiUrl` | — (required) | URL written into client packages, e.g. `https://slaps.example.com:8444/` |
| `PortalPort` / `AgentPort` | 8443 / 8444 | Container ports (must differ) |
| `PortalAllowedNetworks` | private ranges | CIDR list (`;`) allowed to open the portal |
| `OidcAuthority`, `OidcClientId`, `OidcClientSecret` | — | Sign-in (secret optional) |
| `OidcRoleClaim`, `AdminRole`, `ReaderRole` | `roles`, `SLAPS.Admin`, `SLAPS.Reader` | Role mapping |
| `DatabaseProvider` | `sqlite` | `sqlite` or `postgresql` |
| `ConnectionString` | `Data Source=/data/slaps.db` | SQLite file or Npgsql connection string |
| `EnableWebDecryption` | `true` | `false` hides passwords in the portal (offline recovery only) |
| `TlsCertificatePath`, `TlsKeyPath`, `TlsPfxPath`, `TlsPfxPassword`, `TlsDnsNames` | — | TLS (see above) |
| `PortalHttpPort`, `ForwardedHeadersNetworks` | 0, — | Optional plain-HTTP portal port behind a reverse proxy that sends `X-Forwarded-*`; only proxies in the listed networks are trusted. The agent port must never be behind a TLS-terminating proxy. |
| `ServerName` | host of `PublicUrl` | Used in the CA and recovery certificate names |

## PostgreSQL

```bash
docker compose -f compose.yaml -f compose.postgres.yaml up -d --build
```

Create `secrets/postgres_password.txt` (owner uid 999) and `secrets/slaps_db_connection.txt` (owner uid 1654) with
`Host=postgres;Database=slaps;Username=slaps;Password=<same password>`. An external PostgreSQL server works too:
set only `Slaps__DatabaseProvider=postgresql` and the connection string. Run one SLAPS container per database.

## Operations

- **Backup:** the volume `slaps-data` (SQLite: stop the container or copy `slaps.db`, `slaps.db-wal` together) or a
  PostgreSQL dump, plus the master key stored separately.
- **Offline recovery key:** `docker compose exec -it slaps dotnet StandaloneLaps.Server.dll export-recovery-key /data/recovery.pfx`
  asks for a new PFX password (or `SLAPS_EXPORT_PASSWORD`). Move the file to an offline safe and delete it from the volume.
  With it, `StandaloneLaps.Agent.exe recover envelope.json recovery.pfx` decrypts a downloaded envelope.
  `export-ca-key` exports the SLAPS CA the same way.
- **Update:** extract the new release package, keep `secrets/` and `compose.yaml` settings, `docker compose up -d --build`.
  The data volume is kept.
- **Health:** `/healthz` on the portal port (loopback always allowed); the image has a Docker `HEALTHCHECK`.
- **Audit:** all API, portal and key actions are written to the `slaps_audit` table.

## Migrating from the IIS backend

1. On the IIS server, keep the **key backup PFX files** created by `Install-SlapsServer.ps1` (SLAPS CA and recovery
   certificate) and copy `App_Data` (with `Vault` and `clients.json`) to the Docker host.
2. Before the first start of the container, import the keys into the empty database:

   ```bash
   docker compose run --rm -it -v "$PWD/iis:/import:ro" slaps import-keys --ca /import/slaps-ca.pfx --recovery /import/slaps-recovery.pfx
   ```

   (`--previous-recovery <pfx>` for older recovery keys.)
3. Import devices and history: `docker compose run --rm -v "$PWD/iis:/import:ro" slaps import-iis-vault /import/App_Data`
4. Point the agents to the agent port: either publish the agent port as the old URL (e.g. map host port 443 of the
   old host name to container port 8444, `"443:8444"`, and use another name or port for the portal), or rerun the
   client installer with `-ApiUrl https://<host>:8444/` (Linux: `--api-url`).

Agent certificates issued by the IIS server stay valid because the same SLAPS CA is imported; their pins come
from the imported client list.

## Windows LAPS lookup

Like the IIS portal (see README, "Windows LAPS lookup"), the container can **read** Windows LAPS and legacy LAPS passwords from Active Directory and Microsoft Entra ID. Everything is off by default; search and reveal are audited.

**Active Directory on Linux** works like [LAPS-WebUI](https://seji64.github.io/LAPS-WebUI/):

- LDAP via `System.DirectoryServices.Protocols` (libldap in the image) with a simple bind of a **service account over LDAPS (636)**. Plain LDAP with a password is refused. If the DC certificate is issued by an internal CA, mount a directory with the CA certificate (OpenSSL hashed directory, `c_rehash`) and set `WindowsLapsAdCaDirectory`.
- Encrypted passwords (`msLAPS-Encrypted*`) are decrypted by `/app/dpapi/slaps_dpapi_ng.py` with the Python library [dpapi-ng](https://github.com/jborean93/dpapi-ng) (installed in a venv at `/opt/dpapi` by the Dockerfile). It fetches the group key from the DC over RPC (MS-GKDI, TCP 135 + dynamic RPC ports) with the same service account. Credentials and blobs go to the helper through stdin, never the command line. Default authentication is NTLM via pyspnego; for Kerberos build with `--build-arg SLAPS_DPAPI_KERBEROS=true` and provide a `krb5.conf`.
- The service account needs read permission on the LAPS attributes (`Set-LapsADReadPasswordPermission`, `Set-AdmPwdReadPasswordPermission`) and must be a member of the group in the LAPS policy *Configure authorized password decryptors*.
- On a Windows host (development) the server uses native DPAPI-NG with its own identity when no service account is configured.

**Entra ID:** app-only Graph access with `DeviceLocalCredential.Read.All` (application permission, admin consent). Use a certificate (PFX as Docker secret) or a client secret. The setup assistant with self-renewing certificate exists only in the IIS portal so far; in the container provide the PFX and renew it yourself. The search shows only computers with a stored password, the AD description and the stored kinds; mixed legacy/Windows LAPS computers show both passwords. Settings shows the configuration with *Test connection* buttons.

| Setting (`Slaps__…`) | Default | Meaning |
|---|---|---|
| `WindowsLapsRequiredRole` | `Admin` | `Admin` or `Reader` |
| `WindowsLapsAdEnabled` | `false` | Active Directory lookup |
| `WindowsLapsAdServer` | — (required on Linux) | DC host name (LDAP and DPAPI-NG key server) |
| `WindowsLapsAdUseSsl`, `WindowsLapsAdPort` | `true`, 636 | LDAPS; must stay on with a service account on Linux |
| `WindowsLapsAdUsername`, `WindowsLapsAdPassword[File]` | — (required on Linux) | Service account (UPN) |
| `WindowsLapsAdSearchBase` | domain | Limit to an OU |
| `WindowsLapsAdCaDirectory` | — | Trusted CA directory for LDAPS (Linux) |
| `WindowsLapsAdLegacy`, `WindowsLapsAdModern`, `WindowsLapsAdDecrypt`, `WindowsLapsAdHistory` | `true` | What to read |
| `WindowsLapsAdDecryptMode` | `auto` | `auto` (native on Windows without service account, else Python), `native`, `python` |
| `WindowsLapsAdDecryptServer`, `WindowsLapsAdDecryptAuth` | AD server, `negotiate` | RPC target and `negotiate`/`kerberos`/`ntlm` for dpapi-ng |
| `WindowsLapsPython`, `WindowsLapsDpapiScript` | `/opt/dpapi/bin/python` (image), `/app/dpapi/slaps_dpapi_ng.py` | Helper location |
| `WindowsLapsEntraEnabled` | `false` | Entra ID lookup |
| `WindowsLapsEntraTenantId`, `WindowsLapsEntraClientId` | from `OidcAuthority` / `OidcClientId` | App registration for Graph |
| `WindowsLapsEntraCertificatePath`, `WindowsLapsEntraCertificatePassword[File]` | — | PFX for the client assertion (recommended) |
| `WindowsLapsEntraClientSecret[File]` | — | Alternative to the certificate |
| `WindowsLapsEntraHistory` | `true` | Show older Entra passwords |

## Limits

- Windows LAPS lookup (1.6.0): the Python dpapi-ng path, LDAPS on Linux and the Docker image build have not been run yet (no Docker/Python on the development host); Graph and the helper protocol are tested with fakes.
- One container instance per database (write serialization and API rate limit are in-process).
- The portal has no local accounts: an OpenID Connect provider is required.
- Development sign-in (`Slaps__AuthMode=Development`) works only with `ASPNETCORE_ENVIRONMENT=Development` and only
  from loopback; it exists for tests.
