# Standalone LAPS (SLAPS)

Policy-controlled local administrator password rotation for standalone/DMZ Windows servers. Each server runs a small Windows service that reads the **Windows-supplied System > LAPS policy**, generates a new password, encrypts it, backs it up to a dedicated IIS server over HTTPS with a client certificate, verifies the backup and only then changes the account. The IIS server hosts an **internal admin portal** (Microsoft Entra ID sign-in) where administrators view history, reveal passwords and **add clients**: the server issues the agent certificate itself and offers a ready-to-install client package.

Everything targets **.NET Framework 4.7.2**, which ships with Windows Server 2019. No .NET runtime, SDK, NuGet package, ASP.NET Core hosting bundle or application DLL is deployed. The IIS site is source-only ASP.NET Web Forms; ASP.NET compiles it at runtime. This is an independent implementation, not a replacement for Microsoft's native LAPS engine.

**Download:** ready-to-install, code-signed server packages (`StandaloneLaps-Server-<version>-<timestamp>.zip`, including the Windows and Linux agents) are attached to the [GitHub releases](../../releases). Building from source is only needed for changes.

## Architecture

```text
DMZ server (workgroup)                          IIS server (internal)
 gpedit: System > LAPS policy                    https://slaps.example.com/
 StandaloneLapsAgent service ── HTTPS 443 ──────> api.aspx      agent API, client certificate only
   agent certificate (SLAPS CA, 30 years)          Default.aspx  portal, Entra sign-in, internal networks only
   recovery.cer (public key)                       addclient.aspx  issue certificate + client package
 HKLM\SOFTWARE\PriCoSoft\SLAPS                     App_Data\Vault  encrypted history (files)
                                                   LocalMachine\My: TLS cert, SLAPS CA key, recovery key
Admin workstation (internal network) ── browser ──> portal ──> login.microsoftonline.com (OIDC)
```

- **Agent API** (`api.aspx`): reachable from the DMZ; every request needs a client certificate that is valid, trusted by IIS and pinned by SHA-256. An agent can only write and read its own device.
- **Portal** (all other pages): only from the networks in `PortalAllowedNetworks`; other sources (e.g. the DMZ) get 403 before any sign-in. Users sign in with Microsoft Entra ID; access requires an app role (`SLAPS.Admin` or `SLAPS.Reader`) on an enterprise application with *Assignment required = Yes*.
- **Encryption**: each version uses a fresh AES-256-GCM key wrapped with the recovery certificate (RSA-OAEP-SHA256). The server stores ciphertext only. Because the recovery private key is installed on the IIS server, administrators can reveal passwords in the portal; keep an offline backup of that key.

## Install the IIS server

Prerequisites:

1. Windows Server 2019 or later, joined or standalone, with outbound HTTPS to `login.microsoftonline.com` (set `OutboundProxyUrl` in web.config if a proxy is required).
2. A DNS name for the service (e.g. `slaps.example.com`) that resolves for admins and DMZ servers, and its **TLS server certificate with private key in LocalMachine\My**. DMZ servers must trust the issuing CA.
3. The Entra app registration (next section): tenant ID and application (client) ID.
4. Firewall: TCP 443 from the DMZ servers and from the internal admin networks to the IIS server.

Build the package on a development machine (`scripts\Build-ServerPackage.ps1` → `artifacts\StandaloneLaps-Server-<timestamp>.zip`), copy it to the server, extract it and run in an elevated **Windows PowerShell 5.1**:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Install-SlapsServer.ps1 -TargetDirectory D:\Web\SLAPS -HostName slaps.example.com
```

The installer needs only these two values. It

- installs IIS with ASP.NET 4.x,
- finds the valid TLS certificate for the host name in LocalMachine\My (or use `-CertificateThumbprint`),
- inspects existing HTTPS bindings: other sites on port 443 stay untouched; it refuses if another site already uses the same host name,
- creates the application pool and website `SLAPS` with an **SNI binding** `*:443:<host>` (HTTP/2 disabled, on Server 2022+ also TLS 1.3, because client certificates are requested by renegotiation), *SSL required*, client certificates *Accept* **only on `api.aspx`** (portal pages never trigger a browser certificate prompt; with `PortalAuthMode=Certificate` the whole site accepts client certificates), `uploadReadAheadSize` 128 KiB — all through IIS configuration, no `netsh` settings that IIS Manager would overwrite,
- copies the website; on an upgrade it backs up the previous directory, keeps `App_Data\Vault` and `clients.json` and merges web.config,
- grants the pool read access to the site and Modify only on `App_Data\Vault`,
- creates, if missing, the **SLAPS CA** (RSA 4096, 35 years) and the **recovery certificate** (RSA 4096, 30 years) in LocalMachine\My, trusts the CA on this server, imports an empty CRL valid until the CA expires into the intermediate CA store (so agent certificates validate without network access) and grants the pool read access to both private keys,
- asks for a password, exports both new keys as PFX backups (store them offline), verifies the backups and re-imports the keys on the server as **non-exportable** (see *Key protection*),
- asks once for the Entra tenant ID, client ID and the internal networks (CIDR list), writes web.config (including a generated machine key) and runs a smoke test.

Rerun the same command to upgrade or repair; stored answers are reused. Optional parameters: `-TenantId`, `-ClientId`, `-PortalAllowedNetworks`, `-CertificateThumbprint`, `-SiteName`, `-AppPoolName`, `-KeyBackupDirectory`.

### Key protection

After the backup, the SLAPS CA and recovery keys on the server cannot be exported (no PFX export in certlm.msc or PowerShell). The pool can still sign and decrypt with them. This stops casual or accidental key copies; it does not stop an attacker with administrator rights or code execution in the pool, who can still use the keys on the server. The offline PFX backups are therefore the only copies you can move, so keep them and their password in a safe.

If the backup was skipped, the keys stay exportable and the installer warns on every run. To lock them later: export each key with certlm.msc (*Yes, export the private key*), store the PFX offline, delete the certificate including its key, and re-import it as non-exportable into the CNG provider:

```powershell
certutil -f -csp "Microsoft Software Key Storage Provider" -importpfx My .\slaps-recovery.pfx NoExport
```

Then rerun the installer to grant the pool access to the new key files. For a migration to a new server, import the offline backups the same way.

## Microsoft Entra sign-in

The portal uses OpenID Connect directly (ID token via `form_post`, no client secret). The server validates the token signature against the tenant's published keys and checks issuer, audience, tenant, lifetime, nonce and state. Create the app once in the Entra admin center:

1. **App registrations > New registration**: name `SLAPS`, *Accounts in this organizational directory only*, redirect URI platform **Web** = `https://slaps.example.com/signin.aspx`.
2. **Authentication**: enable **ID tokens (used for implicit and hybrid flows)**. No client secret is needed.
3. **App roles > Create app role** twice (allowed member types: Users/Groups):
   - display name *SLAPS Admin*, value **`SLAPS.Admin`** — full access including Add client, delete/restore and reveal,
   - display name *SLAPS Reader*, value **`SLAPS.Reader`** — view history, download envelopes, reveal passwords.
4. **API permissions**: keep *Microsoft Graph > User.Read* (delegated) and click **Grant admin consent** so users are not asked for consent.
5. **Enterprise applications > SLAPS > Properties**: **Assignment required = Yes** (optionally *Visible to users = No*).
6. **Users and groups > Add user/group**: assign users or groups with the SLAPS Admin or SLAPS Reader role. Assigned users without a SLAPS role are denied.
7. Note the **Directory (tenant) ID** and **Application (client) ID** for the installer. Conditional Access policies targeting this app apply as usual.

Sessions last 8 hours (`slaps_auth` cookie, protected with the machine key). *Sign out* ends the SLAPS session and offers the Microsoft sign-out. Break-glass alternative: `PortalAuthMode=Certificate` accepts pinned client certificates with role `reader`/`admin` from `clients.json` (still limited to `PortalAllowedNetworks`).

## Add a client

1. Sign in as **SLAPS.Admin** and choose **Add client**. Enter the server's computer name.
2. The server issues an agent certificate from its SLAPS CA (RSA 3072, Client Authentication, end entity, valid 30 years), pins its SHA-256 for a new device ID and builds `SLAPS-Agent-<name>.zip`.
3. The **PFX password is shown once**. The ZIP is downloadable for 24 hours; it is useless without the password.
4. For an existing portal-managed device, **New certificate package** in the device drawer issues a replacement certificate: the old pin is revoked immediately, history and device ID stay.

Package contents: `Install.cmd`, `Install-SlapsAgent.ps1`, `slaps-settings.json` (device ID, API URL, certificate fingerprints), `agent.pfx`, `recovery.cer`, `bin\StandaloneLaps.Agent.exe(.config)`, `README.txt`.

## Install the agent from a client package

On the DMZ server, extract the ZIP, right-click **Install.cmd > Run as administrator** and enter the PFX password. `Install-SlapsAgent.ps1`

- checks 64-bit Windows, .NET Framework 4.7.2+, not a domain controller, and the System > LAPS policy (BackupDirectory must be Disabled; automatic account management, post-authentication actions and complexity 5–8 are unsupported),
- imports the agent certificate into LocalMachine\My (private key not exportable) and verifies its fingerprint,
- installs or upgrades the service `StandaloneLapsAgent` (LocalSystem, automatic start, restart on failure) in `%ProgramFiles%\StandaloneLapsAgent`, with state in `%ProgramData%\StandaloneLaps`,
- writes `HKLM\SOFTWARE\PriCoSoft\SLAPS` (64-bit, SYSTEM/Administrators only) and removes a superseded agent certificate,
- runs `StandaloneLaps.Agent.exe validate-config`, tests the API (history read must return 200, an authenticated test upload 400) and starts the service.

Parameters override the predefined values: `-ApiUrl`, `-InstallDirectory`, `-PfxPassword`, `-NoStart`, `-SkipConnectivityTest`, `-KeepCertificate`; `-Uninstall` removes service, settings, files and the agent certificate. Delete the package afterwards; `agent.pfx` contains the private key.

**Agent type:** the agent is a Windows service, not a Group Policy client-side extension. It is still controlled by Group Policy: it rereads the System > LAPS policy and its registry settings every five minutes, and a missing local state triggers the first rotation immediately.

## Linux agent

Choose **Linux (systemd)** in **Add client** (also for **New certificate package**). The ZIP `SLAPS-Agent-<name>-linux.zip` contains `install.sh`, `slaps-agent_<version>_all.deb`, the plain agent files, `agent.pfx`, `recovery.cer` and `slaps-settings.json`. On the server:

```bash
python3 -m zipfile -e SLAPS-Agent-<name>-linux.zip .
cd SLAPS-Agent-<name>-linux && sudo sh install.sh
```

`install.sh` checks systemd, python3 ≥ 3.6, openssl and chpasswd; installs the `.deb` with dpkg on Debian/Ubuntu, otherwise copies `/usr/sbin/slaps-agent` and `/etc/systemd/system/slaps-agent.service` (RHEL, SUSE, …); runs `slaps-agent self-test`; asks for the PFX password and enrolls (key → `/etc/slaps/agent.key`, mode 600; certificate, recovery certificate and settings in `/etc/slaps`); validates; tests the API (GET 200 / PUT 400) and starts `slaps-agent.service`. Options: `--api-url`, `--no-start`, `--skip-connectivity-test`, `--uninstall [--purge]`.

- **Runtime:** a Python 3 script using only the standard library; AES-256-GCM through the system libcrypto (ctypes), RSA-OAEP-SHA256 and PKCS#12 through the `openssl` command (`-legacy` fallback for Windows-exported PFX files on OpenSSL 3). No pip packages. Same envelope format, backup-verify-then-set sequencing and API as the Windows agent; HTTPS is limited to TLS 1.2 because IIS requests the client certificate by renegotiation.
- **Password rules:** `/etc/slaps/agent.conf` (conffile of the .deb): `Account` (default `root`), `PasswordLength` 8–64 (14), `PasswordComplexity` 1–4 (4), `PasswordAgeDays` 1–365 (30), optional `CaFile` for the server's TLS CA. Reread every five minutes. Setting a password on a locked root account unlocks it for console/su; sshd's default `PermitRootLogin prohibit-password` keeps SSH password logins blocked.
- **Commands:** `slaps-agent validate-config | test-connection | once | rotate-now | self-test | enroll <dir>`; log `journalctl -u slaps-agent` (1000 rotated, 1001 failed, 1002 started/stopped). State: `/var/lib/slaps/state.json`.
- **Not supported on Linux:** post-authentication actions; passwords are set with `chpasswd` (PAM password-quality modules may reject short rules).
- The `.deb` alone (server package `linux\`) suits distribution tools; enroll afterwards with `sudo slaps-agent enroll <extracted client package>` (`SLAPS_PFX_PASSWORD` environment variable or prompt).
## Password policy (System > LAPS)

Open `gpedit.msc` on each standalone server: **Computer Configuration > Administrative Templates > System > LAPS**. The agent reads the 64-bit key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS`.

| Built-in value | Agent behavior |
| --- | --- |
| `PasswordAgeDays` | 1–365 days; default 30. |
| `PasswordLength` | 8–64 characters; default 14. Choose a stronger explicit value. |
| `PasswordComplexity` | 1 uppercase; 2 upper/lowercase; 3 plus digits; 4 plus special characters (default). 5–8 are rejected. |
| `AdministratorAccountName` | Empty: built-in administrator by RID 500 (also when renamed). Otherwise the named existing local account, only if it is a member of the local Administrators group. No account is created or enabled. |
| `BackupDirectory` | **Must be Disabled (0) or absent.** It controls Microsoft's engine (Entra ID/AD targets) and would compete with this agent. |
| `PostAuthenticationResetDelay`, `PostAuthenticationActions` ("Post-authentication actions") | Supported like Windows LAPS: when the managed account signs in after the last rotation, the password is reset when the grace period (0–24 h, default **24**; **0 disables** the feature) has passed, then the action runs: **1** reset only, **3** (default) reset and sign out interactive sessions with a two-minute warning and delete the account's SMB sessions, **5** reset and restart after one minute, **11** like 3 plus terminate remaining processes of the account. Note: as with Windows LAPS, *Not configured* means the defaults (24 h, action 3) apply. |
| `AutomaticAccountManagementEnabled` | Must be 0/absent. |
| AD encryption/history, DSRM, expiration protection | Not used. Retention is set on the portal's Settings page (default 20 versions per device). |

**Detecting use of the account:** the agent checks every five minutes for a successful sign-in of the managed account after the last rotation: the SAM "last logon" time and Security event 4624 (covers network/SMB sign-ins when logon auditing is enabled, the Windows Server default). The password is reset only after the new password is backed up and verified, exactly like a scheduled rotation; the action runs afterwards. A failing action is logged as warning 1004 but does not undo the reset. Events: 1003 = use detected and reset time scheduled, 1000 = reset done (with reason), 1001 = cycle failed (with reason). As with Windows LAPS, an administrator who signs in with the password can work around these mechanisms; they limit how long a revealed password stays valid. `validate-config` prints the effective settings.

Do not let another product rotate the same account. Domain controllers are rejected. Windows password filters can reject a generated password; such attempts remain unconfirmed and are retried.

Rotation order: generate → encrypt → upload → server stores durably → read back and compare → change the SAM account → save local state atomically → report applied. A failed backup prevents the change. Lost reports are retried without another reset. The password from before the first installation is unknown to this product.

## View history and recover passwords

Open `https://slaps.example.com/` from an internal network and sign in. Search devices by name or ID; a device opens a drawer with *Overview* and *Password history* (up to the configured limit, newest first). “Reported applied” is the agent's statement, not an independent check; unconfirmed candidates are kept for crash recovery. Consider account lockout when trying historical candidates.

- **Reveal password** (web): decrypts with the recovery key on the IIS server (`EnableWebDecryption=true`, set by the installer). Every attempt is audited.
- **Offline recovery**: download the encrypted envelope and run `StandaloneLaps.Agent.exe recover envelope.json recovery.pfx` on a recovery workstation with the backup PFX.

Administrators can delete a device (recoverable: tombstone blocks the agent, history is archived under `_deleted`) and restore it. Readers cannot manage devices. Reveal, delete, restore and Add client use session-bound CSRF tokens; deletion requires typing the device name. The portal HTML-encodes output, forbids caching and framing and logs access and management actions to `App_Data\Vault\audit.jsonl` (ordinary protected storage, not a tamper-evident log).

## Settings page

*Settings* (all signed-in users can view; only `SLAPS.Admin` can change):

- **Password history:** versions kept per device, 2–100 (default 20), stored in `App_Data\Vault\settings.json`. Raising takes effect immediately. Lowering requires a confirmation and **permanently deletes** versions above the new limit on all active devices (the most recent version reported as applied is always kept). Deleted devices are trimmed when restored. Changes are audited. A damaged `settings.json` stops the portal instead of falling back to a smaller limit; fix or delete it (delete = default 20).
- **Certificates:** SLAPS CA and current/previous recovery certificates with subject, validity, key size, private-key status (accessible, exportable or not) and fingerprints. The public part can be downloaded as `.cer` (DER) or `.pem`; downloads are audited. Private keys are never offered.
- **About:** portal version, agent version in the client packages, sign-in mode, reveal setting; for admins also public URL, portal networks and .NET runtime.

The version number (single source: `web\IisVault\App_Code\AppVersion.cs`, also stamped into the agent and the package name) is shown in the navigation and on the Settings page. The installer prints the old and new version on an upgrade.

PowerShell alternative with a reader certificate (certificate mode): `scripts\Get-PasswordHistory.ps1 -ApiUrl https://slaps.example.com/ -DeviceId <guid> -ReaderCertificateThumbprint <sha1>`.

## Configuration reference (web.config)

| Setting | Meaning |
| --- | --- |
| `VaultDataDirectory` | `~/App_Data/Vault`; must be a dedicated App_Data subdirectory. |
| `PublicBaseUrl` | `https://<host>/`; used for the Entra redirect URI and in client packages. |
| `PortalAuthMode` | `Entra` (default) or `Certificate` (break-glass). |
| `EntraTenantId`, `EntraClientId` | Directory and application IDs of the SLAPS app registration. |
| `PortalAllowedNetworks` | Semicolon-separated CIDR list allowed to open portal pages. Empty denies the portal. The agent API is exempt. |
| `OutboundProxyUrl` | Optional proxy for downloading the Entra signing keys. |
| `IssuingCaSha256` | SHA-256 of the SLAPS CA certificate in LocalMachine\My (with private key). |
| `CrlDistributionUrl` | URL written into agent certificates; the CRL itself is preinstalled locally on the IIS server. |
| `EnableWebDecryption` | `true` enables Reveal password. |
| `RecoveryCertificateSha256` | Semicolon list; the first entry is the recipient for new packages, later entries are historical keys that can still be revealed. |

Static agents, readers or admins (certificate mode) can still be listed in `App_Data\clients.json`; portal-added clients are stored in `App_Data\Vault\_clients\<device>.json`.

## Agent registry settings

`HKLM\SOFTWARE\PriCoSoft\SLAPS` (64-bit view): `Enabled` (DWORD 1/0), `DeviceId`, `ApiUrl` (HTTPS, ending in `/`), `ClientCertificateSha256`, `RecoveryCertificatePath` (local absolute path), `RecoveryCertificateSha256`. SHA-256 means the hash of the complete DER certificate, not the SHA-1 store thumbprint. The client package installer writes these values; `scripts\Install-Service.ps1` and `scripts\Configure-Agent.ps1` remain for manual installations. Set `Enabled=0` or stop the service to stop rotations.

## API contract

All calls are relative to `PublicBaseUrl` and require the agent/reader certificate. Redirects are not followed.

| Request | Meaning |
| --- | --- |
| `PUT api.aspx?device=<guid>&rotation=<guid>` | Store envelope JSON; 204, or 409 for different content at an existing ID. |
| `GET api.aspx?device=<guid>&rotation=<guid>` | Return the encrypted envelope. |
| `POST api.aspx?device=<guid>&rotation=<guid>&action=applied` | Agent confirms the reset; idempotent. |
| `GET api.aspx?device=<guid>&skip=0&take=20` | Encrypted version metadata (`take` 1–100, results capped at the configured history limit). |

Requests are limited to 64 KiB and 60 calls per minute per certificate and worker process. There is no plaintext API.

## Build and test

```powershell
.\scripts\Test-IisBackend.ps1        # build agent, 131 Framework checks, ASPX compilation, script syntax
.\scripts\Build-LinuxAgent.ps1       # Linux agent files + slaps-agent_<version>_all.deb in artifacts\Agent-Linux (no Linux tools needed)
.\scripts\Build-ServerPackage.ps1    # tests + Linux agent + signing + artifacts\StandaloneLaps-Server-<version>-<timestamp>.zip
.\scripts\Start-Preview.ps1          # optional local IIS Express UI preview with synthetic data
.\scripts\New-AppIcons.ps1           # after changing icon.svg: regenerate favicon.ico and icon-180.png
```

**Code signing (Defender/ASR):** `Build-ServerPackage.ps1` signs the staged `StandaloneLaps.Agent.exe`, `Install-SlapsAgent.ps1` and `Install-SlapsServer.ps1` with the PriCoSoft Authenticode certificate through `C:\Program Files (x86)\PriCoSoft\SignCode\signcode.cmd` (Azure Trusted Signing, RFC 3161 timestamp) and fails unless every signature is valid and timestamped. Sources in the repository stay unsigned. The website copies the agent EXE and `Install-SlapsAgent.ps1` byte-for-byte into each client package, so the signatures stay valid there; `Install.cmd`, the generated settings and the PFX cannot be Authenticode-signed. The signing certificates are short-lived; the timestamp keeps the signatures valid after they expire. `-SkipSigning` builds a `-UNSIGNED` package for local tests only.

The scripts use the Windows-supplied .NET Framework compiler and `aspnet_compiler`; no .NET SDK or NuGet restore. The checks cover registry/policy mapping, password generation, outage/crash/reset sequencing with fake accounts, AES-GCM integrity, API access rules, retention, delete/restore, Entra ID token validation (signature, issuer, audience, tenant, expiry, nonce, roles, tampering), internal-network matching, SLAPS CA issuing, CRL signature, portal-managed clients/rekey and client packages. No real account, service, policy, certificate store or registry setting is changed by tests. The preview patches authentication for localhost and must never be deployed.

**Not yet validated on a real server:** IIS installation and bindings on Server 2019/2022, client-certificate renegotiation with the IIS-trusted SLAPS CA and locally stored CRL, Entra sign-in against a real tenant, the client package installer and a real SAM reset/recovery drill. Run the installer smoke test and the client installer's connectivity test first.

## Limits

File storage without SQL/HA; audit is not tamper-evident; no automatic purge of deleted-device archives. The SLAPS CA and recovery keys live on the IIS server (non-exportable, which only blocks casual copies): an attacker who controls that server can decrypt stored passwords and issue agent certificates. Passwords briefly exist in managed memory. Back up `App_Data\Vault` and the key backups independently; application startup trims histories to the configured limit (default 20).

See [Storage, encryption and migration](docs/Migration.md) for the data layout and moving to another server.

## Superseded material

The original .NET 10 Core/Agent/API projects, the custom ADMX templates under `policy/`, the Entra Application Proxy header mode and old publish ZIPs are historical. The current build uses `src/StandaloneLaps.Agent.Framework` and `web/IisVault`. The encrypted v1 envelope and agent state formats are unchanged.

## Microsoft references

- [Windows LAPS policy settings](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-management-policy-settings)
- [Microsoft identity platform ID tokens](https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens)
- [Add app roles and receive them in the token](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)
- [IIS binding sslFlags](https://learn.microsoft.com/iis/configuration/system.applicationhost/sites/site/bindings/binding)
- [.NET Framework versions in Windows Server](https://learn.microsoft.com/en-us/dotnet/framework/install/versions-and-dependencies)

## License

Copyright 2026 PriCoSoft GmbH. Licensed under the [Apache License, Version 2.0](LICENSE). Provided "as is", without warranties or conditions of any kind; see the license for details. "PriCoSoft" is a name of PriCoSoft GmbH; the license does not grant permission to use it (Apache-2.0, section 6).
