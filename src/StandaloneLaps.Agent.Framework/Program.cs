using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using StandaloneLapsWeb;

namespace StandaloneLaps.FrameworkAgent
{
    public static class Program
    {
        public static int Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "recover") return Recover(args);
            if (args.Length > 0 && args[0] == "validate-config")
            {
                try
                {
                    var join = DeviceJoin.Detect();
                    if (join != DeviceJoinType.None) { Console.Error.WriteLine(DeviceJoin.RefusalMessage(join)); return 1; }
                    var policy = AgentPolicy.Read();
                    if (policy == null) { Console.WriteLine("Agent is disabled (Enabled=0 or absent)."); return 0; }
                    Console.WriteLine("Registry settings and native LAPS policy are valid. No password was changed.");
                    Console.WriteLine("  Device:               standalone (not joined to Active Directory or Microsoft Entra ID)");
                    Console.WriteLine("  Account:              " + (policy.AccountName ?? "built-in administrator (RID 500)"));
                    Console.WriteLine("  Password:             " + policy.Length + " characters, complexity " + policy.Complexity + ", rotated every " + policy.AgeDays + " days");
                    Console.WriteLine("  Post-authentication:  " + (policy.PostAuthenticationResetDelayHours == 0 ? "disabled (grace period 0)" :
                        ActionName(policy.PostAuthenticationActions) + " " + policy.PostAuthenticationResetDelayHours + " hours after the account is used"));
                    return 0;
                }
                catch (Exception ex) { Console.Error.WriteLine("Configuration invalid: " + ex.Message); return 1; }
            }
            if (Environment.UserInteractive) { Console.Error.WriteLine("Run through Windows Service Control Manager. Commands: validate-config, recover <envelope.json> <recovery.pfx>."); return 2; }
            ServiceBase.Run(new AgentService()); return 0;
        }
        private static int Recover(string[] args)
        {
            if (args.Length != 3) { Console.Error.WriteLine("Usage: StandaloneLaps.Agent recover <envelope.json> <recovery.pfx>"); return 2; }
            Console.Error.Write("PFX password: "); var password = new StringBuilder();
            while (true)
            {
                var key = Console.ReadKey(true); if (key.Key == ConsoleKey.Enter) break;
                if (key.Key == ConsoleKey.Backspace) { if (password.Length > 0) password.Length--; } else if (!char.IsControl(key.KeyChar)) password.Append(key.KeyChar);
            }
            Console.Error.WriteLine();
            try
            {
                using (var certificate = new X509Certificate2(File.ReadAllBytes(args[2]), password.ToString(), X509KeyStorageFlags.EphemeralKeySet))
                {
                    password.Clear();
                    var payload = EnvelopeCrypto.Decrypt(EnvelopeJson.Deserialize<Envelope>(File.ReadAllText(args[1])), certificate);
                    Console.WriteLine("Computer: " + payload.computerName + "\nAccount: " + payload.accountName + "\nSID: " + payload.accountSid + "\nCreated: " + payload.createdUtc + "\nPassword: " + payload.password);
                }
                return 0;
            }
            catch { Console.Error.WriteLine("Recovery failed. Check envelope, certificate and PFX password."); return 1; }
            finally { password.Clear(); }
        }
        // Event log text for a failed cycle. Messages are included only for exception types whose text comes from this
        // agent, Windows error codes or HTTP status lines (never password material); other types are logged by name only.
        public static string ActionName(int actions)
        {
            switch (actions)
            {
                case AgentPolicy.ActionReset: return "reset password";
                case AgentPolicy.ActionResetLogoff: return "reset password and sign out";
                case AgentPolicy.ActionResetReboot: return "reset password and restart";
                case AgentPolicy.ActionResetLogoffTerminate: return "reset password, sign out and terminate remaining processes";
                default: return "unknown";
            }
        }
        public static string DescribeFailure(Exception ex)
        {
            var web = ex as System.Net.WebException;
            string detail = null;
            if (web != null)
            {
                var response = web.Response as System.Net.HttpWebResponse;
                detail = response != null ? "HTTP " + (int)response.StatusCode + " " + response.StatusDescription : web.Status.ToString();
            }
            else if (ex is InvalidOperationException || ex is InvalidDataException || ex is CryptographicException || ex is System.ComponentModel.Win32Exception ||
                     ex is UnauthorizedAccessException || ex is FileNotFoundException || ex is DirectoryNotFoundException || ex is FormatException)
                detail = ex.Message;
            if (string.IsNullOrWhiteSpace(detail)) return ex.GetType().Name;
            detail = detail.Replace('\r', ' ').Replace('\n', ' ').Trim();
            if (detail.Length > 300) detail = detail.Substring(0, 300) + "...";
            return ex.GetType().Name + ": " + detail;
        }
        public static void ValidateRecipient(X509Certificate2 certificate, string fingerprint)
        {
            var now = DateTime.UtcNow;
            if (!string.Equals(EnvelopeCrypto.Fingerprint(certificate), fingerprint, StringComparison.OrdinalIgnoreCase) ||
                now < certificate.NotBefore.ToUniversalTime() || now >= certificate.NotAfter.ToUniversalTime()) throw new CryptographicException("Recovery certificate pin or validity mismatch.");
            using (var rsa = certificate.GetRSAPublicKey()) if (rsa == null || rsa.KeySize < 3072) throw new CryptographicException("RSA 3072 or stronger required.");
            var usage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (usage != null && !usage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyEncipherment)) throw new CryptographicException("Key Encipherment usage required.");
        }
    }

    internal sealed class AgentService : ServiceBase
    {
        private CancellationTokenSource cancellation; private Task worker;
        public AgentService() { ServiceName = "StandaloneLapsAgent"; CanStop = true; AutoLog = false; }
        protected override void OnStart(string[] args) { cancellation = new CancellationTokenSource(); worker = Task.Run(() => Run(cancellation.Token)); }
        protected override void OnStop() { cancellation.Cancel(); RequestAdditionalTime(40000); worker.Wait(TimeSpan.FromSeconds(35)); }
        private static void Log(string message, EventLogEntryType type, int id)
        {
            // The installer provisions this source. Never let logging expose a provider's secret-bearing exception text.
            try { EventLog.WriteEntry("StandaloneLapsAgent", message, type, id); } catch { }
        }
        // Windows LAPS compatible state (registry) for the account SLAPS manages; never fails the rotation cycle.
        private static void UpdateLapsState(StateStore state, LocalAccount account)
        {
            try
            {
                var saved = state.Read();
                if (saved != null && saved.AccountSid == account.Sid)
                    WindowsLapsCompatibility.WriteState(account.Sid, DateTimeOffset.Parse(saved.LastAppliedUtc, System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.None));
            }
            catch (Exception ex) { Log("Windows LAPS compatible state could not be written (" + Program.DescribeFailure(ex) + ").", EventLogEntryType.Warning, 1006); }
        }
        private static void WriteLapsCycle(AgentPolicy policy, LocalAccount account, bool rotated, Exception error)
        {
            try
            {
                using (var writer = new LapsEventWriter())
                    writer.WriteCycle(policy, account == null ? string.Empty : account.Name, account == null ? "S-1-5-0" : account.Sid, rotated && account != null, error);
            }
            catch { }
        }
        private static void Run(CancellationToken token)
        {
            using (var singleton = new Semaphore(1, 1, @"Global\StandaloneLapsAgentRotation"))
            {
                if (!singleton.WaitOne(0)) { Log("Another agent instance is already running.", EventLogEntryType.Error, 1002); return; }
                try
                {
                    DateTimeOffset? announced = null; // pending post-authentication deadline already written to the event log
                    DateTimeOffset? refused = null, lapsCycle = null; // last join refusal / last Windows LAPS compatible event cycle
                    while (!token.IsCancellationRequested)
                    {
                        AgentPolicy compatible = null; LocalAccount managed = null; var rotated = false;
                        try
                        {
                            var policy = AgentPolicy.Read();
                            var join = policy == null ? DeviceJoinType.None : DeviceJoin.Detect();
                            if (join != DeviceJoinType.None)
                            {
                                // Joined devices belong to Windows LAPS: change nothing, say so at start and once a day.
                                if (!refused.HasValue || DateTimeOffset.UtcNow - refused.Value >= TimeSpan.FromDays(1))
                                { refused = DateTimeOffset.UtcNow; Log(DeviceJoin.RefusalMessage(join), EventLogEntryType.Error, 1005); }
                                policy = null;
                            }
                            else refused = null;
                            if (policy != null)
                            {
                                compatible = policy;
                                using (var recipient = new X509Certificate2(policy.RecoveryCertificatePath))
                                using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
                                {
                                    Program.ValidateRecipient(recipient, policy.RecoveryCertificateSha256);
                                    store.Open(OpenFlags.ReadOnly);
                                    using (var client = store.Certificates.Cast<X509Certificate2>().FirstOrDefault(c => c.HasPrivateKey && EnvelopeCrypto.Fingerprint(c) == policy.ClientCertificateSha256))
                                    {
                                        if (client == null) throw new CryptographicException("Client certificate not found.");
                                        var state = new StateStore(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "StandaloneLaps"));
                                        var accounts = new WindowsAccountManager(policy.AccountName);
                                        managed = accounts.Resolve();
                                        var engine = new RotationEngine(accounts, state, new ApiBackupClient(policy, client), new WindowsSessionController());
                                        rotated = engine.RotateIfDue(policy, recipient, DateTimeOffset.UtcNow, token);
                                        UpdateLapsState(state, managed);
                                        if (rotated)
                                        {
                                            announced = null;
                                            if (engine.LastReason == RotationReason.PostAuthentication)
                                            {
                                                Log("Administrator password reset after the account was used (post-authentication action " + policy.PostAuthenticationActions + ": " + Program.ActionName(policy.PostAuthenticationActions) + "); encrypted backup verified.", EventLogEntryType.Information, 1000);
                                                if (engine.PostAuthenticationActionError != null)
                                                    Log("The password was reset, but the post-authentication action failed (" + Program.DescribeFailure(engine.PostAuthenticationActionError) + ").", EventLogEntryType.Warning, 1004);
                                            }
                                            else Log("Administrator password rotated; encrypted backup verified.", EventLogEntryType.Information, 1000);
                                        }
                                        else if (engine.PendingPostAuthenticationUtc.HasValue && engine.PendingPostAuthenticationUtc != announced)
                                        {
                                            announced = engine.PendingPostAuthenticationUtc;
                                            Log("The managed administrator account was used. Its password will be reset at " + announced.Value.ToString("yyyy-MM-dd HH:mm") + " UTC (" + Program.ActionName(policy.PostAuthenticationActions) + ").", EventLogEntryType.Information, 1003);
                                        }
                                    }
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            if (!token.IsCancellationRequested)
                            {
                                Log("Rotation cycle failed (" + Program.DescribeFailure(ex) + "). Retry in five minutes; inspect unconfirmed backup candidates.", EventLogEntryType.Error, 1001);
                                if (compatible != null && (!lapsCycle.HasValue || DateTimeOffset.UtcNow - lapsCycle.Value >= TimeSpan.FromHours(1)))
                                { lapsCycle = DateTimeOffset.UtcNow; WriteLapsCycle(compatible, managed, false, ex); }
                            }
                            compatible = null;
                        }
                        // Like Windows LAPS: one processing cycle in its log per hour, plus immediately after a password change.
                        if (compatible != null && (rotated || !lapsCycle.HasValue || DateTimeOffset.UtcNow - lapsCycle.Value >= TimeSpan.FromHours(1)))
                        { lapsCycle = DateTimeOffset.UtcNow; WriteLapsCycle(compatible, managed, rotated, null); }
                        if (token.WaitHandle.WaitOne(TimeSpan.FromMinutes(5))) break;
                    }
                }
                finally { singleton.Release(); }
            }
        }
    }
}
