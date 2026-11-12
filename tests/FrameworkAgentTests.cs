using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using StandaloneLapsWeb;
using StandaloneLaps.FrameworkAgent;

public static class FrameworkAgentTests
{
    public static int Run(X509Certificate2 certificate, string directory)
    {
        var passed = 0;
        Action<bool, string> check = (ok, label) => { if (!ok) throw new Exception("FAILED: " + label); passed++; Console.WriteLine("PASS Framework agent " + label); };
        Action<Action, string> fails = (action, label) => { var failed = false; try { action(); } catch { failed = true; } check(failed, label); };
        var settings = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase) { { "Enabled", 1 }, { "DeviceId", Guid.NewGuid().ToString("D") },
            { "ApiUrl", "https://vault.test/Laps/" }, { "ClientCertificateSha256", new string('A', 64) }, { "RecoveryCertificatePath", @"C:\Recovery\public.cer" }, { "RecoveryCertificateSha256", EnvelopeCrypto.Fingerprint(certificate) } };
        var values = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
        var policy = AgentPolicy.FromValues(settings, values);
        check(policy.Length == 14 && policy.AgeDays == 30 && policy.Complexity == 4, "native defaults map from registry dictionaries");
        check(AgentPolicy.SettingsPath == @"SOFTWARE\PriCoSoft\SLAPS", "exact HKLM SOFTWARE PriCoSoft SLAPS namespace");
        settings["Enabled"] = 0; check(AgentPolicy.FromValues(settings, values) == null, "disabled registry switch stops management");
        settings["Enabled"] = "1"; fails(() => AgentPolicy.FromValues(settings, values), "wrong registry type rejected"); settings["Enabled"] = 1;
        values["PasswordLength"] = 32; values["PasswordAgeDays"] = 7; values["AdministratorAccountName"] = "RecoveryAdmin";
        policy = AgentPolicy.FromValues(settings, values);
        check(policy.Length == 32 && policy.AgeDays == 7 && policy.AccountName == "RecoveryAdmin" && policy.ApiUrl.AbsolutePath == "/Laps/", "native account/password values and IIS subdirectory");
        values["BackupDirectory"] = 2; fails(() => AgentPolicy.FromValues(settings, values), "competing native backup rejected"); values["BackupDirectory"] = 0;
        values["PasswordComplexity"] = 8; fails(() => AgentPolicy.FromValues(settings, values), "unsupported passphrase mode rejected"); values["PasswordComplexity"] = 4;
        check(policy.PostAuthenticationResetDelayHours == 24 && policy.PostAuthenticationActions == AgentPolicy.ActionResetLogoff, "post-authentication defaults match Windows LAPS (24 h, reset and sign out)");
        values["PostAuthenticationActions"] = 11; values["PostAuthenticationResetDelay"] = 2; policy = AgentPolicy.FromValues(settings, values);
        check(policy.PostAuthenticationActions == 11 && policy.PostAuthenticationResetDelayHours == 2, "post-authentication actions and grace period read from policy");
        values["PostAuthenticationActions"] = 7; values["PostAuthenticationResetDelay"] = 99; policy = AgentPolicy.FromValues(settings, values);
        check(policy.PostAuthenticationActions == 3 && policy.PostAuthenticationResetDelayHours == 24, "unsupported post-authentication values fall back to Windows LAPS defaults");
        values.Remove("PostAuthenticationActions"); values.Remove("PostAuthenticationResetDelay");
        values["AutomaticAccountManagementEnabled"] = 1; fails(() => AgentPolicy.FromValues(settings, values), "automatic account management rejected"); values.Remove("AutomaticAccountManagementEnabled");
        policy = AgentPolicy.FromValues(settings, values);
        settings["ApiUrl"] = "http://vault.test/"; fails(() => AgentPolicy.FromValues(settings, values), "unencrypted API URL rejected"); settings["ApiUrl"] = "https://vault.test/Laps/";
        StandaloneLaps.FrameworkAgent.Program.ValidateRecipient(certificate, EnvelopeCrypto.Fingerprint(certificate));
        fails(() => StandaloneLaps.FrameworkAgent.Program.ValidateRecipient(certificate, new string('0', 64)), "recovery certificate pin verified");
        for (var complexity = 1; complexity <= 4; complexity++)
        {
            for (var i = 0; i < 100; i++)
            {
                var password = RotationEngine.GeneratePassword(32, complexity);
                if (password.Length != 32 || !password.Any(char.IsUpper) || (complexity > 1 && !password.Any(char.IsLower)) ||
                    (complexity > 2 && !password.Any(char.IsDigit)) || (complexity > 3 && !password.Any(c => !char.IsLetterOrDigit(c))) ||
                    (complexity == 1 && !password.All(char.IsUpper)) || (complexity < 3 && password.Any(char.IsDigit)) || (complexity < 4 && !password.All(char.IsLetterOrDigit))) throw new Exception("Invalid password category.");
            }
            check(true, "100 passwords satisfy complexity mode " + complexity);
        }
        var account = new FakeAccounts(); var state = new FakeState(); var backup = new FakeBackup();
        var engine = new RotationEngine(account, state, backup); var now = DateTimeOffset.UtcNow;
        backup.FailStore = true; fails(() => engine.RotateIfDue(policy, certificate, now, CancellationToken.None), "backup failure aborts reset");
        check(account.Changes == 0 && state.Value == null, "backup failure leaves SAM/state unchanged");
        backup.FailStore = false; account.FailChange = true;
        fails(() => engine.RotateIfDue(policy, certificate, now, CancellationToken.None), "reset failure propagated");
        check(state.Value == null && backup.Reports == 0 && backup.Records.Count == 1, "failed reset remains unconfirmed candidate"); account.FailChange = false;
        check(engine.RotateIfDue(policy, certificate, now, CancellationToken.None), "first rotation completes");
        check(EnvelopeCrypto.Decrypt(backup.Records.Last(), certificate).password == account.Password, "backed-up secret equals applied secret");
        check(!engine.RotateIfDue(policy, certificate, now.AddDays(1), CancellationToken.None), "rotation interval respected");
        check(engine.RotateIfDue(policy, certificate, now.AddDays(7), CancellationToken.None), "expiration triggers rotation");
        backup.FailReport = true; fails(() => engine.RotateIfDue(policy, certificate, now.AddDays(14), CancellationToken.None), "lost report propagated");
        backup.FailReport = false; var before = account.Changes;
        check(!engine.RotateIfDue(policy, certificate, now.AddDays(15), CancellationToken.None) && before == account.Changes, "lost report retried without another reset");
        state.FailWrite = true; fails(() => engine.RotateIfDue(policy, certificate, now.AddDays(21), CancellationToken.None), "post-reset state failure propagated");
        var uncertain = backup.Records.Last().rotationId; state.FailWrite = false;
        check(engine.RotateIfDue(policy, certificate, now.AddDays(21), CancellationToken.None) && backup.Records.Last().rotationId != uncertain && backup.Records.Any(e => e.rotationId == uncertain), "uncertain generation retained on retry");
        using (var cancellation = new CancellationTokenSource())
        { cancellation.Cancel(); before = account.Changes; fails(() => engine.RotateIfDue(policy, certificate, now.AddDays(30), cancellation.Token), "cancellation handled"); check(before == account.Changes, "cancellation prevents mutation"); }
        fails(() => engine.RotateIfDue(policy, certificate, now, CancellationToken.None), "clock rollback rejected");
        // Post-authentication: use of the account after the last rotation triggers a reset after the grace period.
        {
            var pa = new FakeAccounts(); var ps = new FakeState(); var pb = new FakeBackup(); var sessions = new FakeSessions();
            var pe = new RotationEngine(pa, ps, pb, sessions); var start = DateTimeOffset.UtcNow.AddDays(-1);
            check(pe.RotateIfDue(policy, certificate, start, CancellationToken.None) && pe.LastReason == RotationReason.Initial, "initial rotation reason recorded");
            check(!pe.RotateIfDue(policy, certificate, start.AddHours(1), CancellationToken.None) && pe.PendingPostAuthenticationUtc == null, "no post-authentication reset without account use");
            pa.LastLogon = start.AddMinutes(-5);
            check(!pe.RotateIfDue(policy, certificate, start.AddHours(2), CancellationToken.None) && pe.PendingPostAuthenticationUtc == null, "sign-in before the last rotation is ignored");
            pa.LastLogon = start.AddHours(3);
            check(!pe.RotateIfDue(policy, certificate, start.AddHours(4), CancellationToken.None) && pe.PendingPostAuthenticationUtc == start.AddHours(27) && pa.Changes == 1, "account use schedules reset after the 24 h grace period");
            check(pe.RotateIfDue(policy, certificate, start.AddHours(27), CancellationToken.None) && pe.LastReason == RotationReason.PostAuthentication && pa.Changes == 2, "grace period expiry resets the password");
            check(sessions.Calls == 1 && sessions.LastActions == AgentPolicy.ActionResetLogoff && pb.Records.Count == 2, "sign-out action runs after the verified backup");
            check(!pe.RotateIfDue(policy, certificate, start.AddHours(28), CancellationToken.None) && pa.Changes == 2, "same sign-in does not trigger another reset");
            pa.LastLogon = start.AddHours(29); sessions.Fail = true;
            check(pe.RotateIfDue(policy, certificate, start.AddHours(53), CancellationToken.None) && pe.PostAuthenticationActionError != null && pa.Changes == 3, "failing sign-out keeps the completed reset and is reported");
            sessions.Fail = false; pa.LastLogon = start.AddHours(54);
            var resetOnly = AgentPolicy.FromValues(settings, new Dictionary<string, object>(values, StringComparer.OrdinalIgnoreCase) { { "PostAuthenticationActions", 1 } });
            var callsBefore = sessions.Calls;
            check(pe.RotateIfDue(resetOnly, certificate, start.AddHours(78), CancellationToken.None) && sessions.Calls == callsBefore, "action 1 resets the password without sign-out");
            pa.LastLogon = start.AddHours(79);
            var disabled = AgentPolicy.FromValues(settings, new Dictionary<string, object>(values, StringComparer.OrdinalIgnoreCase) { { "PostAuthenticationResetDelay", 0 } });
            check(!pe.RotateIfDue(disabled, certificate, start.AddHours(120), CancellationToken.None) && pe.PendingPostAuthenticationUtc == null, "grace period 0 disables post-authentication actions");
        }
        var disk = new StateStore(directory); var expected = new RotationState { AccountSid = "S-1-5-21-1-2-3-500", LastAppliedUtc = now.ToString("O"), RotationId = Guid.NewGuid() };
        disk.Write(expected); check(disk.Read().RotationId == expected.RotationId, "durable state round trip");
        expected.RotationId = Guid.NewGuid(); disk.Write(expected); check(disk.Read().RotationId == expected.RotationId, "atomic state replacement");
        File.WriteAllText(Path.Combine(directory, "state.json"), "invalid"); fails(() => disk.Read(), "corrupt state fails closed");
        check(Program.DescribeFailure(new InvalidOperationException("Native BackupDirectory must be Disabled (0).")) == "InvalidOperationException: Native BackupDirectory must be Disabled (0).", "event log names the reason of agent errors");
        check(Program.DescribeFailure(new System.Net.WebException("x", System.Net.WebExceptionStatus.ConnectFailure)) == "WebException: ConnectFailure", "event log names the network failure status");
        check(Program.DescribeFailure(new ArgumentException("secret-bearing text")) == "ArgumentException", "unlisted exception types are logged by name only");
        return passed;
    }
    private sealed class FakeAccounts : IAccountManager
    {
        public int Changes; public string Password; public bool FailChange; public DateTimeOffset? LastLogon;
        public LocalAccount Resolve() { return new LocalAccount { Name = "RenamedAdmin", Sid = "S-1-5-21-1-2-3-500" }; }
        public void SetPassword(LocalAccount account, string password) { if (FailChange) throw new InvalidOperationException(); Changes++; Password = password; }
        public DateTimeOffset? LastAuthenticationUtc(LocalAccount account, DateTimeOffset since) { return LastLogon.HasValue && LastLogon.Value > since ? LastLogon : null; }
    }
    private sealed class FakeSessions : ISessionController
    {
        public int Calls, LastActions; public bool Fail;
        public void RunPostAuthenticationActions(LocalAccount account, int actions, CancellationToken token) { Calls++; LastActions = actions; if (Fail) throw new InvalidOperationException("sign-out failed"); }
    }
    private sealed class FakeState : IStateStore
    {
        public RotationState Value; public bool FailWrite;
        public RotationState Read() { return Value; }
        public void Write(RotationState state) { if (FailWrite) throw new IOException(); Value = state; }
    }
    private sealed class FakeBackup : IBackupClient
    {
        public bool FailStore, FailReport; public int Reports; public List<Envelope> Records = new List<Envelope>();
        public void StoreAndVerify(Envelope envelope, CancellationToken token) { token.ThrowIfCancellationRequested(); if (FailStore) throw new IOException(); Records.Add(envelope); }
        public void ReportApplied(Guid id, CancellationToken token) { if (FailReport) throw new IOException(); Reports++; }
    }
}
