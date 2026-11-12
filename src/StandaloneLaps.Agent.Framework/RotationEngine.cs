using System;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using StandaloneLapsWeb;

namespace StandaloneLaps.FrameworkAgent
{
    public sealed class LocalAccount { public string Name, Sid; }
    public sealed class RotationState { public string AccountSid, LastAppliedUtc; public Guid RotationId; }
    public interface IAccountManager
    {
        LocalAccount Resolve();
        void SetPassword(LocalAccount account, string password);
        // Most recent successful authentication of the account after 'since', or null if none is known.
        DateTimeOffset? LastAuthenticationUtc(LocalAccount account, DateTimeOffset since);
    }
    public interface ISessionController { void RunPostAuthenticationActions(LocalAccount account, int actions, CancellationToken token); }
    public interface IStateStore { RotationState Read(); void Write(RotationState state); }
    public interface IBackupClient { void StoreAndVerify(Envelope envelope, CancellationToken token); void ReportApplied(Guid rotationId, CancellationToken token); }

    public enum RotationReason { None, Initial, Expired, PostAuthentication }

    public sealed class RotationEngine
    {
        private readonly IAccountManager accounts; private readonly IStateStore state; private readonly IBackupClient backup; private readonly ISessionController sessions;
        public RotationEngine(IAccountManager accounts, IStateStore state, IBackupClient backup) : this(accounts, state, backup, null) { }
        public RotationEngine(IAccountManager accounts, IStateStore state, IBackupClient backup, ISessionController sessions)
        { this.accounts = accounts; this.state = state; this.backup = backup; this.sessions = sessions; }

        // Details of the last RotateIfDue call, for the service's event log.
        public RotationReason LastReason { get; private set; }
        public DateTimeOffset? PendingPostAuthenticationUtc { get; private set; }
        public Exception PostAuthenticationActionError { get; private set; }

        public bool RotateIfDue(AgentPolicy policy, X509Certificate2 certificate, DateTimeOffset now, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            LastReason = RotationReason.None; PendingPostAuthenticationUtc = null; PostAuthenticationActionError = null;
            var account = accounts.Resolve();
            var previous = state.Read();
            var reason = RotationReason.Initial;
            if (previous != null && previous.AccountSid == account.Sid)
            {
                var last = DateTimeOffset.Parse(previous.LastAppliedUtc, CultureInfo.InvariantCulture, DateTimeStyles.None);
                if (last > now) throw new InvalidDataException("Clock precedes saved rotation.");
                reason = RotationReason.Expired;
                if (now - last < TimeSpan.FromDays(policy.AgeDays))
                {
                    // Post-authentication: the current password was used after it was set; reset it when the grace period ends.
                    var used = policy.PostAuthenticationResetDelayHours > 0 ? accounts.LastAuthenticationUtc(account, last) : null;
                    if (used.HasValue && used.Value > last)
                    {
                        var deadline = used.Value.AddHours(policy.PostAuthenticationResetDelayHours);
                        if (now < deadline) PendingPostAuthenticationUtc = deadline;
                        else reason = RotationReason.PostAuthentication;
                    }
                    if (reason != RotationReason.PostAuthentication) { backup.ReportApplied(previous.RotationId, token); return false; }
                }
            }
            var id = Guid.NewGuid();
            var password = GeneratePassword(policy.Length, policy.Complexity);
            var envelope = EnvelopeCrypto.Encrypt(new Payload { version = 1, deviceId = policy.DeviceId, computerName = Environment.MachineName,
                accountName = account.Name, accountSid = account.Sid, rotationId = id, createdUtc = now.ToString("O"), password = password }, certificate);
            backup.StoreAndVerify(envelope, token);
            token.ThrowIfCancellationRequested();
            accounts.SetPassword(account, password);
            state.Write(new RotationState { AccountSid = account.Sid, LastAppliedUtc = now.ToString("O"), RotationId = id });
            LastReason = reason;
            backup.ReportApplied(id, token);
            // The password is already reset and backed up; a failing sign-out/reboot must not undo or repeat that.
            if (reason == RotationReason.PostAuthentication && policy.PostAuthenticationActions != AgentPolicy.ActionReset && sessions != null)
            {
                try { sessions.RunPostAuthenticationActions(account, policy.PostAuthenticationActions, token); }
                catch (OperationCanceledException) { throw; }
                catch (Exception ex) { PostAuthenticationActionError = ex; }
            }
            return true;
        }
        public static string GeneratePassword(int length, int complexity)
        {
            if (length < 8 || length > 64 || complexity < 1 || complexity > 4) throw new ArgumentOutOfRangeException();
            var categories = new[] { "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz", "0123456789", "!#$%&()*+,-.:;<=>?@[]^_{|}~" };
            var alphabet = string.Concat(new ArraySegment<string>(categories, 0, complexity));
            var password = new char[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                for (var i = 0; i < length; i++) { var source = i < complexity ? categories[i] : alphabet; password[i] = source[RandomIndex(rng, source.Length)]; }
                for (var i = length - 1; i > 0; i--) { var j = RandomIndex(rng, i + 1); var value = password[i]; password[i] = password[j]; password[j] = value; }
            }
            return new string(password);
        }
        private static int RandomIndex(RandomNumberGenerator rng, int upper)
        {
            var bytes = new byte[4]; var limit = uint.MaxValue - (uint.MaxValue % (uint)upper); uint sample;
            do { rng.GetBytes(bytes); sample = BitConverter.ToUInt32(bytes, 0); } while (sample >= limit);
            return (int)(sample % (uint)upper);
        }
    }

    public sealed class StateStore : IStateStore
    {
        private readonly string path;
        public StateStore(string directory) { path = Path.Combine(directory, "state.json"); }
        public RotationState Read()
        {
            if (!File.Exists(path)) return null;
            var state = EnvelopeJson.Deserialize<RotationState>(File.ReadAllText(path));
            if (state == null || string.IsNullOrEmpty(state.AccountSid) || state.RotationId == Guid.Empty) throw new InvalidDataException("Invalid state.");
            return state;
        }
        public void Write(RotationState state)
        {
            var temporary = Path.Combine(Path.GetDirectoryName(path), Guid.NewGuid().ToString("N") + ".tmp");
            try
            {
                var bytes = Encoding.UTF8.GetBytes(EnvelopeJson.Serialize(state));
                using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
                { stream.Write(bytes, 0, bytes.Length); stream.Flush(true); }
                if (File.Exists(path)) File.Replace(temporary, path, null); else File.Move(temporary, path);
            }
            finally { if (File.Exists(temporary)) File.Delete(temporary); }
        }
    }
}
