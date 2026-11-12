using System;
using System.ComponentModel;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace StandaloneLaps.FrameworkAgent
{
    public sealed class WindowsAccountManager : IAccountManager
    {
        private readonly string configuredName;
        public WindowsAccountManager(string name) { configuredName = name; }
        public LocalAccount Resolve()
        {
            using (var product = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ProductOptions"))
            {
                var type = product == null ? null : product.GetValue("ProductType") as string;
                if (type == null || type.Equals("LanmanNT", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Domain controllers and unknown machine roles are unsupported.");
            }
            if (!string.IsNullOrWhiteSpace(configuredName)) { var named = ReadAccount(configuredName); EnsureAdministrator(named.Name); return named; }
            uint resume = 0;
            do
            {
                IntPtr buffer; uint count, total;
                var status = NetUserEnum(null, 0, 2, out buffer, 65536, out count, out total, ref resume);
                try
                {
                    if (status != 0 && status != 234) throw new Win32Exception((int)status);
                    for (var i = 0; i < count; i++)
                    {
                        var account = ReadAccount(Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, i * IntPtr.Size)));
                        if (account.Sid.EndsWith("-500", StringComparison.Ordinal)) return account;
                    }
                }
                finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
                if (status == 0) break;
            } while (true);
            throw new InvalidOperationException("Built-in administrator was not found.");
        }
        private static LocalAccount ReadAccount(string name)
        {
            IntPtr buffer; var status = NetUserGetInfo(null, name, 23, out buffer);
            if (status != 0) throw new Win32Exception((int)status);
            try
            {
                var info = (UserInfo23)Marshal.PtrToStructure(buffer, typeof(UserInfo23));
                return new LocalAccount { Name = name, Sid = new SecurityIdentifier(info.Sid).Value };
            }
            finally { NetApiBufferFree(buffer); }
        }
        public void SetPassword(LocalAccount account, string password)
        {
            if (ReadAccount(account.Name).Sid != account.Sid) throw new InvalidOperationException("Local account identity changed.");
            EnsureAdministrator(account.Name);
            var secret = Marshal.StringToHGlobalUni(password);
            try
            {
                var info = new UserInfo1003 { Password = secret }; uint parameter;
                var status = NetUserSetInfo(null, account.Name, 1003, ref info, out parameter);
                if (status != 0) throw new Win32Exception((int)status);
            }
            finally { Marshal.ZeroFreeGlobalAllocUnicode(secret); }
        }
        // Combines the SAM "last logon" time with Security event 4624 (successful logon, includes network/SMB logons
        // when logon auditing is enabled, which is the Windows Server default). Either source may be unavailable.
        public DateTimeOffset? LastAuthenticationUtc(LocalAccount account, DateTimeOffset since)
        {
            DateTimeOffset? result = null;
            try
            {
                IntPtr buffer;
                if (NetUserGetInfo(null, account.Name, 2, out buffer) == 0)
                {
                    try
                    {
                        var info = (UserInfo2)Marshal.PtrToStructure(buffer, typeof(UserInfo2));
                        if (info.LastLogon != 0) result = DateTimeOffset.FromUnixTimeSeconds(info.LastLogon);
                    }
                    finally { NetApiBufferFree(buffer); }
                }
            }
            catch (Exception) { }
            try
            {
                var query = "*[System[(EventID=4624) and TimeCreated[@SystemTime>='" + since.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", System.Globalization.CultureInfo.InvariantCulture) +
                    "']]] and *[EventData[Data[@Name='TargetUserSid']='" + new SecurityIdentifier(account.Sid).Value + "']]";
                using (var reader = new EventLogReader(new EventLogQuery("Security", PathType.LogName, query) { ReverseDirection = true }))
                using (var record = reader.ReadEvent())
                    if (record != null && record.TimeCreated.HasValue)
                    {
                        var logon = new DateTimeOffset(record.TimeCreated.Value.ToUniversalTime());
                        if (!result.HasValue || logon > result.Value) result = logon;
                    }
            }
            catch (Exception) { }
            return result.HasValue && result.Value > since ? result : null;
        }
        private static void EnsureAdministrator(string name)
        {
            var group = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Translate(typeof(NTAccount)).Value.Split('\\').Last();
            IntPtr buffer; uint count, total;
            var status = NetUserGetLocalGroups(null, name, 0, 1, out buffer, uint.MaxValue, out count, out total);
            try
            {
                if (status != 0) throw new Win32Exception((int)status);
                for (var i = 0; i < count; i++) if (string.Equals(Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, i * IntPtr.Size)), group, StringComparison.OrdinalIgnoreCase)) return;
                throw new InvalidOperationException("Configured account is not a local administrator.");
            }
            finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
        }
        [StructLayout(LayoutKind.Sequential)] private struct UserInfo23 { public IntPtr Name, FullName, Comment; public uint Flags; public IntPtr Sid; }
        [StructLayout(LayoutKind.Sequential)] private struct UserInfo2
        {
            public IntPtr Name, Password; public uint PasswordAge, Privilege; public IntPtr HomeDirectory, Comment; public uint Flags; public IntPtr ScriptPath;
            public uint AuthFlags; public IntPtr FullName, UserComment, Parameters, Workstations; public uint LastLogon, LastLogoff, AccountExpires, MaxStorage, UnitsPerWeek;
            public IntPtr LogonHours; public uint BadPasswordCount, NumberOfLogons; public IntPtr LogonServer; public uint CountryCode, CodePage;
        }
        [StructLayout(LayoutKind.Sequential)] private struct UserInfo1003 { public IntPtr Password; }
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern uint NetUserEnum(string server, uint level, uint filter, out IntPtr buffer, uint maximum, out uint read, out uint total, ref uint resume);
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern uint NetUserGetInfo(string server, string user, uint level, out IntPtr buffer);
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern uint NetUserSetInfo(string server, string user, uint level, ref UserInfo1003 buffer, out uint parameter);
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern uint NetUserGetLocalGroups(string server, string user, uint level, uint flags, out IntPtr buffer, uint maximum, out uint read, out uint total);
        [DllImport("Netapi32.dll")] private static extern uint NetApiBufferFree(IntPtr buffer);
    }
}
