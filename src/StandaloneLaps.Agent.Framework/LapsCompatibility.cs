using System;
using System.Diagnostics.Eventing;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace StandaloneLaps.FrameworkAgent
{
    public enum DeviceJoinType { None, ActiveDirectory, EntraId }

    // SLAPS is only for standalone (workgroup) servers. On Active Directory or Microsoft Entra joined devices
    // Windows LAPS is the supported solution, so the agent and the installer refuse to work there.
    public static class DeviceJoin
    {
        public const string WindowsLapsOverview = "https://learn.microsoft.com/windows-server/identity/laps/laps-overview";
        public const string WindowsLapsActiveDirectory = "https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-windows-server-active-directory";
        public const string WindowsLapsEntraId = "https://learn.microsoft.com/windows-server/identity/laps/laps-scenarios-azure-active-directory";

        public static DeviceJoinType Detect()
        {
            IntPtr name; int status;
            var result = NetGetJoinInformation(null, out name, out status);
            if (name != IntPtr.Zero) NetApiBufferFree(name);
            if (result != 0) throw new System.ComponentModel.Win32Exception(result);
            if (status == NetSetupDomainName) return DeviceJoinType.ActiveDirectory;
            try
            {
                IntPtr info;
                var hr = NetGetAadJoinInformation(null, out info);
                if (info != IntPtr.Zero)
                {
                    // DSREG_JOIN_INFO starts with DSREG_JOIN_TYPE: 1 = Entra joined, 2 = workplace (registered only).
                    try { if (Marshal.ReadInt32(info) == DsregDeviceJoin) return DeviceJoinType.EntraId; }
                    finally { NetFreeAadJoinInformation(info); }
                }
                else if (hr < 0) throw new InvalidOperationException("Microsoft Entra join state could not be read (0x" + hr.ToString("X8", CultureInfo.InvariantCulture) + ").");
            }
            catch (EntryPointNotFoundException) { } // Windows without Entra join support
            return DeviceJoinType.None;
        }

        public static string RefusalMessage(DeviceJoinType join)
        {
            var directory = join == DeviceJoinType.EntraId ? "Microsoft Entra ID" : "Active Directory";
            var guide = join == DeviceJoinType.EntraId ? WindowsLapsEntraId : WindowsLapsActiveDirectory;
            return "This computer is joined to " + directory + ". Standalone LAPS manages only standalone (workgroup) servers and makes no changes here. " +
                   "Use Windows LAPS with password backup to " + directory + " instead and uninstall the SLAPS agent. Guide: " + guide + " Overview: " + WindowsLapsOverview;
        }

        private const int NetSetupDomainName = 3, DsregDeviceJoin = 1;
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetGetJoinInformation(string server, out IntPtr name, out int status);
        [DllImport("Netapi32.dll")] private static extern int NetApiBufferFree(IntPtr buffer);
        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetGetAadJoinInformation(string tenantId, out IntPtr info);
        [DllImport("Netapi32.dll")] private static extern void NetFreeAadJoinInformation(IntPtr info);
    }

    // On standalone servers SLAPS takes the role of Windows LAPS: it reports its state and processing cycle in the
    // same places Windows LAPS uses (State registry key and the Microsoft-Windows-LAPS/Operational log), so that
    // inventory and compliance tools that look there see a managed local administrator password.
    public static class WindowsLapsCompatibility
    {
        public const string StatePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State";
        public static readonly Guid ProviderId = new Guid("4fcc72a9-d7ca-5dd2-8d34-6f41a0cdb7e0"); // Microsoft-Windows-LAPS
        public const int PolicySourceGroupPolicy = 2; // Assumption: Windows LAPS writes 1 for the CSP root; Group Policy is the next root.
        public const string PolicySourceText = "GPO", BackupDirectoryText = "Standalone LAPS server (SLAPS)";
        public const int EventStart = 10003, EventSucceeded = 10004, EventFailed = 10005, EventNoUpdate = 10016, EventAccountUpdated = 10020, EventPolicy = 10022, EventScheduled = 10052;

        public static int Rid(string sid)
        {
            var index = sid == null ? -1 : sid.LastIndexOf('-');
            uint rid;
            if (index < 0 || !uint.TryParse(sid.Substring(index + 1), NumberStyles.None, CultureInfo.InvariantCulture, out rid)) throw new FormatException("Invalid account SID.");
            return unchecked((int)rid);
        }

        // Same value names and types as Windows LAPS (DWORD, LastPasswordUpdateTime as FILETIME QWORD).
        public static object[][] StateValues(string accountSid, DateTimeOffset lastUpdatedUtc)
        {
            var rid = Rid(accountSid);
            return new[]
            {
                new object[] { "PolicySource", PolicySourceGroupPolicy, RegistryValueKind.DWord },
                new object[] { "DSRMMode", 0, RegistryValueKind.DWord },
                new object[] { "LastManagedAccountRid", rid, RegistryValueKind.DWord },
                new object[] { "LastAccountRidUpdated", rid, RegistryValueKind.DWord },
                new object[] { "LastPasswordUpdateTime", lastUpdatedUtc.UtcDateTime.ToFileTimeUtc(), RegistryValueKind.QWord }
            };
        }

        public static void WriteState(string accountSid, DateTimeOffset lastUpdatedUtc)
        {
            using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var key = hklm.CreateSubKey(StatePath))
            {
                foreach (var value in StateValues(accountSid, lastUpdatedUtc))
                {
                    var name = (string)value[0];
                    var current = key.GetValue(name);
                    if (current == null || !current.Equals(value[1])) key.SetValue(name, value[1], (RegistryValueKind)value[2]);
                }
            }
        }

        public static void RemoveState()
        {
            using (var hklm = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
            using (var key = hklm.OpenSubKey(StatePath, true))
                if (key != null) foreach (var value in StateValues("S-1-5-500", DateTimeOffset.UtcNow)) key.DeleteValue((string)value[0], false);
        }

        // Payload of event 10022 in the order of the Windows LAPS manifest template.
        public static object[] PolicyEventData(AgentPolicy policy)
        {
            return new object[] { PolicySourceText, BackupDirectoryText, policy.AccountName ?? string.Empty, policy.AgeDays, policy.Complexity, policy.Length,
                policy.PostAuthenticationResetDelayHours, policy.PostAuthenticationActions, 0, "BuiltInAdminAccount", string.Empty, 0, 0 };
        }
    }

    // Writes Windows LAPS processing events (same provider, IDs, channel and payload layout as laps.dll), so the
    // messages render from the Windows LAPS manifest. Only events that are true for SLAPS are used: no
    // "updated Active Directory/Entra ID" events, since SLAPS backs up to its own server.
    public sealed class LapsEventWriter : IDisposable
    {
        private const byte Channel = 16, Information = 4, Error = 2;
        private static readonly long Keywords = unchecked((long)0x8000000000000000UL);
        private readonly EventProvider provider = new EventProvider(WindowsLapsCompatibility.ProviderId);

        public void WriteCycle(AgentPolicy policy, string accountName, string accountSid, bool rotated, Exception error)
        {
            Write(WindowsLapsCompatibility.EventStart, Information);
            Write(WindowsLapsCompatibility.EventScheduled, Information);
            Write(WindowsLapsCompatibility.EventPolicy, Information, WindowsLapsCompatibility.PolicyEventData(policy));
            if (error != null) { Write(WindowsLapsCompatibility.EventFailed, Error, error.HResult); return; }
            if (rotated) Write(WindowsLapsCompatibility.EventAccountUpdated, Information, accountName, WindowsLapsCompatibility.Rid(accountSid));
            else Write(WindowsLapsCompatibility.EventNoUpdate, Information);
            Write(WindowsLapsCompatibility.EventSucceeded, Information);
        }
        private void Write(int id, byte level, params object[] data)
        {
            var descriptor = new EventDescriptor(id, 0, Channel, level, 0, 0, Keywords);
            provider.WriteEvent(ref descriptor, data);
        }
        public void Dispose() { provider.Dispose(); }
    }
}
