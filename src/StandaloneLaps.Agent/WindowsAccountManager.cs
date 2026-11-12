using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using Microsoft.Win32;

namespace StandaloneLaps.Agent;

public sealed class WindowsAccountManager(string? configuredName = null) : IAccountManager
{
    public LocalAccount ResolveManagedAdministrator()
    {
        using var product = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ProductOptions");
        if (product?.GetValue("ProductType") is not string type || type.Equals("LanmanNT", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Domain controllers and unknown machine roles are not supported.");
        if (!string.IsNullOrWhiteSpace(configuredName))
        {
            var named = ReadAccount(configuredName);
            EnsureAdministrator(named.Name);
            return named;
        }
        uint resume = 0;
        do
        {
            var status = NetUserEnum(null, 0, 2, out var buffer, 65536, out var count, out _, ref resume);
            if (status is not (0 or 234)) throw new Win32Exception((int)status);
            try
            {
                for (var i = 0; i < count; i++)
                {
                    var name = Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, i * IntPtr.Size))!;
                    var account = ReadAccount(name);
                    if (account.Sid.EndsWith("-500", StringComparison.Ordinal)) return account;
                }
            }
            finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
            if (status == 0) break;
        } while (true);
        throw new InvalidOperationException("Built-in local administrator (RID 500) was not found.");
    }

    private static LocalAccount ReadAccount(string name)
    {
        var status = NetUserGetInfo(null, name, 23, out var buffer);
        if (status != 0) throw new Win32Exception((int)status);
        try
        {
            var info = Marshal.PtrToStructure<UserInfo23>(buffer);
            return new LocalAccount(name, new SecurityIdentifier(info.Sid).Value);
        }
        finally { NetApiBufferFree(buffer); }
    }

    public void SetPassword(LocalAccount account, string password)
    {
        // Resolve again immediately before mutation to avoid changing a replaced/renamed target by accident.
        if (ReadAccount(account.Name).Sid != account.Sid)
            throw new InvalidOperationException("Local administrator identity changed.");
        EnsureAdministrator(account.Name);
        var secret = Marshal.StringToHGlobalUni(password);
        try
        {
            var info = new UserInfo1003 { Password = secret };
            var status = NetUserSetInfo(null, account.Name, 1003, ref info, out _);
            if (status != 0) throw new Win32Exception((int)status);
        }
        finally { Marshal.ZeroFreeGlobalAllocUnicode(secret); }
    }

    [StructLayout(LayoutKind.Sequential)] private struct UserInfo23
    { public IntPtr Name; public IntPtr FullName; public IntPtr Comment; public uint Flags; public IntPtr Sid; }
    [StructLayout(LayoutKind.Sequential)] private struct UserInfo1003 { public IntPtr Password; }
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern uint NetUserEnum(
        string? server, uint level, uint filter, out IntPtr buffer, uint preferredMaximum,
        out uint entriesRead, out uint totalEntries, ref uint resumeHandle);
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern uint NetUserGetInfo(string? server, string user, uint level, out IntPtr buffer);
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern uint NetUserSetInfo(string? server, string user, uint level, ref UserInfo1003 buffer, out uint parameterError);
    [DllImport("Netapi32.dll")] private static extern uint NetApiBufferFree(IntPtr buffer);
    [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)] private static extern uint NetUserGetLocalGroups(
        string? server, string user, uint level, uint flags, out IntPtr buffer, uint preferredMaximum,
        out uint entriesRead, out uint totalEntries);

    private static void EnsureAdministrator(string name)
    {
        var adminGroup = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null)
            .Translate(typeof(NTAccount)).Value.Split('\\').Last();
        var status = NetUserGetLocalGroups(null, name, 0, 1, out var buffer, uint.MaxValue, out var count, out _);
        if (status != 0) throw new Win32Exception((int)status);
        try
        {
            for (var i = 0; i < count; i++)
                if (string.Equals(Marshal.PtrToStringUni(Marshal.ReadIntPtr(buffer, i * IntPtr.Size)), adminGroup, StringComparison.OrdinalIgnoreCase)) return;
            throw new InvalidOperationException("Configured local account is not a member of Administrators.");
        }
        finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
    }
}
