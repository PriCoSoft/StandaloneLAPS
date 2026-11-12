using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;

namespace StandaloneLaps.FrameworkAgent
{
    // Post-authentication actions with the same behavior as Windows LAPS:
    //   3  = sign out interactive sessions of the managed account (two-minute warning) and delete its SMB sessions,
    //   5  = restart the device after one minute,
    //   11 = like 3, then terminate remaining processes running as the managed account.
    public sealed class WindowsSessionController : ISessionController
    {
        public static readonly TimeSpan SignOutWarning = TimeSpan.FromMinutes(2);

        public void RunPostAuthenticationActions(LocalAccount account, int actions, CancellationToken token)
        {
            if (actions == AgentPolicy.ActionResetReboot) { Restart(); return; }
            if (actions != AgentPolicy.ActionResetLogoff && actions != AgentPolicy.ActionResetLogoffTerminate) return;
            var sessions = InteractiveSessions(account.Name);
            foreach (var id in sessions)
            {
                int response;
                const string title = "Local administrator password was reset";
                const string text = "The password of this account was reset by SLAPS because it was used. This session will be signed out in two minutes. Save your work now.";
                WTSSendMessage(IntPtr.Zero, id, title, title.Length * 2, text, text.Length * 2, 0x30, 120, out response, false);
            }
            if (sessions.Length > 0 && token.WaitHandle.WaitOne(SignOutWarning)) token.ThrowIfCancellationRequested();
            foreach (var id in InteractiveSessions(account.Name)) WTSLogoffSession(IntPtr.Zero, id, true);
            NetSessionDel(null, null, account.Name); // removes SMB sessions of the account; "no session" is not an error here
            if (actions == AgentPolicy.ActionResetLogoffTerminate) TerminateProcesses(account.Sid);
        }

        private static int[] InteractiveSessions(string accountName)
        {
            IntPtr buffer; int count;
            if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out buffer, out count)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var result = new System.Collections.Generic.List<int>();
            try
            {
                var size = Marshal.SizeOf(typeof(SessionInfo));
                for (var i = 0; i < count; i++)
                {
                    var session = (SessionInfo)Marshal.PtrToStructure(new IntPtr(buffer.ToInt64() + i * size), typeof(SessionInfo));
                    if (session.SessionId == 0) continue;
                    if (string.Equals(Query(session.SessionId, 5), accountName, StringComparison.OrdinalIgnoreCase) &&
                        string.Equals(Query(session.SessionId, 7), Environment.MachineName, StringComparison.OrdinalIgnoreCase)) result.Add(session.SessionId);
                }
            }
            finally { WTSFreeMemory(buffer); }
            return result.ToArray();
        }

        private static string Query(int sessionId, int infoClass)
        {
            IntPtr buffer; int bytes;
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, infoClass, out buffer, out bytes)) return null;
            try { return Marshal.PtrToStringUni(buffer); } finally { WTSFreeMemory(buffer); }
        }

        private static void TerminateProcesses(string sid)
        {
            var own = Process.GetCurrentProcess().Id;
            foreach (var process in Process.GetProcesses())
            {
                using (process)
                {
                    if (process.Id == own || process.Id <= 4) continue;
                    try
                    {
                        if (string.Equals(OwnerSid(process.Id), sid, StringComparison.OrdinalIgnoreCase)) process.Kill();
                    }
                    catch (Exception) { } // process exited or is protected
                }
            }
        }

        private static string OwnerSid(int processId)
        {
            var handle = OpenProcess(0x1000, false, processId); // PROCESS_QUERY_LIMITED_INFORMATION
            if (handle == IntPtr.Zero) return null;
            try
            {
                IntPtr token;
                if (!OpenProcessToken(handle, 0x0008, out token)) return null; // TOKEN_QUERY
                try { using (var identity = new WindowsIdentity(token)) return identity.User == null ? null : identity.User.Value; }
                finally { CloseHandle(token); }
            }
            finally { CloseHandle(handle); }
        }

        private static void Restart()
        {
            var shutdown = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "shutdown.exe");
            using (var process = Process.Start(new ProcessStartInfo(shutdown, "/r /t 60 /d p:0:0 /c \"SLAPS: the local administrator password was reset after use. The computer restarts in one minute.\"") { UseShellExecute = false, CreateNoWindow = true }))
            {
                process.WaitForExit(30000);
                if (process.ExitCode != 0) throw new Win32Exception(process.ExitCode, "shutdown.exe failed.");
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct SessionInfo { public int SessionId; public IntPtr WinStationName; public int State; }
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WTSEnumerateSessionsW")]
        private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WTSQuerySessionInformationW")]
        private static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
        [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "WTSSendMessageW")]
        private static extern bool WTSSendMessage(IntPtr server, int sessionId, string title, int titleLength, string message, int messageLength, int style, int timeout, out int response, bool wait);
        [DllImport("wtsapi32.dll", SetLastError = true)] private static extern bool WTSLogoffSession(IntPtr server, int sessionId, bool wait);
        [DllImport("wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr memory);
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)] private static extern int NetSessionDel(string server, string client, string user);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(int access, bool inherit, int processId);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr process, int access, out IntPtr token);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr handle);
    }
}
