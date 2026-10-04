// lib\native\Native.cs - P/Invoke helpers for the win-debug monitor (compiled at run time with Add-Type).
// Namespace WinDebug. Types: WinDebug.ProcOwner (process owner via token), WinDebug.Session (user idle time,
// session lock state). Everything here works without administrator rights; access-denied results are
// returned as strings / negative numbers, never thrown, so the caller can degrade gracefully.
// UTF-8 with BOM, CRLF, ASCII content only. No dependencies beyond mscorlib.
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace WinDebug
{
    /// <summary>Owner of a process resolved through its primary token (fast: ~0.2 ms per PID).</summary>
    public static class ProcOwner
    {
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        private const uint TOKEN_QUERY = 0x0008;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, int processId);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        /// <summary>
        /// Returns "SID|DOMAIN\user" for the process, or an error token:
        /// "E_OPEN&lt;code&gt;" when OpenProcess failed (5 = access denied: another user's or a SYSTEM
        /// process when not elevated; 87 = invalid parameter: the process has exited),
        /// "E_TOKEN&lt;code&gt;" when OpenProcessToken failed, "E_ID &lt;message&gt;" when the SID could not be translated.
        /// </summary>
        public static string Get(int pid)
        {
            IntPtr process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (process == IntPtr.Zero)
            {
                return "E_OPEN" + Marshal.GetLastWin32Error();
            }
            IntPtr token = IntPtr.Zero;
            try
            {
                if (!OpenProcessToken(process, TOKEN_QUERY, out token))
                {
                    return "E_TOKEN" + Marshal.GetLastWin32Error();
                }
            }
            finally
            {
                CloseHandle(process);
            }
            try
            {
                using (WindowsIdentity identity = new WindowsIdentity(token))
                {
                    string sid = identity.User == null ? "" : identity.User.Value;
                    string name = "";
                    try { name = identity.Name; } catch (Exception) { name = ""; }
                    return sid + "|" + name;
                }
            }
            catch (Exception e)
            {
                return "E_ID " + e.Message;
            }
            finally
            {
                CloseHandle(token);
            }
        }

        /// <summary>SID only ("S-1-5-...") or "" when the owner is not accessible.</summary>
        public static string GetSid(int pid)
        {
            string s = Get(pid);
            if (s.StartsWith("E_", StringComparison.Ordinal)) { return ""; }
            int i = s.IndexOf('|');
            return i < 0 ? s : s.Substring(0, i);
        }
    }

    /// <summary>Interactive-session state: seconds since the last keyboard/mouse input and the lock state.</summary>
    public static class Session
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO
        {
            public uint cbSize;
            public uint dwTime;
        }

        [DllImport("user32.dll")]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [DllImport("kernel32.dll")]
        private static extern ulong GetTickCount64();

        [DllImport("wtsapi32.dll", SetLastError = true)]
        private static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytesReturned);

        [DllImport("wtsapi32.dll")]
        private static extern void WTSFreeMemory(IntPtr memory);

        [DllImport("kernel32.dll")]
        private static extern bool ProcessIdToSessionId(uint processId, out uint sessionId);

        [DllImport("kernel32.dll")]
        private static extern uint GetCurrentProcessId();

        private const int WTS_CURRENT_SERVER_HANDLE = 0;
        private const int WTSSessionInfoEx = 25;

        /// <summary>
        /// Seconds since the last user input in this session; -1 when unavailable (no interactive session,
        /// e.g. a task running as S4U / service). dwTime is a 32-bit tick count: unsigned subtraction wraps correctly
        /// across the 49.7-day boundary.
        /// </summary>
        public static double IdleSeconds()
        {
            LASTINPUTINFO info = new LASTINPUTINFO();
            info.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
            if (!GetLastInputInfo(ref info)) { return -1; }
            uint now = (uint)(GetTickCount64() & 0xFFFFFFFFUL);
            uint idleMs = unchecked(now - info.dwTime);
            return idleMs / 1000.0;
        }

        /// <summary>Session id of the current process, or -1.</summary>
        public static int CurrentSessionId()
        {
            uint sid;
            if (!ProcessIdToSessionId(GetCurrentProcessId(), out sid)) { return -1; }
            return (int)sid;
        }

        /// <summary>
        /// WTSINFOEX_LEVEL1.SessionFlags of the current session: 0 = locked (WTS_SESSIONSTATE_LOCK),
        /// 1 = unlocked (WTS_SESSIONSTATE_UNLOCK), -1 = unknown (WTS_SESSIONSTATE_UNKNOWN),
        /// -2 = the query failed, -3 = unexpected buffer layout. Windows 8 and later semantics (Windows 7 swapped 0/1).
        /// Layout: WTSINFOEX { DWORD Level @0; (pad) ; WTSINFOEX_LEVEL1 Data @8: SessionId @8, SessionState @12, SessionFlags @16 ... }.
        /// </summary>
        public static int LockFlag()
        {
            int sessionId = CurrentSessionId();
            if (sessionId < 0) { return -2; }
            IntPtr buffer;
            int length;
            if (!WTSQuerySessionInformation(IntPtr.Zero, sessionId, WTSSessionInfoEx, out buffer, out length)) { return -2; }
            try
            {
                if (buffer == IntPtr.Zero || length < 20) { return -3; }
                int level = Marshal.ReadInt32(buffer, 0);
                if (level != 1) { return -3; }
                return Marshal.ReadInt32(buffer, 16);
            }
            finally
            {
                if (buffer != IntPtr.Zero) { WTSFreeMemory(buffer); }
            }
        }

        /// <summary>"Locked", "Unlocked" or "Unknown" from LockFlag().</summary>
        public static string LockState()
        {
            int f = LockFlag();
            if (f == 0) { return "Locked"; }
            if (f == 1) { return "Unlocked"; }
            return "Unknown";
        }
    }
}
