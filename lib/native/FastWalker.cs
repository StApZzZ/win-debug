// lib\native\FastWalker.cs - P/Invoke directory walker for win-debug Disk mode (WinDebug.FastWalker).
//
// Compiled at run time by Add-Type in Windows PowerShell 5.1 (.NET Framework 4.x CodeDom compiler),
// therefore the code sticks to C# 5 syntax (no string interpolation, no ?., no expression-bodied members).
//
// What it does (read-only, one pass per root):
//   * enumerates with FindFirstFileExW(FindExInfoBasic, FIND_FIRST_EX_LARGE_FETCH) and the \\?\ prefix
//     (lifts MAX_PATH regardless of the LongPathsEnabled policy);
//   * never follows links: directories whose reparse tag is a junction / mount point (0xA0000003),
//     a symbolic link (0xA000000C) or a WSL symlink (0xA000001D) are skipped and counted, so nothing is
//     counted twice. Other reparse points (OneDrive cloud files, WOF/CompactOS, dedup, ProjFS) are descended;
//   * takes the allocated size from GetCompressedFileSizeW for sparse / compressed / offline / cloud files
//     (this does NOT hydrate OneDrive placeholders; the file content is never opened);
//   * counts access-denied directories instead of throwing, keeps a sample of their paths;
//   * records per-directory totals for depth 0..maxDepth, files at or above a size threshold, and the bytes of
//     files older than N days (for "reclaimable" estimates).
//   * ScanUnique() is the optional deep step: it opens every file with dwDesiredAccess = 0 (attributes only)
//     and deduplicates hard links by file index so C:\Windows can be reported as "unique bytes".
//   * Cancellation: Scan()/ScanUnique() are single synchronous calls, so PowerShell cannot stop a pipeline
//     while they run. HookCancel() subscribes to Console.CancelKeyPress and sets the volatile Cancel flag; the
//     walk unwinds at the next directory and the result carries Cancelled = true. The handler does not swallow
//     the key press (e.Cancel stays false), so the console host still stops the pipeline afterwards.
//   * UNC paths get the \\?\UNC\server\share form so that long paths work there too (Disk mode itself never
//     walks network locations, but the helper must not silently truncate at MAX_PATH if a caller does).
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace WinDebug
{
    public class DirEntry
    {
        public string Path;
        public int Depth;
        public long Bytes;            // logical size of all files below
        public long Alloc;            // allocated-on-disk size of all files below
        public long Files;
        public long Dirs;
        public int Denied;            // inaccessible directories below (or this one when it is denied itself)
        public long CloudOnlyFiles;   // OneDrive / cloud placeholders below (0 bytes on disk)
        public long CloudOnlyBytes;   // their logical size
    }

    public class FileEntry
    {
        public string Path;
        public long Bytes;
        public long Alloc;
        public DateTime LastWriteUtc;
        public DateTime CreatedUtc;
        public uint Attributes;
        public bool CloudOnly { get { return (Attributes & 0x400000u) != 0; } }
    }

    public class UniqueResult
    {
        public string Root;
        public long Files;
        public long Bytes;            // summed (every hard link counted)
        public long UniqueBytes;      // each file index counted once
        public long LinkedFiles;      // files with more than one hard link
        public long DuplicateLinks;   // additional links that were not counted again
        public long OpenErrors;
        public int Denied;
        public bool Cancelled;        // Ctrl+C: the walk was cut short, totals are partial
        public double ElapsedMs;
    }

    public class ScanResult
    {
        public string Root;
        public int MaxDepth;
        public long Files;
        public long Dirs;
        public long Bytes;
        public long Alloc;
        public long CloudOnlyFiles;
        public long CloudOnlyBytes;
        public long OldFiles;
        public long OldBytes;
        public int Denied;
        public int SkippedLinks;
        public int Errors;
        public int DeepestLevel;
        public bool Cancelled;        // Ctrl+C: the walk was cut short, totals are partial
        public double ElapsedMs;
        public List<DirEntry> Directories = new List<DirEntry>();
        public List<FileEntry> LargeFiles = new List<FileEntry>();
        public List<string> DeniedPaths = new List<string>();
        private Dictionary<string, DirEntry> index;

        internal static string NormalizeKey(string path)
        {
            if (string.IsNullOrEmpty(path)) return string.Empty;
            string p = path.Trim();
            if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) p = @"\\" + p.Substring(8);
            else if (p.StartsWith(@"\\?\")) p = p.Substring(4);
            p = p.TrimEnd('\\');
            if (p.Length == 2 && p[1] == ':') p += "\\";
            return p;
        }

        public DirEntry Find(string path)
        {
            if (index == null)
            {
                index = new Dictionary<string, DirEntry>(StringComparer.OrdinalIgnoreCase);
                foreach (DirEntry d in Directories) index[NormalizeKey(d.Path)] = d;
            }
            DirEntry e;
            if (index.TryGetValue(NormalizeKey(path), out e)) return e;
            return null;
        }

        public List<DirEntry> TopDirectories(int depth, int top)
        {
            List<DirEntry> list = new List<DirEntry>();
            foreach (DirEntry d in Directories) if (d.Depth == depth) list.Add(d);
            list.Sort(delegate(DirEntry a, DirEntry b)
            {
                int c = b.Alloc.CompareTo(a.Alloc);
                if (c != 0) return c;
                c = b.Bytes.CompareTo(a.Bytes);
                if (c != 0) return c;
                return string.Compare(a.Path, b.Path, StringComparison.OrdinalIgnoreCase);
            });
            if (top > 0 && list.Count > top) list.RemoveRange(top, list.Count - top);
            return list;
        }

        public List<FileEntry> TopFiles(int top)
        {
            List<FileEntry> list = new List<FileEntry>(LargeFiles);
            list.Sort(delegate(FileEntry a, FileEntry b)
            {
                int c = b.Alloc.CompareTo(a.Alloc);
                if (c != 0) return c;
                c = b.Bytes.CompareTo(a.Bytes);
                if (c != 0) return c;
                return string.Compare(a.Path, b.Path, StringComparison.OrdinalIgnoreCase);
            });
            if (top > 0 && list.Count > top) list.RemoveRange(top, list.Count - top);
            return list;
        }
    }

    public static class FastWalker
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WIN32_FIND_DATA
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint dwReserved0;
            public uint dwReserved1;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string cFileName;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)] public string cAlternateFileName;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION
        {
            public uint dwFileAttributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;
            public System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;
            public uint dwVolumeSerialNumber;
            public uint nFileSizeHigh;
            public uint nFileSizeLow;
            public uint nNumberOfLinks;
            public uint nFileIndexHigh;
            public uint nFileIndexLow;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindFirstFileExW(string lpFileName, int fInfoLevelId, out WIN32_FIND_DATA lpFindFileData, int fSearchOp, IntPtr lpSearchFilter, int dwAdditionalFlags);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool FindNextFileW(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool FindClose(IntPtr hFindFile);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetCompressedFileSizeW(string lpFileName, out uint lpFileSizeHigh);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern uint GetLongPathNameW(string lpszShortPath, StringBuilder lpszLongPath, uint cchBuffer);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(IntPtr hFile, out BY_HANDLE_FILE_INFORMATION lpFileInformation);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

        private const uint ATTR_DIRECTORY = 0x10;
        private const uint ATTR_SPARSE = 0x200;
        private const uint ATTR_REPARSE_POINT = 0x400;
        private const uint ATTR_COMPRESSED = 0x800;
        private const uint ATTR_OFFLINE = 0x1000;
        private const uint ATTR_RECALL_ON_OPEN = 0x40000;
        private const uint ATTR_RECALL_ON_DATA_ACCESS = 0x400000;
        private const uint ATTR_NEEDS_ALLOC_QUERY = ATTR_SPARSE | ATTR_COMPRESSED | ATTR_REPARSE_POINT | ATTR_OFFLINE | ATTR_RECALL_ON_OPEN | ATTR_RECALL_ON_DATA_ACCESS;

        private const uint TAG_MOUNT_POINT = 0xA0000003;   // junction / volume mount point
        private const uint TAG_SYMLINK = 0xA000000C;
        private const uint TAG_LX_SYMLINK = 0xA000001D;    // WSL symlink

        private const int FindExInfoBasic = 1;
        private const int FindExSearchNameMatch = 0;
        private const int FIND_FIRST_EX_LARGE_FETCH = 2;
        private const int ERROR_FILE_NOT_FOUND = 2;
        private const int ERROR_PATH_NOT_FOUND = 3;
        private const int ERROR_ACCESS_DENIED = 5;
        private const int ERROR_NO_MORE_FILES = 18;
        private const int MAX_NESTING = 512;
        private const int DENIED_SAMPLE = 200;

        private const uint FILE_SHARE_ALL = 0x1 | 0x2 | 0x4;
        private const uint OPEN_EXISTING = 3;
        private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

        private class Agg
        {
            public long Bytes;
            public long Alloc;
            public long Files;
            public long Dirs;
            public long CloudFiles;
            public long CloudBytes;
            public int Denied;
        }

        private static long ToLong(uint high, uint low)
        {
            return ((long)high << 32) | (long)low;
        }

        private static long FileTimeToLong(System.Runtime.InteropServices.ComTypes.FILETIME ft)
        {
            return ((long)ft.dwHighDateTime << 32) | (uint)ft.dwLowDateTime;
        }

        private static DateTime FileTimeToUtc(System.Runtime.InteropServices.ComTypes.FILETIME ft)
        {
            long v = FileTimeToLong(ft);
            if (v <= 0) return DateTime.MinValue;
            try { return DateTime.FromFileTimeUtc(v); } catch (ArgumentOutOfRangeException) { return DateTime.MinValue; }
        }

        /// <summary>Set by the Ctrl+C handler (or by a caller); every Walk()/WalkUnique() step checks it.</summary>
        public static volatile bool Cancel;
        private static ConsoleCancelEventHandler cancelHandler;

        /// <summary>Resets Cancel and subscribes to Console.CancelKeyPress (no-op without a console).</summary>
        public static void HookCancel()
        {
            Cancel = false;
            if (cancelHandler != null) return;
            ConsoleCancelEventHandler h = new ConsoleCancelEventHandler(OnCancelKeyPress);
            try { Console.CancelKeyPress += h; cancelHandler = h; }
            catch (Exception) { cancelHandler = null; }
        }

        public static void UnhookCancel()
        {
            ConsoleCancelEventHandler h = cancelHandler;
            cancelHandler = null;
            if (h == null) return;
            try { Console.CancelKeyPress -= h; } catch (Exception) { }
        }

        private static void OnCancelKeyPress(object sender, ConsoleCancelEventArgs e)
        {
            Cancel = true;   // e.Cancel stays false: the host's own Ctrl+C handling (pipeline stop) still runs
        }

        private static string NormalizeRoot(string root)
        {
            return ScanResult.NormalizeKey(root);
        }

        /// <summary>\\?\ form of a path: lifts MAX_PATH; UNC paths become \\?\UNC\server\share\... .</summary>
        private static string Extended(string path)
        {
            if (path.StartsWith(@"\\?\")) return path;
            if (path.StartsWith(@"\\")) return @"\\?\UNC\" + path.Substring(2);
            return @"\\?\" + path;
        }

        private static string SearchPattern(string dir)
        {
            string prefix = Extended(dir);
            return prefix.EndsWith("\\") ? prefix + "*" : prefix + "\\*";
        }

        private static string Combine(string dir, string name)
        {
            return dir.EndsWith("\\") ? dir + name : dir + "\\" + name;
        }

        private static bool IsLinkTag(uint tag)
        {
            return tag == TAG_MOUNT_POINT || tag == TAG_SYMLINK || tag == TAG_LX_SYMLINK;
        }

        /// <summary>Allocated size of one file (falls back to the logical size when the query fails).</summary>
        private static long AllocatedSize(string fullPath, long logical)
        {
            uint high;
            uint low = GetCompressedFileSizeW(Extended(fullPath), out high);
            if (low == 0xFFFFFFFF && Marshal.GetLastWin32Error() != 0) return logical;
            return ToLong(high, low);
        }

        /// <summary>
        /// One pass over root. maxDepth = deepest directory level that gets its own DirEntry (0 = totals only);
        /// largeFileThreshold = files at or above this logical or allocated size are listed (long.MaxValue = none);
        /// oldDays = files whose last write is older than this many days are summed into OldFiles/OldBytes (0 = off).
        /// </summary>
        public static ScanResult Scan(string root, int maxDepth, long largeFileThreshold, int oldDays)
        {
            System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
            ScanResult r = new ScanResult();
            string start = NormalizeRoot(root);
            r.Root = start;
            r.MaxDepth = maxDepth;
            long oldCutoff = 0;
            if (oldDays > 0) oldCutoff = DateTime.UtcNow.AddDays(-oldDays).ToFileTimeUtc();
            Agg agg = new Agg();
            Walk(r, start, 0, agg, largeFileThreshold, oldCutoff);
            r.Files = agg.Files;
            r.Dirs = agg.Dirs;
            r.Bytes = agg.Bytes;
            r.Alloc = agg.Alloc;
            DirEntry rootEntry = new DirEntry();
            rootEntry.Path = start;
            rootEntry.Depth = 0;
            rootEntry.Bytes = agg.Bytes;
            rootEntry.Alloc = agg.Alloc;
            rootEntry.Files = agg.Files;
            rootEntry.Dirs = agg.Dirs;
            rootEntry.Denied = agg.Denied;
            rootEntry.CloudOnlyFiles = agg.CloudFiles;
            rootEntry.CloudOnlyBytes = agg.CloudBytes;
            r.Directories.Insert(0, rootEntry);
            sw.Stop();
            r.ElapsedMs = sw.Elapsed.TotalMilliseconds;
            return r;
        }

        private static void Walk(ScanResult r, string dir, int depth, Agg agg, long threshold, long oldCutoff)
        {
            if (Cancel) { r.Cancelled = true; return; }
            if (depth > r.DeepestLevel) r.DeepestLevel = depth;
            WIN32_FIND_DATA fd;
            IntPtr h = FindFirstFileExW(SearchPattern(dir), FindExInfoBasic, out fd, FindExSearchNameMatch, IntPtr.Zero, FIND_FIRST_EX_LARGE_FETCH);
            if (h == INVALID_HANDLE)
            {
                int e = Marshal.GetLastWin32Error();
                if (e == ERROR_ACCESS_DENIED)
                {
                    r.Denied++;
                    agg.Denied++;
                    if (r.DeniedPaths.Count < DENIED_SAMPLE) r.DeniedPaths.Add(dir);
                }
                else if (e != ERROR_FILE_NOT_FOUND && e != ERROR_PATH_NOT_FOUND)
                {
                    r.Errors++;
                }
                return;
            }
            try
            {
                do
                {
                    string name = fd.cFileName;
                    if (name == "." || name == "..") continue;
                    if (Cancel) { r.Cancelled = true; break; }
                    uint attrs = fd.dwFileAttributes;
                    string full = Combine(dir, name);
                    if ((attrs & ATTR_DIRECTORY) != 0)
                    {
                        if ((attrs & ATTR_REPARSE_POINT) != 0 && IsLinkTag(fd.dwReserved0))
                        {
                            r.SkippedLinks++;
                            continue;
                        }
                        agg.Dirs++;
                        Agg child = new Agg();
                        if (depth < MAX_NESTING) Walk(r, full, depth + 1, child, threshold, oldCutoff);
                        else r.Errors++;
                        agg.Bytes += child.Bytes;
                        agg.Alloc += child.Alloc;
                        agg.Files += child.Files;
                        agg.Dirs += child.Dirs;
                        agg.CloudFiles += child.CloudFiles;
                        agg.CloudBytes += child.CloudBytes;
                        agg.Denied += child.Denied;
                        if (depth + 1 <= r.MaxDepth)
                        {
                            DirEntry de = new DirEntry();
                            de.Path = full;
                            de.Depth = depth + 1;
                            de.Bytes = child.Bytes;
                            de.Alloc = child.Alloc;
                            de.Files = child.Files;
                            de.Dirs = child.Dirs;
                            de.Denied = child.Denied;
                            de.CloudOnlyFiles = child.CloudFiles;
                            de.CloudOnlyBytes = child.CloudBytes;
                            r.Directories.Add(de);
                        }
                    }
                    else
                    {
                        long size = ToLong(fd.nFileSizeHigh, fd.nFileSizeLow);
                        long alloc = size;
                        if ((attrs & ATTR_NEEDS_ALLOC_QUERY) != 0)
                        {
                            alloc = AllocatedSize(full, size);
                            if ((attrs & ATTR_RECALL_ON_DATA_ACCESS) != 0)
                            {
                                r.CloudOnlyFiles++;
                                r.CloudOnlyBytes += size;
                                agg.CloudFiles++;
                                agg.CloudBytes += size;
                            }
                        }
                        agg.Files++;
                        agg.Bytes += size;
                        agg.Alloc += alloc;
                        if (oldCutoff != 0 && FileTimeToLong(fd.ftLastWriteTime) < oldCutoff)
                        {
                            r.OldFiles++;
                            r.OldBytes += alloc;
                        }
                        if (size >= threshold || alloc >= threshold)
                        {
                            FileEntry fe = new FileEntry();
                            fe.Path = full;
                            fe.Bytes = size;
                            fe.Alloc = alloc;
                            fe.LastWriteUtc = FileTimeToUtc(fd.ftLastWriteTime);
                            fe.CreatedUtc = FileTimeToUtc(fd.ftCreationTime);
                            fe.Attributes = attrs;
                            r.LargeFiles.Add(fe);
                        }
                    }
                } while (FindNextFileW(h, out fd));
                if (!r.Cancelled)
                {
                    int e2 = Marshal.GetLastWin32Error();
                    if (e2 != ERROR_NO_MORE_FILES && e2 != 0) r.Errors++;
                }
            }
            finally
            {
                FindClose(h);
            }
        }

        /// <summary>Long-name form of a path that may contain 8.3 segments (e.g. %TEMP%); input on failure.</summary>
        public static string GetLongPath(string path)
        {
            if (string.IsNullOrEmpty(path)) return path;
            try
            {
                StringBuilder sb = new StringBuilder(1024);
                uint n = GetLongPathNameW(path, sb, (uint)sb.Capacity);
                if (n == 0 || n > sb.Capacity) return path;
                return sb.ToString();
            }
            catch (Exception) { return path; }
        }

        /// <summary>
        /// Deep step: walks root like Scan() but opens every file (attributes only, no content access) to read its
        /// hard-link count and file index; bytes of a file index already seen are not counted twice.
        /// </summary>
        public static UniqueResult ScanUnique(string root)
        {
            System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
            UniqueResult u = new UniqueResult();
            u.Root = NormalizeRoot(root);
            HashSet<ulong> seen = new HashSet<ulong>();
            WalkUnique(u, seen, u.Root, 0);
            sw.Stop();
            u.ElapsedMs = sw.Elapsed.TotalMilliseconds;
            return u;
        }

        private static void WalkUnique(UniqueResult u, HashSet<ulong> seen, string dir, int depth)
        {
            if (Cancel) { u.Cancelled = true; return; }
            WIN32_FIND_DATA fd;
            IntPtr h = FindFirstFileExW(SearchPattern(dir), FindExInfoBasic, out fd, FindExSearchNameMatch, IntPtr.Zero, FIND_FIRST_EX_LARGE_FETCH);
            if (h == INVALID_HANDLE)
            {
                if (Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED) u.Denied++;
                return;
            }
            try
            {
                do
                {
                    string name = fd.cFileName;
                    if (name == "." || name == "..") continue;
                    if (Cancel) { u.Cancelled = true; break; }
                    uint attrs = fd.dwFileAttributes;
                    string full = Combine(dir, name);
                    if ((attrs & ATTR_DIRECTORY) != 0)
                    {
                        if ((attrs & ATTR_REPARSE_POINT) != 0 && IsLinkTag(fd.dwReserved0)) continue;
                        if (depth < MAX_NESTING) WalkUnique(u, seen, full, depth + 1);
                        continue;
                    }
                    long size = ToLong(fd.nFileSizeHigh, fd.nFileSizeLow);
                    if ((attrs & ATTR_NEEDS_ALLOC_QUERY) != 0) size = AllocatedSize(full, size);
                    u.Files++;
                    u.Bytes += size;
                    bool unique = true;
                    IntPtr fh = CreateFileW(Extended(full), 0, FILE_SHARE_ALL, IntPtr.Zero, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, IntPtr.Zero);
                    if (fh == INVALID_HANDLE)
                    {
                        u.OpenErrors++;
                    }
                    else
                    {
                        try
                        {
                            BY_HANDLE_FILE_INFORMATION info;
                            if (GetFileInformationByHandle(fh, out info) && info.nNumberOfLinks > 1)
                            {
                                u.LinkedFiles++;
                                ulong key = ((ulong)info.nFileIndexHigh << 32) | (ulong)info.nFileIndexLow;
                                if (!seen.Add(key)) { unique = false; u.DuplicateLinks++; }
                            }
                        }
                        finally { CloseHandle(fh); }
                    }
                    if (unique) u.UniqueBytes += size;
                } while (FindNextFileW(h, out fd));
            }
            finally
            {
                FindClose(h);
            }
        }
    }
}
