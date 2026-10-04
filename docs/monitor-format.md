# Monitor session format (contract for `lib\Analyze.ps1`)

Format version **1** (`FormatVersion` in `run.json` and `procsum.json`). Written by `lib\Monitor.ps1`
(`Start-ProcessMonitor`), Windows PowerShell 5.1. Everything below is what Analyze may rely on.

## Session folder

`<OutputRoot>\<COMPUTERNAME>_<yyyyMMdd-HHmmss>_monitor[-N]\` (created by `New-ReportDirectory`).

| File | Written | Purpose |
|---|---|---|
| `run.json` | at start, after the first completed sample, at every 60 s `procsum.json` flush, at stop (temp file + atomic replace) | host facts, settings, stop reason, counters (`SamplesWritten`, `LastSampleTime`, `ProcessesWithoutPath` are real for a live or killed session) |
| `samples_<yyyy-MM-dd>.csv` | one row per sample | system totals (rotates at local midnight) |
| `procs_<yyyy-MM-dd>.csv` | filtered rows per sample | per-process metrics (rotates at local midnight) |
| `procmeta.csv` | once per process (`Key`) | static facts: path, command line, owner, signature, hash, rule flags |
| `procsum.json` | rewritten atomically every 60 s and at stop | cumulative per-process totals over **all** samples (authoritative, unaffected by the row filter) |
| `net.csv` | first sight of a connection | TCP Established/Listen endpoints per process |
| `dns.csv` | first sight of a name/address pair | DNS client cache (not attributable to a PID) |
| `events.csv` | as they happen / every 60 s | monitor events, process start/exit, idle transitions, event-log hits |
| `filecache.json` | every 60 s when changed, at stop | executable facts keyed by lower-case path (signature, hash, version info) |
| `monitor.log` | continuously | diagnostics: run header, one `Sample N: ... ms, ..., steps=<step ms/...>` line per sample (per-step times are folded into that line), throttled warnings (a failing step is reported 3 times, then every 100th), event-log backlog notes, stop reason. `-Verbose` adds one `DEBUG` line per step (`Monitor.<Step> ok in N ms`); without it the file grows by roughly 300 bytes per sample |
| `run.log` | header only | written by the entry point; points to `monitor.log` |
| `monitor.running` | while running | own PID (line 1) and start time (line 2); removed at a clean stop |
| `STOP` | by the user or `Stop-ProcessMonitor` | stop request; removed at a clean stop |

A crash or `taskkill` leaves `monitor.running` and possibly a truncated last line in a CSV (see "Robustness").
`Stop-ProcessMonitor` treats a marker whose PID is not a live `powershell` process as stale. It returns one of
`Stopped` (every live monitor confirmed within 30 s), `Signaled` (STOP file written, no confirmation yet; the monitor
stops at its next check) or `None` (no live monitor); the entry point maps these to exit codes 0 / 0 / 3.

## Conventions

- CSV: comma delimiter, header line, **UTF-8 with BOM**, CRLF, one physical line per row (line breaks inside a
  value are replaced by spaces). Values are quoted only when they contain `,` or `"` (`"` doubled).
- **Excel formula guard** (`Protect-WdCsvText` in `lib\Common.ps1`, shared with the Inventory/Disk CSVs): a text cell
  that starts with `=`, `+`, `@`, TAB, CR, or with `-` (unless the whole cell is a number such as `-5` or `-1.50`), is
  written with one leading space (`" --distro-id {...}"`, `" =cmd|..."`, `" -2+3"`). Cells that carry text chosen by the observed process (`CommandLine`,
  `Company`, `Description`, `OriginalFilename`, `Detail` incl. 4104 script text, DNS names) would otherwise be
  evaluated as formulas or rendered as `#NAME?` when the file is opened in Excel. Numbers, booleans and timestamps are
  never prefixed. Readers that compare or match such cells should `TrimStart(' ')` them first (Analyze's regex rules
  are unanchored and unaffected; `Key`, `Path`, `Name`, `Timestamp` never start with one of these characters).
- **Secret masking** (`Hide-WdSecret` in `lib\Common.ps1`, best effort): `procmeta.CommandLine`,
  `procsum.json` `CommandLine` and `events.Detail` (4104 script text, 7045 service install messages, `WmiProcessStart`
  command lines and every other event-log `Detail`) are written with the value of a password / key / token argument
  replaced by `***` (`--password ***`, `PrivateKey = ***`, `"token": "***"`, `https://user:***@host`, `?token=***`).
  The key name stays, so the shape of the command line is still visible. Miner pool hosts, ports and wallet
  addresses (`-o pool:4444 -u 48abc...`) are **not** masked - they are the evidence Analyze needs. The rule flags
  (`MinerTokens`, `ScriptHostRedFlag`, `ScriptHostWeakArgs`, `WinDebugTool`) are always evaluated on the **original**
  command line before masking, so a masked row can carry a flag whose trigger is no longer visible in the cell.
- Numbers are culture-invariant (`.` decimal). Percentages have 2 decimals, `CpuCores` 3, `TempC` and
  `IntervalSec` 1. Byte counts and rates are integers. Empty cell = not available for that row.
- Booleans are `True` / `False`. Timestamps are local ISO 8601 with offset: `2026-09-28T00:00:26.992+03:00`.
- JSON files: UTF-8 without BOM, compact, only strings/numbers/booleans/objects (no `\/Date(`).
- **Key** = `"<pid>|<creation FILETIME>"`, e.g. `12940|134350164191466293`. The second part is the raw
  `ElapsedTime` of `Win32_PerfRawData_PerfProc_Process` (100 ns ticks since 1601, local FILETIME); it equals the
  process start time to the tick and makes the key immune to PID reuse. `[DateTime]::FromFileTime([int64]$ticks)`
  gives the start time. The same `Key` is used in `procs`, `procmeta`, `net`, `events` and as the object name in
  `procsum.json`. A TCP row whose owning PID was not in the process snapshot has `Key = "<pid>|?"`.
- `Name` is the PerfProc instance name without the `#N` suffix and without extension (`svchost`, `powershell`).
  `procmeta.ImageName` has the real image name (`svchost.exe`) when readable.
- The monitor's own `powershell.exe` is tagged `Self` (procs `Flags`, procmeta `Flags`). It is excluded from the
  Top-N selection and from `TopCpuName`, but included in `CpuProcSumPct`. `WmiPrvSE.exe` (WMI provider host) shows a
  few percent CPU because of the sampling itself; it is not tagged.
- User idle: `IsIdle = IdleSeconds >= 300 OR SessionLocked` (threshold in `run.json.IdleThresholdSec`).
  `SessionLocked` is true when `WTSQuerySessionInformation` reports the lock flag or a `LogonUI` process exists
  (also true during UAC prompts and the logon screen).

## Sampling

- Interval `IntervalSeconds` (default 10, minimum 5), absolute-clock scheduling. A sample that started more than
  1 s late, or that follows a sample longer than the interval, has `Overrun = True`; missed ticks are skipped, not
  caught up. `IntervalSec` is the real distance to the previous sample (from the performance-counter timestamps).
- Sample 1 is a **baseline**: rates need two snapshots, so its `CpuPct`, per-process CPU/IO and GPU columns are empty
  and it writes **no `procs` rows** and no `ProcessNew` events. All processes present at start get a `procmeta`
  row with `FirstSeen = start` and `PresentAtStart = true` in `procsum.json`.
- `HasWindow` / `PrivateBytes` come from `Get-Process` every 3rd sample; DNS is read every 3rd sample; event logs
  are polled every 60 s; TCP every sample.
- Per-process CPU is the delta of the raw cumulative `PercentProcessorTime` over the sample window: the true
  average over the interval (not an instantaneous value). New processes get their first values one sample later.

## `samples_<date>.csv` (one row per sample)

| Column | Type | Unit | Meaning / computation |
|---|---|---|---|
| Timestamp | ISO | | sample start (local) |
| SampleNo | int | | 1-based counter for the run |
| IntervalSec | number(1) | s | seconds since the previous sample (`_Total` `Timestamp_Sys100NS` delta / 1e7); empty on sample 1 |
| SampleMs | int | ms | wall time of the collection (excludes post-sample work) |
| Overrun | bool | | see Sampling |
| CpuPct | number | % of all cores | `100 - 100*dIdle/dT` from `Win32_PerfRawData_PerfOS_Processor(_Total)` |
| CpuKernelPct | number | % | privileged time, same source |
| CpuDpcIntPct | number | % | DPC + interrupt time, same source |
| CpuProcSumPct | number | % | sum of `CpuPct` of all processes (incl. Self, excl. Idle). Typically 3-8 points below `CpuPct`: kernel time charged to no process (about 4-5 points on a 12-core laptop) |
| CpuPerfPct | number | % | `% Processor Performance` (`Win32_PerfRawData_Counters_ProcessorInformation`, dValue/dBase): > 100 turbo, < 100 sustained under load = throttling |
| CpuUtilityPct | number | % | `% Processor Utility` (frequency-weighted busy), same source |
| CpuFreqMHz | int | MHz | nominal frequency |
| MemTotalMB | int | MB | `Win32_OperatingSystem.TotalVisibleMemorySize` (constant) |
| MemUsedMB / MemAvailMB | int | MB | `MemTotalMB - AvailableBytes/1MB` / `AvailableBytes/1MB` (`Win32_PerfRawData_PerfOS_Memory`) |
| CommitBytes / CommitLimitBytes / CommitPct | int / int / number | B / B / % | committed charge and limit |
| PagesPerSec | int | /s | hard page faults (delta of `PagesPersec`) |
| PoolNonpagedBytes | int | B | non-paged pool (leak indicator when growing) |
| DiskActivePct | number | % | `100 - idle` from `PhysicalDisk(_Total)` `PercentIdleTime/_Base` deltas |
| DiskQueue | int | | `CurrentDiskQueueLength` (gauge) |
| DiskReadBps / DiskWriteBps | int | B/s | bulk-counter deltas |
| DiskAvgMs | number | ms | average seconds per transfer * 1000 (`AvgDisksecPerTransfer` delta / `Frequency_PerfTime` / transfers) |
| DiskTransfersPerSec | int | /s | |
| NetRecvBps / NetSentBps | int | B/s | sum over all `Win32_PerfRawData_Tcpip_NetworkInterface` instances |
| GpuPct | number | % | busiest single GPU engine (max over `luid|engine` of the per-process sum), 0-100, Task Manager style |
| Gpu3DPct, GpuComputePct, GpuCopyPct, GpuVideoDecodePct, GpuVideoEncodePct, GpuOtherPct | number | engine-% | sum over all processes and all engine instances of that type; one fully busy engine = 100, several engines of the same type can exceed 100 |
| GpuDedicatedBytes / GpuSharedBytes | int | B | `GPUAdapterMemory` summed over adapters |
| BatteryPct | int | % | `Win32_Battery.EstimatedChargeRemaining`; empty on desktops |
| OnBattery | bool | | `BatteryStatus = 1` (discharging) -> True; AC -> False; empty without battery |
| TempC | number(1) | C | hottest `ThermalZoneInformation` zone (Kelvin - 273.15); empty when the class has no instances |
| ThrottleReasons | int | bit mask | OR of `ThrottleReasons` over zones; 0 = none |
| IdleSeconds | int | s | `GetLastInputInfo` (seconds since the last keyboard/mouse input in this session); empty when unavailable |
| SessionLocked | bool | | see Conventions |
| IsIdle | bool | | see Conventions |
| ProcessCount / ThreadCount | int | | `Win32_PerfRawData_PerfOS_System` gauges |
| ContextSwitchesPerSec | int | /s | delta |
| ProcQueue | int | | `ProcessorQueueLength` |
| TopCpuName / TopCpuPct | string / number | | process with the highest `CpuPct` this sample (Self excluded) |

## `procs_<date>.csv` (filtered per-process rows)

A row is written when **any** of these holds for the process in that sample: `CpuPct >= 0.5` or `CpuCores >= 0.25`;
`GpuPct > 0.5`; `ReadBps + WriteBps > 102400`; `WorkingSet >= 104857600` (100 MB); it is `New`, `Exited` or
its `HasWindow` changed (`WindowChanged`); it is in the **Top-15 by CpuPct** or **Top-5 by GpuPct** of the sample
(Self excluded); or it is on the watch list (any procmeta `Flags` other than the informational
`Self` / `WinDebugTool` / `ScriptHostWeakArgs`, or a pool-port connection). Everything else is only in `procsum.json`. Typical volume on a PC with ~1000 processes: 40-60 rows per sample.

| Column | Type | Unit | Meaning |
|---|---|---|---|
| Timestamp | ISO | | sample start (same value as the `samples` row) |
| Key, Pid, Name | string, int, string | | see Conventions |
| CpuPct | number | % of all cores | `100 * dCpu / dT / NCPU` |
| CpuCores | number(3) | cores | `dCpu / dT`; 1.000 = one full core, up to NCPU |
| GpuPct | number | engine-% | sum over all engines used by the process (can exceed 100) |
| Gpu3D, GpuCompute, GpuCopy, GpuVideoDecode, GpuVideoEncode, GpuOther | number | engine-% | per engine type. Buckets by `engtype_` name: `Compute|Cuda` -> Compute, `3D` -> 3D (incl. High Priority 3D), `Copy*` -> Copy, `*Encode*` -> VideoEncode, other `Video*` (Decode, Codec, JPEG, Processing) -> VideoDecode, rest (Security, Timer, True Audio, ...) -> Other. AMD reports encode and decode as `Video Codec` -> it lands in VideoDecode |
| GpuDedicatedBytes / GpuSharedBytes | int | B | `GPUProcessMemory` summed over adapters |
| ReadBps / WriteBps | int | B/s | IO bytes (all I/O incl. network and pipes) |
| WorkingSet / WorkingSetPrivate | int | B | |
| PrivateBytes | int | B | `Get-Process.PrivateMemorySize64`, refreshed every 3rd sample; empty for a brand-new process |
| Threads / Handles | int | | |
| BasePriority | int | | 4 Idle, 6 BelowNormal, 8 Normal, 10 AboveNormal, 13 High, 24 Realtime |
| HasWindow | bool | | `MainWindowHandle != 0`; empty when not yet known; always False for session-0 processes |
| IsIdle | bool | | copy of the sample's `IsIdle` |
| Flags | string | | `;`-joined subset of `New`, `Exited`, `Self`, `WindowChanged`; empty for an ordinary row |

`New` rows have empty CPU/IO cells (no delta yet). `Exited` rows carry only `Timestamp, Key, Pid, Name, IsIdle, Flags`.

## `procmeta.csv` (one row per Key)

Rows for processes with a readable path are written when the file facts are known (a queue with a time budget
resolves ~25 paths per sample; the initial ~250 unique paths take 1-3 minutes). Rows may therefore appear later than
the process and are **not** in time order. At stop, unresolved rows are written with empty file columns and
`AccessNote = "file info pending at stop"`.

| Column | Meaning |
|---|---|
| Key, Pid, Name | see Conventions |
| ImageName | `Win32_Process.Name` (with extension); empty when not readable |
| Path | `Win32_Process.ExecutablePath`; empty for SYSTEM/service/other-user processes when not elevated |
| CommandLine | full command line (line breaks flattened, **secrets masked** - see Conventions: `--password ***`, `PrivateKey = ***`; pool/wallet arguments untouched); empty as above |
| Ppid | creating process id (from PerfProc) |
| ParentKey | Key of the parent if it was alive in the same snapshot, else empty |
| ParentName | parent name from the snapshot or history; `<none>` (ppid 0), `<exited>` (unknown) |
| Started | process creation time (from the Key's FILETIME) |
| FirstSeen | first sample that contained the process (`= run start` for processes present at start) |
| SessionId | 0 = services, 1+ = interactive |
| Owner / OwnerSid | `DOMAIN\user` and SID from the process token (P/Invoke). Not elevated: own processes only; others show `Owner = "(requires administrator)"` |
| LocationClass | `Get-ProcessLocationClass` of Path: System32, Windows, ProgramFiles, ProgramData, Public, Downloads, AppData, UserProfile, Temp, RecycleBin, Network, Removable, Other, Unknown (no path) |
| Company, Description, ProductVersion, OriginalFilename | `FileVersionInfo` (strings verbatim) |
| FileSize, FileCreated, FileModified | file facts |
| SigStatus | `Get-AuthenticodeSignature` status: Valid, NotSigned, HashMismatch, NotTrusted, UnknownError, Error; empty without path |
| Signer | certificate subject (first 200 chars) |
| IsOSBinary | signature bound to the Windows catalog |
| Sha256 | lower-case hex; `SKIPPED_SIZE` for files > 64 MB; `ERROR` on read failure |
| Flags | `;`-joined, evaluated on the **original** (unmasked) command line. **Informational** (never a red flag, not on the watch list): `Self` (the monitor itself), `WinDebugTool` (command line contains `WinDebug.ps1`: another win-debug mode running concurrently), `ScriptHostWeakArgs` (`ScriptHostRegex` executable such as powershell/wscript/mshta/cmd **plus** a `ScriptHostWeakArgRegex` launch option: `-ExecutionPolicy Bypass`, `-NoProfile`, `-WindowStyle Hidden`, `-NonInteractive` - how every ordinary scheduled script is started; Analyze scores it with at most 2 points). **Watch-list** flags (the process gets a `procs` row every sample): `SuspiciousPath` (`SuspiciousPathRegex`: Temp, AppData, ProgramData, Public, Recycle Bin ... with folder boundaries), `MinerTokens` (`MinerTokenRegex` on the command line: `stratum+tcp`/`stratum+ssl`, `-o host:port`, `--url=stratum...`, `--algo`, `--donate-level`, `randomx`, `kawpow`, miner product names, Monero wallets; **only a stratum URL counts** - a bare `--url=` does not match, so Electron/Chromium helpers with `--url=https://...` are not flagged), `ScriptHostRedFlag` (`ScriptHostRegex` executable **plus** a `ScriptHostStrongArgRegex` payload indicator: `-EncodedCommand`/`-enc`/`-e <base64>`, `DownloadString`/`DownloadFile`, `IEX`/`Invoke-Expression`, `FromBase64String`, `scrobj.dll`, `urlcache`, `certutil -decode`, `bitsadmin`, `curl`/`wget`, an `http(s)://` URL, `javascript:`/`vbscript:`; a command line that matches both regexes gets only `ScriptHostRedFlag`), `SystemNameOutsideSystem32` (`SystemBinaryNames` whose directory is **not exactly** one of its `SystemBinaryLocations`; subfolders such as `System32\Tasks`, `System32\spool\drivers\color`, `Windows\Tasks` and sibling names such as `System32Evil` are flagged; Defender's `Platform\<version>\` is the only allowed one-level subfolder), `UnexpectedParent` (`ExpectedParents`; not evaluated when the parent has exited). Rule data lives in `lib\Common.ps1` (`docs\ARCHITECTURE.md`, "Shared rule data") |
| AccessNote | empty = complete; `(requires administrator)` = path/command line/owner not readable; `owner (requires administrator)`; `exited before metadata`; `path not available`; `file not found` (the image is no longer on disk - signature/hash columns are empty, never copied from an earlier cache entry); `file info pending at stop` |

## `procsum.json`

```
{ "Meta": { "Version", "FormatVersion", "Computer", "Start", "Written", "IntervalSec", "NCPU", "Samples",
            "IsElevated", "StopReason", "Processes" },
  "Processes": { "<Key>": { ... }, ... } }
```

Per process (numbers are unrounded doubles; times are ISO strings):

| Field | Meaning |
|---|---|
| Key, Pid, Name, Path, ImageName, CommandLine (first 300 chars, secrets masked), Flags, SessionId, ParentName, LocationClass, Owner | as in procmeta (empty until metadata was resolved) |
| Started, FirstSeen, LastSeen | ISO |
| PresentAtStart | true when the process existed at sample 1 |
| Samples | samples with a CPU delta (excludes the first sight) |
| RowsWritten | rows in `procs_*.csv` |
| CpuSeconds | sum of `CpuCores * IntervalSec` = CPU time consumed during the run |
| CpuSum, CpuMax, CpuCoresMax | sum of `CpuPct` (average = `CpuSum / Samples`), peak `CpuPct`, peak `CpuCores` |
| SamplesIdle, SamplesActive, CpuIdleSum, CpuActiveSum | split by the sample's `IsIdle` (averages = sums / counts) |
| GpuSum, GpuMax, GpuSeconds, GpuComputeSeconds, Gpu3DSeconds, GpuVideoSeconds, GpuIdleSum, GpuActiveSum | `GpuPct` totals; seconds = engine-% / 100 * interval |
| ReadBytes, WriteBytes | integrated IO bytes |
| WSMax, WSFirst, WSLast | working-set peak, first and last value (leak trend) |
| LowPrioSamples, BasePriority | samples with base priority <= 6; last base priority |
| HasWindow, HasWindowEver | last known window state / ever had a window |
| Exited, ExitTime | set when the Key disappeared |
| DistinctEndpoints, DistinctRemoteIPs, PublicEndpoints, ListenPorts, PortHits | from `net.csv` first sights of Established / Listen rows (PortHits = pool ports); pre-existing connections are included |
| ConnectionsWhileIdle | Established connections first seen in an `IsIdle` sample that were **opened during the run**: a **pre-existing** connection (see `net.csv`) is never counted, whatever the sample state. Same rule as Analyze indicator I14 |

Processes are never removed from the file, except on very long runs when more than 20000 keys exist: exited,
unflagged processes with fewer than 3 samples and no pool-port connection are dropped from memory (they remain in the
CSV files).

## `net.csv` (first sight per `Key|Remote|Port` or `Key|L|LocalPort`)

Source: `MSFT_NetTCPConnection` (`root/StandardCimv2`), states Established (5) and Listen (2), every sample.
Loopback/unspecified/link-local remotes are skipped. Columns: `Timestamp, Key, Pid, Name, State`
(`Established`/`Listen`), `LocalAddress, LocalPort, RemoteAddress, RemotePort` (empty for Listen),
`IsPrivate` (`PrivateIpRegex`), `PoolPort` (`PoolPorts`), `IsIdle` (sample state at first sight),
`ConnCreated` (connection creation time from the OS; empty when the provider gives none). A connection is listed once
per run; a re-connect to the same endpoint by the same process is not repeated.

**Pre-existing connections.** A row whose `ConnCreated` is earlier than `run.json.Start` (or, without `ConnCreated`,
one first seen in sample 1, `Timestamp = Start`) describes a connection that was merely **discovered** at monitor
start, not opened during the run. It is written like any other row (the endpoint is still evidence for the
raw-IP / pool-port / DNS rules), but neither `procsum.json.ConnectionsWhileIdle` nor Analyze's "opened while idle"
indicator (I14) counts it, even when `IsIdle = True` - an overnight recording started on a locked PC would otherwise
attribute every long-lived connection to idle-time behaviour.

## `dns.csv` (first sight per lower-case name + address)

Source: `MSFT_DNSClientCache`, every 3rd sample, records with `Status = 0` and types A/AAAA/CNAME.
Columns: `Timestamp, Name, Data` (address or CNAME target), `Type` (`A`/`AAAA`/`CNAME`), `TTL` (s).
Not attributable to a process; use it to map `net.RemoteAddress` to names ("raw IP without DNS" heuristic).

## `events.csv`

Columns: `Timestamp` (when recorded), `Type`, `Key`, `Pid`, `Name`, `Detail` (max 500 chars, line breaks -> ` | `;
event-log and `WmiProcessStart` text is **secret-masked**, see Conventions), `Source`, `EventId`, `EventTime`
(event-log time), `RecordId`.

| Type | Key/Pid/Name | Detail |
|---|---|---|
| MonitorStarted | own PID | `Interval=..; Duration=..; Elevated=..; User=..` |
| MonitorStopped | own PID | `Reason=<STOP file / Duration reached / Ctrl+C / Q key / Interrupted / Repeated sample failures>; Samples=..; Overruns=..; DurationSec=..; PendingMetaRows=..` |
| ProcessNew | process | `Path=..; Parent=<name> (<ppid>); Session=..; Owner=..; Flags=..; Started=..` (not emitted for processes present at start) |
| ProcessExited | process | `Path=..; Samples=..; CpuSeconds=..; FirstSeen=..` |
| IdleStart / IdleEnd | | `IdleSeconds=..; Locked=..` (transition of `IsIdle`) |
| EventLog | | `Source` = log name, `EventId`, `EventTime`, `RecordId`; `Detail` = first message line, with structured prefixes: System 7045 `Service installed: "<name>" image="<path>"`, TaskScheduler `Task <path>`, PowerShell 4104 `ScriptBlock: <first 300 chars>`, Application 1000/1002 `<line> | app=<exe> module=<dll>` |
| WmiProcessStart | pid/name | only with `-TrackShortLived`: `Ppid=..; Path=..; Cmd=..` from `__InstanceCreationEvent WITHIN 2` (misses processes living < 2 s); `Cmd` is secret-masked before it is cut to 300 chars |

Polled logs and IDs (every 60 s; `run.json.EventLogs` lists which logs were enabled): Defender/Operational 1006 1007
1015 1116 1117 1118 1119 5001 5007; System 7045 7040 41 1074 6008; Application 1000 1001 1002; TaskScheduler/Operational
100 106 129 140 141 200 (tasks under `\Microsoft\` are dropped); PowerShell/Operational 4104; WMI-Activity/Operational 5861.

4104 noise filter (`Test-WdMonScriptBlockNoise`, decided on the original script text before masking): a script-block
event is dropped when (a) its `Execution ProcessID` is the monitor itself (already excluded in the XPath query) or a
process currently flagged `WinDebugTool` / `Self` in `procmeta` (another win-debug mode running at the same time; the
PID set is maintained from the process snapshots and cleared when the process exits), (b) the text contains a
win-debug marker (`WdMon`, `WinDebug`, `win-debug`, `Invoke-Safely`, `Get-CimSafe`), or (c) it is an auto-generated
CDXML cmdlet-adapter block (text contains `$__cmdletization_` or `Microsoft.PowerShell.Cmdletization`; every
`Get-NetTCPConnection` / `Get-ScheduledTask` call compiles one). Every other 4104 event is kept, including encoded
and download-cradle blocks from any other process.
Each log is read from a **RecordId bookmark** (`EventRecordID > last`, oldest first, batches of 300, at most 5 batches
per poll): the bookmark is seeded with the newest record at monitor start, so only events written after the start
appear, no event is ever skipped by the batch cap, and a backlog larger than 1500 events per log is carried over to
the next poll with a throttled warning in `monitor.log`. The Security log needs administrator rights and is never read
(listed under "Skipped (requires administrator)").

## `run.json`

`Tool, Version, FormatVersion, Mode, Computer, User, IsElevated, OSBuild, PSVersion, Culture, UICulture, NCPU,
MemTotalMB, GPUs [{Name, AdapterRAM, DriverVersion}], GpuLuids [], GpuCounterMode (raw | formatted | none | unknown),
IntervalSeconds, DurationMinutes, Start, Pid, SessionFolder, TrackShortLived, NativeHelpers {ProcOwner, Session},
EventLogs [{Log, Ids, Enabled}], IdleThresholdSec, Stop, StopReason, Samples, SamplesWritten, LastSampleTime, Written,
Overruns, DurationSec, ProcessesAtStart, ProcessesWithoutPath`.

The file is written before sampling starts (host facts and settings; the counters are 0 / empty), rewritten after the
**first completed sample** (`ProcessesAtStart` and `ProcessesWithoutPath` become real), then at **every 60 s
`procsum.json` flush** and at stop - always via a temp file and an atomic replace, so a reader never sees a truncated
file. `Written` is the time of the last rewrite. `Samples` is the number of samples started, `SamplesWritten` the
number whose `samples_*.csv` row is on disk, `LastSampleTime` the `Timestamp` of that last row; for a live or killed
session they lag the CSV files by at most one flush interval (60 s). `Stop`, `StopReason` and `DurationSec` stay
empty / 0 until a clean stop (an empty `Stop` with a stale `monitor.running` means the monitor was killed).

## `filecache.json`

Object keyed by lower-case executable path: `Size, Modified` (UTC ticks), `ModifiedIso, CreatedIso, Company,
Description, ProductVersion, OriginalFilename, SigStatus, Signer, IsOSBinary, Sha256, Status` (`ok`, `NotFound`,
`Error`), `Resolved`. A new session seeds its cache from the newest sibling session's `filecache.json`; an entry is
used only when the file still exists with the same size and modification time. A file that has disappeared is
re-resolved as `NotFound` (`AccessNote = "file not found"`, empty signature/hash columns) and replaces the old entry.

## Robustness rules for readers

1. Skip a CSV line whose field count differs from the header (a killed monitor leaves at most one truncated line;
   every row is flushed immediately, so Analyze can read a session while it is being recorded).
2. Treat empty cells as missing, never as 0. Parse numbers with `ConvertTo-Double` (invariant culture).
3. Join `procs` to `samples` by `Timestamp` (identical string) when the sample context is needed; `IsIdle` is
   already copied into `procs`.
4. Use `procsum.json` for totals and averages (the row filter drops quiet samples); use `procs_*.csv` for timelines
   and pattern detection (flat-core, watchdog restarts, idle-vs-active behaviour).
5. Aggregate across restarts by `Path` (fallback `Name`) since a restarted process has a new Key.
6. Ignore rows with `Flags` containing `Self`, and expect `WinDebugTool`-flagged PowerShell processes when several
   win-debug modes run concurrently (their 4104 script blocks are already filtered out of `events.csv`).
7. Read all `procs_*.csv` / `samples_*.csv` of a session in file-name order (daily rotation).
8. Never treat a masked `CommandLine` / `Detail` (`***`) as the literal text of the process: the rule flags were
   computed on the original, and `***` itself must not be scored as a token.
