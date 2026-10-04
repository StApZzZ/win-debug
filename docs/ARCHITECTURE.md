# Architecture and conventions

This document is for contributors. It describes how the repository is organised, the rules every source file follows, the shared API in `lib\Common.ps1`, the entry-point flow and the decisions that shaped the tool. User-facing documentation is in [../README.md](../README.md); the data dictionaries are [inventory-rules.md](inventory-rules.md), [monitor-format.md](monitor-format.md) and [analyze-scoring.md](analyze-scoring.md).

## Product summary

`win-debug` is a public (MIT) read-only diagnostic toolkit for a Windows 10/11 home PC that "became slow". Modes:

| Mode | Function | Result folder suffix | Typical runtime |
|---|---|---|---|
| `Inventory` | hardware / OS / drivers / software / autostart / security / event-log inventory + rule-based findings | `_inventory` | 1-2 min |
| `Disk` | disk usage per volume, top folders/files, cleanup candidates with safety class (report only) | `_disk` | 1-3 min per SSD volume; several minutes on an HDD |
| `Monitor` | background sampler: per-process CPU/GPU/memory/IO/network + system totals + events, written continuously to CSV | `_monitor` | until stopped (10 s interval) |
| `Analyze` | turns a monitor session into `report.md` with a suspicion ranking (miner hunt) | writes into the session folder | seconds to minutes |
| `All` | Inventory then Disk (Monitor is not part of All) | two folders | |
| `Menu` (default) | interactive text menu | | |

Hard constraints, binding for every contributor:

1. **Windows PowerShell 5.1 only.** No PowerShell 7 syntax (`??`, `?.`, ternary, `-Parallel`), no external modules, no downloads, no internet, no binaries beyond what ships with Windows 10/11 x64.
2. **Works without administrator rights**, degrades gracefully and states in the reports what was skipped, using the literal text `(requires administrator)`.
3. **A localized OS is the norm.** Never parse localized text output (`netsh`, `robocopy`, `dism`, `wmic`, `systeminfo`, `w32tm`, `fsutil`, `powercfg /a`, `schtasks` labels). Never use `Get-Counter` with counter names. Prefer CIM (`Get-CimInstance`, including `Win32_PerfFormattedData_*` / `Win32_PerfRawData_*`), the registry and .NET APIs. All numbers written to files are culture-invariant.
4. **Never `Win32_Product`, never `Get-WmiObject`.** Nothing that takes more than 1-2 minutes unless it is a clearly labelled optional deep step (`-Deep`).
5. **Read-only.** The tool creates only the report folder contents and, on explicit request, one per-user scheduled task. No deletions, no registry writes, no service changes. Disk mode reports only.
6. Public repository: English code, comments and messages; no personal data in the repo; reports are gitignored.

## Repository layout

```
win-debug\
  WinDebug.cmd              double-click launcher (ASCII only, CRLF)
  WinDebug.ps1              entry point: parameters, menu, elevation, dispatch, exit codes
  lib\
    Common.ps1              shared helpers (API below) + rule data ($script:Rules)
    Inventory.ps1           Invoke-InventoryScan
    DiskUsage.ps1           Invoke-DiskScan
    Monitor.ps1             Start-ProcessMonitor, Stop-ProcessMonitor, Install-/Uninstall-MonitorTask, Test-MonitorTaskInstalled
    Analyze.ps1             Invoke-MonitorAnalysis
    native\
      FastWalker.cs         P/Invoke directory walker (WinDebug.FastWalker)
      Native.cs             process owner + session idle/lock P/Invoke (WinDebug.ProcOwner, WinDebug.Session)
  docs\
    ARCHITECTURE.md         this file
    inventory-rules.md      every Inventory and Disk rule (id, condition, severity, admin requirement)
    monitor-format.md       data dictionary of every monitor file and column (contract for Analyze)
    analyze-scoring.md      Analyze indicators, damping, thresholds, output columns
  tests\
    Invoke-Checks.ps1       repository self-check (no Pester dependency)
  reports\                  output, gitignored (reports\.gitkeep is kept)
    <COMPUTERNAME>_<yyyyMMdd-HHmmss>_<mode>\   one folder per run
  README.md / README.ru.md / LICENSE / .gitignore / .gitattributes
```

All library files are dot-sourced by `WinDebug.ps1` into one script scope, `Common.ps1` first. Private helpers use a module prefix (`*-WdInv*`, `*-WdDisk*`, `*-WdMon*`, `*-WdAn*`, entry point `*-Wd*`) so that names never collide.

The tool refuses to run from a path that starts with `\\` (network share, WSL): scripts there land in the Internet zone, `cmd.exe` cannot use a UNC working directory and `-ExecutionPolicy Bypass` cannot override a Group Policy. Both the launcher and the entry point exit with code 2. Develop and test from a local copy (for example `C:\Tools\win-debug`).

## Source file rules

| Rule | Why |
|---|---|
| Every `.ps1` / `.cs` is **UTF-8 with BOM**, **CRLF** | A BOM-less `.ps1` containing non-ASCII text fails to parse in PowerShell 5.1 (`TerminatorExpectedAtEndOfString`). CRLF avoids diff noise from Notepad and keeps here-strings that generate `.cmd` text valid. |
| `WinDebug.cmd` is **ASCII only**, **CRLF**, no BOM | An LF-only `.cmd` misparses labels and multi-line blocks (`'ho' is not recognized`); console code page 866 garbles non-ASCII literals. |
| `.md`, `.json` in the repo: UTF-8 without BOM, LF | Enforced by `.gitattributes`. |
| Line 1 of `WinDebug.ps1`: `#Requires -Version 5.1`, followed by a blank line; **never** `#Requires -RunAsAdministrator` | A hard admin requirement would prevent graceful degradation. The blank line is required for comment-based help to be recognised by `Get-Help`. |
| `[CmdletBinding()]` on every function; typed `param()` blocks; **no aliases** (`?`, `%`, `select`, `gci`, `ls`, `sort`...); full parameter names | Checked by `tests\Invoke-Checks.ps1`. |
| Approved verbs only (`Invoke-`, `Start-`, `Stop-`, `Get-`, `Test-`, `New-`, `Export-`, `Measure-`, `Install-`, `Uninstall-`, `Add-`, `Format-`, `ConvertTo-`, `Write-`); never `Scan-`, `Analyze-` | Unapproved verbs warn at import; checked by the self-check. |
| `Set-StrictMode -Off` at top level; be defensive by hand: `$null -eq $x`, `@(...)`, `.ContainsKey()` | CIM objects have optional properties; StrictMode Latest throws on missing hashtable keys, `$null.Count` and out-of-range indexes. |
| `$ErrorActionPreference = 'Stop'` at the entry point; calls that may legitimately miss use `-ErrorAction SilentlyContinue` explicitly | So that `Invoke-Safely` catches everything else. |
| Always `-LiteralPath` (`Test-Path`, `Get-ChildItem`, `Get-Item`, `Export-Csv`, `Out-File`, `Get-Content`); `New-Item` has no `-LiteralPath` in 5.1, use `[IO.Directory]::CreateDirectory()` | `[ ]` in paths break wildcard parsing. |
| `Test-Path` before any `Get-ChildItem -Recurse` | A missing last path segment is treated as a filter and recurses the parent. |
| `[IO.Path]::Combine()` instead of `Join-Path` for hypothetical paths | `Join-Path` validates that the drive exists. |
| `[math]::Round($x, 2, [MidpointRounding]::AwayFromZero)` or `[math]::Floor` | `[math]::Round` and `[int]` casts use banker's rounding. |
| `Measure-Object -Sum` returns `Double` and `.Sum` is `$null` for empty input | Cast to `[int64]`, guard empty input. |
| WQL: backslashes doubled, single quote as `\'` | |
| Every `Get-CimInstance` passes `-OperationTimeoutSec` (30; monitor 20) and `-ErrorAction Stop` inside try/catch (`Get-CimSafe`) | A stuck WMI provider must not hang a run. |
| UI text goes through `Write-Host` (via `Write-Log`); data is returned. Never `Write-Output` for UI text | Checked heuristically by the self-check. |
| `$PSScriptRoot` for all paths; never `$PWD` | The elevated relaunch starts in System32. |
| Never a bare `powershell.exe`: the launcher uses `"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"`, `WinDebug.ps1` uses `Get-WdPowerShellPath` (`$PSHOME\powershell.exe`, fallback `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`) for the elevated relaunch and the logon task | `cmd.exe` resolves a bare name from the current directory first and the tool folder is user-writable (`reports\` lives there); `Start-Process` / the Task Scheduler resolve it through `PATH`. Checked by the self-check (section f). |
| Comments and docs refer to `docs/ARCHITECTURE.md` (this file); the original design spec is retired and never referenced | The spec was a private working document; the self-check fails on any `.ps1` token that still mentions it. |
| Command-line values for a child process go through `ConvertTo-CommandLineArgument` | Win32/CRT splitting: `-OutputRoot "D:\"` written naively becomes `D:"` plus everything after it; the helper doubles backslashes before a quote and escapes embedded quotes as `\"`. |
| No `Start-Job` / runspaces | The culture switch is per thread and not inherited; keeps the design single-threaded and debuggable. |

## Culture

`Initialize-Common` sets `[Threading.Thread]::CurrentThread.CurrentCulture = InvariantCulture`. Afterwards `(1.5).ToString()` gives `1.5` and `ConvertTo-Csv` writes `1234.5`, but dates would still not be ISO, so DateTimes are pre-formatted. `CurrentUICulture` is left alone. The switch is a safety net only: **every helper still passes `InvariantCulture` explicitly**.

| Value | Format in files | Helper |
|---|---|---|
| double | `[math]::Round(v, d, AwayFromZero).ToString('F'+d, Invariant)` | `ConvertTo-InvariantString` |
| integer / int64 | `.ToString(Invariant)`; byte counts are always `[int64]`, never doubles | `ConvertTo-InvariantString` |
| DateTime (data) | `yyyy-MM-ddTHH:mm:ss.fffK` local with offset, e.g. `2026-09-27T19:44:09.295+03:00` | `Get-IsoTimestamp` |
| DateTime (file name) | `yyyyMMdd-HHmmss` | `Get-IsoTimestamp -ForFileName` |
| bool | `True` / `False` in CSV; native `true` / `false` in JSON | |
| bytes for humans | `12.3 GB` (1024 base) | `Format-Bytes` |
| parsing (Analyze) | `[double]::TryParse($s, Float, Invariant, [ref]$d)`; **never** `[double]$s` (`[double]'1,5'` is 15) | `ConvertTo-Double` |

Never use `Get-Date -Format 'u'` (appends `Z` without converting to UTC). `ConvertTo-Json` turns `[DateTime]` into `\/Date(...)\/`; `Export-Json` converts DateTimes to ISO strings first.

## Output file encodings

| File type | Writer | Encoding | Reason |
|---|---|---|---|
| `*.csv` | `Export-Csv -NoTypeInformation -Encoding UTF8 -LiteralPath` (Inventory, Disk, Analyze); `StreamWriter` with `UTF8Encoding($true)` (Monitor) | UTF-8 **with BOM** | Excel needs the BOM for non-Latin text; the default `Export-Csv` writes ASCII and turns Cyrillic into `????`. A `StreamWriter` opened in Append mode on a non-empty file does not emit a second BOM. |
| `*.json`, `*.md`, `run.log`, `monitor.log`, `analyze.log` | `[IO.File]::WriteAllText/AppendAllText($p, $s, $script:Utf8NoBom)` | UTF-8 **without BOM** | `Set-Content`/`Add-Content` default to the ANSI code page; Notepad, GitHub and VS Code read BOM-less UTF-8; sparkline block characters need UTF-8. |
| Reading text back | `Get-Content -LiteralPath -Encoding UTF8`, `[IO.File]::ReadAllText` / `ReadLines` | | BOM-less UTF-8 read with plain `Get-Content` gives mojibake. |
| Console | `Initialize-Common`: `[Console]::OutputEncoding = UTF8; $OutputEncoding = UTF8` in try/catch | | A fresh console is CP 866 / 437. |

## JSON and CSV rules

- Always `ConvertTo-Json -Depth 8` (the default depth 2 silently replaces deeper objects with the string `System.Collections.Hashtable`).
- Only `[ordered]@{}` hashtables and `[pscustomobject]` go to JSON, never raw `CimInstance` objects. Project with `Select-Object` or build ordered hashtables.
- Compact JSON for data files (`procsum.json`, `filecache.json`, `run.json`); pretty JSON for `inventory.json`, `disk-usage.json`, `analysis.json` (read by humans too).
- `ConvertFrom-Json` yields `Decimal` for non-integers and `PSCustomObject` for objects; large files are slow. Analyze never loads a monitor CSV through JSON; it streams CSV files line by line with a header map and skips rows whose field count differs from the header.
- CSV: comma delimiter always (never `-UseCulture`), one physical line per row (line breaks inside values are replaced by spaces), empty cell = not available, arrays joined with `;`.
- CSV formula guard (`Protect-WdCsvText`, applied by `Export-CsvInvariant` only to values that were `[string]` before conversion): a cell that starts with `=`, `+`, `@`, TAB, CR, or `-` gets one leading space, because Excel evaluates such cells as formulas even when quoted (an autostart command line or a planted `DisplayName` is attacker-controlled text). The leading `-` is exempt only when the whole cell is a number (`^-\d+([.,]\d+)?$`): `-5`, `-1.50`, `-1,5` stay raw, while `-2+3`, `-1+cmd|x` or `-Command x` get the space. Report CSVs written by `Export-CsvInvariant` are never read back by the tool. The monitor's own CSV writer (`Write-WdMonCsvRow`) applies the same guard to every value that is a `[string]` (`CommandLine`, `Company`, `Description`, `OriginalFilename`, `Detail`, DNS names ...); numbers, booleans and timestamps are formatted separately and never prefixed. The key columns Analyze compares as strings (`Key`, `Path`, `Name`, `Timestamp`) can never start with one of the guarded characters, so the join between `procs`, `procmeta`, `net` and `procsum.json` is unaffected; readers that match other text cells should `TrimStart(' ')` first (see `docs\monitor-format.md`, Conventions).
- CSV schema and empty results (`Export-CsvInvariant -Columns <string[]>`): `-Columns` fixes the column order, fills columns missing from a row with empty cells and appends properties that are not in the schema after it (first-seen order), so no data is lost when rows are heterogeneous. With no rows and `-Columns`, the file holds the quoted header line only (Export-Csv quoting, CRLF, UTF-8 BOM) so that an empty `devices-problems.csv` still tells the reader what it would hold; without `-Columns` an empty result is still a BOM-only file. Inventory passes `-Columns` for the four CSVs that are legitimately empty on a healthy PC (`scheduled-tasks.csv`, `devices-problems.csv`, `drivers.csv`, `events.csv`); a CSV that may be empty must pass it. The monitor's `StreamWriter` files always start with the header line (`Open-WdMonCsv`).
- Secret masking (`Hide-WdSecret -Text`): best-effort masking of credential-like values in command lines, service paths, task arguments, script text and event messages before they are written. Key names are kept and the value becomes `***`: `key = value` / `key: value` / `"key": "value"` assignments (`password`, `passwd`, `passphrase`, `pwd`, `secret`, `token`, `api-key`, `access-key`, `private-key`, `client-secret`, `authorization`, `auth-token`, `bearer`, `credential(s)`, `session-id`, `signature`), switches (`--password x`, `/password:x`, `--token=x`, `-secret x`; a single `-p` is left alone), URL user info (`scheme://user:***@host`) and URL query parameters (`token`, `key`, `secret`, `password`, `pwd`, `sig`, `signature`, `access_token`, `auth`, `apikey`, `api_key`). Mining-pool hosts, ports and wallet addresses are deliberately not masked (`xmrig -o pool:4444 -u 48abc` is unchanged): they are the evidence. Every consumer matches its rules on the **original** text first and stores only the masked copy (Inventory: autostart, tasks, services, Winlogon/IFEO/WMI values, `UninstallString`, `processes-snapshot.csv`, profile evidence, event sample messages; Monitor: `procmeta.CommandLine`, `procsum.json`, `events.Detail`; Analyze: every rendered command line, script text and event message, as defense in depth for sessions recorded by older monitors). Over-masking is the preferred failure mode; the masking is heuristic and the README says so.
- `ConvertTo-JsonReady` writes a `[bigint]` as `[long]` when it fits and as an invariant numeric string otherwise.

## Error handling

- Every collection item is wrapped in `Invoke-Safely -Name '<Section.Item>' { ... }`. One failure never kills a run; the error is logged (`Warn`), recorded through `Add-WdCollectionError` in `$script:CollectionErrors` and listed at the end of the summary under **Collection errors**. The exception message is flattened to one line and capped at 1000 characters plus ` ... [truncated, N chars]` (N = original length, invariant) before it is logged or recorded, so a .NET stack dump or a 50 KB WMI error cannot flood `run.log` or the summary table.
- **Admin skips are not collection errors.** A failure whose message ends with the literal `(requires administrator)` is an admin skip: `Add-WdCollectionError` (used by `Invoke-Safely`, `Get-CimSafe` and `Get-WinEventSafe`) passes it to the private `Test-WdAdminSkipMessage -Name -Message`, which drops it from the collection errors, and, when nobody registered the skip yet, registers it with `Add-AdminSkip` under the `Invoke-Safely` name (items are matched against `Get-AdminSkips` ignoring case and whitespace, so `EventLog Security` equals `Event log Security`). The summary therefore lists such an item exactly once, under **Skipped (requires administrator)**, and `Invoke-Safely` logs it at `Debug` instead of `Warn`. A non-admin Inventory run ends with `Collection errors: _none_`.
- `Get-WinEvent` throws a non-terminating "No events were found" for empty results, and the Security log returns the same misleading message without administrator rights. `Get-WinEventSafe` therefore treats empty as OK and pre-emptively skips the `Security`, `Microsoft-Windows-Diagnostics-Performance/Operational` and `Microsoft-Windows-Storage-Storport/Operational` logs when not elevated, recording an admin skip (Inventory registers its own Storport skip before calling; the list is the safety net for other callers). It classifies errors by `FullyQualifiedErrorId` (`NoMatchingEventsFound*` -> empty result, `NoMatchingLogsFound*` -> Debug note) and by exception type / HResult (`UnauthorizedAccessException`, `0x80070005`, FQID `UnauthorizedAccess|AccessDenied` -> the `(requires administrator)` branch, which registers an admin skip and a Debug line, never a collection error); the English message regexes are only a fallback, because the UI culture may be Russian or anything else. It passes `-Verbose:$false` like `Get-CimSafe`, and the entry point sets `$VerbosePreference = 'SilentlyContinue'` after deriving `$script:VerboseLog`, so `-Verbose` enables only the tool's own DEBUG lines.
- `Write-Log` never throws: it has no `[ValidateSet]` (binding validation would run outside its try/catch); the level is normalized in the body (`^warn` -> Warn, `^err` -> Error, `^(dbg|debug|verbose)` -> Debug, anything else -> Info). The self-check walks the AST and fails on any literal `-Level` outside `Info` / `Warn` / `Error` / `Debug`.
- A missing CIM class, a disabled perf adapter or `PercentProcessorTime -eq $null` for all rows produces the warning "performance counters unavailable - run `lodctr /R` as administrator" (Inventory rule `CPU-COUNTERS`; Monitor logs the same hint).
- Data that needs administrator rights is registered with `Add-AdminSkip` and rendered by `Get-SummaryFooterLines` as the section **Skipped (requires administrator)**; the literal text `(requires administrator)` is used in the report body wherever a value is missing for that reason.

## Administrator detection and elevation

`Test-IsAdmin` checks membership of the well-known SID `S-1-5-32-544` (BUILTIN\Administrators) on the current `WindowsIdentity`. Never check by group name: the name is localized and a lookup by name fails on a domain-joined machine that cannot reach its domain controller.

Elevation flow (`WinDebug.ps1`): in a real console the entry point asks `Run with administrator rights for a complete picture? [Y/n]` (Enter = yes) unless `-NoElevate`, `-Elevate` or `-Elevated` is given or the process is already elevated. It relaunches itself with `Start-Process -FilePath (Get-WdPowerShellPath) -Verb RunAs -WorkingDirectory $PSScriptRoot` (`Start-WdElevatedRelaunch`), re-marshalling every bound parameter (switches as `-Name`, every value and the `-File` path quoted with `ConvertTo-CommandLineArgument`, arrays joined with `,`, plus `-Elevated`, minus `-Elevate`). `$script:EntryBoundParameters` carries the **resolved** `-OutputRoot` (always), the resolved `-SessionPath` and the normalized `-Drives`, because the elevated copy starts in `System32` and could not resolve `.\out` or `..\sess` itself. A declined UAC prompt throws `The operation was canceled by the user`; that is caught and the run continues non-admin with a warning. `Analyze` and `Menu` never elevate on their own (the menu offers item `A`). When input is redirected no question is asked.

## Inline C# (`Add-Type`)

- Compiled with the .NET Framework C# compiler in a few hundred milliseconds; needs write access to `%TEMP%`. If compilation fails the module degrades: the disk walker falls back to `DirectoryInfo` recursion, owner / idle time become blank.
- Re-adding an existing type name throws, so `Add-NativeType` guards with `if ($TypeName -as [type]) { return $true }` before `Add-Type -TypeDefinition (Get-Content -LiteralPath $cs -Raw -Encoding UTF8)`; it returns `$true`/`$false` and logs a warning on failure. Because a loaded type cannot be replaced, a changed `.cs` file needs a fresh PowerShell process.
- Namespace for all native types: `WinDebug`. Types: `WinDebug.FastWalker`, `WinDebug.ProcOwner`, `WinDebug.Session`.

## Ctrl+C, window close and the STOP file (Monitor)

Ctrl+C runs `finally` blocks and fires `PowerShell.Exiting`; closing the window with X, `Stop-Process`, `taskkill /F`, logoff and shutdown run neither. Consequences:

1. Every sample is flushed immediately (`StreamWriter.AutoFlush = $true`, `FileShare.Read`), so Analyze can read a session while the monitor is running.
2. Rows of a sample are built in memory first and written in one loop, so a kill leaves at most one truncated line. Readers skip rows with the wrong field count.
3. `try { loop } finally { close writers; write procsum.json and run.json; remove monitor.running and STOP }` is a courtesy, never a requirement. `run.json` is therefore not written only at start and stop: it is rewritten atomically (temp file + `[IO.File]::Replace` / `Move`, `Write-WdMonJsonAtomic -Pretty`) after the first completed sample and at every 60 s `procsum.json` flush, and carries `SamplesWritten` (completed samples whose `samples_*.csv` row is on disk), `LastSampleTime` (that row's `Timestamp`) and `Written` (time of the rewrite), so `ProcessesAtStart` / `ProcessesWithoutPath` are real for a live or killed session (see `docs\monitor-format.md`, `run.json`).
4. `[Console]::KeyAvailable` / `TreatControlCAsInput` throw `The handle is invalid` without a console, so key handling (Q, Ctrl+C) is guarded by `[Console]::IsInputRedirected` and try/catch.
5. A file named `STOP` in the session folder is the primary stop mechanism (it works for the hidden scheduled task); `-DurationMinutes` is the second. `Stop-ProcessMonitor` creates STOP in every folder under `OutputRoot` whose `monitor.running` marker names a live `powershell` process and waits up to 30 s for each; a marker whose PID is gone is treated as stale. It returns one of three strings: `Stopped` (every live monitor confirmed), `Signaled` (STOP delivered but at least one monitor did not confirm within 30 s; it stops at its next check and the STOP file stays in place) or `None` (no live monitor). The entry point owns the console message (`Write-WdStopOutcome`): `Monitor stopped.` / `STOP signal sent; the monitor did not confirm within 30 s - check monitor.log.` / `No running monitor found.` with exit codes 0 / 0 / 3; the module itself logs details only (`-NoConsole` or Debug), so nothing is printed twice.
6. Only one monitor per `OutputRoot`: the entry point checks `Get-WdMonRunningSessions` **before** `New-ReportDirectory` and refuses with `A monitor is already running (PID .., folder ..)` and exit code 3, so no orphan `<PC>_<ts>_monitor` folder with a lone `run.log` is left behind. `Start-ProcessMonitor` keeps a defensive throw (message containing `already running`) for direct callers, mapped to exit 3 by the main catch as well.

Ctrl+C in **Disk** mode: `FastWalker.Scan()` / `ScanUnique()` are single synchronous calls, so PowerShell cannot stop a pipeline inside them. `HookCancel()` subscribes to `Console.CancelKeyPress` and sets the volatile `Cancel` flag; the walk unwinds at the next directory (milliseconds) and the result carries `Cancelled = true`. The handler does not swallow the key press, so the console host still stops the pipeline afterwards; if it did not (other hosts), `Get-WdDiskVolumeScan` throws `Volume X:\ scan interrupted by Ctrl+C; partial totals discarded` (the `-Deep` step throws the same way) so that partial totals are never reported as facts. Volumes mounted in a folder and volumes without a drive letter are listed in the volume table with the note `mounted in a folder, not scanned` / `no drive letter, not scanned`; the walker never follows junctions, symbolic links or volume mount points, and only lettered fixed NTFS/ReFS volumes are selected for a scan.

## Scheduled task (Monitor as logon task)

Task name (exact): **`WinDebug Monitor`**, root task folder `\`, registered only on `-InstallTask` / menu item 6 and removed with `-UninstallTask` / menu item 7. Per user, `-LogonType Interactive` (the monitor must live in the user's session for `GetLastInputInfo`, window handles and GPU counters of session apps), `-RunLevel Highest` when the installing session is elevated, otherwise `Limited`. Action: the fully qualified Windows PowerShell host (`$PSHOME\powershell.exe`, never a bare `powershell.exe`) with `-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "<repo>\WinDebug.ps1" -Mode Monitor -NoElevate -OutputRoot "<root>" -IntervalSeconds <n>`. Trigger `AtLogOn` for the installing user with `Delay = 'PT1M'`. Settings: `-ExecutionTimeLimit ([TimeSpan]::Zero)` (unlimited), `-AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -StartWhenAvailable`. **Not `-Hidden`**: a hidden task is exactly what the Inventory rule `AUT-HIDDEN-TASK` flags. The rule data key `KnownScheduledTasks` contains `\WinDebug Monitor` so the tool never flags its own task. `schtasks.exe` output is localized and never parsed; only cmdlets are used. A `-WindowStyle Hidden` console still flashes briefly at logon (Windows behaviour); this is accepted and documented in the README rather than worked around with `wscript`/`conhost --headless` tricks.

## Report directory and common files

`New-ReportDirectory -OutputRoot -Mode` creates `<OutputRoot>\<COMPUTERNAME>_<yyyyMMdd-HHmmss>_<mode>` (mode lower-case: `inventory`, `disk`, `monitor`); on a collision `-2`, `-3` is appended. Default `OutputRoot` is `<repo>\reports`. Analyze does not create a folder: it writes `report.md`, `analysis.json`, `suspects.csv`, `process-summary.csv` and `analyze.log` into the session folder and leaves the monitor's `run.log` untouched.

| File | Written by | Content |
|---|---|---|
| `run.log` | `Write-Log` | `<ISO time> [INFO ] message` lines with a 5-character level (`INFO `, `WARN `, `ERROR`, `DEBUG`). First line: `win-debug <version> \| mode=<mode> \| user=<DOMAIN\user> \| admin=<True/False> \| ps=<version> \| os=<build.UBR> \| culture=<culture>/<UI culture>`. In Monitor mode `run.log` holds the header and a pointer; sampling diagnostics go to `monitor.log`. |
| `summary.md` (Inventory, Disk) / `report.md` (Analyze) | module | human report; first section **Run info** (`Get-RunInfoSectionLines`, whose last line is `- Privacy: this report and its CSV/JSON files contain personal data (...). Secrets on command lines are masked best-effort. Review before sharing.`), last sections **Skipped (requires administrator)** and **Collection errors** (`Get-SummaryFooterLines`) |
| `*.json`, `*.csv` | module | machine-readable data; see the three data-dictionary documents. Every CSV artifact exists even for an empty result (a header line when the writer passed `-Columns` or is the monitor's `StreamWriter`; otherwise a BOM-only file, see "JSON and CSV rules") |

## `lib\Common.ps1` API

`Common.ps1` is dot-sourced before the module files, so `$script:` variables set here are visible to every module. Modules never re-implement these helpers.

| Helper | Purpose |
|---|---|
| `Initialize-Common [-ToolVersion]` | culture/console setup, script state, `$script:Rules`; idempotent |
| `Test-IsAdmin` | `[bool]`, SID based (`S-1-5-32-544`); cached in `$script:IsAdmin` |
| `New-ReportDirectory -OutputRoot -Mode` | creates `<root>\<PC>_<yyyyMMdd-HHmmss>_<mode>[-N]`, sets `$script:ReportDir` / `$script:LogPath`, writes the log header |
| `Write-Log -Level Info\|Warn\|Error\|Debug -Message [-NoConsole]` | console (Warn yellow, Error red, Debug dark gray only with `-Verbose`) + `run.log`; never throws |
| `Write-SectionHeader -Title` | console `=== Title ===` + log line |
| `Invoke-Safely -Name -ScriptBlock [-Default] [-Quiet]` | catch-all wrapper for one collection item; logs the failure (`Warn`; `Debug` with `-Quiet` or for an admin skip), caps the message at 1000 characters + ` ... [truncated, N chars]` and records it through `Add-WdCollectionError` |
| `Add-WdCollectionError -Name -Message` (private) | appends `Name`, `Error`, `Time` to `$script:CollectionErrors`, unless the message is an admin skip |
| `Test-WdAdminSkipMessage -Name -Message` (private) | `[bool]`: message ends with `(requires administrator)` (case/whitespace-insensitive match of the item against `Get-AdminSkips`); registers the skip under `Name` when nobody did, so `summary.md` lists it exactly once |
| `Measure-Step -Name -ScriptBlock` | timing wrapper for a whole section (does not catch) |
| `Get-CimSafe -ClassName [-Namespace] [-Filter] [-Property] [-TimeoutSec]` | `Get-CimInstance` with timeout and error capture; always a list (possibly empty) |
| `Get-WinEventSafe -FilterHashtable [-MaxEvents]` | `Get-WinEvent` wrapper; empty on "no events"; pre-emptive admin skip for `Security`, `Microsoft-Windows-Diagnostics-Performance/Operational` and `Microsoft-Windows-Storage-Storport/Operational` when not elevated; access denied -> admin skip, never a collection error |
| `Get-RegistryValueSafe -Path -Name [-Default] [-Expand]` | registry value or default; works for numeric value names such as `'01'` |
| `Export-Json -Object -Path [-Depth] [-Compress]` | ISO dates, no `\/Date(`, UTF-8 without BOM |
| `Export-CsvInvariant -InputObject -Path [-Columns] [-Append]` | pipeline or array; dot decimals, ISO dates, UTF-8 with BOM. `-Columns` fixes the column order, fills missing columns with empty cells, appends unlisted properties after the schema and writes the quoted header line for an empty result; without `-Columns` an empty result is a BOM-only file |
| `ConvertTo-InvariantString -Value [-Decimals]` | culture-invariant text for any value (`$null` -> empty, arrays joined with `;`) |
| `ConvertTo-Double -Text` | safe parse (`"1.5"` or `"1,5"`), `$null` on failure |
| `Format-Bytes -Bytes [-Decimals]` | `12.3 GB`; `$null`/negative -> `n/a` |
| `Get-IsoTimestamp [-Date] [-Utc] [-ForFileName]` | `yyyy-MM-ddTHH:mm:ss.fffK` / `yyyyMMdd-HHmmss` |
| `Add-Finding -Severity -Category -Title -Detail -Recommendation [-RuleId] [-Data]` | appends to `$script:Findings`; duplicate `RuleId` + `Title` pairs are ignored |
| `Get-Findings [-Severity]` | Critical -> Warning -> Info, then Category, then insertion order |
| `Add-AdminSkip -Item [-Detail]` / `Get-AdminSkips` | items skipped because they need administrator rights |
| `ConvertTo-MarkdownTable -InputObject -Columns [-Headers]` | markdown lines; `_none_` when empty; cells escaped and trimmed to 200 characters |
| `Get-RunInfoSectionLines [-DurationSeconds] [-Mode]` | `## Run info` markdown lines (first section of every summary); ends with the `- Privacy: ...` line (personal data, best-effort secret masking, review before sharing) |
| `Get-SummaryFooterLines` | `## Skipped (requires administrator)` + `## Collection errors` |
| `Get-ProcessLocationClass -Path` | `System32, Windows, ProgramFiles, ProgramData, Public, Downloads, AppData, UserProfile, Temp, RecycleBin, Network, Removable, Other, Unknown` (order matters; `%TEMP%` may be an 8.3 short path, hence the `\temp\` regex) |
| `Add-NativeType -TypeName -SourcePath` | guarded `Add-Type` from `lib\native\*.cs`; `[bool]` |
| `Get-WinDebugRule -Name` | rule data item from `$script:Rules`; throws on an unknown name |
| `Test-DirectoryExists -Path` / `Test-FileExists -Path` / `Get-FileSizeSafe -Path` | `[IO.Directory]::Exists` / `[IO.File]::Exists` / `IO.FileInfo` (never throw; `Test-Path` and `Get-Item` do on some protected paths) |
| `Get-CurrentDirectory` / `Resolve-PathSafe -Path` | file-system cwd without provider prefix; relative -> absolute |
| `ConvertTo-CommandLineArgument -Text` | one quoted Win32 argument for a child process: `D:\` -> `"D:\\"`, embedded quotes -> `\"`; never throws |
| `Protect-WdCsvText -Text` | CSV formula guard: a leading space for cells starting with `=`, `+`, `@`, TAB, CR or `-`; the `-` is exempt only when the whole cell is a number (`^-\d+([.,]\d+)?$`: `-5`, `-1.50` raw; `-2+3`, `-Command x` guarded) |
| `Hide-WdSecret -Text` | best-effort masking of passwords / keys / tokens in command lines, service paths, task arguments, script text and event messages (key name kept, value -> `***`; URL user info and query tokens masked; miner pool / wallet arguments intentionally not masked). Consumers: Inventory, Monitor (`procmeta`, `procsum.json`, `events`), Analyze (every rendered command line and event) - always after the rules matched the original text |
| `Get-WdFolderPrefix -Value` | lower-cased folder path with exactly one trailing backslash, used by `Get-ProcessLocationClass` so that `C:\Program FilesFake\` is not `ProgramFiles` and `C:\Users\Publicity\` is not `Public` |
| `Write-TextFile -Path -Content` / `Write-MarkdownFile -Path -Lines` | UTF-8 without BOM |
| `Get-ReportRunInfo [-Mode]` | `[ordered]` Tool, Version, Mode, Computer, User, IsAdmin, StartTime, PSVersion, OSBuild, Culture, UICulture |

**Return convention.** Helpers that return lists (`Get-CimSafe`, `Get-WinEventSafe`, `Get-Findings`, `Get-AdminSkips`, `ConvertTo-MarkdownTable`, `Get-*Lines`, `Get-WinDebugRule`) enumerate their items like every PowerShell command. Callers **must** wrap them in `@(...)`, for example `@(Get-CimSafe -ClassName Win32_Process).Count`, because in PowerShell 5.1 a single result is not an array.

**Script state** set by `Initialize-Common`: `$script:Inv`, `$script:Utf8NoBom`, `$script:Utf8Bom`, `$script:ToolVersion`, `$script:IsAdmin`, `$script:Findings`, `$script:CollectionErrors`, `$script:AdminSkips`, `$script:ReportDir`, `$script:LogPath`, `$script:VerboseLog`, `$script:Rules`, `$script:NCPU`, `$script:RepoRoot`, `$script:LibRoot`, `$script:DownloadsDir` (relocated Downloads folder from `User Shell Folders`), `$script:CurrentMode`, `$script:RunStart`.

## Shared rule data (`$script:Rules`)

Data, not code, defined in `Get-WdRuleTable` in `Common.ps1` and read with `Get-WinDebugRule -Name`. All regexes are case-insensitive strings used with `-match`. Consumers: Inventory (autostart, services, tasks, processes), Monitor (location class, pool ports, flags in `procmeta.csv`), Analyze (scoring). Cyrillic fragments are built from code points so the source stays ASCII.

| Key | Content |
|---|---|
| `SuspiciousPathRegex` | user-writable locations (Temp, AppData except WindowsApps/Programs, ProgramData except Defender/Windows/Package Cache, Public, Recycle Bin) plus the user-writable folders inside `%windir%` where a standard user can drop a binary that still "looks like Windows": `Windows\Temp`, `PerfLogs`, `Fonts`, `Windows\Tasks`, `System32\Tasks`, `spool\drivers\color`, `System32\com\dmp`, `SysWOW64\com\dmp`, `Windows\tracing`, `Windows\Registration\CRMLog`. Every folder name carries its trailing backslash so that `Templates\`, `Tempo\`, `Temperature\`, `ProgramDataX\`, `TasksX\` or `Taskschd.dll` do not match. The same list is documented in `docs\inventory-rules.md` ("Suspicious locations"); keep the two in sync |
| `MinerTokenRegex` | `stratum+tcp`/`stratum+ssl`, `xmr`, `monero`, `pool`, `--donate-level`, `--algo`, `--randomx`, `cryptonight`, `kawpow`, `ethash`, miner product names, `-o host:port`, `-o stratum...`, `--url=stratum...`, Monero wallet addresses. The bare `--url=` alternative was removed: Electron/Chromium helpers carry `--url=https://...`, so only a stratum URL counts |
| `ScriptHostRegex` | script-host executables: powershell, pwsh, wscript, cscript, mshta, rundll32, regsvr32, msbuild, installutil, certutil, bitsadmin, cmd |
| `ScriptHostWeakArgRegex` | **weak** launch options that legitimate installers and scheduled scripts also use: `-ExecutionPolicy`/`-ep Bypass`, `-NoProfile`/`-nop`, `-WindowStyle Hidden`/`-w hidden`, `-NonInteractive`/`-noni`. Informational only: never a red flag in Inventory or Monitor; Analyze scores a weak-only match with at most 2 points |
| `ScriptHostStrongArgRegex` | **strong** payload-delivery indicators: `-EncodedCommand`/`-enc`/`-ec`/`-e <base64>`, `DownloadString`/`DownloadFile`, `IEX`/`Invoke-Expression`, `FromBase64String`, `scrobj.dll`, `urlcache`, `certutil ... -decode`, `bitsadmin`, `curl`/`wget`, `http(s)://` URLs (this also covers `mshta` with a URL), `javascript:`/`vbscript:`, `/i:http`. This is the red-flag regex for Inventory (`StrongRedFlagArgs`), Monitor (`ScriptHostRedFlag`) and Analyze (I11); Inventory's former private strong-indicator regex is replaced by this shared one |
| `ScriptHostArgRegex` | backward-compatible alias of `ScriptHostStrongArgRegex` (the self-check asserts they are equal); new code should name the strength explicitly |
| `SystemBinaryNames` / `SystemBinaryLocations` | Windows binaries (svchost, csrss, lsass, explorer, RuntimeBroker, MsMpEng...) and the folders they must live in |
| `ExpectedParents` | expected parent per system binary (`svchost -> services`, `lsass -> wininit`, `conhost -> any`...) |
| `PoolPorts` | 3333, 3334, 3335, 3357, 4444, 5555, 6666, 7777, 8888, 9999, 14433, 14444, 45560, 45700, 20535, 1314, 17777, 18081 |
| `TrustedDnsServers` / `PrivateIpRegex` | public resolvers that are not a hijack; RFC1918, link-local, loopback, multicast ranges |
| `PupNameRegex` / `PupInfoOnlyRegex` | "optimizer", driver-updater and toolbar product names (Warning); names that are Info only (CCleaner) |
| `KnownHeavyProcesses` | legitimate heavy background processes (Defender, Search, Update workers, OneDrive, Photos, WSL/Hyper-V VMs, GPU vendor services, updaters, browsers, Electron apps, Java, Python, encoders...) |
| `TrustedSignerRegex` | certificate subjects of well-known vendors, anchored on the organisation attribute: the `O=` value must **start** with a vendor name followed by a word boundary (optional quotes for comma-containing values such as `O="Advanced Micro Devices, Inc."`), so `Tracer LLC`, `Dellwood Games`, `L=Dell` or a bare `CN=Dell Inc` do not match |
| `KnownDebuggers` | IFEO `Debugger` whitelist (vsjitdebugger, procexp, windbg, cdb, devenv, DebugView...) |
| `NoisyEventProviders` | providers whose error counts are reported but never warned about |
| `KnownScheduledTasks` / `MonitorTaskName` | `\WinDebug Monitor` (own task, never flagged) / `WinDebug Monitor` |

## Entry point flow (`WinDebug.ps1`)

1. `Set-StrictMode -Off; $ErrorActionPreference = 'Stop'`; `$root = $PSScriptRoot` (fallback: current location). If `$root` starts with `\\`: message "Run from a local folder", `exit 2`.
2. Check that `lib\Common.ps1`, `Inventory.ps1`, `DiskUsage.ps1`, `Monitor.ps1`, `Analyze.ps1` exist (`exit 4` otherwise), then dot-source them in that order.
3. `Initialize-Common -ToolVersion '1.0.0'`; `$script:VerboseLog` from `-Verbose`, then `$VerbosePreference = 'SilentlyContinue'` (PowerShell's own verbose stream stays silent); `OutputRoot` defaults to `<repo>\reports` and is resolved to an absolute path; `-SessionPath` is resolved at the top level; `-Drives "C,D"` is normalized into single letters. The resolved values are saved in `$script:EntryBoundParameters` for the elevated relaunch. The `param()` block is `[CmdletBinding(PositionalBinding = $false)]` and carries no `[ValidateSet]` / `[ValidateRange]`: a stray positional token fails binding (exit 1, PowerShell's message), while `-Mode` (canonicalized case-insensitively), `-IntervalSeconds` (5-3600), `-DurationMinutes` (0-100000) and `-TopN` (5-500) are validated in the body so that a wrong value prints a red message plus the usage text and exits 5 as documented.
4. Banner `win-debug <version> | mode: <Mode> | Administrator: YES/NO` (the task switches show `StopMonitor` / `InstallTask` / `UninstallTask` as the mode). Task switches run first and exit on their own: `-StopMonitor` -> `Stop-ProcessMonitor -OutputRoot`, whose result `Stopped` / `Signaled` / `None` is printed by `Write-WdStopOutcome` as `Monitor stopped.` / `STOP signal sent; the monitor did not confirm within 30 s - check monitor.log.` / `No running monitor found.` (exit 0 / 0 / 3; a legacy `[bool]` result is still accepted); `-InstallTask` / `-UninstallTask` -> `Install-MonitorTask -OutputRoot -IntervalSeconds` / `Uninstall-MonitorTask` (exit 0 / 6).
5. Elevation (skipped when `-Elevated`, `-NoElevate`, already admin, or Mode is `Analyze` / `Menu`): `-Elevate` relaunches immediately; otherwise, in a real console, the `[Y/n]` question. After a successful `Start-Process` the first window prints `Continuing in the elevated window` and exits 0.
6. Menu (Mode `Menu`): needs a console; with redirected input it prints the usage text and exits 5. After a menu action it prints the report folder, resets per-run state (findings, collection errors, admin skips, log path) and waits for Enter. Only `Q` (or Ctrl+C) leaves the menu; a bare Enter redraws it. A refusal raised by a menu action (see 8) is printed in yellow and returns to the menu instead of quitting.
7. Dispatch (`Invoke-WdMode`, which never calls `exit` itself): `Inventory` -> `New-ReportDirectory` + `Invoke-InventoryScan -OutDir -Deep`; `Disk` -> `Invoke-DiskScan -OutDir -TopN -Deep [-Drives]`; `Monitor` -> refuse with exit 3 when `Get-WdMonRunningSessions` finds a live monitor **before** any folder is created, then `New-ReportDirectory` + `Start-ProcessMonitor -OutDir -IntervalSeconds -DurationMinutes -TrackShortLived`; `Analyze` -> resolve `SessionPath` (given, or the newest `*_monitor` folder under `OutputRoot` that passes `Test-WdMonitorSessionFolder`, so an orphan folder with only `run.log` never wins; none -> exit 5), validate that the folder exists and holds `samples_*.csv`, `procs_*.csv` or `procsum.json` (otherwise exit 5 `Not a monitor session ...`) **before** `$script:LogPath` is set, so an arbitrary folder stays untouched; then set `$script:ReportDir` to the session and `$script:LogPath` to `analyze.log`, `Invoke-MonitorAnalysis -SessionPath -TopN`; `All` -> Inventory then Disk with the shared state cleared in between.
8. Refusals with a documented exit code are thrown as a marker string `WD_EXIT:<code>|<message>` (`New-WdExitRequest` / `Get-WdExitRequest`). Top-level `try/catch`: a marker is printed (yellow for 3, red otherwise) and becomes that exit code without `Unhandled error`, stack trace or log file; a message containing `already running` becomes exit 3; everything else is logged with the script stack trace, prints `See <run.log>` and exits 1. Success prints `Done. Report: <dir>` and exits 0.

Exit codes: `0` ok, `1` unhandled error (also PowerShell binding errors: a non-numeric value, a stray positional token), `2` network/UNC location, `3` monitor already running / no monitor to stop, `4` missing lib file, `5` invalid parameters (unknown `-Mode`, `-IntervalSeconds` / `-DurationMinutes` / `-TopN` out of range, session folder missing or not a monitor session, menu with redirected input), `6` task install/uninstall failed. The launcher starts PowerShell with `-File`, so `exit N` propagates to `%ERRORLEVEL%` (with `-Command` it would become 1). The launcher itself strips the mode word from `%*` (`call set "REST=%%ARGS:*%1=%%"`) and forwards the rest verbatim instead of re-tokenizing through `%1`/`shift`, so `-Drives C,D` and quoted paths with a trailing backslash reach PowerShell unchanged.

## Module contracts

| Function | Signature | Notes |
|---|---|---|
| `Invoke-InventoryScan` | `-OutDir <string> [-Deep]` | `-Deep`: Authenticode signature of every autostart binary (not only flagged ones) and the full `Win32_PnPSignedDriver` list in `drivers.csv` |
| `Invoke-DiskScan` | `-OutDir <string> [-Drives <string[]>] [-TopN <int>] [-Deep]` | default drives: fixed NTFS/ReFS volumes with a letter; `-Deep`: hard-link deduplication of `%windir%` (native walker only) |
| `Start-ProcessMonitor` | `-OutDir -IntervalSeconds -DurationMinutes [-TrackShortLived]` | throws a message containing `already running` when another monitor owns the OutputRoot (defensive; the entry point refuses earlier). `-TrackShortLived` stays opt-in: the WMI process-creation subscription costs CPU and misses processes living under 2 s |
| `Stop-ProcessMonitor` | `-OutputRoot` -> `'Stopped'` \| `'Signaled'` \| `'None'` | `Stopped`: every live monitor confirmed within 30 s; `Signaled`: STOP files written, at least one monitor did not confirm (it stops at its next check); `None`: no live monitor. The console message belongs to the entry point (`Write-WdStopOutcome`), the module logs details only |
| `Install-MonitorTask` / `Uninstall-MonitorTask` / `Test-MonitorTaskInstalled` | `-OutputRoot -IntervalSeconds` -> `[bool]` / -> `[bool]` / -> `[bool]` | task `WinDebug Monitor` |
| `Invoke-MonitorAnalysis` | `-SessionPath <string> [-TopN <int>]` -> path of `report.md` | relies on `$script:ReportDir` / `$script:LogPath` pointing to the session folder |

## Testing

`tests\Invoke-Checks.ps1` is the repository self-check and needs no Pester. Sections: (a) syntax - it parses every `.ps1`; (b) encoding - UTF-8 BOM + CRLF for `.ps1`/`.cs`, ASCII + CRLF + no BOM for `.cmd`/`.bat`; (c) no command aliases; (d) approved verbs on every function; (e) banned APIs (`Get-WmiObject`, `Get-Counter`, `Win32_Product` even as a string) and `Write-Output` with a string literal (UI text); (f) source hygiene - every literal `Write-Log -Level` is one of `Info`/`Warn`/`Error`/`Debug`, no bare `powershell(.exe)` command, `Start-Process -FilePath 'powershell.exe'` or `New-ScheduledTaskAction -Execute 'powershell.exe'` in `.ps1` files and no bare `powershell.exe` line in `.cmd` files, no reference to the retired spec file; (f2) **Param/variable case** - for every function, the `param()` names are compared with the variables assigned in its own body (`$x =`, `[type]$x =`, `$x +=`, `foreach ($x in ...)`; nested functions excluded, scoped variables such as `$script:x` ignored): a name equal ignoring case but different in case (`$Path` vs `$path`) is a failure, because PowerShell treats them as one variable and the assignment silently overwrites the parameter - never reuse a parameter name in a different case as a local; (f3) **Rule ids documented** - every literal `-RuleId` in `lib\*.ps1` (AST, `CommandParameterAst`) must appear in `docs\inventory-rules.md` or `docs\analyze-scoring.md` as a table row whose first cell is the id (`| ID | ...`) or as a back-ticked `` `ID` ``; an undocumented id fails, an id documented but no longer used in code is printed as a yellow warning, and a one-line count summary (`rule ids: N in code, M documented, U undocumented, S stale`) is printed; (g) behaviour of the `lib\Common.ps1` helpers - rule regexes (miner tokens incl. the Electron `--url=https://` non-match, WEAK/STRONG script-host split and the `ScriptHostArgRegex` alias, suspicious-path folder boundaries incl. the user-writable Windows folders, trusted-signer anchoring), `Get-ProcessLocationClass` prefixes, `ConvertTo-CommandLineArgument` round-tripped through a real `powershell.exe` child, the CSV guard row (incl. `-2+3` guarded and `-1.50` raw), `Export-CsvInvariant -Columns` (empty result -> header line, without `-Columns` -> BOM-only, fixed order with missing cells, pipeline input), `Hide-WdSecret` (`[Interface] PrivateKey = <base64>` -> `PrivateKey = ***`, `--password hunter2` -> `--password ***`, `{"token": "abc.def"}` -> `{"token": "***"}`, `xmrig -o pool:4444 -u 48abc` unchanged), `Invoke-Safely` capping a 3000-character message at 1000 + `[truncated, 3000 chars]`, a `(requires administrator)` failure becoming one admin skip and no collection error, `Get-WinEventSafe` on the Security log without administrator rights (0 collection errors, 1 admin skip) and under a ru-RU UI culture, `[bigint]` JSON, `Write-Log` never throwing, the `- Privacy:` line of `Get-RunInfoSectionLines`; (h) entry-point exit codes - Analyze on a non-session folder -> 5 with the folder untouched, no session -> 5, unknown `-Mode` -> 5, `-TopN` out of range -> 5, stray positional token -> 1, `-StopMonitor` with nothing running -> 3, and no report folder created by any of them (skipped automatically when the repository is on a UNC path). Scratch files go to `%TEMP%\wd-selfcheck-<guid>` and are deleted. Exit code 1 on any failure; the summary rows are named `Syntax`, `Encoding`, `No aliases`, `Approved verbs`, `Banned APIs`, `Source hygiene`, `Param/variable case`, `Rule ids documented`, `Common.ps1 behaviour` and `Entry-point exit codes`. The whole run takes about 15 s. Run it from anywhere: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-Checks.ps1 [-Path <repo>]`. Consequence for rule authors: a new `-RuleId` is documented as a `| ID | ... |` table row (or a back-ticked `` `ID` ``) in `docs\inventory-rules.md` / `docs\analyze-scoring.md` in the same change, and an id removed from the code is removed from the docs to silence the stale warning.

Manual testing must happen from a local copy of the repository; the interactive paths (UAC prompt, menu, Ctrl+C / Q) need a real console. Analyze can be exercised on any recorded session folder with `-SessionPath`.

`tests\Invoke-FunctionalChecks.ps1 [-IncludeMonitor]` adds runtime regressions: native and fallback directory walkers (including a junction loop and bracketed paths), synthetic miner versus ordinary HTTPS command lines, protected indicators under trusted-vendor damping, quoted-secret masking in every analysis output, empty/corrupt sessions, and failed report writes. `-IncludeMonitor` starts a temporary hidden monitor, waits for two samples, sends STOP, verifies final state and analyzes the recording. It requires a local Windows checkout, creates no scheduled task, and removes its temporary data. Both test scripts run in GitHub Actions on Windows PowerShell 5.1.

Analyze sets `Verdict.Inconclusive` in `analysis.json` and prints **Inconclusive** when no usable process observations exist or reading/scoring failed and no suspect reached the threshold. `Verdict.Clean` is false in that case. Existing suspects remain visible despite incomplete data. Report export failures throw after preserving partial files (`Confirm-WdReportExport`), so the entry point exits 1 instead of printing success. Invalid/empty drive selections exit 5 before report creation.

## Decision log

| Decision | Reason |
|---|---|
| `CurrentCulture` is switched to invariant, `CurrentUICulture` is left alone | Files must be identical on every Windows language; error messages may stay in the user's language. Every helper still passes `InvariantCulture` explicitly because the switch is per thread. |
| The `WinDebug Monitor` task is **not** hidden | A hidden task is exactly what the Inventory rule `AUT-HIDDEN-TASK` reports as miner persistence. |
| No `Start-Job` / runspaces | The culture switch is not inherited; single-threaded code is easier to debug and cannot leave orphan runspaces. |
| Common list helpers enumerate; callers wrap in `@(...)` | `Write-Output -NoEnumerate` nests an array inside `@(...)` on PowerShell 5.1; a single convention at the call site is simpler. |
| `tests\Invoke-Checks.ps1` instead of a Pester encoding test | The Pester that ships with Windows is version 3.4; a plain script with the parser API covers syntax, encoding, aliases, verbs and banned APIs without a dependency. |
| Rule documentation split into `inventory-rules.md` and `analyze-scoring.md` | Two audiences and two owners; each file is the contract of one module. |
| Monitor writes sampling diagnostics to `monitor.log`; `run.log` keeps the header and a pointer | A multi-day run would otherwise grow `run.log` with one line per sample. |
| Analyze writes `analyze.log` into the session folder | Re-analysing a session must not append to the monitor's own `run.log`; the session folder stays self-contained. |
| `Security`, `Diagnostics-Performance` and `Storage-Storport/Operational` logs are skipped pre-emptively when not elevated | `Get-WinEvent` returns "No events were found" instead of "access denied" for them, which would silently produce "0 events". |
| A failure message ending with `(requires administrator)` is an admin skip, never a collection error; the skip is registered if missing | Without this a non-admin Inventory run listed the same item twice (`Skipped (requires administrator)` and `Collection errors`), which read like a broken run instead of a rights gap. `Test-WdAdminSkipMessage` is deliberately lenient (drop and register) rather than strict (drop only when already registered), so an item can never vanish from `summary.md`. |
| `Export-CsvInvariant -Columns` writes a header line for an empty result; without `-Columns` the old BOM-only file is kept | A BOM-only `devices-problems.csv` looked like a broken write; callers whose result is legitimately empty pass the schema, other callers are unchanged. |
| `Get-LocalGroupMember` is skipped on domain-joined PCs | Domain SID lookups can stall for 30 s or more when the domain controller is unreachable; the tool targets home PCs. |
| Script-host arguments are two rule keys, `ScriptHostWeakArgRegex` (`-ExecutionPolicy Bypass`, `-NoProfile`, `-WindowStyle Hidden`, `-NonInteractive`) and `ScriptHostStrongArgRegex` (`-EncodedCommand`/`-enc`, `DownloadString`/`DownloadFile`, `IEX`, `FromBase64String`, `scrobj.dll`, `urlcache`, `certutil -decode`, `bitsadmin`, `curl`/`wget`, `http(s)://`, `javascript:`/`vbscript:`, `mshta` with a URL); `ScriptHostArgRegex` stays as an alias of the STRONG one | Almost every legitimate scheduled script uses the weak flags, so Inventory, Monitor and Analyze raise red flags only on STRONG matches and treat WEAK matches as informational (Analyze: at most 2 points). Inventory's private strong-indicator regex was replaced by the shared key so the three modules cannot drift apart; the alias keeps older call sites working. |
| `MinerTokenRegex` matches `--url=stratum` and `-o stratum`, not a bare `--url=` | Electron/Chromium helper processes (Spotify, VS Code, Yandex Browser crashpad handlers) carry `--url=https://...`; a 20-point protected indicator must not fire on them. Everything else in the regex is kept. |
| `Stop-ProcessMonitor` returns `Stopped` / `Signaled` / `None` and the entry point prints the message | A `[bool]` could not distinguish "stopped" from "STOP written but not confirmed within 30 s"; the user must know whether to look at `monitor.log`. Messages: `Monitor stopped.` (0), `STOP signal sent; the monitor did not confirm within 30 s - check monitor.log.` (0), `No running monitor found.` (3). |
| `MEM-POOL`: with a hypervisor present (`Win32_ComputerSystem.HypervisorPresent`) or a running `vmmem` / `vmmemWSL` process the non-paged pool threshold is 2.5 GB and the finding is Info | WSL2 / Hyper-V / Windows Sandbox legitimately pin gigabytes of non-paged pool; a Warning on every developer laptop would drown the real driver-leak case that the rule exists for. |
| The original design spec is retired; comments and documents refer to `docs/ARCHITECTURE.md` | One contributor-facing document in the repository; the self-check fails on stale references in `.ps1` files. |
| Per-mode logs stay: `monitor.log` and `analyze.log` next to a minimal `run.log` | See the two rows above; merging them was considered and rejected because a multi-day session must stay self-contained and greppable. |
| `-TrackShortLived` stays opt-in | The WMI `__InstanceCreationEvent` subscription costs CPU on a ~1000-process PC, misses processes living under 2 s anyway, and most miners live long. |
| `processes-snapshot.csv` (Inventory), `procmeta.csv` / `procsum.json` / `events.csv` (Monitor) and the Analyze outputs keep full command lines, stored **secret-masked** (`Hide-WdSecret`) after the rules matched the original | A miner is often identifiable only by its arguments (pool URL, wallet), so pool hosts and wallets stay visible; a VPN private key or a `--password` value passed on a command line must not travel with a shared summary, so credential-like values become `***` (key name kept). The rule flags are always computed on the unmasked text, so masking can never hide a miner argument. The README documents command lines as personal data and the masking as heuristic. |
| On a domain-joined PC (`Win32_ComputerSystem.PartOfDomain`) findings about corporate-style configuration (`NET-DNS` unknown resolvers, `NET-PROXY` proxy/PAC, a disabled Domain firewall profile) are downgraded to Info, not suppressed | The tool targets home PCs; on a managed machine these are the administrator's decisions, but the data still belongs in the report. |
| `top-files.csv` keeps its extra columns beyond `Path` / `Bytes`: `Modified`, `Created`, `Extension`, `LogicalBytes`, `CloudOnly` | They cost nothing once the walker has the data, and allocated versus logical size plus the cloud-only flag are what distinguishes a sparse VHDX or a OneDrive placeholder from a real space hog. |
| Two verdict classes (Suspicious 8+, Highly suspicious 15+) plus a "near-certain indicator fired" marker | A third "almost certainly malicious" class added no information beyond the marker; miner tokens and Defender detections are never damped anyway. |
| `Analyze` and `Menu` never elevate automatically | Analyze only reads files; the menu offers elevation as an explicit item. |
| `-Deep` is one switch for all optional slow steps | One user-facing knob; each module documents what it adds. |
| The tool refuses UNC paths instead of trying to cope | Internet-zone scripts, `cmd.exe` without a UNC cwd and GPO execution policies make it unreliable there; copying to a local folder is a one-time step. |
| The only external programs are `schtasks.exe /query` (row count) and `powercfg.exe /batteryreport /xml` | Everything else is available through CIM, the registry or .NET; localized text output is never parsed. |
