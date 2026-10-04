# Analyze scoring (mode `Analyze`, `lib\Analyze.ps1`)

`Invoke-MonitorAnalysis -SessionPath <folder> [-TopN 50]` reads a monitor session (format in `docs\monitor-format.md`)
and writes four files **into the session folder**: `report.md` (human report), `analysis.json` (everything machine
readable), `suspects.csv` (every process with a raw score above 0, best first) and `process-summary.csv` (every
process aggregate). Log lines go to `analyze.log` in the same folder. Nothing outside the session folder is touched and
nothing is uploaded; the VirusTotal links are plain URLs built from the SHA256 recorded by the monitor.

The analysis works without administrator rights. What the monitor could not read without elevation stays unknown and
is marked `(requires administrator)` in the report (see "Data gaps").

## Inputs and how they are combined

| File | Used for |
|---|---|
| `procsum.json` | authoritative per-process totals over **all** samples (CPU seconds, averages, idle/active split, GPU seconds per engine type, IO, working set, window state, restarts, connection counters) |
| `procs_*.csv` | streamed line by line: per-process timelines (sparklines), flat-core detection, GPU Compute idle/active split, and totals for processes that are missing from `procsum.json` (written every 60 s; a killed monitor loses up to one minute) |
| `samples_*.csv` | system timeline, idle/active state per sample, real interval per sample, peaks, throttling, memory pressure |
| `procmeta.csv` | path, command line, parent, owner, session, location class, version info, signature, SHA256, monitor rule flags |
| `net.csv` + `dns.csv` | remote endpoints per process (first sight), pool ports, raw IPs without a cached DNS name, connections while idle |
| `events.csv` | Defender detections and configuration changes, new services / tasks / WMI consumers, crashes, PowerShell script blocks |
| `run.json` | host facts, interval, elevation, stop reason |

Reader rules (from the monitor contract): CSV lines are streamed with a `StreamReader` and a header map (never
`Import-Csv`); a line whose field count differs from the header is skipped and counted (a killed monitor leaves at most
one truncated line); empty cells are missing values, never 0; numbers are parsed culture-invariantly; several daily
files are read in name order; rows of the monitor's own `powershell.exe` (`Flags` contains `Self`) are ignored.

**Aggregation.** Processes are grouped into *subjects* by executable path (lower-case), so a restarted or multi-process
program is one row. Processes without a readable path (SYSTEM/service processes when the monitor was not elevated)
are grouped by name, except system binary names (`svchost`, `dllhost`, `conhost`, `RuntimeBroker`, ...) which stay one
row per instance so that one hot instance is not averaged away. Other win-debug processes (`WinDebugTool` flag) are
kept apart and never scored.

Because concurrent instances (30 `Code.exe` helpers) would otherwise dilute averages, sample counts of a subject are
capped at the session totals ("effective samples"): average CPU % = sum of the instances' CPU % per sample / effective
samples. Sequential restarts keep their summed counts. `Present` in the report = effective samples / session samples.

For processes that exist only in `procs_*.csv` (not in `procsum.json`) the idle/active sample counts are the session
samples between first and last sight; a missing row means the process was below the row filter (quiet) in that sample.

## Indicators

Points are summed per subject; each indicator is capped at the value shown. Group *Resource* indicators describe
behaviour, *Protected* indicators are near-certain and are never damped, everything else is *Other*.

| Id | Indicator | Condition | Points (cap) | Group | Data | False-positive notes |
|---|---|---|---|---|---|---|
| I1 | CPU while the user is idle | idle average >= 5 % (all cores) AND idle average >= 2 x max(0.5, active average); needs >= 20 samples in **both** states | 6, +2 if idle average >= 25 % (8) | Resource | procsum / procs + samples | Defender scans, Search indexer, Windows Update, OneDrive, photo indexing, backups run at idle (damped when signed). When the user was never active during the run only a partial 3-point variant fires ("no active baseline") |
| I2 | GPU Compute engine | Compute/CUDA engine average >= 10 % over >= 30 samples | 6, +3 without window, +2 if higher while idle than while active (11) | Resource | procsum GpuComputeSeconds, procs GpuCompute | WebGPU/WebGL pages and video effects in browsers, Photos ML tagging, Ollama / LM Studio / torch, video encoders. 3D and Video engines never score |
| I3 | Windowless interactive load | never had a window, session >= 1, CPU average >= 10 %, present in >= 50 % of samples | 4 | Resource | procsum | tray-only and minimised-to-tray programs have no window |
| I4 | Flat integer core count | >= 80 % of the CPU rows within +-10 % of the same integer number of cores (>= 1), >= 10 min span, rows cover >= 80 % of the samples | 3 | Resource | procs CpuCores | encoders and renderers with a fixed thread count |
| I18 | Low base priority with real load | base priority <= 6 (Idle/BelowNormal) in >= 50 % of samples and CPU average >= 5 % | 3 | Resource | procsum LowPrioSamples | Search indexer, backup tools, Defender scans deliberately run at low priority |
| I5 | Location | Temp, RecycleBin, Public: 5; AppData, ProgramData, Downloads, Removable: 3; UserProfile: 2; a user-writable sub-folder of `%windir%` (`C:\Windows\Tasks`, `\Tracing`, `\Temp`, `\debug\WIA`, `\Registration\CRMLog`, `\servicing\Packages`, `\System32\Tasks`, `\SysWOW64\Tasks`, `\System32\spool\drivers\color`, `\System32\spool\PRINTERS`, `\System32\Microsoft\Crypto\RSA\MachineKeys`, `\System32\com\dmp`, `\SysWOW64\com\dmp`): 3 | 5 | Other | procmeta LocationClass + path | Spotify, Telegram, VS Code, Discord, GeForce NOW and many installers live in AppData; dev tools in the profile. The writable Windows folders are classified `Windows`/`System32` by the monitor but are never a trusted location here (I8, I9, I12, I16, I17 and damping treat them like ProgramData) |
| I6 | Signature | NotSigned 2; HashMismatch or NotTrusted 5; UnknownError / Error 2 | 5 | Other | procmeta SigStatus | indie games, Python/Node tooling, portable apps, self-built tools are often unsigned |
| I7 | Masquerade | system binary name outside its Windows location (`SystemNameOutsideSystem32`), unexpected parent (`UnexpectedParent`), or `svchost` without `-k <group>` | 8 | Protected | procmeta Flags + command line | none known; parents that already exited are not evaluated by the monitor |
| I8 | Look-alike name | Levenshtein distance 1-2 to a system binary name (`svch0st`, `scvhost`, `lsas`, `explore`, ...) for a process outside System32/Windows/Program Files (user-writable Windows folders count as outside) that is not trusted-signed | 5 | Other | procmeta | names shorter than 5 characters are not compared |
| I9 | Random-looking name | `^[a-z0-9]{10,}$` with >= 2 digits, or `^[0-9a-f]{8,}$` with a digit, or Shannon entropy >= 3.3 with 8-16 characters and no company/description; not for System32/Windows (except the user-writable folders) or validly signed files | 3 | Other | procmeta | installer temp names such as `is-KP0P5.tmp` contain other characters and do not match |
| I10 | Miner tokens | command line matches `MinerTokenRegex` (`stratum+tcp`/`stratum+ssl`, `--url=stratum...`, `-o stratum...`, `xmr`, `monero`, `--donate-level`, `--randomx`, `cryptonight`, `kawpow`, `xmrig`, `nicehash`, `--cpu-max-threads-hint`, Monero address, ...). Of the `--url=` forms **only** `--url=stratum...` counts | **20** | Protected | procmeta CommandLine | the weak tokens `pool`, `--algo`, `-o host:port` (without `stratum`) score only 3 (Other) and score 0 for Chromium/Electron child processes (`--type=`) or trusted-signed files. **Electron exception:** a bare `--url=` does not match at all, because Chromium/Electron crashpad and utility children (Spotify, VS Code, Yandex Browser, Chrome `--type=gpu-process`) carry `--url=https://...`; a 20-point protected indicator must never fire on them |
| I11 | Script host arguments | name matches `ScriptHostRegex`. **STRONG** = arguments matching the shared `ScriptHostStrongArgRegex` (`-enc`/`-EncodedCommand`, `DownloadString`/`DownloadFile`, `IEX`/`Invoke-Expression`, `FromBase64String`, `scrobj.dll`, `urlcache`, `certutil -decode`, `bitsadmin`, `curl`/`wget`, `http(s)://` URLs, `javascript:`/`vbscript:`): a red flag. **WEAK** = arguments matching only `ScriptHostWeakArgRegex` (`-ExecutionPolicy Bypass`, `-NoProfile`, `-WindowStyle Hidden`/`-w hidden`, `-NonInteractive`): informational evidence | 6 for a STRONG match; **capped at 2** for WEAK-only evidence (`$script:WdAnWeakScriptHostPoints`) | Other | procmeta CommandLine + Flags | every PowerShell started with `-ExecutionPolicy Bypass` or `-NoProfile` (IDE and agent shells, scheduled scripts, installers, win-debug itself) matches the weak rule; 2 points can never reach the Suspicious threshold (8) alone and are never a "near-certain" marker. Win-debug's own processes are not scored. The analyzer's own match on the recorded command line always wins over the monitor's flags: sessions recorded by **older monitors** carry `ScriptHostRedFlag` for mere launch options, so a flag that the command line does not reproduce is only noted ("not reproduced ... not scored"). Without a recorded command line the monitor flags are used as they are: `ScriptHostRedFlag` -> 2 (unverifiable), `ScriptHostWeakArgs` -> 2 (informational) |
| I12 | Parent chain | script host / cmd / powershell started by winword, excel, outlook, powerpnt, onenote, wordpad, acrord32, acrobat; any process started by wscript, cscript, mshta, regsvr32, rundll32; a Temp/AppData/ProgramData/Public/Downloads/writable-Windows-folder executable started by svchost, services, wmiprvse, taskeng or taskhostw (task, service or WMI consumer) | 5 | Other | procmeta ParentName | updaters in AppData started by the Task Scheduler (Zoom, OneDrive, Edge, Spotify) hit the third rule and reach I5 + I12 = 8; the AppData/ProgramData damping (-4) for a valid signature of a trusted vendor keeps them below the threshold |
| I13 | Mining pool ports | established connection to a `PoolPorts` port (3333, 3334, 3335, 3357, 4444, 5555, 6666, 7777, 8888, 9999, 14433, 14444, 45560, 45700, 20535, 1314, 17777, 18081) | 4 per distinct port (max 8), +4 if the remote is a raw public IP without a cached DNS name (12) | Other | net + dns | 4444/5555/8888/9999 are also used by dev servers and ADB; combined with DNS absence and other indicators |
| I14 | Connections opened while idle | public (non-private) connections **opened during the run** while the user was idle (`ConnCreated` at or after the first sample; a connection that already existed at monitor start, or without `ConnCreated` one first seen in sample 1, is ignored), for a process that is neither a known heavy process nor trusted-signed (system-named processes without a path are skipped); not evaluated in an all-idle run shorter than 20 samples | 2 | Other | net | chat clients, sync tools and updaters talk while idle; most are on the known list or trusted-signed. Without the `ConnCreated` rule every connection discovered at the start of an overnight recording would count |
| I15 | Many endpoints | >= 30 distinct remote addresses, no window, not a known heavy process | 3 | Other | net | torrent clients, CDN-heavy apps |
| I16 | Watchdog restarts | >= 3 starts during the run, >= 2 of them within 5 min after a previous instance exited; not for validly signed System32/Windows binaries | 4 | Other | procsum / procs New+Exited | developer sessions start git, bash, conhost, python dozens of times; the report prints the maximum number of concurrent instances so a true one-at-a-time watchdog can be told apart |
| I17 | Long-running background from a user location | started >= 7 days before the run, no window, not in System32/Windows/Program Files | 1 | Other | procmeta Started | tray tools, launchers, sync agents |
| I19 | Defender events | 1006/1007/1015/1116/1117/1118/1119 naming the path or image: 15; 5007 configuration change mentioning `Exclusions` and the folder: 8 | 15 / 8 | Protected | events | the monitor stores only the first message line; detections that do not name the file are listed in the Events section but not attributed |
| I20 | Persistence created during the run | System 7045 (service installed), TaskScheduler 106 (task registered) or WMI-Activity 5861 (consumer) naming the path or image | 5 | Other | events | software installers register services and update tasks |
| I21 | No version info and young file | CompanyName and FileDescription empty AND file created <= 30 days before the run | 2 | Other | procmeta | freshly built or downloaded developer tools |
| I22 | Renamed binary | OriginalFilename (without `.mui`/extension) differs from the running image name, neither contains the other, file not validly signed, original is not `electron` | 6 | Other | procmeta | validly signed files are skipped (Microsoft ships many `.MUI` names) |

Indicators I5-I12, I17, I21 and I22 need the path/command line/signature. When the monitor ran without
administrator rights these are unknown for SYSTEM/service processes; the report shows `?` for them, and a process whose
resource indicators (I1-I4, I18) fired without a readable path is listed under "Re-run the monitor elevated to inspect".

## Damping and score

```
raw       = sum of all indicator points (per-indicator caps applied)
resource  = I1 + I2 + I3 + I4 + I18
protected = I7 + I10 (20-point strong tokens only) + I19
other     = raw - resource - protected

known heavy process (name on KnownHeavyProcesses) AND (valid signature OR path unknown): resource = max(0, resource - 4)
valid signature of a trusted vendor (TrustedSignerRegex or Windows catalog) in System32/Windows/Program Files
  (not in a user-writable Windows folder):                                    rest = max(0, resource + other - 6)
otherwise, the same valid trusted signature in AppData or ProgramData
  (updaters started by the Task Scheduler):                                  rest = max(0, resource + other - 4)
score = protected + rest
```

Example: `Zoom.exe --action=UpdateSchedule` in `AppData\Roaming\Zoom\bin`, signed by Zoom Communications, started by
svchost: I5 +3, I12 +5, raw 8, damping -4, score 4 (Below threshold). The same file unsigned would keep its 8.

`KnownHeavyProcesses` and `TrustedSignerRegex` are the shared rule data in `lib\Common.ps1` (Defender, Search,
Windows Update workers, OneDrive, Photos, WMI provider host, WSL/Hyper-V VMs, GPU vendor services, browsers, Electron
apps, Java, Python, encoders...). The raw score, the applied damping and every indicator text are kept in
`suspects.csv` / `analysis.json`, so a damped hit can always be reviewed.

## Thresholds

When no usable process observations exist, or a reader/scoring step failed and no suspect reached the threshold,
the verdict is **Inconclusive**, not a clean result. `analysis.json` includes `Verdict.Inconclusive = true` and
`Verdict.Clean = false`; the report explains the gaps and recommends recording again. Detected suspects are
retained even if other data is incomplete. A failed output write exits with an error and preserves partial files.

| Score | Class | Meaning |
|---|---|---|
| 0 | Clean | no indicator fired (or everything was damped) |
| 1-7 | Below threshold | some indicators fired; the five highest are printed for transparency when nothing reaches the threshold |
| **8-14** | **Suspicious** | review the process: path, signer, command line, VirusTotal link, how it starts |
| **>= 15** | **Highly suspicious** | several independent indicators or a near-certain one (miner tokens, Defender detection) fired; treat as malicious until proven otherwise |

The Verdict lists the top 3 suspects with their indicators, or "Nothing suspicious found" with the reasons (no miner
tokens, no idle-heavy process, no Compute engine use, no masquerade, no pool ports, highest scores seen). Suspects are
also emitted as findings (`AN-SUSPECT`, Warning for Suspicious, Critical for Highly suspicious).

### Expected scores

- Real 2-minute session on a developer laptop (not elevated, user idle the whole time, 24 idle / 0 active samples):
  highest score 6 (`extension-host.exe`: UserProfile + not signed + young file without version info), `CodeSetup-*.tmp`
  5 (Temp), AppData apps 3, `powershell.exe -ExecutionPolicy Bypass` raw 2 damped to 0. I14 does not fire: all 28 public
  connections of the run already existed when the monitor started (discovered in sample 1). Nothing reaches 8.
- Synthetic miner (`svchost.exe` in `AppData\Roaming`, unsigned, OriginalFilename `xmrig.exe`, `--donate-level` in the
  command line, parent `wscript`, 40 % CPU and 60 % GPU Compute only while idle, pool ports 3333 and 14444 at raw IPs):
  **83 points** = I1 8 + I2 11 + I3 4 + I5 3 + I6 2 + I7 8 + I10 20 + I12 5 + I13 12 + I14 2 + I21 2 + I22 6.
  A benign Chrome (Program Files, Google LLC signature, window, 45 % 3D engine while active) in the same session: 0.

## How to read report.md

1. **Run info / Monitor session** - who recorded what, whether the monitor was elevated, duration, samples, idle
   share. A 100 % idle or 100 % active run cannot compare idle vs active behaviour: record longer.
2. **Verdict** - the answer. System-level warnings (throttling, memory pressure, Defender events) follow.
3. **System timeline** - one glyph per bucket (1 min / 10 min / 1 h / 3 h ... chosen by run length, at most 60
   columns) for CPU, GPU, GPU Compute, memory, disk, network; `_`/`.` marks idle/active buckets; a dot means no data.
   Peaks with timestamps and the process that was on top at the CPU peak.
4. **Top consumers** - by CPU seconds (with per-process sparkline), GPU seconds split by engine type, working-set peak
   and growth (leak hint), IO bytes. Instance counts in brackets, `unknown (requires administrator)` for SYSTEM
   processes of a non-elevated run; `unknown (exited before metadata)` and `unknown (kernel/protected process)` are
   not rights problems and are printed without the marker (also in an elevated run). **Multi-instance subjects show
   the peak instance's memory values:** in the memory table Peak, First, Last and Growth all describe the one instance
   with the highest working set (never a sum or an average over the instances), so Growth is a real per-process trend
   for multi-process programs (browsers, Electron apps); the "possible leak" recommendation and the `WSMaxBytes` /
   `WSFirstBytes` / `WSLastBytes` columns of `process-summary.csv` / `suspects.csv` use the same instance. CPU, GPU and
   IO totals, in contrast, are summed over all instances.
5. **Idle vs active** - the miner signal: average CPU while nobody uses the PC vs while working; ratio >= 2 with >= 5 %
   idle CPU is indicator I1. Legitimate idle workers are named.
6. **Suspicious processes** - score, class, every indicator with its evidence, path, signature, SHA256 with a
   VirusTotal link, first/last seen, details (command line, parent, owner, session, resource totals), the list of
   processes to re-check elevated, and rule hits that were recognised as false positives.
7. **Network endpoints of interest** - pool ports, raw IPs without DNS names for unknown programs, endpoints of scored
   processes, processes with 30+ addresses.
8. **New, short-lived and restarted processes** - starts/exits, restart patterns (starts, quick restarts, maximum
   concurrent instances), new processes from user-writable locations.
9. **Events** - Defender, services/tasks/WMI persistence, crashes and shutdowns, PowerShell script blocks (4104) with
   red-flag patterns. A script block is listed with `Evidence = red flag` when its text matches the shared
   `ScriptHostStrongArgRegex` (encoded command, download cradle, `IEX`, `FromBase64String`, URL, LOLBin decoding) and
   with `Evidence = weak (window hiding; max 2 points)` when it only contains a window-hiding option
   (`-WindowStyle Hidden` / `-w hidden`); strong rows are listed first, at most 10 rows in total. The former inline
   pattern matched the bare word `hidden`, which listed every CDXML module block (they declare an `-IncludeHidden`
   parameter, e.g. `Get-NetAdapter`); those are no longer listed. Script blocks are not attributed to a process and
   never add to a score.
10. **Recommendations** - what to do next, generated from the findings.
11. **Appendix** - methodology, false-positive notes, data gaps (non-admin, skipped rows, csv-only processes, pending
    file info), the monitor's own footprint (`powershell.exe` tagged `Self` excluded; `WmiPrvSE.exe` 1-2 % CPU caused by
    the sampling), then the standard "Skipped (requires administrator)" and "Collection errors" sections.

## Output columns

`process-summary.csv` / `suspects.csv` (one row per subject; suspects = raw score > 0): `Process, Name, Path,
LocationClass, Instances, Pids, Score, RawScore, Class, Reasons, Damping, NeedsAdmin, Samples, SamplesIdle,
SamplesActive, EffectiveSamples*, CpuSeconds, CpuAvgPct, CpuMaxPct, CpuCoresMax, CpuIdleAvgPct, CpuActiveAvgPct,
GpuSeconds, GpuComputeSeconds, Gpu3DSeconds, GpuVideoSeconds, GpuMaxPct, GpuComputeAvgPct, ReadBytes, WriteBytes,
WSMaxBytes, WSFirstBytes, WSLastBytes, HasWindowEver, SessionId, BasePriority, LowPrioSamples, Started, FirstSeen,
LastSeen, PresentAtStart, Starts, Exits, QuickRestarts, MaxConcurrent, RemoteIps, PublicIps, PoolPorts, RawIpNoDns,
IdlePublicConnections, ListenPorts, DefenderDetections, ExclusionChanges, PersistenceEvents, ParentName, Owner,
Company, Description, OriginalFilename, SigStatus, Signer, IsOSBinary, Sha256, VirusTotal, Flags, AccessNote,
CommandLine, Sources, IsTool`. Numbers use a dot decimal separator; byte columns are integers.

**Secret masking.** Every command line, script text and event message that is rendered into `report.md`,
`suspects.csv`, `process-summary.csv` and `analysis.json` (the `CommandLine` column/field of every subject record, the
`command line:` and `event:` lines of the suspect details, the Events tables of the report including the 4104 script
text) passes through the shared helper `Hide-WdSecret` (`lib\Common.ps1`): the key name is kept and the value becomes `***`
for `password=`, `--token x`, `"apikey": "..."`, `PrivateKey = <base64>`, URL user info (`https://user:***@host`) and
query tokens. Matching and scoring (I7, I10, I11, event attribution) always use the **original** text, so a masked
value can never hide a miner; pool hosts and wallet addresses are deliberately not masked because they are evidence.
The monitor masks the same way when it writes `procmeta.csv` / `events.csv`; Analyze repeats it as defense in depth for
sessions recorded by older monitors.

`analysis.json`: `Meta` (analysis run info), `AnalyzeDurationSeconds` (reading + scoring only: the JSON cannot hold
the time of its own write; the console line "Analysis finished in N s (reading and scoring A s, writing the outputs W s)"
has the total), `Thresholds`, `Session` (facts from run.json and the samples; `ProcessesWithoutPath` falls back to a
count of procmeta rows with the `(requires administrator)` marker when run.json still holds the start-of-run 0), `Stats`
(rows read/skipped per file), `Verdict` (with full indicator lists of the suspects), `Timeline` (bucket labels and
series), `Peaks`, `TopConsumers` (by CPU/GPU/working set/IO, `-TopN` rows each), `Scored` (every subject with raw score
> 0, with indicators and public endpoints; an endpoint's `Idle` means "opened during the run while the user was idle"),
`NeedsElevatedCheck`, `Recommendations`, `AdminSkips`, `CollectionErrors`.

Robustness: a `procs_*.csv` row with a wrong field count or a Timestamp shorter than 19 characters is skipped and
counted (never aborts the pass); a corrupt `procsum.json`/`run.json` is reported as `<file> is not valid JSON (<n>
chars): <reason> (<offset>)` without echoing the file; the command line is flattened to one line before it is cut for
the report; when one half of report.md cannot be rendered the file is still written with a note in place of that half
(the error is logged and listed under Collection errors).

## Limits

- Pure PowerShell 5.1 streaming reads about 22 000 procs rows per second on a modern laptop (1241 rows in 0.1-0.2 s,
  124 000 rows / 17 MB in 5.5 s); a 500 MB / 3.5 million-row session takes roughly 3 minutes for the CSV pass. Totals
  come from `procsum.json`, so the CSV pass is only needed for timelines and pattern detection. The whole analysis of
  the 2-minute reference session (1129 processes) takes about 5 s plus 5 s for writing the JSON/CSV outputs.
- The per-process timeline is kept for the top consumers and every flagged process (bounded memory); other processes
  keep only their totals.
- Idle detection follows the monitor: no keyboard/mouse input for 300 s or a locked session. Remote-desktop and
  scheduled-task sessions without an interactive logon report no idle time.
- Watchdog detection uses first/last sight per sampling interval; processes that live less than one interval are only
  seen with the monitor's `-TrackShortLived` option.
- Defender detections are attributed to a process only when the first message line names its path or image.
