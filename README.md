# win-debug

English | [Русский](README.ru.md)

**win-debug** is a read-only diagnostic toolkit for a Windows 10/11 PC that "became slow". It answers three questions without changing anything on the machine: *what is this computer and what is wrong with it* (Inventory), *what is eating the disk* (Disk usage) and *what runs in the background when nobody is looking* (Monitor + Analyze, a background process recorder with a scoring engine tuned to find crypto-miners and other resource hogs). Everything is written into a report folder as Markdown, JSON and CSV files that you can read on the spot or take home on a USB stick. Nothing is uploaded, nothing is installed, nothing is deleted.

## Requirements

- Windows 10 or Windows 11, 64-bit.
- Windows PowerShell 5.1 - preinstalled on every supported Windows. PowerShell 7 is **not** required and not used.
- Administrator rights are optional but recommended: without them the reports state exactly what was skipped (marked `(requires administrator)`).
- No internet connection, no installation, no external binaries. Two small C# helpers are compiled in memory at run time by the .NET Framework compiler that ships with Windows (needs a writable `%TEMP%`; if compilation fails the tool falls back to slower pure-PowerShell code).

## Quick start

1. Download the repository as a ZIP (GitHub: *Code -> Download ZIP*).
2. Right-click the ZIP -> *Properties* -> tick **Unblock** -> OK (or run `Unblock-File .\win-debug.zip` in PowerShell). This removes the "downloaded from the Internet" mark from every file inside before you extract them.
3. Extract it to a **local** folder, for example `C:\Tools\win-debug`. Never run it from a network share, a `\\server\...` path or a WSL path - the tool refuses those with exit code 2.
4. Double-click **`WinDebug.cmd`**.
5. The menu opens with your current rights - a double-click never shows a UAC prompt by itself. Pick **A** in the menu to restart the tool elevated (recommended for a complete picture). When you start a mode directly (`WinDebug.cmd inventory|disk|monitor|all`), the tool first asks `Run with administrator rights for a complete picture? [Y/n]` - Enter means *yes* and shows the UAC prompt; if you decline, it continues with the current rights.
6. Pick an item in the menu:

```
 win-debug 1.0.0  —  read-only Windows diagnostics          Administrator: NO (some data will be missing)
 Reports folder: C:\Tools\win-debug\reports

  1  Inventory     hardware, drivers, software, autostart, security, event logs  (~1-2 min)
  2  Disk usage    what occupies the disk and what could be freed                 (~2-5 min)
  3  Monitor       record processes / CPU / GPU / network in the background      (runs until stopped)
  4  Analyze       build report.md from a recorded monitor session
  5  All           Inventory + Disk usage
  6  Install monitor as logon task ("WinDebug Monitor")
  7  Remove the logon task
  8  Stop a running monitor
  A  Restart with administrator rights
  Q  Quit
```

When a mode finishes it prints `Done. Report: <folder>`. Every run gets its own folder under `reports\` named `<COMPUTERNAME>_<yyyyMMdd-HHmmss>_<inventory|disk|monitor>`; open `summary.md` (Inventory, Disk) or `report.md` (Analyze) first.

### SmartScreen and execution policy

- On the first double-click SmartScreen may show *Windows protected your PC*. Click **More info -> Run anyway**. The launcher is a plain `.cmd` file that starts `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -ExecutionPolicy Bypass -File WinDebug.ps1` (the fully qualified Windows PowerShell 5.1 host, never a bare `powershell.exe` taken from the current folder or `PATH`); nothing is installed.
- The `-ExecutionPolicy Bypass` switch avoids the default *Restricted* policy of a home PC without changing any setting. It cannot override a policy enforced by Group Policy (corporate machines) - see [Troubleshooting](#troubleshooting).
- If you skipped step 2 and see `... is not digitally signed` or `AuthorizationManager check failed`, unblock the extracted files: open PowerShell in the folder and run `Get-ChildItem -Recurse | Unblock-File`.

## Modes

| Mode | What it collects | Typical duration | Main files |
|---|---|---|---|
| **Inventory** | Hardware, OS, updates, drivers and problem devices, installed programs, Store apps, autostart entries, scheduled tasks, services, security state (Defender, firewall, UAC, accounts), network, battery, recent event-log errors, a performance snapshot of all processes (five counter samples 750 ms apart plus two process tables; the measured spacing between the two process tables is written to `summary.md` and `inventory.json`). 150 rules turn the data into findings (Critical / Warning / Info) with a recommendation each. | 1-2 minutes (leave the PC alone during the snapshot) | `summary.md`, `inventory.json`, `installed-programs.csv`, `autostart.csv`, `services.csv`, `scheduled-tasks.csv`, `devices-problems.csv`, `drivers.csv`, `events.csv`, `processes-snapshot.csv`, `battery-report.xml` (laptops) |
| **Disk** | Per volume: largest folders (depth 1-3) and files, user profiles, installed apps by size, Store apps, and a catalogue of cleanup candidates (temp, caches, Windows Update leftovers, Windows.old, browser and messenger caches, game libraries, WSL/Docker disks, dev caches, Recycle Bin...) with a safety class and the built-in tool to clean each one. **Report only - nothing is deleted.** Only fixed NTFS/ReFS volumes with a drive letter are scanned; volumes mounted in a folder and volumes without a letter are listed in the volume table but not measured. Ctrl+C during a volume walk aborts it immediately and the partial totals are discarded, not reported. | 1-3 minutes per SSD volume, several minutes on an HDD | `summary.md`, `disk-usage.json`, `volumes.csv`, `top-folders.csv`, `top-files.csv`, `cleanup-candidates.csv`, `user-profiles.csv` |
| **Monitor** | Background sampler: every 10 s (configurable) it records per-process CPU, GPU (per engine type), memory, IO, threads/handles, window state and TCP connections, plus system totals (CPU, memory, disk, network, GPU, battery, temperature, throttling, user idle / locked state), DNS cache, process starts and exits, and selected event-log entries (Defender, new services/tasks, crashes, PowerShell script blocks). Executable path, signature and SHA256 are recorded once per process. | Until stopped (hours or days). Roughly 20-40 MB per day at the default interval on a PC with ~1000 processes. | `run.json`, `samples_<date>.csv`, `procs_<date>.csv`, `procmeta.csv`, `procsum.json`, `net.csv`, `dns.csv`, `events.csv`, `filecache.json`, `monitor.log` |
| **Analyze** | Reads a monitor session and writes a human report: verdict, system timeline, top consumers (CPU/GPU/memory/IO), idle-vs-active comparison, suspicious processes with a score and a VirusTotal link for the hash, network endpoints of interest, new/restarted processes, events, recommendations. Writes **into** the session folder. | 10-20 s for a short session, a few minutes for a multi-day one | `report.md`, `analysis.json`, `suspects.csv`, `process-summary.csv`, `analyze.log` |
| **All** | Inventory followed by Disk (two report folders). Monitor is not part of All. | | |
| **Menu** | The interactive menu above (default when double-clicking). | | |

Every report folder also contains `run.log`. Details: [docs/inventory-rules.md](docs/inventory-rules.md) (every Inventory and Disk rule with its threshold - 150 Inventory and 19 Disk rule ids), [docs/monitor-format.md](docs/monitor-format.md) (every monitor column), [docs/analyze-scoring.md](docs/analyze-scoring.md) (every Analyze indicator and the score formula).

Numbers in all files use a dot as decimal separator regardless of the Windows language, timestamps are ISO 8601 with offset (`2026-09-27T23:08:17.742+03:00`), CSV files are UTF-8 with BOM (open directly in Excel), JSON/Markdown/log files are UTF-8 without BOM. In every CSV file (Inventory, Disk, Analyze and the monitor's) a text cell that begins with `=`, `+`, `@`, a tab, or with `-` unless the whole cell is a number (`-5`, `-1.50`) gets one leading space so that Excel does not evaluate a planted command line such as `-2+3` or `=cmd|...` as a formula; numeric cells are never touched. A CSV file is written even when it has no rows: `scheduled-tasks.csv`, `devices-problems.csv`, `drivers.csv` and `events.csv` then carry only their header line, and the monitor's files always start with the header.

## Finding a miner or a resource hog

A crypto-miner hides in two ways: it works only when nobody uses the PC (idle time, locked screen), and it looks like a system process. A single snapshot cannot catch that; a recording can.

### 1. Record

- **Interactive:** `WinDebug.cmd monitor` (or menu item 3). Leave the window open and use the PC normally for a few hours, and also leave it alone for at least 30-60 minutes (screen locked is fine). The monitor needs at least 20 samples (about 3.5 min at the 10 s interval) in **both** states - active and idle - to compare them; more is better.
- **Several days, unattended:** `WinDebug.cmd -InstallTask` (or menu item 6) registers a per-user logon task named **`WinDebug Monitor`** that starts the monitor hidden one minute after every logon. Let it run for a few days of normal use. Remove it later with `WinDebug.cmd -UninstallTask` (menu item 7). Do not move the `win-debug` folder while the task exists - the task points to the folder it was installed from.
- Run the monitor **with administrator rights** if you can: without them the path, command line, owner, signature and hash of SYSTEM/service processes (typically 100-200 of them) stay unknown, and a miner installed as a service is then visible only through its CPU/GPU behaviour.
- Optional: `-TrackShortLived` also records processes that live only a few seconds (via WMI process-creation events).

### 2. Stop

Any of these ends the recording cleanly:

- create an empty file named **`STOP`** in the session folder (`reports\<PC>_<date>_monitor\`);
- run `WinDebug.cmd -StopMonitor` (menu item 8) - it creates the STOP file for every running monitor and waits up to 30 s. It ends with one of three messages: `Monitor stopped.` (exit code 0), `STOP signal sent; the monitor did not confirm within 30 s - check monitor.log.` (exit code 0; the monitor stops at its next sample, the STOP file stays in place) or `No running monitor found.` (exit code 3);
- press **Q** or **Ctrl+C** in the monitor window;
- start with `-DurationMinutes <n>`.

Closing the window with the X or `taskkill` also stops it, losing at most one partial line; the leftover `monitor.running` marker is ignored once its process is gone.

### 3. Analyze

`WinDebug.cmd analyze` (menu item 4) picks the newest `*_monitor` folder under `reports\`; pass `-SessionPath <folder>` for another one. Analyze never asks for administrator rights and can even run while the monitor is still recording. Open `report.md` in the session folder.

### 4. Read the report

- **Verdict** - the answer. Either `Nothing suspicious found` with the reasons (no miner tokens, no idle-heavy process, no GPU Compute use, no masquerade, no pool ports, highest scores seen), or the top three suspects with their score and class. `Inconclusive` means no usable process observations were recorded, or some data could not be read or scored; check the collection errors and record again. Detected suspects are still reported when other data is incomplete. `near-certain indicator fired` means a miner command line or a Defender detection was seen - treat that process as malicious until proven otherwise.
- **Scores.** 22 indicators add points per executable (see [docs/analyze-scoring.md](docs/analyze-scoring.md)): **8-14 = Suspicious**, **15+ = Highly suspicious**. Miner tokens (20 points) and Defender detections (15) are never damped; a valid signature of a well-known vendor in System32/Windows/Program Files subtracts 6, a known heavy-but-legitimate background process (Defender, Search indexer, Windows Update, OneDrive, browsers, WSL, GPU vendor services) subtracts 4 from resource indicators. The raw score and every indicator text stay in `suspects.csv`, so a damped hit can always be reviewed. Below the threshold the report still lists the five highest scores "for transparency".
- **Idle vs active** - the strongest miner signal: average CPU of each process while nobody used the PC versus while working. A process with >= 5 % CPU while idle and at least twice its active average gets indicator I1 (6-8 points). If the run had fewer than 20 samples in one state the section says `insufficient data` and shows only the idle top list - record longer.
- **Suspicious processes** - for each: score, indicators with evidence, path, signer, SHA256 with a **VirusTotal link** (`https://www.virustotal.com/gui/file/<sha256>`). The link is for you to open manually; the tool never contacts VirusTotal. `SKIPPED_SIZE` means the file was larger than 64 MB and was not hashed. A `?` means the indicator could not be evaluated because the path is unknown (non-admin run). The list *Re-run the monitor elevated to inspect these processes* names SYSTEM/service processes whose resource use fired indicators but whose file could not be examined.
- **Network endpoints of interest** - connections to known mining-pool ports (3333, 4444, 14444 and others), raw IP addresses without a DNS name, endpoints of scored processes.
- **Appendix** - methodology, false-positive notes, data gaps, the monitor's own footprint.

### What to expect (false positives)

- **Legitimate idle workers:** Defender scans (`MsMpEng`), Search indexer, Windows Update workers (`TiWorker`, `MoUsoCoreWorker`), OneDrive, Photos (uses GPU Compute for face tagging), backups, `svchost` hosting Update/BITS/Delivery Optimization. They are damped but still appear in the idle table.
- **GPU:** browsers, Electron apps (VS Code, Discord, Telegram, Spotify) and games use the 3D/Video engines even when minimised - only the **Compute** engine scores. Ollama / LM Studio / Python with torch are user-installed compute.
- **Command lines:** only a mining-pool URL (`--url=stratum...`, `-o stratum...`, `-o host:port`) counts as a miner token - the plain `--url=https://...` of Electron/Chromium helper processes (Spotify, VS Code, Yandex Browser) does not match. Script-host arguments are split into two strengths: *weak* launch options (`-ExecutionPolicy Bypass`, `-NoProfile`, `-WindowStyle Hidden`, `-NonInteractive`) are informational only - every PowerShell started that way (IDE shells, scheduled scripts, win-debug itself) is listed but scores at most 2 points - while *strong* payload indicators (`-EncodedCommand`, `DownloadString`, `IEX`, `FromBase64String`, `scrobj.dll`, `certutil -decode`, `bitsadmin`, `curl`/`wget`, `http(s)://` URLs, `javascript:`/`vbscript:`, `mshta` with a URL) are the red flags.
- **Unsigned but legitimate:** indie games, Python/Node tooling, portable apps, self-built tools (2 points each for location and signature).
- **The monitor itself:** its `powershell.exe` is tagged `Self` and excluded; `WmiPrvSE.exe` (WMI provider host) shows 1-2 % CPU because of the sampling. Nobody should "find" the monitor.
- **Developer machines:** git, bash, python and conhost started dozens of times trigger the watchdog-restart indicator (4 points, below threshold).

## Command line reference

Launcher forms (the launcher pauses at the end except in monitor mode and prints `WinDebug exited with code N.` when non-zero):

```
WinDebug.cmd                                  interactive menu
WinDebug.cmd inventory|disk|monitor|analyze|all [options]
WinDebug.cmd -Mode Disk -Drives C -NoElevate   option-first form: everything is passed to WinDebug.ps1 unchanged
WinDebug.cmd -StopMonitor
WinDebug.cmd -InstallTask -IntervalSeconds 10
```

Direct: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\WinDebug.ps1 -Mode <Mode> [options]`. Full help: `Get-Help .\WinDebug.ps1 -Full`.

| Parameter | Meaning | Default |
|---|---|---|
| `-Mode Inventory\|Disk\|Monitor\|Analyze\|All\|Menu` | What to run. | `Menu` |
| `-OutputRoot <folder>` | Folder that receives one sub-folder per run. | `<script folder>\reports` |
| `-IntervalSeconds <5-3600>` | Monitor: seconds between samples. 5 s is a floor, not a recommendation. | `10` |
| `-DurationMinutes <0-100000>` | Monitor: stop after n minutes; 0 = run until STOP file, `-StopMonitor`, Q or Ctrl+C. | `0` |
| `-SessionPath <folder>` | Analyze: the monitor session to analyze. | newest `*_monitor` folder under OutputRoot |
| `-Drives C,D` | Disk: volumes to scan (`C`, `C:` and `C,D` are accepted). | all fixed volumes with a drive letter |
| `-TopN <5-500>` | Number of top items in Disk and Analyze reports. | `50` |
| `-Deep` | Optional slow steps: Inventory checks the Authenticode signature of every autostart binary (not only flagged ones) and lists all signed drivers; Disk de-duplicates hard links in `%windir%` (about 30 s extra). | off |
| `-NoElevate` | Never ask for administrator rights; run with the current rights. | |
| `-Elevate` | Relaunch elevated (UAC prompt) without asking. | |
| `-InstallTask` | Register the per-user logon task `WinDebug Monitor` (uses `-OutputRoot` and `-IntervalSeconds`), then exit. | |
| `-UninstallTask` | Remove the logon task, then exit. | |
| `-StopMonitor` | Ask every running monitor under OutputRoot to stop (creates its STOP file, waits up to 30 s), then exit: `Monitor stopped.` (0), `STOP signal sent; the monitor did not confirm within 30 s - check monitor.log.` (0) or `No running monitor found.` (3). | |
| `-TrackShortLived` | Monitor: also record short-lived processes via WMI process-creation events (misses processes living under 2 s). | off |
| `-Verbose` | Also show the tool's DEBUG lines on the console (they are always written to `run.log` / `analyze.log`); the monitor additionally logs one DEBUG line per collection step to `monitor.log`. | |

`-Elevated` is internal (set by the relaunched elevated copy). Analyze and Menu never ask for elevation; the menu offers it as item **A**. In the menu only **Q** (or Ctrl+C) quits; a bare Enter redraws the menu. Parameters are named only: a stray positional token (for example `D` from an unquoted `-Drives C,D` that `cmd.exe` split at the comma) is a binding error (exit code 1), never a silent `-OutputRoot`.

Exit codes (propagate to `%ERRORLEVEL%` through `WinDebug.cmd`):

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | Unhandled error or failed report export - see `run.log` or `analyze.log` in the report folder (partial files are preserved); also PowerShell's own parameter-binding errors (a non-numeric `-TopN`, a stray positional token) |
| 2 | Started from a network / UNC path - copy to a local folder |
| 3 | A monitor is already running under this OutputRoot (`-Mode Monitor`, refused before any folder is created), or no monitor to stop (`-StopMonitor`: `No running monitor found.`) |
| 4 | A file in `lib\` is missing - download the tool again as a whole |
| 5 | Invalid parameters (the usage text is printed): unknown `-Mode`, `-IntervalSeconds` / `-DurationMinutes` / `-TopN` out of range, Analyze session folder missing, not found under OutputRoot or not a monitor session (no `samples_*.csv`, `procs_*.csv` or `procsum.json` - the folder is left untouched), or the menu was started with redirected input |
| 6 | Logon task install/uninstall failed (for example `-UninstallTask` when the task does not exist) |

## What runs without administrator and what needs it

The tool never fails for lack of rights. Anything it could not read is marked `(requires administrator)` in the report and listed in the section **Skipped (requires administrator)** at the end of `summary.md` / `report.md`.

| Works without administrator | Needs administrator |
|---|---|
| Hardware, OS, updates, drivers, devices, installed programs, your own Store apps and autostart entries, services, scheduled tasks visible to you, Defender status and signature age, firewall/UAC/SmartScreen state, local accounts, network configuration, hosts file, battery report, Application/System/Defender/TaskScheduler/PowerShell event logs, performance snapshot | SMART / disk reliability counters, file-system dirty bit, Defender **exclusions**, scheduled tasks visible only to SYSTEM, the **Security** event log, Diagnostics-Performance boot-time events, Storport disk-latency events, `LiveKernelReports` and WER `ReportQueue` folders, Windows Search index size, Store apps and autostart entries of **other user accounts**, path and command line of other users' processes |
| Disk: your own profile, all top folders/files readable by you, cleanup candidates in your profile and in world-readable system folders, installed apps, Storage Sense settings | Disk: BitLocker status, `Windows\Temp` and `SystemTemp`, Prefetch, Windows Search index, Defender scan history, shadow storage / System Volume Information (restore points), other users' profiles, caches and Recycle Bins, the `WindowsApps` root |
| Monitor: CPU, GPU, memory, IO, threads/handles, TCP connections and DNS cache for **every** process; path, command line, owner, signature and SHA256 for your own processes; all event logs except Security | Monitor: path, command line, owner, signature and SHA256 of SYSTEM, service and other users' processes. The Security log (process creation 4688, task created 4698) is not polled by the monitor at all; a non-elevated run lists it under *Skipped (requires administrator)* |
| Analyze: everything (it only reads the session) | Analyze inherits the gaps of the session: indicators about location, signature, command line and parent chain show `?` for processes the monitor could not inspect |
| Logon task: installs with run level *Limited* (the monitor then runs non-admin at logon) | Logon task with run level *Highest*: install it from an elevated session |

Invalid or empty `-Drives` values are rejected with exit code 5 before creating a report folder. They never fall back to scanning all volumes.

## Privacy

The reports are meant to be read by the person who runs the tool. They contain personal data:

- computer name, `DOMAIN\user` name and SID of the user, OS build, whether the run was elevated;
- hardware serial numbers (disks; on laptops the battery in `battery-report.xml`, the raw `powercfg` report, together with **weeks of power-on / standby history**), MAC and IP addresses, DNS servers, active `hosts` entries, local account names;
- the list of installed programs and Store apps, autostart entries, scheduled task actions, service paths;
- every running process with its **full command line**: `processes-snapshot.csv` (Inventory), `procmeta.csv` / `procsum.json` (Monitor), `report.md` / `suspects.csv` / `process-summary.csv` / `analysis.json` (Analyze). Command lines may contain tokens or keys passed as arguments, so values that look like credentials (`password=...`, `--token x`, `PrivateKey = ...`, `"apikey": "..."`, `https://user:secret@host`, `?token=...`) are replaced by `***` before they are written; the key name stays, and mining-pool hosts and wallet addresses are deliberately left visible because they are the evidence. **The masking is a heuristic** (best effort): a secret passed in an unusual form still ends up in the files;
- Disk mode: profile names and paths, file names in Downloads, OneDrive folder names, **browser profile display names** (usually the signed-in account name), the **Outlook `.ost` file name** (= the mailbox address), game names;
- Monitor/Analyze: remote IP addresses and ports, DNS cache names, window presence, event-log excerpts (service install details, PowerShell script-block text up to 300 characters, masked the same way), SHA256 hashes of executables.

The first section of every `summary.md` / `report.md` repeats this in a one-line *Privacy* note. Nothing is uploaded or queried online - the tool makes no network connections at all; the VirusTotal links are plain URLs for you to open. The `reports\` folder is in `.gitignore`. Review the files before sharing them with anyone, and delete them when you are done.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `This folder is on a network/UNC path` or exit code 2 | The tool is on a share, a `\\server\...` or `\\wsl.localhost\...` path. Copy the folder to a local disk (`C:\Tools\win-debug`) and start it there. |
| `... is not digitally signed`, `AuthorizationManager check failed` | The files still carry the "downloaded from the Internet" mark (the ZIP was not unblocked) or are on a network path. Copy locally, then `Get-ChildItem -Recurse \| Unblock-File` in the folder. |
| PowerShell refuses to run the script although `WinDebug.cmd` passes `-ExecutionPolicy Bypass` | A Group Policy (`MachinePolicy` / `UserPolicy` in `Get-ExecutionPolicy -List`) enforces the execution policy; `Bypass` cannot override it. This happens on managed (corporate) PCs - ask the administrator. Home PCs are not affected. |
| Exit code 3, `A monitor is already running` | Only one monitor per reports folder. Stop it (`WinDebug.cmd -StopMonitor`) or wait; a `monitor.running` marker whose process no longer exists is ignored automatically. |
| Exit code 5 with the usage text instead of the menu | The menu needs a real console; when input is redirected (scheduler, remote shell) pass `-Mode` explicitly. |
| Exit code 5, `Not a monitor session (...)` or `No monitor session found under ...` | Analyze only accepts a folder that contains `samples_*.csv`, `procs_*.csv` or `procsum.json`; it refuses anything else without writing into it. Record a session first or pass `-SessionPath` to a real `*_monitor` folder. |
| Exit code 1, `A positional parameter cannot be found that accepts argument 'D'` | `cmd.exe` split an unquoted `-Drives C,D` at the comma. Quote it (`-Drives "C,D"`) or repeat the switch (`-Drives C -Drives D`); a stray token is rejected instead of being taken for `-OutputRoot`. |
| `STOP signal sent; the monitor did not confirm within 30 s` | The STOP file was written but the monitor did not finish within 30 s (long sample, PC under load). It stops at its next check; look at `monitor.log` in the session folder. Nothing else needs to be done. |
| `Missing ...\lib\...` / exit code 4 | Incomplete extraction; download the ZIP again and extract everything. |
| Inventory says performance counters are unavailable (`CPU-COUNTERS`), Monitor logs `Process performance counters returned no data`, or `run.json` shows `GpuCounterMode: none` while a real GPU is installed | The performance counter registry is corrupted. In an **elevated** command prompt run `lodctr /R` (twice if the first attempt reports an error), reboot, and run again. Per-process GPU counters also need a WDDM driver from the GPU vendor (not the Microsoft Basic Display Adapter). |
| A console window flashes for a fraction of a second at logon | That is the `WinDebug Monitor` task starting `powershell.exe -WindowStyle Hidden` - Windows shows the console briefly before hiding it. Harmless. |
| `WmiPrvSE.exe` and a `powershell.exe` use CPU while the monitor runs | That is the monitor: its own `powershell.exe` (a few percent of one core at the default interval, tagged `Self` and excluded from the reports) and the WMI provider host (1-2 %) that serves the performance counters. Use a longer `-IntervalSeconds` on very slow machines; 10 s is the default. |
| Monitor samples are flagged `Overrun` | The collection took longer than the interval - normal for the first two samples and during the first minute (signature/hash queue). Frequent overruns later mean the interval is too short for this PC. |
| Disk mode ends with `scan interrupted by Ctrl+C; partial totals discarded` | You pressed Ctrl+C during a volume walk. The walk stops within milliseconds and its partial totals are thrown away instead of being reported as facts; run Disk mode again (or `-Drives` for one volume) when the PC can be left alone. |
| Inventory finding `MEM-POOL` on a PC with WSL2 / Hyper-V, or `CPU-BUSY-IDLE` right after starting something heavy | Expected: virtualization and large GPU drivers use non-paged pool; the CPU rule cannot know whether you were idle during the snapshot. When a hypervisor is present (`HypervisorPresent`) or a `vmmem` / `vmmemWSL` process is running, `MEM-POOL` uses a 2.5 GB threshold and is reported as Info only. |
| Disk mode logs `Directory walker: .NET fallback` | The C# helper could not be compiled (read-only `%TEMP%`, missing .NET Framework compiler). The scan still works but is slower and the allocated size of compressed/sparse files is approximate. |
| Analyze: `insufficient data` in *Idle vs active* | The session lacks 20 samples in one of the two states. Record longer, covering both normal use and idle time. |

## How it works

- Pure Windows PowerShell 5.1 plus two C# sources compiled in memory with `Add-Type` (`lib\native\FastWalker.cs`: a `FindFirstFileEx` directory walker with allocated sizes and reparse-point awareness; `lib\native\Native.cs`: process owner from the token, user idle time via `GetLastInputInfo`, session lock state). No external binaries, no modules, no downloads.
- Data comes from CIM/WMI (`Get-CimInstance`, including the raw performance counter classes), the registry and .NET APIs. Localized command-line tools are never parsed; the only external programs executed are `schtasks.exe /query` (row count only) and `powercfg.exe /batteryreport` (writes into the report folder).
- Culture-invariant by design: the thread culture is switched to invariant and every number is formatted and parsed explicitly, so the files look the same on a Russian, German or English Windows.
- Read-only: the tool writes only into its report folder (plus, on explicit request, one per-user scheduled task). No deletions, no registry writes, no service changes, no cleanup actions.
- Every collection item is isolated: one failing WMI class or event log never aborts a run; the failure is listed under *Collection errors*.

## Project layout

```
win-debug\
  WinDebug.cmd              double-click launcher (ASCII, CRLF)
  WinDebug.ps1              entry point: parameters, menu, elevation, exit codes
  lib\
    Common.ps1              shared helpers (logging, CIM, CSV/JSON writers, findings) + rule data
    Inventory.ps1           Invoke-InventoryScan
    DiskUsage.ps1           Invoke-DiskScan
    Monitor.ps1             Start-ProcessMonitor, Stop-ProcessMonitor, Install-/Uninstall-MonitorTask
    Analyze.ps1             Invoke-MonitorAnalysis
    native\
      FastWalker.cs         P/Invoke directory walker (compiled at run time)
      Native.cs             process owner, idle time, session lock (compiled at run time)
  docs\
    ARCHITECTURE.md         conventions, Common.ps1 API, entry-point flow, decision log
    inventory-rules.md      every Inventory and Disk rule: condition, severity, admin requirement
    monitor-format.md       every monitor file and column
    analyze-scoring.md      every Analyze indicator, damping, thresholds, output columns
  tests\
    Invoke-Checks.ps1       repository self-check (syntax, encoding, aliases, verbs, banned APIs, source hygiene,
                            parameter/variable case collisions, rule ids vs docs, helper behaviour, exit codes)
  reports\                  output (gitignored)
```

## Contributing

Run `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-FunctionalChecks.ps1 -IncludeMonitor` from a local Windows checkout for runtime regressions and a short monitor/STOP/Analyze test. Both this suite and the repository self-check run automatically in GitHub Actions.

- Target is **Windows PowerShell 5.1** only: no PowerShell 7 syntax (`??`, `?.`, ternary, `-Parallel`), no external modules, no `Start-Job`/runspaces.
- No aliases (`?`, `%`, `select`, `gci`...), full parameter names, approved verbs, `[CmdletBinding()]` on every function, `-LiteralPath` everywhere.
- Never `Get-WmiObject`, `Get-Counter`, `Win32_Product`; never parse localized console output.
- Source encodings: `.ps1` and `.cs` are UTF-8 **with BOM** and CRLF; `WinDebug.cmd` is ASCII with CRLF; `.md`/`.json` are UTF-8 without BOM and LF (enforced by `.gitattributes`).
- Everything written to files must be culture-invariant (dot decimals, ISO timestamps) - use the helpers in `lib\Common.ps1`.
- The tool stays read-only on the machine and must degrade gracefully without administrator rights, marking gaps with the literal text `(requires administrator)`.
- Never start a bare `powershell.exe`: the launcher, the elevated relaunch and the logon task use the fully qualified Windows PowerShell 5.1 host (`$PSHOME\powershell.exe` / `%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe`); the self-check flags bare occurrences.
- Before a pull request run the self-check: `powershell -NoProfile -ExecutionPolicy Bypass -File tests\Invoke-Checks.ps1` (no Pester needed; exit code 1 on any failure). Besides syntax, encodings, aliases, verbs and banned APIs it checks source hygiene (`Write-Log` levels, bare `powershell.exe`, stale spec references), that no function assigns a local variable that differs from one of its parameters only by case (`$Path` vs `$path` are the same variable in PowerShell), that every `-RuleId` used in `lib\*.ps1` is documented in `docs\inventory-rules.md` or `docs\analyze-scoring.md` (a documented id no longer used in code is only a warning), the behaviour of the `lib\Common.ps1` helpers (rule regexes, location class, argument quoting, CSV guard, `Export-CsvInvariant -Columns`, `Hide-WdSecret`, admin skips versus collection errors, the privacy line) and the documented exit codes of `WinDebug.ps1` (the last group is skipped when the repository is on a UNC path). Run the tool itself from a local copy - it refuses UNC paths.
- Architecture, conventions and the shared API are described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). Rule data (regular expressions, port lists, trusted signers) lives in `lib\Common.ps1` and is shared by all modules; document every new rule id as a table row in the corresponding `docs\` file - the self-check fails on an undocumented one.

## License

MIT - see [LICENSE](LICENSE).

## Disclaimer

win-debug is a diagnostic aid, not an antivirus. It collects evidence and ranks it; it does not remove anything and it can be wrong in both directions. A `Highly suspicious` verdict deserves a VirusTotal lookup and a full offline scan with your antivirus; a `Nothing suspicious found` verdict means only that nothing in the recorded period behaved like a miner. Use the reports together with common sense, and keep in mind that they contain personal data.
