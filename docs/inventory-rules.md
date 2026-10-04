# Inventory and Disk findings rules

Every rule that `lib\Inventory.ps1` (mode `Inventory`) can emit as a finding in `summary.md` / `inventory.json`, plus
the Disk-mode rules of `lib\DiskUsage.ps1` (mode `Disk`, category `Disk`, last section of this document).
Findings have a severity (**Critical** = very likely the cause of the slowness or data at risk, **Warning** = contributes
or should be fixed, **Info** = context), a short title, a detail line built from the collected data and a recommendation.
Duplicate `RuleId` + title pairs are emitted once.

Column *Admin* says whether the rule needs administrator rights to fire at all. Everything else works for a standard
user; data that a standard user cannot read is marked `(requires administrator)` in the report and listed in the
section "Skipped (requires administrator)".

Thresholds are for a home PC. Values in the tables are the ones implemented; "SYS" = system drive / boot disk.
Shared rule data (regular expressions, trusted DNS servers, PUP names, pool ports, known debuggers) lives in
`lib\Common.ps1` (`$script:Rules`, see `docs\ARCHITECTURE.md`, section "Shared rule data").

**Secret masking.** Every free-text field that can carry a credential is passed through the shared helper
`Hide-WdSecret` (`lib\Common.ps1`) *before* it enters the data model, so `summary.md`, `inventory.json` and every CSV
show the same masked text: service `PathName`, scheduled-task actions and arguments, autostart commands (Run keys,
Startup folders, Active Setup, Winlogon values, IFEO debuggers, SilentProcessExit monitors, WMI consumer command
lines / script text), `UninstallString`, process command lines in `processes-snapshot.csv` and the PROC-* findings,
PowerShell-profile evidence, event sample messages (`events.csv`, 7045 image paths, Defender / SCM / reliability
messages). The key name is kept and the value becomes `***` (`PrivateKey = ***`, `--password ***`, `"token": "***"`,
`https://user:***@host`, `?token=***`). Rules always match the **original** text first (a masked value would hide a
miner argument); only the stored copy is masked. Mining-pool hosts, ports and wallet addresses are evidence and are
deliberately **not** masked.

**Suspicious locations** (`SuspiciousPathRegex`): `Temp\`/`Tmp\`, `AppData\Local\Temp\`, `AppData\Roaming\`,
`AppData\Local\` (except `Microsoft\WindowsApps` and `Programs`), `ProgramData\` (except `Microsoft\Windows Defender\Platform`,
`Microsoft\Windows\` and `Package Cache`), `Users\Public\`, `$Recycle.Bin`, and the **user-writable folders inside the
Windows directory**: `Windows\Temp\`, `PerfLogs\` and `Fonts\`. A program under `C:\Windows\Temp\` or `C:\Windows\Fonts\`
is therefore classified exactly like one in `%AppData%` (flag `SuspiciousPath`), even though its location class is
`Windows`. Every folder name carries its trailing backslash so that `Templates\`, `Tempo\` or `ProgramDataX\` do not match.
The regex is read at classification time, so a change in `lib\Common.ps1` flows into the autostart, service, task,
7045, process and Defender-exclusion rules without any change in `lib\Inventory.ps1`.

Sections run in the order System, CPU, Storage, Memory, GPU, Devices, Network, Battery, Software, Autostart, Security,
Events, Performance; Storage precedes Memory because MEM-PAGING needs the system disk media type. Every event-log query
is capped (20000 events for the System/Application error scans and WHEA, 10000 for application crashes / SCM / storage
ids / Defender events, 2000-5000 for the rest); a count that hit the cap is shown as `>= N` and the JSON section carries
a `...Capped = true` field.

## System & OS (category `System`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| SYS-REBOOT | `CBS\RebootPending` or `WindowsUpdate\Auto Update\RebootRequired` key exists | Warning | Restart (not Shut down) to finish updates. | no |
| SYS-UPTIME | Uptime > 14 days, or Fast Startup on and uptime > 7 days; also all boots of the last 14 days were fast-startup/hibernate resumes (Kernel-Boot 27) | Info | Do a real Restart. | no |
| SYS-EOL | Windows 11 build < 22631, Windows 10 build < 19045, or Windows 10 after 2025-10-14 | Warning | Install the latest feature update / upgrade. | no |
| SYS-BIOS-OLD | BIOS release date older than 3 years | Info | Check for a firmware update. | no |
| SYS-KMS | Non-domain PC with license channel `KMSCLIENT` or LicenseStatus <> Licensed | Warning | Possible activator tool (frequent miner carrier); check exclusions, tasks, services. | no |
| SYS-WU-OLD | Last successful update installation > 60 days (> 180 days: Critical) | Warning / Critical | Fix Windows Update, free disk space. | no |
| SYS-WU-BLOCK | `NotificationLevel=1`, policy `NoAutoUpdate=1`, WSUS `WUServer` or `DoNotConnectToWindowsUpdateInternetLocations=1` on a non-domain PC | Warning | Remove the update-blocking policies. | no |
| SYS-WU-PAUSED | Updates paused until a future date | Info | Resume updates. | no |
| SYS-WU-FAIL | The same update title failed (ResultCode 4) 3 or more times in the last 60 history entries | Warning | Investigate the failing KB. | no |
| SYS-TIME | W32Time `Type=NoSync`, or Time-Service events 129/36/131 in 14 days without any 35/37 | Warning | Sync the clock. | no |

## CPU (category `CPU`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| CPU-COUNTERS | `Win32_PerfFormattedData_Counters_ProcessorInformation` returned nothing | Info | Run `lodctr /R` as administrator. | no |
| CPU-THROTTLE | Average `PercentProcessorPerformance` < 60 while `PercentProcessorTime` > 50; or `PercentPerformanceLimit` < 80; or `PerformanceLimitFlags` <> 0; or thermal zone `PercentPassiveLimit` < 100 or `ThrottleReasons` <> 0 | Warning | Clean fans, thermal paste, original power adapter, battery health. | no |
| CPU-HOT | Plausible ACPI thermal zone temperature > 90 C during the snapshot (zones below 20 C are treated as bogus) | Warning | Overheating: clean dust, airflow, thermal paste. | no |
| CPU-BUSY-IDLE | Average total CPU > 40 % over the samples (the tool itself uses a few percent) | Warning | If the PC was idle, a background process burns CPU; see PROC-* findings. | no |
| CPU-INTR | Interrupt + DPC time > 10 % | Warning | Driver/interrupt storm: update network/audio/USB/GPU drivers. | no |
| CPU-CORES | `NumberOfEnabledCore` < `NumberOfCores` | Warning | Restore all cores (msconfig / BIOS). | no |
| CPU-OLD | CPU name matches Celeron/Pentium/Atom/Core 2/A4/A6/E1/E2, an Intel N-series part (Celeron/Pentium N2000-N6000, N50/N95/N97/N100/N200, Core i3-N3xx), or 2 or fewer logical processors | Info | CPU is the bottleneck; expectations / hardware upgrade. | no |
| CPU-VBS | HVCI (memory integrity) running and CPU name matches older generations (Intel Core 2000-7000 series, Ryzen 1000) | Info | Memory integrity costs 5-15 % on this CPU. | no |
| CPU-PLAN | Active power scheme GUID is Power saver (`a1841308-...`) | Warning | Switch to Balanced. | no |
| CPU-MAXSTATE | Processor maximum state (AC) < 100 % in the active scheme (user scheme key or `DefaultPowerSchemeValues`) | Warning | Restore 100 % and fix cooling instead. | no |
| CPU-FW-LIMIT | Kernel-Processor-Power event 37 present in 90 days | Warning | Firmware limits CPU speed; adapter, battery, BIOS. | no |

## Memory (category `Memory`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| MEM-LOW-CRIT | Installed RAM < 3.5 GB | Critical | Upgrade RAM. | no |
| MEM-LOW | Installed RAM 3.5-7.5 GB | Warning | 8 GB is the practical minimum. | no |
| MEM-SINGLE | One module, 2 or more slots, desktop chassis | Info | Second module for dual channel. | no |
| MEM-OLDTYPE | `SMBIOSMemoryType` DDR/DDR2/DDR3 | Info | Old platform. | no |
| MEM-XMP | `ConfiguredClockSpeed` < `Speed` | Info | Enable XMP/EXPO. | no |
| MEM-PRESSURE | Average AvailableMBytes < 10 % of RAM or < 1024 MB, or `PercentCommittedBytesInUse` > 90 | Warning | Memory exhausted; see top memory processes. | no |
| MEM-POOL | `PoolNonpagedBytes` > 10 % of RAM or > 1.5 GB. When a hypervisor is present (`Win32_ComputerSystem.HypervisorPresent`) or a `vmmem`/`vmmemWSL` process is running (Hyper-V, WSL2, Docker Desktop, Sandbox), only > 2.5 GB counts and the finding is Info | Warning (Info with a hypervisor) | Kernel driver memory leak; with WSL2/Hyper-V stop the VMs and compare. | no |
| MEM-NOPF | `Win32_PageFileUsage` empty and `PagingFiles` registry value empty | Warning | Re-enable a system-managed page file. | no |
| MEM-PAGING | Average PagesPersec > 1000 (SSD) / > 200 (HDD; the Storage section runs first so the media type is known), or page file PeakUsage > 2 x RAM | Warning | Heavy swapping: RAM shortage. | no |
| MEM-DIAG | MemoryDiagnostics-Results event 1202 in the last 90 days that is not followed by a passing run (1201), or WHEA-Logger ids 1/18/19/20/46/47 in 90 days | Critical | RAM/CPU hardware errors: memtest, remove overclock. | no |
| MEM-OOM | Resource-Exhaustion-Detector 2004 in 30 days (5 or more: Critical) | Warning / Critical | System ran out of memory; consumers listed. | no |

## GPU (category `GPU`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| GPU-NODRV | Every display adapter is a Microsoft Basic Display/Render adapter or a virtual adapter | Critical | Install the GPU driver. | no |
| GPU-ERR | `ConfigManagerErrorCode` <> 0 on a display adapter | Warning | Reinstall the GPU driver. | no |
| GPU-OLDDRV | Non-Microsoft display driver older than 3 years | Info | Update the GPU driver. | no |
| GPU-IGPU-LOWRAM | No discrete GPU detected and RAM < 7.5 GB | Warning | iGPU shares scarce RAM; add RAM. | no |
| GPU-BUSY | A process (not `dwm`, not in `KnownHeavyProcesses`) uses > 30 % on 3D/Compute engines in every GPU sample; Critical when its path matches `SuspiciousPathRegex`. Damping: when the binary is validly signed by a vendor in `TrustedSignerRegex` (Windows components, browsers, GPU vendor tools, Electron apps in AppData) the finding is Info with the signer named - GPU load alone never makes a trusted-signed binary a miner suspicion | Warning / Critical (Info for trusted-signed binaries) | Possible GPU miner; check path, signature, autostart, connections. | no |
| GPU-TOTAL-BUSY | Summed 3D/Compute utilization > 80 % | Warning | Something renders/computes heavily right now. | no |
| GPU-VRAM-FULL | `GPUAdapterMemory.DedicatedUsage` > 90 % of the largest registry `qwMemorySize` | Info | Close GPU-heavy applications. | no |

## Storage (category `Storage`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| STO-HDD | SYS disk effective media type HDD (`MediaType=HDD`, or Unspecified with `SpindleSpeed` > 0) | Critical | Clone Windows to an SSD (#1 cause). | no |
| STO-MEDIA-UNKNOWN | SYS disk media type cannot be determined | Info | Check the model manually. | no |
| STO-HEALTH | `Get-PhysicalDisk.HealthStatus` <> Healthy; SMART Wear > 95; SMART uncorrected read/write errors > 0 | Critical | Back up now, replace the disk. | partly (SMART) |
| STO-WEAR | SMART Wear 81-95 | Warning | Plan SSD replacement. | yes |
| STO-TEMP | SMART temperature > 65 C | Warning | Airflow / heatsink. | yes |
| STO-LAT-MAX | SMART Read/Write/FlushLatencyMax > 1000 ms | Warning | Cables, firmware, SMART. | yes |
| STO-USB-SYS | SYS disk BusType USB | Warning | Use an internal drive. | no |
| STO-MBR-UEFI | SYS disk MBR on UEFI firmware | Info | mbr2gpt (not a slowness cause). | no |
| STO-ALIGN | Partition offset not a multiple of 4096 on an SSD | Warning | Re-partition with alignment. | no |
| STO-FREE-CRIT | SYS volume free < 5 % or < 5 GB | Critical | Free space (Disk mode). | no |
| STO-FREE-WARN | SYS volume free < 10 % or < 20 GB | Warning | Clean up, Storage Sense. | no |
| STO-FS | SYS volume file system is not NTFS | Info | NTFS expected. | no |
| STO-VOL-HEALTH | Volume `HealthStatus` <> Healthy | Warning | chkdsk, SMART. | no |
| STO-TRIM | `DisableDeleteNotify=1` and SYS disk is SSD | Warning | `fsutil behavior set DisableDeleteNotify 0`. | no |
| STO-DIRTY | `Win32_Volume.DirtyBitSet` = True on the SYS volume | Warning | `chkdsk /f`. | yes |
| STO-LAT | Raw counters over the snapshot (`_Total`): ms/transfer > 5 (SSD) / > 25 (HDD) with > 50 transfers, or idle < 20 %, or average queue > 2 | Warning | Disk saturated/slow: top I/O processes, storage events, SMART. | no |
| STO-FRAG | HDD SYS volume `LastRunPercentFragmentation` > 10 (> 30: Critical) from `HKLM\SOFTWARE\Microsoft\Dfrg\Statistics` | Warning / Critical | Optimize Drives, enable ScheduledDefrag. | no |
| STO-FRAG-HW | Dfrg statistics `HardwareIssue` <> 0 | Warning | Check SMART and cables. | no |
| STO-DEFRAG-TASK | ScheduledDefrag task disabled or last run > 60 days | Info | Turn scheduled optimization on. | no |
| STO-BLENC | Shell property `System.Volume.BitLockerProtection` = 3 (encrypting) | Info | Wait for encryption to finish. | no |
| STO-HIBERFIL | `hiberfil.sys` present on a desktop whose SYS volume has < 10 % free | Info | `powercfg /h off` frees the space. | no |
| STO-SENSE | Storage Sense off and SYS free < 10 % | Info | Enable Storage Sense. | no |
| STO-EVT | System log ids 7/51 (disk) or 55 (Ntfs) from storage providers in 90 days | Critical | Bad blocks / corruption: back up, chkdsk, SMART, cable. | no |
| STO-RESET | Ids 11/129/153/157 from storage providers, 3 or more in 90 days | Warning | Controller resets: driver/firmware/cable/LPM. | no |
| STO-FLUSH | Ntfs ids 130/140 (flush / transaction log failures), 3 or more in 90 days | Warning | Disk stopped answering writes; check SMART/cables if SYS. | no |
| STO-LAT (events) | Storport/Operational ids 500/505, 10 or more in 30 days | Warning | Disk regularly takes seconds to answer. | yes (the log is readable only by administrators; marked `(requires administrator)` otherwise) |

## Devices & drivers (category `Devices`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| DEV-NODRV | Present device with `ConfigManagerErrorCode` 1/28/31/39 in classes Display, Net, System, HDC, SCSIAdapter, DiskDrive, Processor, USB, MEDIA, Bluetooth (or no class) | Warning | Install the missing driver. | no |
| DEV-FAIL | Present device with code 10/43/3/37/38; or Kernel-PnP event 219 for the same device 5 or more times in 14 days | Warning | Update/reinstall driver, check hardware. | no |
| DEV-DISABLED | Code 22 | Info | Fine if intentional. | no |
| DEV-UNSIGNED | Code 52, or `Win32_PnPSignedDriver.IsSigned` = False | Warning | Use a signed vendor driver. | no |
| DEV-OLD | Non-Microsoft driver of class DISPLAY/NET/SCSIADAPTER/HDC older than 4 years (aggregated into one finding) | Info | Update chipset/storage/network/GPU drivers. | no |

## Network (category `Network`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| NET-LINK | Connected wired adapter with `Speed` <= 100 Mbps whose name indicates a gigabit NIC | Warning | Replace the patch cable / port. | no |
| NET-WIFI | Connected Wi-Fi adapter with `ReceiveLinkSpeed` < 50 Mbps | Info | Weak Wi-Fi: "slow internet", not slow PC. | no |
| NET-VPNS | More than 3 third-party virtual adapters (`Get-NetAdapter Virtual=True` whose description and name do not match Microsoft/Hyper-V/WAN Miniport/Bluetooth/Loopback/Wi-Fi Direct/Kernel Debug/Teredo/ISATAP/6to4/IP-HTTPS/Npcap; adapters with a blank description are not counted); the detail lists exactly the counted adapters | Info | Remove unused VPN clients. | no |
| NET-NOGW | IP-enabled adapters but no default gateway | Info | Router/DHCP (not a PC slowness cause). | no |
| NET-DNS | DNS server that is not in `TrustedDnsServers`, not a gateway, not the DHCP server and not private/link-local/loopback (Info on domain-joined PCs) | Warning / Info | Possible DNS hijack; set DNS to automatic or a known resolver. | no |
| NET-PROXY | `ProxyEnable=1` with a server, or `AutoConfigURL` set (Info on domain-joined PCs) | Warning / Info | Remove proxy/PAC unless intentional. | no |
| NET-HOSTS | Critical: an active hosts entry for security/update infrastructure (windowsupdate, update.microsoft, msftconnecttest, Defender, antivirus vendors, virustotal, sberbank, paypal, smartscreen ...), or a broad vendor domain (microsoft.com, google.com, bing.com, apple.com, adobe.com, yandex, nvidia/amd/intel ...) redirected to a real IP. Warning: vendor domains pointed only at a block address (0.0.0.0, 127.0.0.1, ::1) - the shape of an ad/telemetry block list; Info when the file has more than 20 active entries | Critical / Warning / Info | Restore the default hosts file and scan (Critical); verify the block list was intentional (Warning/Info). | no |
| NET-HOSTS-MANY | More than 20 active hosts entries (emitted alongside NET-HOSTS) | Info | Large hosts file (ad-block list). | no |
| NET-ERR | `ReceivedPacketErrors` > 0.1 % of received packets (with > 10000 packets) | Warning | Cable/driver. | no |
| NET-POOL | Established connection to a remote port in `PoolPorts`, or a process from `SuspiciousPathRegex` with an external connection whose binary is not validly signed by a trusted vendor; Critical when both | Warning / Critical | Possible mining-pool / backdoor traffic. | no |
| NET-MANYCONN | Unknown process (path not readable) with > 20 external connections | Info | Re-run as administrator. | no |

## Battery (category `Battery`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| BAT-MISSING | Laptop chassis without `Win32_Battery` | Info | Battery removed/dead; some laptops throttle. | no |
| BAT-WORN | `FullChargeCapacity / DesignCapacity` < 50 % (from `powercfg /batteryreport /xml`) | Warning | Replace the battery (throttling under load). | no |
| BAT-WORN-INFO | 50-80 % | Info | Normal wear. | no |
| BAT-DC | The scan ran on battery power | Info | Judge performance while plugged in. | no |

## Software (category `Software`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| SW-PUP | Installed program name matches `PupNameRegex` (`PupInfoOnlyRegex`, e.g. CCleaner: Info) | Warning / Info | Uninstall optimizers/driver updaters/toolbars. | no |
| SW-RECENT | Programs with `InstallDate` in the last 30 days | Info | Correlate with when slowness began. | no |
| SW-SIDELOAD | Appx packages with `SignatureKind` None/Developer from non-Microsoft publishers (one aggregated finding) | Info | Check unknown ones. | no |
| SW-APPX-MANY | More than 300 Store apps for the user | Info | Uninstall unused apps. | no |
| SW-DOTNET-OLD | .NET Framework Release < 461808 (4.7.2) | Info | Install .NET 4.8. | no |

## Autostart & persistence (category `Autostart`)

Every Run/RunOnce/Policies/Winlogon-Load entry, Startup-folder item (shortcut targets resolved), Active Setup stub,
scheduled-task action, service path and 7045-installed service is split into executable + arguments (unquoted command
lines are resolved the way CreateProcess does: the first whitespace boundary whose prefix exists on disk, also with
`.exe` appended, wins), expanded and classified: location class (`Get-ProcessLocationClass`), `SuspiciousPathRegex`
(path and arguments), `ScriptHostRegex` with `ScriptHostStrongArgRegex` (flags `RedFlagArgs;StrongRedFlagArgs`) and
`ScriptHostWeakArgRegex` (flag `WeakRedFlagArgs`, informational only), `MinerTokenRegex`, system binary names outside
their expected folder, script file extensions, missing files. The two script-host argument classes are the shared
rule keys from `lib\Common.ps1` and Inventory keeps no private copy of them: **weak** flags are the launch options
every legitimate installer or scheduled script also uses (`-ExecutionPolicy Bypass`, `-NoProfile`, `-WindowStyle
Hidden`, `-NonInteractive`) and never make an entry suspicious or escalate a task; **strong** flags are payload
delivery (`-EncodedCommand`/`-enc`, `DownloadString`/`DownloadFile`, `IEX`, `FromBase64String`, `scrobj.dll`,
`urlcache`, `certutil -decode`, `bitsadmin`, `curl`/`wget`, `http(s)://` URLs, `javascript:`/`vbscript:`) and make a
script-host entry suspicious on their own (Warning) or, in a scheduled task running PowerShell, Critical. A validly signed binary of a vendor in
`TrustedSignerRegex` is not suspicious even in AppData (flag `SignedTrusted`). For a script host / LOLBin (rundll32,
regsvr32, wscript, cscript, cmd, powershell, mshta ...) the trusted signature belongs to the Windows host, so a
suspicious path in the arguments stays suspicious unless the payload itself is validly signed by a trusted vendor
(flags `PayloadSignedTrusted`, `PayloadSigned`, `PayloadUnsigned`, `PayloadScript`, `PayloadMissing`). Signatures are
checked for suspicious entries always and for every entry with `-Deep`.

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| AUT-SUSP | Run/Startup/Active Setup entry, scheduled task or service classified suspicious: suspicious path (unsigned or unknown signer), suspicious path in the arguments of a script host / LOLBin whose payload is not trusted-signed (`rundll32.exe %AppData%\x.dll,Run`, `cmd.exe /c %Temp%\x.bat`, `wscript.exe %AppData%\x.vbs`), miner token, system binary name outside System32, script host with strong red-flag arguments (encoded command, download, IEX, base64, scrobj, urlcache, URL...), network path; script files in Startup folders. Services are reported regardless of whether the host image lives in the Windows folder. A scheduled task that runs wscript/cscript with a script outside suspicious locations is reported with the wording "runs a user script" plus the script path and location (flag `UserScript`). Weak flags alone (`-ExecutionPolicy Bypass`, `-NoProfile`, `-WindowStyle Hidden`, `-NonInteractive`) are only recorded in the `Flags` column (`WeakRedFlagArgs`) | Warning | Verify publisher, remove entry and file. | no |
| AUT-MANY | More than 15 enabled autostart entries (Run keys + Startup folders, Task Manager disabled state honoured) | Info | Disable unneeded startup apps. | no |
| AUT-HIDDEN-TASK | Task with `Settings.Hidden=True` whose action is not a Windows binary (outside `\Microsoft\`, or inside `\Microsoft\*` with an executable action that is neither under `%SystemRoot%` nor Microsoft-signed; COM-handler actions are exempt) and whose binary is not validly signed by a trusted vendor; a task action running mshta; PowerShell with strong red-flag arguments (`ScriptHostStrongArgRegex`: encoded command, download, IEX, base64 ...; weak flags such as `-ExecutionPolicy Bypass -WindowStyle Hidden` alone never escalate); wscript/cscript with a script in a suspicious location (for wscript/cscript the script file, not the host, is the binary that is checked). A hidden task whose binary is signed by a vendor in `TrustedSignerRegex` is reported as Info instead | Critical (Info for vendor-signed hidden tasks) | Hidden/script task = miner persistence. | no |
| AUT-TASKS-PARTIAL | `schtasks /query` lists more tasks than `Get-ScheduledTask` returns (tasks readable only by SYSTEM) | Info | Re-run as administrator. | no (fires only non-admin) |
| AUT-WINLOGON | `Shell` <> explorer.exe, extra `Userinit` entries, HKCU Shell/Userinit present, `AppInit_DLLs` set with `LoadAppInit_DLLs=1` | Critical | Logon hijack; restore values, full scan. | no |
| AUT-IFEO | IFEO `Debugger` value whose executable is not in `KnownDebuggers`; SilentProcessExit `MonitorProcess` that is suspicious or a script host | Critical | IFEO hijack (Task Manager/AV replaced). | no |
| AUT-WMI | Any `__EventFilter` other than "SCM Event Log Filter", any binding not to the SCM consumer, any CommandLine/ActiveScript consumer in root\subscription | Critical | WMI persistence (fileless). | no |
| AUT-PSPROFILE | A PowerShell profile contains strong script-host indicators (`ScriptHostStrongArgRegex`), miner tokens or suspicious paths. Profile text is never copied into the report (profiles often hold API keys as environment variables); only the matched token of each rule that fired is recorded (`Evidence`, passed through `Hide-WdSecret` so key/token/secret/password values become `***`) | Warning | Review the profile. | no |
| AUT-PSPROFILE-ALLUSERS | An AllUsers profile exists on a non-domain PC | Info | Check its content. | no |
| AUT-LSA | LSA Authentication/Notification/Security Packages contain non-default names | Warning | Verify the DLL (credential theft vector). | no |
| SVC-UNQUOTED | Non-Windows service path with spaces and no quotes | Info | Vendor should quote the path. | no |
| SVC-DIS | Core service disabled: WinDefend (unless a third-party AV is installed), MpsSvc, Schedule, EventLog = Critical; DPS = Warning; wuauserv = Info. Not running (not disabled) = Warning | Critical / Warning / Info | Re-enable, full scan. | no |
| SVC-SYSMAIN | SysMain or WSearch disabled / not running on an HDD system | Warning | Re-enable them. | no |

## Security (category `Security`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| SEC-NOAV | Defender `RealTimeProtectionEnabled=False` or running mode Passive/Off with no other enabled AV in SecurityCenter2; Defender status unavailable and no other AV; Defender disabled by policy (`DisableAntiSpyware`, `DisableAntiVirus`, `DisableRealtimeMonitoring`) | Critical | Enable real-time protection; offline scan if it turns off again. | no |
| SEC-2AV | Two or more enabled `AntiVirusProduct` entries in SecurityCenter2 | Warning | Keep one antivirus. | no |
| SEC-SIG | Defender signature age > 7 days (> 30: Critical); SecurityCenter2 product enabled but not up to date | Warning / Critical | Update definitions. | no |
| SEC-TAMPER | `IsTamperProtected=False` (no third-party AV) | Warning | Enable tamper protection. | no |
| SEC-SCAN-OLD | `QuickScanAge` > 30 days | Info | Run a scan. | no |
| SEC-PUA | `PUAProtection=0` | Info | Enable PUA blocking. | no |
| SEC-EXCL | Exclusion covering a drive root, Windows/Users/Program Files, Temp/AppData/ProgramData, `*.exe`/`*.dll`/script extensions, system binaries (powershell, svchost, explorer, rundll32, wscript, cscript, mshta, cmd), a path matching `SuspiciousPathRegex`, or the folder of a running process from a suspicious location | Critical | Remove planted exclusions, full offline scan. | yes |
| SEC-EXCL-ANY | Any exclusion configured | Warning | Review exclusions. | yes |
| SEC-EXCL-NA | Exclusions not readable | Info | Re-run as administrator. | no (fires only non-admin) |
| SEC-EXCL-CHANGED | Defender event 5007 whose data mentions `\Exclusions\`, `DisableRealtimeMonitoring` or `DisableAntiSpyware` in 30 days | Warning | Review who changed exclusions. | no |
| SEC-MINER-HIST | Threat detection in 90 days whose ThreatName matches Miner/XMRig/CoinMiner/Crypto | Critical | Verify removal, check persistence. | no |
| SEC-THREAT-ACTIVE | `MSFT_MpThreat.IsActive=True` | Critical | Remove threats, full scan. | no |
| SEC-PUA-HIST | Detections whose ThreatName starts with `PUA` | Info | Check installed programs. | no |
| SEC-RTP-EVT | Defender event 5001 (real-time protection off) without a later 5000 and RTP currently off | Critical | Re-enable; the disabling program is the malware. | no |
| SEC-RTP-TOGGLE | 3 or more 5001 events in 30 days | Warning | Frequent toggling is suspicious. | no |
| SEC-FW | Firewall profile `EnableFirewall=0` (policy or local) without a third-party firewall; Info when only the Domain profile on a domain-joined PC | Warning / Info | Enable the firewall. | no |
| SEC-UAC | `EnableLUA=0` | Critical | Re-enable UAC. | no |
| SEC-UAC-WEAK | `ConsentPromptBehaviorAdmin=0` or `PromptOnSecureDesktop=0` | Warning | Restore default UAC level. | no |
| SEC-SS | `SmartScreenEnabled=Off` or policy `EnableSmartScreen=0` | Warning | Enable SmartScreen. | no |
| SEC-ACCT | Enabled local account with `PasswordRequired=False` (except Guest RID 501); more than 2 enabled local administrators on a non-domain PC | Warning | Review accounts. | no |
| SEC-ACCT-ADMIN500 | Built-in Administrator (RID 500) enabled | Info | Disable unless needed. | no |
| SEC-ACCT-EVT | Security log 4720/4732/4728/4756 in 90 days | Warning | Verify account changes. | yes |

Note: `Get-LocalGroupMember` (Administrators membership) is skipped on domain-joined PCs because resolving domain
SIDs can take 30 s or more when the domain controller is unreachable.

## Event logs (category `Events`)

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| EVT-NOISY | Provider with > 50 errors/criticals in 14 days that is not in `NoisyEventProviders` (newest 20000 events per log are analysed) | Info | Check the component. | no |
| PWR-41 | Kernel-Power 41 with BugcheckCode <> 0, or WER-SystemErrorReporting 1001, in 90 days (3 or more: Critical) | Warning / Critical | Analyse minidumps; drivers/RAM/heat/disk. | no |
| PWR-41-0 | Kernel-Power 41 with BugcheckCode 0, 3 or more in 90 days | Warning | Hard power-offs: PSU/heat/forced shutdowns. | no |
| WHEA-17 | WHEA-Logger 17 (corrected PCIe) > 100 in 90 days | Info | Update drivers/firmware, reseat cards. | no |
| BOOT-SLOW | Diagnostics-Performance 100 `BootTime` (event property 5; `MainPathBootTime` = 6, `BootPostBootTime` = 19) > 120 s (SSD) / > 300 s (HDD) for at least half of the boots in 30 days | Warning | Reduce autostart; SSD. | yes |
| APP-CRASH | Application Error 1000: same application 5 or more times in 14 days, or explorer/dwm/svchost/lsass/services/winlogon/csrss 2 or more | Warning | Update/reinstall; suspect RAM/disk/hooks for system processes. | no |
| APP-HANG | Application Hang 1002, 5 or more in 14 days | Warning | Disk/RAM/driver. | no |
| SVC-TIMEOUT | SCM 7009/7011/7022, 3 or more in 14 days | Warning | Services time out at boot. | no |
| SVC-CRASH | SCM 7031/7034 for the same service, 3 or more in 14 days | Warning | Service crashing. | no |
| SVC-NEW | SCM 7045 (service installed) in 90 days whose image path is suspicious or a script host (powershell/cmd/mshta/wscript/cscript); the image path is matched unmasked and reported secret-masked | Critical | Malicious service installed. | no |
| DMP-PRESENT | Minidump files or LiveKernelReports WATCHDOG dumps newer than 90 days | Warning | Kernel crashes recorded. | no (LiveKernelReports needs admin) |
| DMP-DISABLED | `CrashControl\CrashDumpEnabled=0` | Info | Enable automatic memory dump. | no |
| REL-LOW | Latest `SystemStabilityIndex` < 5 (< 3: Critical) | Warning / Critical | Reliability Monitor timeline. | no |

## Performance snapshot (category `Performance`)

Two `Win32_PerfFormattedData_PerfProc_Process` samples taken before and after five counter samples 750 ms apart
(typically 4-8 s apart on a PC with ~1000 processes; the measured spacing is written to `summary.md` and to
`Performance.SampleIntervalSeconds` in `inventory.json`); CPU percentages are divided by the number of logical
processors. Process paths and command lines come from `Win32_Process` (null for other users' processes without
administrator rights); owners come from the `Win32_LoggedOnUser` / `Win32_SessionProcess` associations. Command lines
are secret-masked (`Hide-WdSecret`) after the miner-token rule has seen the original.

Process classification uses the same shared rule data as the Autostart section: `SuspiciousPathRegex` on the
executable path (flag `SuspiciousPath`), `MinerTokenRegex` on path + command line (`MinerToken`), `SystemBinaryNames`
outside their expected folder (`SystemNameOutsideSystem32`), `svchost` with a parent other than `services.exe`
(`UnexpectedParent:<name>`). Damping for the CPU rules: a process in `KnownHeavyProcesses` never produces PROC-CPU or
PROC-MINER, and a binary validly signed by a vendor in `TrustedSignerRegex` (flag `SignedTrusted`, checked only for
the processes that cross the CPU threshold) is never a Critical miner suspicion by CPU plus location alone. A miner
token is never damped.

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| PROC-COUNT | More than 400 processes | Info | Review autostart and software. | no |
| PROC-CPU | Process with >= 25 % CPU in both samples, not in `KnownHeavyProcesses`, not this tool | Warning | Background CPU hog; identify, update, uninstall; Monitor mode. | no |
| PROC-MINER | >= 25 % CPU in both samples plus suspicious path, miner token in path/command line, or system binary name outside System32. Damped to Info ("Sustained CPU from an unusual location, damped") with the reason in the detail when there is no miner token and the process is in `KnownHeavyProcesses` or its binary is validly signed by a vendor in `TrustedSignerRegex` (Discord/Spotify/Teams updaters in AppData) | Critical (Info when damped) | Probable crypto-miner; kill, remove persistence, full scan. | no |
| PROC-DEFENDER | MsMpEng >= 25 % in both samples | Info | Defender scan in progress. | no |
| PROC-SERVICING | TiWorker/TrustedInstaller/MoUsoCoreWorker/UsoClient/wuauclt >= 25 % in both samples | Info | Windows Update servicing. | no |
| IDX-BUSY | SearchIndexer/SearchProtocolHost/SearchFilterHost >= 25 % in both samples | Info | Indexing in progress. | no |
| IDX-LARGE | Windows.edb/Windows.db > 5 GB | Info | Rebuild the index. | yes (file not readable otherwise) |
| PROC-MEM | One process private working set > 25 % of RAM | Warning | Restart it / memory leak. | no |
| PROC-LEAK | HandleCount > 50000 or ThreadCount > 2000 | Warning | Handle/thread leak. | no |
| PROC-PARENT | svchost.exe whose parent is not services.exe (parent visible) | Warning | Fake svchost disguise. | no |
| PROC-FAKE-SYS | Process named like a Windows system binary running outside its expected folder | Warning | Verify signature. | no |
| SYNC-BUSY | OneDrive > 25 % CPU | Info | Sync in progress. | no |
| SYS-TWEAKS | `SystemResponsiveness` <> 20 or `NetworkThrottlingIndex` <> 10 | Info | Traces of tweak tools. | no |

Each Events sub-step (12.1 errors by provider ... 12.13 Security log) runs in its own `Invoke-Safely`: a failing query
or a malformed event is logged as a collection error and the other sub-steps, `events.csv` and the section JSON are
still produced.

## Data that needs administrator rights

Listed in `summary.md` under "Skipped (requires administrator)" when the run is not elevated:
SMART/reliability counters, file-system dirty bit, Defender exclusions, scheduled tasks readable only by SYSTEM
(count difference `schtasks` vs `Get-ScheduledTask`), Security event log, Diagnostics-Performance boot events,
Storport/Operational latency events, `LiveKernelReports` and WER `ReportQueue` folders, Windows Search index file
size, Store apps of other users, autostart entries of other user accounts, and executable paths / command lines of
other users' processes.

## Disk usage (category `Disk`, `lib\DiskUsage.ps1`, mode `Disk`)

Emitted by the Disk mode into its `summary.md` / `disk-usage.json`. "Safe" cleanup candidates are temporary files,
caches and the Recycle Bin; "Review"/"Risky" candidates are only reported. Nothing is deleted by the tool.

| RuleId | Condition | Severity | Recommendation (short) | Admin |
|---|---|---|---|---|
| DSK-VOL-UNKNOWN | Lettered volume whose capacity / file system `Win32_Volume` cannot report (BitLocker locked or not formatted); the volume is not scanned | Info | Unlock the drive (BitLocker) or check it in Disk Management. | no |
| DSK-FULL-CRIT | Volume with a drive letter has < 5 % or < 5 GB free | Critical | Free space now (Safe candidates first), move large personal files. | no |
| DSK-FULL-WARN | Volume with a drive letter has < 10 % or < 20 GB free | Warning | Review the cleanup candidates; keep 10-15 % free on an SSD. | no |
| DSK-VOL-COMPRESSED | NTFS compression enabled at volume level | Info | Consider disabling volume compression (CPU cost on a slow PC). | no |
| DSK-WINDOWS-OLD | `Windows.old` exists and is not empty | Info | Settings > Storage > Temporary files > Previous Windows installation(s). | no |
| DSK-PAGEFILE-LARGE | Page files > 8 GB, more than 3 x the peak usage since boot and larger than RAM | Info | Set a fixed initial size or free space elsewhere. | no |
| DSK-MSI-ORPHANS | `Windows\Installer` holds > 1 GB of .msi/.msp packages referenced by no installed product or patch | Info | No built-in cleanup; do not delete by hand. | no |
| DSK-VHDX-LARGE | WSL/Docker virtual disks (.vhdx/.vhd/.avhdx/.qcow2/.img) > 20 GB in total | Info | Clean inside WSL/Docker, then compact the .vhdx. | no |
| DSK-DOWNLOADS-OLD | Downloads contains > 5 GB of files older than one year | Info | Delete finished installers/archives. | no |
| DSK-SAFE-SAVINGS | Safe cleanup candidates total >= 1 GB (>= 10 GB: Warning) | Info / Warning | Storage > Temporary files, empty Recycle Bin, clear browser caches. | no |
| DSK-RECYCLE-BIN | Recycle Bin > 1 GB | Info | Empty the Recycle Bin. | no |
| DSK-TEMP-LARGE | User temp folders hold > 2 GB of files older than one day | Info | Storage > Temporary files or cleanmgr. | no |
| DSK-HIBERFIL | `hiberfil.sys` > 4 GB while the system volume is below the free-space thresholds | Info | `powercfg /h off` or `/h /type reduced`. | no |
| DSK-BROWSER-CACHE | Chromium-family and Firefox caches of readable profiles > 2 GB in total | Info | Clear cached images and files with the browsers closed. | no |
| DSK-OLD-PROFILES | User profiles not used for more than 90 days | Info | Remove through System Properties > User Profiles. | no (sizes of other profiles need admin) |
| DSK-FOLDER-REDIRECTED | Known folders (Documents, Desktop, Downloads ...) redirected to a network or removable location; they were not measured (first 8 paths listed) | Info | Redirected folders do not occupy this PC's disks; their size is not part of the report. | no |
| DSK-STORAGESENSE-OFF | Storage Sense disabled while the system volume is below the free-space thresholds | Info | Turn Storage Sense on. | no |
| DSK-SCAN-RATIO | Scanned bytes vs. volume used bytes ratio < 0.7 or > 1.15 (unreadable folders, shadow copies, hard links, MFT) | Info | Run as administrator for a complete picture. | no |
| DSK-DENIED | Folders were not readable without administrator rights | Info | Re-run as administrator. | no (fires only non-admin) |
