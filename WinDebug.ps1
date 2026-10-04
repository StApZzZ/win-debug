#Requires -Version 5.1

<#
.SYNOPSIS
    Read-only Windows diagnostics: inventory, disk usage, background process monitor, analysis.

.DESCRIPTION
    win-debug collects diagnostic data from a Windows 10/11 PC that "became slow" and writes it
    into a report folder under .\reports (one folder per run). It never changes the machine:
    no deletions, no registry writes, no service changes. The only optional change is a per-user
    scheduled task ("WinDebug Monitor") that is created on explicit request with -InstallTask.

    Modes:
      Inventory  Hardware, OS, drivers, installed software, autostart, security state and recent
                 event log entries, plus rule-based findings (summary.md, inventory.json, CSV files).
      Disk       Disk usage per volume: largest folders and files, cleanup candidates with a safety
                 class. Report only, nothing is deleted.
      Monitor    Background sampler: per-process CPU/GPU/memory/IO/network and system totals written
                 continuously to CSV files until stopped (STOP file, -StopMonitor, Ctrl+C or -DurationMinutes).
      Analyze    Turns a recorded monitor session into report.md with a suspicion ranking.
      All        Inventory followed by Disk (two report folders).
      Menu       Interactive text menu (default when double-clicking WinDebug.cmd).

    Administrator rights are optional. Without them the tool still runs and states in every report
    what was skipped, marked with the text "(requires administrator)".

    Privacy: reports contain personal data (computer and user names, serial numbers, MAC/IP addresses,
    installed programs, running processes with command lines, event log excerpts, battery-report.xml
    (laptops) with weeks of power-on/standby history). Nothing is uploaded; everything stays in the
    reports folder. Secrets on command lines are masked best-effort. Review before sharing.

.PARAMETER Mode
    Inventory, Disk, Monitor, Analyze, All or Menu (default).
.PARAMETER OutputRoot
    Folder that receives one sub-folder per run. Default: <script folder>\reports.
.PARAMETER IntervalSeconds
    Monitor: seconds between samples (5-3600, default 10).
.PARAMETER DurationMinutes
    Monitor: stop after this many minutes; 0 (default) = run until STOP file, -StopMonitor or Ctrl+C.
.PARAMETER SessionPath
    Analyze: a monitor session folder. Default: the newest *_monitor folder under OutputRoot.
.PARAMETER Drives
    Disk: drive letters to scan (for example -Drives C,D or -Drives C -Drives D). Default: all fixed volumes.
.PARAMETER TopN
    Number of top items in Disk and Analyze reports (5-500, default 50).
.PARAMETER InstallTask
    Register the per-user logon task "WinDebug Monitor" that starts the monitor at logon, then exit.
.PARAMETER UninstallTask
    Remove the logon task "WinDebug Monitor", then exit.
.PARAMETER StopMonitor
    Ask every running monitor under OutputRoot to stop (creates its STOP file), then exit.
.PARAMETER Deep
    Enable optional slow steps: Inventory checks the Authenticode signature of every autostart entry (not only
    flagged ones) and lists all signed drivers; Disk de-duplicates hard links in the Windows folder (about 30 s extra).
.PARAMETER NoElevate
    Never ask for administrator rights; run with the current rights.
.PARAMETER Elevate
    Relaunch elevated (UAC prompt) without asking.
.PARAMETER Elevated
    Internal: set by the relaunched elevated copy.
.PARAMETER TrackShortLived
    Monitor: also record short-lived processes via WMI process-creation events (optional).

.EXAMPLE
    .\WinDebug.ps1 -Mode Inventory
.EXAMPLE
    .\WinDebug.ps1 -Mode Disk -Drives C -TopN 100
.EXAMPLE
    .\WinDebug.ps1 -Mode Monitor -IntervalSeconds 10 -DurationMinutes 480
.EXAMPLE
    .\WinDebug.ps1 -Mode Analyze -SessionPath .\reports\PC_20260927-210000_monitor
.EXAMPLE
    .\WinDebug.ps1 -InstallTask
.EXAMPLE
    .\WinDebug.ps1 -StopMonitor

.NOTES
    Windows PowerShell 5.1, Windows 10/11 x64, MIT license. Read-only. Reports contain personal data.
    -Verbose (common parameter) shows the tool's DEBUG lines on the console (they are always written to the
    log files); the monitor additionally logs one DEBUG line per collection step. PowerShell's own verbose
    stream (module imports, Get-WinEvent query details) stays silent.
    Exit codes: 0 ok, 1 unhandled error (also PowerShell binding errors: a non-numeric -TopN, a stray positional
    argument), 2 network/UNC location, 3 monitor already running or none to stop, 4 missing lib file,
    5 invalid parameters (unknown -Mode, -IntervalSeconds/-DurationMinutes/-TopN out of range, session folder
    missing or not a monitor session, menu without a console), 6 task install/uninstall failed.
#>
# PositionalBinding = $false: a stray token (e.g. "D" from an unquoted "-Drives C,D" split by cmd.exe) fails
# with a clear binding error instead of silently becoming -OutputRoot. Mode and ranges are validated in the
# body so that a wrong value prints the usage and exits 5 as documented (attributes would exit 1 before the body runs).
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Mode = 'Menu',
    [string]$OutputRoot,
    [int]$IntervalSeconds = 10,
    [int]$DurationMinutes = 0,
    [string]$SessionPath,
    [string[]]$Drives,
    [int]$TopN = 50,
    [switch]$InstallTask,
    [switch]$UninstallTask,
    [switch]$StopMonitor,
    [switch]$Deep,
    [switch]$NoElevate,
    [switch]$Elevate,
    [switch]$Elevated,
    [switch]$TrackShortLived
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

$toolVersion = '1.0.0'
$root = $PSScriptRoot
if ([string]::IsNullOrEmpty($root)) { try { $root = (Get-Location).ProviderPath } catch { $root = [Environment]::CurrentDirectory } }

# 1. Refuse network / UNC locations (scripts land in the Internet zone, cmd.exe cannot cd to UNC).
if ($root.StartsWith('\\')) {
    Write-Host 'win-debug cannot run from a network (UNC) path.' -ForegroundColor Red
    Write-Host 'Run from a local folder (copy win-debug to e.g. C:\Tools\win-debug) and start it again.' -ForegroundColor Yellow
    exit 2
}

# 2. Dot-source the library. Common.ps1 first, then the modules.
$libFiles = @('Common.ps1', 'Inventory.ps1', 'DiskUsage.ps1', 'Monitor.ps1', 'Analyze.ps1')
foreach ($libName in $libFiles) {
    $libPath = [IO.Path]::Combine([IO.Path]::Combine($root, 'lib'), $libName)
    if (-not (Test-Path -LiteralPath $libPath)) {
        Write-Host ('Missing {0}' -f $libPath) -ForegroundColor Red
        Write-Host 'The lib folder is incomplete. Download win-debug again as a whole.' -ForegroundColor Yellow
        exit 4
    }
}
foreach ($libName in $libFiles) {
    . ([IO.Path]::Combine([IO.Path]::Combine($root, 'lib'), $libName))
}

# 3. Initialize shared state.
Initialize-Common -ToolVersion $toolVersion
$script:VerboseLog = $PSBoundParameters.ContainsKey('Verbose')
# -Verbose only enables the tool's own DEBUG lines. Left at 'Continue' it would flood the console with hundreds of
# "VERBOSE: Exporting ..." lines from module auto-import (Storage, NetAdapter, ScheduledTasks, Defender) and
# Get-WinEvent query details.
$VerbosePreference = 'SilentlyContinue'
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = [IO.Path]::Combine($root, 'reports')
} else {
    $OutputRoot = Resolve-PathSafe -Path $OutputRoot
}
# -Drives "C,D" (as passed by the elevated relaunch or a .cmd) is normalized into separate letters.
$driveError = ''
if ($null -ne $Drives -and $Drives.Count -gt 0) {
    $normalized = New-Object 'System.Collections.Generic.List[string]'
    foreach ($d in $Drives) {
        if ($null -eq $d) { continue }
        foreach ($part in ([string]$d).Split(@(',', ';', ' '), [StringSplitOptions]::RemoveEmptyEntries)) {
            $letter = $part.Trim().TrimEnd('\').TrimEnd(':').ToUpperInvariant()
            if ($letter -notmatch '^[A-Z]$') { $driveError = '-Drives must contain drive letters (for example C,D or C:).'; continue }
            if (-not $normalized.Contains($letter)) { $normalized.Add($letter) }
        }
    }
    $Drives = $normalized.ToArray()
}
if ($PSBoundParameters.ContainsKey('Drives') -and @($Drives).Count -eq 0) { $driveError = '-Drives must contain at least one drive letter.' }
$inputRedirected = $true
try { $inputRedirected = [Console]::IsInputRedirected } catch { $inputRedirected = $true }
# Bound parameters of THIS script (inside functions $PSBoundParameters would be the function's own).
$script:EntryBoundParameters = @{}
foreach ($bpKey in @($PSBoundParameters.Keys)) { $script:EntryBoundParameters[$bpKey] = $PSBoundParameters[$bpKey] }
# The elevated relaunch starts with -WorkingDirectory $PSScriptRoot, so forward RESOLVED paths, not the raw
# (possibly relative) text the user typed; otherwise ".\out" lands in the tool folder in the elevated run.
$script:EntryBoundParameters['OutputRoot'] = $OutputRoot
if (-not [string]::IsNullOrWhiteSpace($SessionPath)) {
    $SessionPath = Resolve-PathSafe -Path $SessionPath
    $script:EntryBoundParameters['SessionPath'] = $SessionPath
}
if ($script:EntryBoundParameters.ContainsKey('Drives')) { $script:EntryBoundParameters['Drives'] = $Drives }

# ---------------------------------------------------------------------------------------------
# Entry-point helpers (private, prefix Wd)
# ---------------------------------------------------------------------------------------------
function Write-WdBanner {
    [CmdletBinding()]
    param([string]$ModeName)
    $adminText = 'NO'
    if ($script:IsAdmin) { $adminText = 'YES' }
    Write-Host ('win-debug {0} | mode: {1} | Administrator: {2}' -f $script:ToolVersion, $ModeName, $adminText) -ForegroundColor Cyan
}

function Write-WdUsage {
    [CmdletBinding()]
    param()
    $lines = @(
        '',
        ('win-debug {0} - read-only Windows diagnostics (Windows PowerShell 5.1)' -f $script:ToolVersion),
        '',
        'Usage:',
        '  WinDebug.cmd [inventory|disk|monitor|analyze|all] [options]',
        '  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\WinDebug.ps1 -Mode <Mode> [options]',
        '',
        'Modes:',
        '  Inventory   hardware, drivers, software, autostart, security, event logs   (~1-2 min)',
        '  Disk        what occupies the disk and what could be freed (report only)  (~2-5 min)',
        '  Monitor     record processes / CPU / GPU / network in the background       (until stopped)',
        '  Analyze     build report.md from a recorded monitor session',
        '  All         Inventory + Disk',
        '  Menu        interactive menu (needs a console; not available with redirected input)',
        '',
        'Options:',
        '  -OutputRoot <folder>       where report folders go (default: <script folder>\reports)',
        '  -IntervalSeconds <5-3600>  Monitor sample interval (default 10)',
        '  -DurationMinutes <n>       Monitor: stop after n minutes (0 = until STOP/Ctrl+C)',
        '  -SessionPath <folder>      Analyze: monitor session (default: newest *_monitor folder)',
        '  -Drives C,D                Disk: volumes to scan (default: all fixed volumes)',
        '  -TopN <5-500>              number of top items in reports (default 50)',
        '  -Deep                      enable optional slow steps',
        '  -NoElevate | -Elevate      never ask for / always request administrator rights',
        '  -InstallTask | -UninstallTask   register / remove the "WinDebug Monitor" logon task',
        '  -StopMonitor               stop a running monitor (creates its STOP file)',
        '',
        'Full help: Get-Help .\WinDebug.ps1 -Full',
        ''
    )
    foreach ($l in $lines) { Write-Host $l }
}

function New-WdExitRequest {
    # Message marker for "stop this run with exit code N": Invoke-WdMode must not call exit (the menu could not
    # catch it), so it throws this text and the caller decides (menu: print and loop; CLI: print and exit N).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][int]$Code, [Parameter(Mandatory = $true)][string]$Message)
    return ('WD_EXIT:{0}|{1}' -f $Code.ToString([Globalization.CultureInfo]::InvariantCulture), $Message)
}

function Get-WdExitRequest {
    # Parses a New-WdExitRequest marker; $null for any other message.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Message)
    if ([string]::IsNullOrEmpty($Message)) { return $null }
    $m = [regex]::Match($Message, '^WD_EXIT:(\d+)\|(.*)$', [Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $m.Success) { return $null }
    return @{ Code = [int]::Parse($m.Groups[1].Value, [Globalization.CultureInfo]::InvariantCulture); Message = $m.Groups[2].Value }
}

function Get-WdPowerShellPath {
    # Fully qualified Windows PowerShell host: a bare "powershell.exe" would be resolved through PATH (or the
    # current directory by cmd.exe), where a user-writable folder could plant a same-named file.
    [CmdletBinding()]
    param()
    $candidates = @()
    if (-not [string]::IsNullOrEmpty($PSHOME)) { $candidates += [IO.Path]::Combine($PSHOME, 'powershell.exe') }
    if (-not [string]::IsNullOrEmpty($env:SystemRoot)) { $candidates += [IO.Path]::Combine($env:SystemRoot, 'System32\WindowsPowerShell\v1.0\powershell.exe') }
    foreach ($c in $candidates) { if (Test-FileExists -Path $c) { return $c } }
    return 'powershell.exe'
}

function ConvertTo-WdStopOutcome {
    # Stop-ProcessMonitor returns 'Stopped' | 'Signaled' | 'None'; older builds returned [bool].
    [CmdletBinding()]
    param([AllowNull()][object]$Result)
    if ($null -eq $Result) { return 'None' }
    $last = @($Result)[-1]
    if ($last -is [bool] -or $last -is [System.Management.Automation.SwitchParameter]) { if ([bool]$last) { return 'Stopped' } else { return 'None' } }
    $s = [string]$last
    if ($s -eq 'Stopped' -or $s -eq 'Signaled') { return $s }
    return 'None'
}

function Write-WdStopOutcome {
    # Prints the -StopMonitor / menu 8 result and returns the exit code (0 / 0 / 3).
    [CmdletBinding()]
    param([AllowNull()][object]$Result)
    $outcome = ConvertTo-WdStopOutcome -Result $Result
    switch ($outcome) {
        'Stopped'  { Write-Host 'Monitor stopped.' -ForegroundColor Green; return 0 }
        'Signaled' { Write-Host 'STOP signal sent; the monitor did not confirm within 30 s - check monitor.log.' -ForegroundColor Yellow; return 0 }
    }
    Write-Host 'No running monitor found.' -ForegroundColor Yellow
    return 3
}

function Start-WdElevatedRelaunch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$BoundParameters,
        [string]$ForceMode
    )
    $argList = New-Object 'System.Collections.Generic.List[string]'
    $argList.Add('-NoProfile')
    $argList.Add('-ExecutionPolicy')
    $argList.Add('Bypass')
    $argList.Add('-File')
    $argList.Add((ConvertTo-CommandLineArgument -Text $PSCommandPath))
    $modeWritten = $false
    foreach ($key in @($BoundParameters.Keys)) {
        if ($key -eq 'Elevate' -or $key -eq 'Elevated') { continue }
        $v = $BoundParameters[$key]
        if ($key -eq 'Mode' -and -not [string]::IsNullOrEmpty($ForceMode)) { $v = $ForceMode }
        if ($key -eq 'Mode') { $modeWritten = $true }
        if ($v -is [System.Management.Automation.SwitchParameter]) {
            if ($v.IsPresent) { $argList.Add('-' + $key) }
            continue
        }
        if ($v -is [bool]) {
            if ($v) { $argList.Add('-' + $key) }
            continue
        }
        if ($null -eq $v) { continue }
        $text = ''
        if ($v -is [System.Collections.IEnumerable] -and -not ($v -is [string])) { $text = (@($v) -join ',') }
        else { $text = ConvertTo-InvariantString -Value $v }
        $argList.Add('-' + $key)
        # Win32 quoting: a value ending in a backslash ("D:\") must not swallow the closing quote and the rest of the line.
        $argList.Add((ConvertTo-CommandLineArgument -Text $text))
    }
    if (-not $modeWritten -and -not [string]::IsNullOrEmpty($ForceMode)) {
        $argList.Add('-Mode')
        $argList.Add($ForceMode)
    }
    $argList.Add('-Elevated')
    Write-Log -Level Debug -Message ('Relaunch arguments: {0}' -f ($argList.ToArray() -join ' '))
    Start-Process -FilePath (Get-WdPowerShellPath) -ArgumentList $argList.ToArray() -Verb RunAs -WorkingDirectory $PSScriptRoot -ErrorAction Stop | Out-Null
}

function Test-WdMonitorSessionFolder {
    # True when the folder holds monitor data (samples_*.csv, procs_*.csv or procsum.json) - the same test
    # Invoke-MonitorAnalysis applies; an orphan folder with only run.log is not a session.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if (-not (Test-DirectoryExists -Path $Path)) { return $false }
    try {
        if (@([IO.Directory]::GetFiles($Path, 'samples_*.csv')).Count -gt 0) { return $true }
        if (@([IO.Directory]::GetFiles($Path, 'procs_*.csv')).Count -gt 0) { return $true }
        if ([IO.File]::Exists([IO.Path]::Combine($Path, 'procsum.json'))) { return $true }
    } catch { }
    return $false
}

function Get-WdNewestSession {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Root)
    if (-not (Test-DirectoryExists -Path $Root)) { return $null }
    $dirs = @(Get-ChildItem -LiteralPath $Root -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '_monitor(-\d+)?$' -and (Test-WdMonitorSessionFolder -Path $_.FullName) })
    if ($dirs.Count -eq 0) { return $null }
    $newest = $dirs | Sort-Object -Property @{ Expression = 'LastWriteTime'; Descending = $true }, @{ Expression = 'Name'; Descending = $true } | Select-Object -First 1
    return $newest.FullName
}

function Invoke-WdMode {
    # Runs one mode and returns the report folder path (or $null for modes without one).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$ModeName)
    switch ($ModeName) {
        'Inventory' {
            $dir = New-ReportDirectory -OutputRoot $OutputRoot -Mode 'Inventory'
            Write-Log -Level Info -Message ('Report folder: {0}' -f $dir)
            Invoke-InventoryScan -OutDir $dir -Deep:$Deep | Out-Null
            return $dir
        }
        'Disk' {
            $dir = New-ReportDirectory -OutputRoot $OutputRoot -Mode 'Disk'
            Write-Log -Level Info -Message ('Report folder: {0}' -f $dir)
            $diskArgs = @{ OutDir = $dir; TopN = $TopN; Deep = $Deep }
            if ($null -ne $Drives -and $Drives.Count -gt 0) { $diskArgs['Drives'] = $Drives }
            Invoke-DiskScan @diskArgs | Out-Null
            return $dir
        }
        'Monitor' {
            # Refuse BEFORE creating the session folder: otherwise an orphan <PC>_<ts>_monitor with only run.log
            # is left behind and can win the Analyze auto-resolve.
            $live = @(Get-WdMonRunningSessions -OutputRoot $OutputRoot | Where-Object { [int]$_.Pid -ne $PID })
            if ($live.Count -gt 0) {
                throw (New-WdExitRequest -Code 3 -Message ('A monitor is already running (PID {0}, folder {1}). Stop it first (WinDebug.cmd -StopMonitor) or create a STOP file in that folder.' -f ([int]$live[0].Pid).ToString([Globalization.CultureInfo]::InvariantCulture), $live[0].Folder))
            }
            $dir = New-ReportDirectory -OutputRoot $OutputRoot -Mode 'Monitor'
            Write-Log -Level Info -Message ('Session folder: {0}' -f $dir)
            Write-Log -Level Info -Message ('To stop: create a file named STOP in that folder, run "WinDebug.cmd -StopMonitor", or press Ctrl+C.')
            Start-ProcessMonitor -OutDir $dir -IntervalSeconds $IntervalSeconds -DurationMinutes $DurationMinutes -TrackShortLived:$TrackShortLived | Out-Null
            return $dir
        }
        'Analyze' {
            $session = $SessionPath
            if ([string]::IsNullOrWhiteSpace($session)) {
                $session = Get-WdNewestSession -Root $OutputRoot
                if ($null -eq $session) {
                    throw (New-WdExitRequest -Code 5 -Message ('No monitor session found under {0}. Record one first (Monitor mode) or pass -SessionPath.' -f $OutputRoot))
                }
            } else {
                $session = Resolve-PathSafe -Path $session
            }
            if (-not (Test-DirectoryExists -Path $session)) {
                throw (New-WdExitRequest -Code 5 -Message ('Session folder not found: {0}' -f $session))
            }
            # Validate the content before analyze.log is created: an arbitrary folder must stay untouched.
            if (-not (Test-WdMonitorSessionFolder -Path $session)) {
                throw (New-WdExitRequest -Code 5 -Message ('Not a monitor session (no samples_*.csv, procs_*.csv or procsum.json): {0}' -f $session))
            }
            $script:ReportDir   = $session
            $script:LogPath     = [IO.Path]::Combine($session, 'analyze.log')
            $script:CurrentMode = 'Analyze'
            $script:RunStart    = Get-Date
            Write-Log -Level Info -Message ('Analyzing session: {0}' -f $session)
            Invoke-MonitorAnalysis -SessionPath $session -TopN $TopN | Out-Null
            return $session
        }
        'All' {
            $d1 = Invoke-WdMode -ModeName 'Inventory'
            Write-Host ('Done. Report: {0}' -f $d1) -ForegroundColor Green
            # Findings and collection errors of the first run must not leak into the second report.
            $script:Findings.Clear()
            $script:CollectionErrors.Clear()
            $script:AdminSkips.Clear()
            $d2 = Invoke-WdMode -ModeName 'Disk'
            return $d2
        }
    }
    return $null
}

function Show-WdMenu {
    [CmdletBinding()]
    param()
    $dash = [string][char]0x2014
    while ($true) {
        $adminText = 'YES'
        if (-not $script:IsAdmin) { $adminText = 'NO (some data will be missing)' }
        Write-Host ''
        Write-Host (' win-debug {0}  {1}  read-only Windows diagnostics          Administrator: {2}' -f $script:ToolVersion, $dash, $adminText) -ForegroundColor Cyan
        Write-Host (' Reports folder: {0}' -f $OutputRoot)
        Write-Host ''
        Write-Host '  1  Inventory     hardware, drivers, software, autostart, security, event logs  (~1-2 min)'
        Write-Host '  2  Disk usage    what occupies the disk and what could be freed                 (~2-5 min)'
        Write-Host '  3  Monitor       record processes / CPU / GPU / network in the background      (runs until stopped)'
        Write-Host '  4  Analyze       build report.md from a recorded monitor session'
        Write-Host '  5  All           Inventory + Disk usage'
        Write-Host '  6  Install monitor as logon task ("WinDebug Monitor")'
        Write-Host '  7  Remove the logon task'
        Write-Host '  8  Stop a running monitor'
        Write-Host '  A  Restart with administrator rights'
        Write-Host '  Q  Quit'
        $choice = ''
        try { $choice = [string](Read-Host ' Choice') } catch { $choice = 'Q' }
        if ($null -eq $choice) { $choice = '' }
        $choice = $choice.Trim().ToUpperInvariant()
        $reportDir = $null
        $ran = $false
        try {
            switch ($choice) {
                '1' { $ran = $true; $reportDir = Invoke-WdMode -ModeName 'Inventory' }
                '2' { $ran = $true; $reportDir = Invoke-WdMode -ModeName 'Disk' }
                '3' { $ran = $true; $reportDir = Invoke-WdMode -ModeName 'Monitor' }
                '4' { $ran = $true; $reportDir = Invoke-WdMode -ModeName 'Analyze' }
                '5' { $ran = $true; $reportDir = Invoke-WdMode -ModeName 'All' }
                '6' {
                    $ran = $true
                    $ok = Install-MonitorTask -OutputRoot $OutputRoot -IntervalSeconds $IntervalSeconds
                    if ($ok) { Write-Host 'Logon task "WinDebug Monitor" installed.' -ForegroundColor Green } else { Write-Host 'Logon task installation failed.' -ForegroundColor Red }
                }
                '7' {
                    $ran = $true
                    $ok = Uninstall-MonitorTask
                    if ($ok) { Write-Host 'Logon task "WinDebug Monitor" removed.' -ForegroundColor Green } else { Write-Host 'Logon task removal failed or the task does not exist.' -ForegroundColor Yellow }
                }
                '8' {
                    $ran = $true
                    Write-WdStopOutcome -Result (Stop-ProcessMonitor -OutputRoot $OutputRoot) | Out-Null
                }
                'A' {
                    if ($script:IsAdmin) {
                        Write-Host 'Already running with administrator rights.' -ForegroundColor Green
                    } else {
                        try {
                            Start-WdElevatedRelaunch -BoundParameters $script:EntryBoundParameters -ForceMode 'Menu'
                            Write-Host 'Continuing in the elevated window.' -ForegroundColor Green
                            exit 0
                        } catch {
                            Write-Log -Level Warn -Message ('Elevation was declined or failed ({0}); continuing without administrator rights.' -f $_.Exception.Message)
                        }
                    }
                }
                'Q' { return }
                ''  { }   # a bare Enter (e.g. one too many after "Press Enter to return") just redraws the menu; only Q quits
                default { Write-Host ('Unknown choice "{0}".' -f $choice) -ForegroundColor Yellow }
            }
        } catch {
            $req = Get-WdExitRequest -Message $_.Exception.Message
            if ($null -ne $req) {
                # Expected refusal (no session, monitor already running): print it and return to the menu.
                Write-Host $req.Message -ForegroundColor Yellow
            } else {
                Write-Log -Level Error -Message ('{0} failed: {1}' -f $choice, $_.Exception.Message)
                Write-Log -Level Debug -Message ([string]$_.ScriptStackTrace)
                if ($script:LogPath) { Write-Host ('See {0}' -f $script:LogPath) -ForegroundColor Yellow }
            }
        }
        if ($ran) {
            if ($reportDir) { Write-Host ('Done. Report: {0}' -f $reportDir) -ForegroundColor Green }
            # Reset per-run state before the next menu action.
            $script:Findings.Clear()
            $script:CollectionErrors.Clear()
            $script:AdminSkips.Clear()
            $script:LogPath = $null
            $script:ReportDir = $null
            try { Read-Host ' Press Enter to return to the menu' | Out-Null } catch { return }
        }
    }
}

# ---------------------------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------------------------
$exitCode = 0
try {
    # 3a. Parameter validation (documented exit 5 + usage; PowerShell's own binding errors stay exit 1).
    $allowedModes = @('Inventory', 'Disk', 'Monitor', 'Analyze', 'All', 'Menu')
    $canonicalMode = $null
    foreach ($m in $allowedModes) { if ([string]::Equals($m, [string]$Mode, [StringComparison]::OrdinalIgnoreCase)) { $canonicalMode = $m } }
    $paramError = ''
    if ($null -eq $canonicalMode) { $paramError = ('Unknown -Mode "{0}". Allowed values: {1}.' -f $Mode, ($allowedModes -join ', ')) }
    elseif ($IntervalSeconds -lt 5 -or $IntervalSeconds -gt 3600) { $paramError = ('-IntervalSeconds must be between 5 and 3600 (got {0}).' -f $IntervalSeconds) }
    elseif ($DurationMinutes -lt 0 -or $DurationMinutes -gt 100000) { $paramError = ('-DurationMinutes must be between 0 and 100000 (got {0}).' -f $DurationMinutes) }
    elseif ($TopN -lt 5 -or $TopN -gt 500) { $paramError = ('-TopN must be between 5 and 500 (got {0}).' -f $TopN) }
    elseif ($driveError -ne '') { $paramError = $driveError }
    if (-not [string]::IsNullOrEmpty($paramError)) {
        Write-Host $paramError -ForegroundColor Red
        Write-WdUsage
        exit 5
    }
    $Mode = $canonicalMode
    if ($script:EntryBoundParameters.ContainsKey('Mode')) { $script:EntryBoundParameters['Mode'] = $Mode }

    $bannerMode = $Mode
    if ($StopMonitor) { $bannerMode = 'StopMonitor' } elseif ($InstallTask) { $bannerMode = 'InstallTask' } elseif ($UninstallTask) { $bannerMode = 'UninstallTask' }
    Write-WdBanner -ModeName $bannerMode

    # 4. Task switches come first and exit on their own.
    if ($StopMonitor) {
        $rc = Write-WdStopOutcome -Result (Stop-ProcessMonitor -OutputRoot $OutputRoot)
        exit $rc
    }
    if ($InstallTask) {
        $ok = Install-MonitorTask -OutputRoot $OutputRoot -IntervalSeconds $IntervalSeconds
        if ($ok) { Write-Host 'Logon task "WinDebug Monitor" installed.' -ForegroundColor Green; exit 0 }
        Write-Host 'Logon task installation failed.' -ForegroundColor Red
        exit 6
    }
    if ($UninstallTask) {
        $ok = Uninstall-MonitorTask
        if ($ok) { Write-Host 'Logon task "WinDebug Monitor" removed.' -ForegroundColor Green; exit 0 }
        Write-Host 'Logon task removal failed or the task does not exist.' -ForegroundColor Red
        exit 6
    }

    # 5. Elevation.
    $skipElevation = $Elevated -or $NoElevate -or $script:IsAdmin -or ($Mode -eq 'Analyze') -or ($Mode -eq 'Menu')
    if (-not $skipElevation) {
        $wantElevation = $false
        if ($Elevate) {
            $wantElevation = $true
        } elseif (-not $inputRedirected) {
            $answer = ''
            try { $answer = [string](Read-Host 'Run with administrator rights for a complete picture? [Y/n]') } catch { $answer = 'n' }
            if ($null -eq $answer) { $answer = '' }
            $answer = $answer.Trim()
            $wantElevation = ($answer -eq '' -or $answer -match '^(y|yes)$')
        }
        if ($wantElevation) {
            try {
                Start-WdElevatedRelaunch -BoundParameters $script:EntryBoundParameters
                Write-Host 'Continuing in the elevated window. This window can be closed.' -ForegroundColor Green
                exit 0
            } catch {
                Write-Log -Level Warn -Message ('Elevation was declined or failed ({0}); continuing without administrator rights (some data will be missing).' -f $_.Exception.Message)
            }
        } else {
            Write-Log -Level Info -Message 'Running without administrator rights (some data will be missing).'
        }
    }

    # 6. Menu.
    if ($Mode -eq 'Menu') {
        if ($inputRedirected) {
            Write-Host 'The interactive menu needs a console (input is redirected). Pass -Mode instead:' -ForegroundColor Yellow
            Write-WdUsage
            exit 5
        }
        Show-WdMenu
        exit 0
    }

    # 7. Dispatch.
    $reportDir = Invoke-WdMode -ModeName $Mode
    if ($reportDir) { Write-Host ('Done. Report: {0}' -f $reportDir) -ForegroundColor Green }
    else { Write-Host 'Done.' -ForegroundColor Green }
    $exitCode = 0
} catch {
    $msg = $_.Exception.Message
    $req = Get-WdExitRequest -Message $msg
    if ($null -ne $req) {
        # Expected refusal with a documented exit code: no "Unhandled error", no stack trace, no log file.
        $color = 'Red'
        if ($req.Code -eq 3) { $color = 'Yellow' }
        Write-Host $req.Message -ForegroundColor $color
        exit $req.Code
    }
    Write-Log -Level Error -Message ('Unhandled error: {0}' -f $msg)
    Write-Log -Level Error -NoConsole -Message ([string]$_.ScriptStackTrace)
    if ($msg -match 'already running') {
        Write-Host 'A monitor is already running. Stop it first (WinDebug.cmd -StopMonitor).' -ForegroundColor Yellow
        $exitCode = 3
    } else {
        if ($script:LogPath) { Write-Host ('See {0}' -f $script:LogPath) -ForegroundColor Yellow } else { Write-Host 'See run.log in the report folder (if one was created).' -ForegroundColor Yellow }
        $exitCode = 1
    }
}
exit $exitCode
