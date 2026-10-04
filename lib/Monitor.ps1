# lib\Monitor.ps1 - background process monitor for win-debug (mode Monitor).
# Dot-sourced by WinDebug.ps1 after lib\Common.ps1 (same script scope). Windows PowerShell 5.1 only.
#
# Public API (called by WinDebug.ps1):
#   Start-ProcessMonitor -OutDir -IntervalSeconds -DurationMinutes [-TrackShortLived]   sampling loop until STOP/duration/Ctrl+C
#   Stop-ProcessMonitor -OutputRoot                                                       creates STOP for every live monitor; returns 'Stopped' | 'Signaled' | 'None'
#   Install-MonitorTask -OutputRoot -IntervalSeconds / Uninstall-MonitorTask / Test-MonitorTaskInstalled   logon task "WinDebug Monitor"
# Private helpers carry the prefix *-WdMon*. The file format is documented in docs\monitor-format.md (the
# contract for lib\Analyze.ps1). Design (verified on the test machine, see the research notes):
#   - per-process CPU/IO from Win32_PerfRawData_PerfProc_Process deltas; key = "<pid>|<creation FILETIME>" (PID-reuse safe)
#   - per-process GPU from Win32_PerfRawData_GPUPerformanceCounters_GPUEngine deltas, bucketed by engine type
#   - system totals from the raw PerfOS/PerfDisk/Tcpip classes (20-40 ms each instead of ~300 ms formatted)
#   - metadata once per process (Win32_Process batch, owner via P/Invoke, signature + SHA256 cached in filecache.json)
#   - everything works without administrator rights; missing data is marked "(requires administrator)"
#   - secrets: CommandLine (procmeta.csv, procsum.json) and event Detail text (4104 script blocks, 7045 service
#     installs, WMI process starts) pass through Hide-WdSecret (lib\Common.ps1) before they are written; the rule
#     flags (MinerTokens, ScriptHost*) are always evaluated on the ORIGINAL command line
#   - run.json is rewritten atomically after the first completed sample and at every 60 s procsum flush, so its
#     counters (SamplesWritten, LastSampleTime, ProcessesWithoutPath) are real for a live or killed session
# Read-only on the machine: the only files written are inside the session folder (plus the optional scheduled task).

Set-StrictMode -Off

$script:WdMonProcProps = @('Name', 'IDProcess', 'PercentProcessorTime', 'Timestamp_Sys100NS', 'IOReadBytesPersec', 'IOWriteBytesPersec',
                           'WorkingSetPrivate', 'WorkingSet', 'ThreadCount', 'HandleCount', 'ElapsedTime', 'CreatingProcessID', 'PriorityBase')
$script:WdMonGpuRx = New-Object System.Text.RegularExpressions.Regex('^pid_(\d+)_luid_(0x[0-9A-Fa-f]+)_(0x[0-9A-Fa-f]+)_phys_(\d+)_eng_(\d+)_engtype_(.+)$', 'Compiled')
$script:WdMonGpuMemRx = New-Object System.Text.RegularExpressions.Regex('^pid_(\d+)_', 'Compiled')
$script:WdMonIdleThresholdSec = 300
$script:WdMonMaxHashBytes = 64MB
$script:WdMonFileVersion = 1

$script:WdMonColumns = @{
    samples  = @('Timestamp', 'SampleNo', 'IntervalSec', 'SampleMs', 'Overrun', 'CpuPct', 'CpuKernelPct', 'CpuDpcIntPct', 'CpuProcSumPct',
                 'CpuPerfPct', 'CpuUtilityPct', 'CpuFreqMHz', 'MemTotalMB', 'MemUsedMB', 'MemAvailMB', 'CommitBytes', 'CommitLimitBytes', 'CommitPct',
                 'PagesPerSec', 'PoolNonpagedBytes', 'DiskActivePct', 'DiskQueue', 'DiskReadBps', 'DiskWriteBps', 'DiskAvgMs', 'DiskTransfersPerSec',
                 'NetRecvBps', 'NetSentBps', 'GpuPct', 'Gpu3DPct', 'GpuComputePct', 'GpuCopyPct', 'GpuVideoDecodePct', 'GpuVideoEncodePct', 'GpuOtherPct',
                 'GpuDedicatedBytes', 'GpuSharedBytes', 'BatteryPct', 'OnBattery', 'TempC', 'ThrottleReasons', 'IdleSeconds', 'SessionLocked', 'IsIdle',
                 'ProcessCount', 'ThreadCount', 'ContextSwitchesPerSec', 'ProcQueue', 'TopCpuName', 'TopCpuPct')
    procs    = @('Timestamp', 'Key', 'Pid', 'Name', 'CpuPct', 'CpuCores', 'GpuPct', 'Gpu3D', 'GpuCompute', 'GpuCopy', 'GpuVideoDecode', 'GpuVideoEncode',
                 'GpuOther', 'GpuDedicatedBytes', 'GpuSharedBytes', 'ReadBps', 'WriteBps', 'WorkingSet', 'WorkingSetPrivate', 'PrivateBytes', 'Threads',
                 'Handles', 'BasePriority', 'HasWindow', 'IsIdle', 'Flags')
    procmeta = @('Key', 'Pid', 'Name', 'ImageName', 'Path', 'CommandLine', 'Ppid', 'ParentKey', 'ParentName', 'Started', 'FirstSeen', 'SessionId',
                 'Owner', 'OwnerSid', 'LocationClass', 'Company', 'Description', 'ProductVersion', 'OriginalFilename', 'FileSize', 'FileCreated',
                 'FileModified', 'SigStatus', 'Signer', 'IsOSBinary', 'Sha256', 'Flags', 'AccessNote')
    net      = @('Timestamp', 'Key', 'Pid', 'Name', 'State', 'LocalAddress', 'LocalPort', 'RemoteAddress', 'RemotePort', 'IsPrivate', 'PoolPort', 'IsIdle', 'ConnCreated')
    dns      = @('Timestamp', 'Name', 'Data', 'Type', 'TTL')
    events   = @('Timestamp', 'Type', 'Key', 'Pid', 'Name', 'Detail', 'Source', 'EventId', 'EventTime', 'RecordId')
}

# ---------------------------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------------------------
function New-WdMonState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutDir,
        [Parameter(Mandatory = $true)][int]$IntervalSeconds,
        [int]$DurationMinutes = 0
    )
    $now = Get-Date
    $st = @{
        OutDir           = $OutDir
        Interval         = $IntervalSeconds
        DurationMinutes  = $DurationMinutes
        Start            = $now
        StartIso         = (Get-IsoTimestamp -Date $now)
        Deadline         = $null
        Pid              = $PID
        NCPU             = [Math]::Max(1, [int]$script:NCPU)
        Inv              = (Get-WdInv)
        Writers          = @{}
        Prev             = $null
        PrevGpu          = $null
        PrevGpuTs        = 0
        PrevSys          = @{}
        Sum              = @{}
        RemoteIps        = @{}
        PidNames         = @{}
        WinInfo          = @{}
        WinInfoSample    = -1
        FileCache        = @{}
        FileCacheDirty   = $false
        FileQueue        = (New-Object 'System.Collections.Generic.Queue[string]')
        FileQueued       = (New-Object 'System.Collections.Generic.HashSet[string]')
        PendingMeta      = @{}
        NetSeen          = (New-Object 'System.Collections.Generic.HashSet[string]')
        DnsSeen          = (New-Object 'System.Collections.Generic.HashSet[string]')
        Watch            = (New-Object 'System.Collections.Generic.HashSet[string]')
        EventLogs        = (New-Object 'System.Collections.Generic.List[object]')
        LastEventPoll    = $now
        LastSumFlush     = $now
        LastCacheFlush   = $now
        IsIdle           = $null
        SampleNo         = 0
        Overruns         = 0
        OverrunPending   = $false
        Failures         = 0
        RowsWritten      = 0
        GpuMode          = 'unknown'
        GpuNoneSince     = 0
        GpuLuids         = @()
        WarnCounts       = @{}
        StepMs           = @{}
        EventBacklogWarn = @{}
        EventPollNo      = 0
        StopReason       = ''
        ScheduledTick    = $now
        MemTotalMB       = $null
        NativeOwner      = $false
        NativeSession    = $false
        TrackShortLived  = $false
        WmiSource        = 'WdMonProcStart'
        NoPathCount      = 0
        InitialCount     = 0
        CtrlCCaptured    = $false
        PrevLogPath      = $null
        SamplesWritten   = 0
        LastSampleIso    = ''
        ToolPids         = (New-Object 'System.Collections.Generic.HashSet[int]')
    }
    if ($DurationMinutes -gt 0) { $st.Deadline = $now.AddMinutes($DurationMinutes) }
    return $st
}

function Invoke-WdMonStep {
    # Guarded step runner (same contract as Invoke-Safely: ErrorActionPreference Stop, collection error recorded,
    # Default returned on failure) that (a) throttles repeated warnings of the same step - a class that always
    # fails would otherwise write one Warn line per sample for days - and (b) does NOT write a DEBUG "ok in N ms"
    # line per step: at 8-9 steps per sample that grew monitor.log by several MB per day. The per-step times are
    # accumulated in $State.StepMs and appended to the "Sample N:" line; -Verbose restores the per-step lines.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][scriptblock]$ScriptBlock,
        [AllowNull()][object]$Default = $null
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $ErrorActionPreference = 'Stop'
    $failed = $false
    $msg = ''
    $r = $Default
    try {
        $r = & $ScriptBlock
    } catch {
        $failed = $true
        $msg = $_.Exception.Message
        if ([string]::IsNullOrEmpty($msg)) { $msg = [string]$_ }
        $msg = ($msg -replace '\r?\n', ' ').Trim()
        $r = $Default
    }
    $sw.Stop()
    $ms = [int64]$sw.ElapsedMilliseconds
    if ($null -ne $State.StepMs) {
        if ($State.StepMs.ContainsKey($Name)) { $State.StepMs[$Name] = [int64]$State.StepMs[$Name] + $ms } else { $State.StepMs[$Name] = $ms }
    }
    if ($script:VerboseLog) {
        if ($failed) { Write-Log -Level Debug -Message ('Monitor.{0} failed after {1} ms: {2}' -f $Name, $ms.ToString($State.Inv), $msg) }
        else { Write-Log -Level Debug -Message ('Monitor.{0} ok in {1} ms' -f $Name, $ms.ToString($State.Inv)) }
    }
    if ($failed) {
        Add-WdCollectionError -Name ('Monitor.' + $Name) -Message $msg
        $n = 1
        if ($State.WarnCounts.ContainsKey($Name)) { $n = 1 + [int]$State.WarnCounts[$Name] }
        $State.WarnCounts[$Name] = $n
        if ($n -le 3 -or ($n % 100) -eq 0) {
            Write-Log -Level Warn -Message ('{0} failed ({1}x): {2}' -f $Name, $n.ToString($State.Inv), $msg)
        }
        if ($null -ne $script:CollectionErrors -and $script:CollectionErrors.Count -gt 500) { $script:CollectionErrors.RemoveRange(0, $script:CollectionErrors.Count - 500) }
    }
    return $r
}

function Format-WdMonStepTimes {
    # "procs 630/sys 252/gpu 125" style summary of $State.StepMs (then resets it) for the "Sample N:" log line.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    if ($null -eq $State.StepMs -or $State.StepMs.Count -eq 0) { return '' }
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($k in @($State.StepMs.Keys | Sort-Object)) {
        $parts.Add(('{0} {1}' -f $k, ([int64]$State.StepMs[$k]).ToString($State.Inv)))
    }
    $State.StepMs.Clear()
    return ($parts -join '/')
}

# ---------------------------------------------------------------------------------------------
# CSV writers (StreamWriter, UTF-8 with BOM, AutoFlush, FileShare.Read; header only for a new file)
# ---------------------------------------------------------------------------------------------
function Open-WdMonCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Columns,
        [string]$Date = ''
    )
    $enc = $script:Utf8Bom
    if ($null -eq $enc) { $enc = New-Object System.Text.UTF8Encoding($true) }
    $fs = New-Object System.IO.FileStream($Path, [IO.FileMode]::Append, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    $isNew = ($fs.Length -eq 0)     # must be checked before AutoFlush: setting it flushes the 3-byte BOM preamble
    $sw = New-Object System.IO.StreamWriter($fs, $enc)
    $sw.NewLine = "`r`n"
    $sw.AutoFlush = $true
    if ($isNew) { $sw.WriteLine(($Columns -join ',')) }
    $State.Writers[$Name] = @{ Name = $Name; Path = $Path; Writer = $sw; Columns = $Columns; Date = $Date; Rows = 0 }
    return $State.Writers[$Name]
}

function Get-WdMonDailyCsv {
    # samples_<date>.csv / procs_<date>.csv rotate at local midnight.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][DateTime]$Time
    )
    $date = $Time.ToString('yyyy-MM-dd', $State.Inv)
    if ($State.Writers.ContainsKey($Name)) {
        $w = $State.Writers[$Name]
        if ($w.Date -eq $date) { return $w }
        try { $w.Writer.Dispose() } catch { }
        $State.Writers.Remove($Name)
        Write-Log -Level Info -Message ('Rotated {0} to {1}' -f $Name, $date)
    }
    $path = [IO.Path]::Combine($State.OutDir, ('{0}_{1}.csv' -f $Name, $date))
    return (Open-WdMonCsv -State $State -Name $Name -Path $path -Columns $script:WdMonColumns[$Name] -Date $date)
}

function Write-WdMonCsvRow {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Writer,
        [Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][object[]]$Values
    )
    # ([AllowNull()] is required: a mandatory collection parameter rejects arrays that contain $null elements.)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $sb = New-Object System.Text.StringBuilder(256)
    for ($i = 0; $i -lt $Values.Count; $i++) {
        if ($i -gt 0) { [void]$sb.Append(',') }
        $v = $Values[$i]
        $s = ''
        if ($null -eq $v) { $s = '' }
        elseif ($v -is [string]) { $s = $v }
        elseif ($v -is [bool]) { if ($v) { $s = 'True' } else { $s = 'False' } }
        elseif ($v -is [double] -or $v -is [single]) {
            $d = [double]$v
            if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { $s = '' }
            else { $s = ([math]::Round($d, 2, [MidpointRounding]::AwayFromZero)).ToString('F2', $inv) }
        }
        elseif ($v -is [DateTime]) { $s = Get-IsoTimestamp -Date $v }
        elseif ($v -is [ValueType]) { $s = ([IConvertible]$v).ToString($inv) }
        else { $s = ConvertTo-InvariantString -Value $v }
        if ($s.Length -gt 0) {
            # One physical line per row (Analyze streams line by line): line breaks inside a value become spaces.
            if ($s.IndexOf("`n") -ge 0 -or $s.IndexOf("`r") -ge 0) { $s = ($s -replace '\r\n|\r|\n', ' ') }
            # Text cells that come from the observed process (command line, FileVersionInfo strings, script-block
            # text, DNS names) get the shared Excel formula guard: a leading space before = + @ TAB CR and before
            # a '-' that does not start a number (WSL's "--distro-id ..." command lines would render as #NAME?).
            # Numbers are formatted from their types above and never pass through here as strings.
            if ($v -is [string]) { $s = Protect-WdCsvText -Text $s }
            if ($s.IndexOf(',') -ge 0 -or $s.IndexOf('"') -ge 0) { $s = '"' + $s.Replace('"', '""') + '"' }
        }
        [void]$sb.Append($s)
    }
    $Writer.Writer.WriteLine($sb.ToString())
    $Writer.Rows = [int]$Writer.Rows + 1
}

function Close-WdMonWriters {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    foreach ($name in @($State.Writers.Keys)) {
        try { $State.Writers[$name].Writer.Dispose() } catch { }
    }
    $State.Writers.Clear()
}

function Format-WdMonNumber {
    # Fixed-decimals text for a double (null -> empty). Used where a column needs 1 or 3 decimals.
    [CmdletBinding()]
    param([AllowNull()][object]$Value, [int]$Decimals = 2)
    if ($null -eq $Value) { return '' }
    $d = 0.0
    try { $d = [double]$Value } catch { return '' }
    if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return '' }
    return ([math]::Round($d, $Decimals, [MidpointRounding]::AwayFromZero)).ToString('F' + $Decimals.ToString([Globalization.CultureInfo]::InvariantCulture), [Globalization.CultureInfo]::InvariantCulture)
}

function ConvertFrom-WdMonFileTime {
    [CmdletBinding()]
    param([AllowNull()][object]$FileTime)
    if ($null -eq $FileTime) { return '' }
    try {
        $ft = [int64]$FileTime
        if ($ft -le 0) { return '' }
        return (Get-IsoTimestamp -Date ([DateTime]::FromFileTime($ft)))
    } catch { return '' }
}

# ---------------------------------------------------------------------------------------------
# JSON files: run.json, procsum.json (atomic rewrite), filecache.json
# ---------------------------------------------------------------------------------------------
function Write-WdMonJsonAtomic {
    # The object must contain only strings, numbers, bools, arrays and hashtables (no DateTime), so that
    # ConvertTo-Json can be used directly (fast) without producing "\/Date(" or "System.Collections.Hashtable".
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$Depth = 5,
        [switch]$Pretty
    )
    $json = ''
    if ($Pretty) { $json = ConvertTo-Json -InputObject $Object -Depth $Depth }
    else { $json = ConvertTo-Json -InputObject $Object -Depth $Depth -Compress }
    $enc = $script:Utf8NoBom
    if ($null -eq $enc) { $enc = New-Object System.Text.UTF8Encoding($false) }
    $tmp = $Path + '.tmp'
    [IO.File]::WriteAllText($tmp, $json, $enc)
    if ([IO.File]::Exists($Path)) {
        # Replace is atomic on the same volume; the backup name must be a real null ([NullString]::Value), not PowerShell's $null.
        try { [IO.File]::Replace($tmp, $Path, [NullString]::Value) }
        catch { [IO.File]::Copy($tmp, $Path, $true); [IO.File]::Delete($tmp) }
    } else {
        [IO.File]::Move($tmp, $Path)
    }
}

function Get-WdMonRunInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $info = Get-ReportRunInfo -Mode 'Monitor'
    $o = [ordered]@{
        Tool            = [string]$info['Tool']
        Version         = [string]$info['Version']
        FormatVersion   = $script:WdMonFileVersion
        Mode            = 'Monitor'
        Computer        = [string]$info['Computer']
        User            = [string]$info['User']
        IsElevated      = [bool]$script:IsAdmin
        OSBuild         = [string]$info['OSBuild']
        PSVersion       = [string]$info['PSVersion']
        Culture         = [string]$info['Culture']
        UICulture       = [string]$info['UICulture']
        NCPU            = $State.NCPU
        MemTotalMB      = $State.MemTotalMB
        GPUs            = @($State.Gpus)
        GpuLuids        = @($State.GpuLuids)
        GpuCounterMode  = [string]$State.GpuMode
        IntervalSeconds = $State.Interval
        DurationMinutes = $State.DurationMinutes
        Start           = $State.StartIso
        Pid             = $State.Pid
        SessionFolder   = $State.OutDir
        TrackShortLived = [bool]$State.TrackShortLived
        NativeHelpers   = @{ ProcOwner = [bool]$State.NativeOwner; Session = [bool]$State.NativeSession }
        EventLogs       = @($State.EventLogs | ForEach-Object { @{ Log = [string]$_.Log; Ids = @($_.Ids); Enabled = [bool]$_.Enabled } })
        IdleThresholdSec = $script:WdMonIdleThresholdSec
        Stop            = [string]$State.StopIso
        StopReason      = [string]$State.StopReason
        Samples         = $State.SampleNo
        SamplesWritten  = [int]$State.SamplesWritten
        LastSampleTime  = [string]$State.LastSampleIso
        Written         = (Get-IsoTimestamp)
        Overruns        = $State.Overruns
        DurationSec     = $State.DurationSec
        ProcessesAtStart = $State.InitialCount
        ProcessesWithoutPath = $State.NoPathCount
    }
    return $o
}

function Write-WdMonRunJson {
    # Written at start, after the first completed sample, at every procsum flush (60 s) and at stop, always through
    # a temp file + atomic replace, so a reader of a live or killed session never sees a half-written file and the
    # counters (SamplesWritten, LastSampleTime, ProcessesWithoutPath, Overruns) reflect the last flush.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $path = [IO.Path]::Combine($State.OutDir, 'run.json')
    $o = Get-WdMonRunInfo -State $State
    Write-WdMonJsonAtomic -Object $o -Path $path -Depth 5 -Pretty
}

function Write-WdMonProcSum {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $meta = @{
        Version        = [string]$script:ToolVersion
        FormatVersion  = $script:WdMonFileVersion
        Computer       = [string]$env:COMPUTERNAME
        Start          = $State.StartIso
        Written        = (Get-IsoTimestamp)
        IntervalSec    = $State.Interval
        NCPU           = $State.NCPU
        Samples        = $State.SampleNo
        IsElevated     = [bool]$script:IsAdmin
        StopReason     = [string]$State.StopReason
        Processes      = $State.Sum.Count
    }
    $obj = @{ Meta = $meta; Processes = $State.Sum }
    Write-WdMonJsonAtomic -Object $obj -Path ([IO.Path]::Combine($State.OutDir, 'procsum.json')) -Depth 4
    $State.LastSumFlush = Get-Date
}

function Write-WdMonFileCache {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    if (-not $State.FileCacheDirty) { return }
    Write-WdMonJsonAtomic -Object $State.FileCache -Path ([IO.Path]::Combine($State.OutDir, 'filecache.json')) -Depth 3
    $State.FileCacheDirty = $false
    $State.LastCacheFlush = Get-Date
}

function Import-WdMonFileCache {
    # Loads filecache.json (own folder first, then the newest sibling *_monitor session) so signatures and
    # hashes of files already examined are not recomputed. Entries are validated by size + mtime on use.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    $own = [IO.Path]::Combine($State.OutDir, 'filecache.json')
    if ([IO.File]::Exists($own)) { $candidates.Add($own) }
    $root = [IO.Path]::GetDirectoryName($State.OutDir)
    if (Test-DirectoryExists -Path $root) {
        $dirs = @(Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '_monitor(-\d+)?$' -and $_.FullName -ne $State.OutDir } | Sort-Object -Property LastWriteTime -Descending)
        foreach ($d in $dirs) {
            $p = [IO.Path]::Combine($d.FullName, 'filecache.json')
            if ([IO.File]::Exists($p)) { $candidates.Add($p); break }
        }
    }
    foreach ($p in $candidates) {
        try {
            $text = [IO.File]::ReadAllText($p, (New-Object System.Text.UTF8Encoding($false)))
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            $obj = ConvertFrom-Json -InputObject $text
            $n = 0
            foreach ($prop in $obj.PSObject.Properties) {
                $e = @{}
                foreach ($f in $prop.Value.PSObject.Properties) { $e[[string]$f.Name] = $f.Value }
                if (-not $e.ContainsKey('Size') -or -not $e.ContainsKey('Sha256')) { continue }
                $State.FileCache[[string]$prop.Name] = $e
                $n++
            }
            Write-Log -Level Info -Message ('File cache: loaded {0} entries from {1}' -f $n.ToString($State.Inv), $p)
            return
        } catch {
            Write-Log -Level Debug -Message ('File cache {0} not loaded: {1}' -f $p, $_.Exception.Message)
        }
    }
}

# ---------------------------------------------------------------------------------------------
# monitor.running marker and live-session discovery
# ---------------------------------------------------------------------------------------------
function Write-WdMonRunningMarker {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $path = [IO.Path]::Combine($State.OutDir, 'monitor.running')
    $text = '{0}{1}{2}{1}' -f $State.Pid.ToString($State.Inv), "`r`n", $State.StartIso
    [IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))
}

function Test-WdMonPidAlive {
    [CmdletBinding()]
    param([int]$ProcessId)
    if ($ProcessId -le 0) { return $false }
    try {
        $p = Get-Process -Id $ProcessId -ErrorAction Stop
        if ($null -eq $p) { return $false }
        return ($p.ProcessName -match '^(powershell|pwsh)$')
    } catch { return $false }
}

function Get-WdMonRunningSessions {
    # Session folders directly under OutputRoot whose monitor.running names a live powershell process.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$OutputRoot)
    $result = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Test-DirectoryExists -Path $OutputRoot)) { return @($result.ToArray()) }
    $dirs = @(Get-ChildItem -LiteralPath $OutputRoot -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '_monitor(-\d+)?$' })
    foreach ($d in $dirs) {
        $marker = [IO.Path]::Combine($d.FullName, 'monitor.running')
        if (-not [IO.File]::Exists($marker)) { continue }
        $procId = 0
        try {
            $first = ([IO.File]::ReadAllText($marker) -split '\r?\n')[0].Trim()
            $procId = [int]::Parse($first, [Globalization.CultureInfo]::InvariantCulture)
        } catch { $procId = 0 }
        if (Test-WdMonPidAlive -ProcessId $procId) {
            $result.Add(@{ Folder = $d.FullName; Pid = $procId; Marker = $marker })
        }
    }
    return @($result.ToArray())
}

# ---------------------------------------------------------------------------------------------
# Collection: processes (PerfProc raw)
# ---------------------------------------------------------------------------------------------
function Get-WdMonProcSnapshot {
    # Returns @{ Rows = key -> raw row; KeyNames = key -> name without "#N"; Names = pid -> name; PidToKey; Total; Idle; LogonUi }
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $rows = @(Get-CimSafe -ClassName Win32_PerfRawData_PerfProc_Process -Property $script:WdMonProcProps -TimeoutSec 20)
    $snap = @{ Rows = @{}; KeyNames = @{}; Names = @{}; PidToKey = @{}; Total = $null; Idle = $null; LogonUi = $false; Count = 0 }
    foreach ($r in $rows) {
        $n = [string]$r.Name
        if ($n -eq '_Total') { $snap.Total = $r; continue }
        $procId = [int]$r.IDProcess
        if ($procId -eq 0) {
            if ($n -eq 'Idle') { $snap.Idle = $r }
            continue
        }
        $hash = $n.IndexOf('#')
        if ($hash -gt 0) { $n = $n.Substring(0, $hash) }
        $key = '{0}|{1}' -f $procId.ToString($State.Inv), ([uint64]$r.ElapsedTime).ToString($State.Inv)
        $snap.Rows[$key] = $r
        $snap.KeyNames[$key] = $n
        $snap.Names[$procId] = $n
        $snap.PidToKey[$procId] = $key
        if ($n -eq 'LogonUI') { $snap.LogonUi = $true }
    }
    $snap.Count = $snap.Rows.Count
    return $snap
}

# ---------------------------------------------------------------------------------------------
# Collection: GPU (engine deltas per PID + process memory)
# ---------------------------------------------------------------------------------------------
function Get-WdMonGpuBucket {
    [CmdletBinding()]
    param([string]$EngineType)
    if ($EngineType -match 'Compute|Cuda') { return 'Compute' }
    if ($EngineType -match '3D') { return 'ThreeD' }
    if ($EngineType -match '^Copy') { return 'Copy' }
    if ($EngineType -match 'Encode') { return 'VEnc' }
    if ($EngineType -match '^Video') { return 'VDec' }
    return 'Other'
}

function Get-WdMonGpuDelta {
    # Returns @{ Agg = pid -> @{Total;ThreeD;Compute;Copy;VDec;VEnc;Other}; Totals = same buckets summed; Busiest = max single engine %; Available }
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $result = @{ Agg = @{}; Totals = @{ ThreeD = 0.0; Compute = 0.0; Copy = 0.0; VDec = 0.0; VEnc = 0.0; Other = 0.0 }; Busiest = $null; Available = $false }
    if ($State.GpuMode -eq 'none') {
        $State.GpuNoneSince++
        if ($State.GpuNoneSince -lt 60) { return $result }
        $State.GpuMode = 'unknown'
        $State.GpuNoneSince = 0
    }
    $rows = @()
    if ($State.GpuMode -eq 'unknown' -or $State.GpuMode -eq 'raw') {
        $rows = @(Get-CimSafe -ClassName Win32_PerfRawData_GPUPerformanceCounters_GPUEngine -Property Name, RunningTime, Timestamp_Sys100NS -TimeoutSec 20)
        if ($rows.Count -gt 0) { $State.GpuMode = 'raw' }
    }
    if ($rows.Count -eq 0 -and ($State.GpuMode -eq 'unknown' -or $State.GpuMode -eq 'formatted')) {
        $rows = @(Get-CimSafe -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -Property Name, UtilizationPercentage -TimeoutSec 20)
        if ($rows.Count -gt 0) { $State.GpuMode = 'formatted' }
    }
    if ($rows.Count -eq 0) {
        if ($State.GpuMode -eq 'unknown') {
            $State.GpuMode = 'none'
            Write-Log -Level Warn -Message 'GPU performance counters are not available on this system (no GPU engine instances); GPU columns stay empty.'
        }
        $State.PrevGpu = $null
        return $result
    }
    $result.Available = $true
    $engines = @{}
    $luids = @{}
    if ($State.GpuMode -eq 'raw') {
        $prev = $State.PrevGpu
        $curTs = [int64]$rows[0].Timestamp_Sys100NS
        $dt = 0.0
        if ($null -ne $prev) { $dt = [double]($curTs - [int64]$State.PrevGpuTs) }
        $newMap = @{}
        foreach ($r in $rows) {
            $name = [string]$r.Name
            $newMap[$name] = [int64]$r.RunningTime
            if ($dt -le 0 -or $null -eq $prev -or -not $prev.ContainsKey($name)) { continue }
            $u = 100.0 * [double]([int64]$r.RunningTime - [int64]$prev[$name]) / $dt
            if ($u -le 0.05) { continue }
            if ($u -gt 100.0) { $u = 100.0 }
            $m = $script:WdMonGpuRx.Match($name)
            if (-not $m.Success) { continue }
            $procId = [int]$m.Groups[1].Value
            $bucket = Get-WdMonGpuBucket -EngineType $m.Groups[6].Value
            if (-not $result.Agg.ContainsKey($procId)) { $result.Agg[$procId] = @{ Total = 0.0; ThreeD = 0.0; Compute = 0.0; Copy = 0.0; VDec = 0.0; VEnc = 0.0; Other = 0.0 } }
            $a = $result.Agg[$procId]
            $a.Total += $u
            $a[$bucket] += $u
            $result.Totals[$bucket] += $u
            $eng = '{0}|{1}' -f $m.Groups[3].Value, $m.Groups[5].Value
            if ($engines.ContainsKey($eng)) { $engines[$eng] += $u } else { $engines[$eng] = $u }
            $luids[$m.Groups[3].Value] = $true
        }
        $State.PrevGpu = $newMap
        $State.PrevGpuTs = $curTs
        if ($null -eq $prev) { $result.Available = $false }
    } else {
        foreach ($r in $rows) {
            $u = 0.0
            try { $u = [double]$r.UtilizationPercentage } catch { $u = 0.0 }
            if ($u -le 0.05) { continue }
            $m = $script:WdMonGpuRx.Match([string]$r.Name)
            if (-not $m.Success) { continue }
            $procId = [int]$m.Groups[1].Value
            $bucket = Get-WdMonGpuBucket -EngineType $m.Groups[6].Value
            if (-not $result.Agg.ContainsKey($procId)) { $result.Agg[$procId] = @{ Total = 0.0; ThreeD = 0.0; Compute = 0.0; Copy = 0.0; VDec = 0.0; VEnc = 0.0; Other = 0.0 } }
            $a = $result.Agg[$procId]
            $a.Total += $u
            $a[$bucket] += $u
            $result.Totals[$bucket] += $u
            $eng = '{0}|{1}' -f $m.Groups[3].Value, $m.Groups[5].Value
            if ($engines.ContainsKey($eng)) { $engines[$eng] += $u } else { $engines[$eng] = $u }
            $luids[$m.Groups[3].Value] = $true
        }
    }
    if ($result.Available) {
        $max = 0.0
        foreach ($v in $engines.Values) { if ($v -gt $max) { $max = $v } }
        if ($max -gt 100.0) { $max = 100.0 }
        $result.Busiest = $max
    }
    if ($State.GpuLuids.Count -eq 0 -and $luids.Count -gt 0) { $State.GpuLuids = @($luids.Keys | Sort-Object) }
    return $result
}

function Get-WdMonGpuMemory {
    # Returns @{ PerPid = pid -> @{ Dedicated; Shared }; Dedicated; Shared } (formatted classes are gauges; 20-30 ms)
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $r = @{ PerPid = @{}; Dedicated = $null; Shared = $null }
    if ($State.GpuMode -eq 'none') { return $r }
    $rows = @(Get-CimSafe -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUProcessMemory -Property Name, DedicatedUsage, SharedUsage -TimeoutSec 20)
    foreach ($m in $rows) {
        $mm = $script:WdMonGpuMemRx.Match([string]$m.Name)
        if (-not $mm.Success) { continue }
        $procId = [int]$mm.Groups[1].Value
        $ded = 0L
        $sh = 0L
        try { $ded = [int64]$m.DedicatedUsage } catch { }
        try { $sh = [int64]$m.SharedUsage } catch { }
        if ($r.PerPid.ContainsKey($procId)) {
            $r.PerPid[$procId].Dedicated += $ded
            $r.PerPid[$procId].Shared += $sh
        } else {
            $r.PerPid[$procId] = @{ Dedicated = $ded; Shared = $sh }
        }
    }
    $adapters = @(Get-CimSafe -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory -Property Name, DedicatedUsage, SharedUsage -TimeoutSec 20)
    if ($adapters.Count -gt 0) {
        $d = 0L
        $s = 0L
        foreach ($a in $adapters) {
            try { $d += [int64]$a.DedicatedUsage } catch { }
            try { $s += [int64]$a.SharedUsage } catch { }
        }
        $r.Dedicated = $d
        $r.Shared = $s
    }
    return $r
}

# ---------------------------------------------------------------------------------------------
# Collection: system totals from raw classes (deltas computed here; gauges passed through)
# ---------------------------------------------------------------------------------------------
function Get-WdMonRate {
    # (cur - prev) / seconds for cumulative counters; $null when no previous value or a negative delta.
    [CmdletBinding()]
    param([AllowNull()][object]$Cur, [AllowNull()][object]$Prev, [double]$Seconds)
    if ($null -eq $Cur -or $null -eq $Prev -or $Seconds -le 0) { return $null }
    $d = [double]([int64]$Cur - [int64]$Prev)
    if ($d -lt 0) { return $null }
    return ($d / $Seconds)
}

function Get-WdMonPercentOfTime {
    # 100 * d(counter) / d(timestamp) for PERF_100NSEC_TIMER style counters (already in 100 ns units).
    [CmdletBinding()]
    param([AllowNull()][object]$Cur, [AllowNull()][object]$Prev, [double]$DeltaTicks)
    if ($null -eq $Cur -or $null -eq $Prev -or $DeltaTicks -le 0) { return $null }
    $d = [double]([int64]$Cur - [int64]$Prev)
    $p = 100.0 * $d / $DeltaTicks
    if ($p -lt 0) { $p = 0.0 }
    if ($p -gt 100.0) { $p = 100.0 }
    return $p
}

function Get-WdMonSystemTotals {
    # Returns a hashtable with the samples.csv system columns (rates are $null on the first sample).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $o = @{}
    $prev = $State.PrevSys
    $new = @{}

    # CPU: raw PercentProcessorTime of PerfOS_Processor is IDLE time (inverse counter).
    $cpu = @(Get-CimSafe -ClassName Win32_PerfRawData_PerfOS_Processor -Filter "Name='_Total'" -Property Name, PercentProcessorTime, PercentPrivilegedTime, PercentDPCTime, PercentInterruptTime, Timestamp_Sys100NS -TimeoutSec 20)
    if ($cpu.Count -gt 0) {
        $c = $cpu[0]
        $new.Cpu = $c
        if ($prev.ContainsKey('Cpu')) {
            $p = $prev.Cpu
            $dt = [double]([int64]$c.Timestamp_Sys100NS - [int64]$p.Timestamp_Sys100NS)
            $idle = Get-WdMonPercentOfTime -Cur $c.PercentProcessorTime -Prev $p.PercentProcessorTime -DeltaTicks $dt
            if ($null -ne $idle) { $o.CpuPct = 100.0 - $idle }
            $o.CpuKernelPct = Get-WdMonPercentOfTime -Cur $c.PercentPrivilegedTime -Prev $p.PercentPrivilegedTime -DeltaTicks $dt
            $dpc = Get-WdMonPercentOfTime -Cur $c.PercentDPCTime -Prev $p.PercentDPCTime -DeltaTicks $dt
            $int = Get-WdMonPercentOfTime -Cur $c.PercentInterruptTime -Prev $p.PercentInterruptTime -DeltaTicks $dt
            if ($null -ne $dpc -and $null -ne $int) { $o.CpuDpcIntPct = $dpc + $int }
        }
    }

    # Processor performance (turbo/throttling): PERF_AVERAGE_BULK -> dValue / dBase is already a percentage (verified 100.4 vs 101).
    $ci = @(Get-CimSafe -ClassName Win32_PerfRawData_Counters_ProcessorInformation -Filter "Name='_Total'" -Property Name, PercentProcessorPerformance, PercentProcessorPerformance_Base, PercentProcessorUtility, PercentProcessorUtility_Base, ProcessorFrequency, PercentofMaximumFrequency -TimeoutSec 20)
    if ($ci.Count -gt 0) {
        $c = $ci[0]
        $new.CpuInfo = $c
        try { $o.CpuFreqMHz = [int64]$c.ProcessorFrequency } catch { }
        if ($prev.ContainsKey('CpuInfo')) {
            $p = $prev.CpuInfo
            $db = [double]([int64]$c.PercentProcessorPerformance_Base - [int64]$p.PercentProcessorPerformance_Base)
            if ($db -gt 0) {
                $v = [double]([int64]$c.PercentProcessorPerformance - [int64]$p.PercentProcessorPerformance) / $db
                if ($v -ge 0 -and $v -lt 1000) { $o.CpuPerfPct = $v }
            }
            $db = [double]([int64]$c.PercentProcessorUtility_Base - [int64]$p.PercentProcessorUtility_Base)
            if ($db -gt 0) {
                $v = [double]([int64]$c.PercentProcessorUtility - [int64]$p.PercentProcessorUtility) / $db
                if ($v -ge 0 -and $v -lt 10000) { $o.CpuUtilityPct = $v }
            }
        }
    }

    # Memory: gauges + PagesPersec (cumulative hard faults).
    $mem = @(Get-CimSafe -ClassName Win32_PerfRawData_PerfOS_Memory -Property AvailableBytes, CommittedBytes, CommitLimit, PoolNonpagedBytes, PagesPersec, Timestamp_Sys100NS -TimeoutSec 20)
    if ($mem.Count -gt 0) {
        $m = $mem[0]
        $new.Mem = $m
        try {
            $avail = [int64]$m.AvailableBytes
            $o.MemAvailMB = [int64][math]::Floor($avail / 1MB)
            if ($null -ne $State.MemTotalMB) { $o.MemUsedMB = [int64]$State.MemTotalMB - $o.MemAvailMB }
            $o.CommitBytes = [int64]$m.CommittedBytes
            $o.CommitLimitBytes = [int64]$m.CommitLimit
            if ($o.CommitLimitBytes -gt 0) { $o.CommitPct = 100.0 * $o.CommitBytes / $o.CommitLimitBytes }
            $o.PoolNonpagedBytes = [int64]$m.PoolNonpagedBytes
        } catch { }
        if ($prev.ContainsKey('Mem')) {
            $sec = [double]([int64]$m.Timestamp_Sys100NS - [int64]$prev.Mem.Timestamp_Sys100NS) / 1e7
            $r = Get-WdMonRate -Cur $m.PagesPersec -Prev $prev.Mem.PagesPersec -Seconds $sec
            if ($null -ne $r) { $o.PagesPerSec = [int64][math]::Round($r, 0, [MidpointRounding]::AwayFromZero) }
        }
    }

    # Disk _Total: PercentIdleTime is a precision timer against PercentIdleTime_Base; bytes/transfers are bulk counters.
    $disk = @(Get-CimSafe -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk -Filter "Name='_Total'" -Property Name, PercentIdleTime, PercentIdleTime_Base, CurrentDiskQueueLength, DiskReadBytesPersec, DiskWriteBytesPersec, DiskTransfersPersec, AvgDisksecPerTransfer, Frequency_PerfTime, Timestamp_Sys100NS -TimeoutSec 20)
    if ($disk.Count -gt 0) {
        $d = $disk[0]
        $new.Disk = $d
        try { $o.DiskQueue = [int64]$d.CurrentDiskQueueLength } catch { }
        if ($prev.ContainsKey('Disk')) {
            $p = $prev.Disk
            $sec = [double]([int64]$d.Timestamp_Sys100NS - [int64]$p.Timestamp_Sys100NS) / 1e7
            $dBase = [double]([int64]$d.PercentIdleTime_Base - [int64]$p.PercentIdleTime_Base)
            if ($dBase -gt 0) {
                $idle = 100.0 * [double]([int64]$d.PercentIdleTime - [int64]$p.PercentIdleTime) / $dBase
                if ($idle -lt 0) { $idle = 0.0 }
                if ($idle -gt 100) { $idle = 100.0 }
                $o.DiskActivePct = 100.0 - $idle
            }
            $r = Get-WdMonRate -Cur $d.DiskReadBytesPersec -Prev $p.DiskReadBytesPersec -Seconds $sec
            if ($null -ne $r) { $o.DiskReadBps = [int64][math]::Round($r, 0, [MidpointRounding]::AwayFromZero) }
            $r = Get-WdMonRate -Cur $d.DiskWriteBytesPersec -Prev $p.DiskWriteBytesPersec -Seconds $sec
            if ($null -ne $r) { $o.DiskWriteBps = [int64][math]::Round($r, 0, [MidpointRounding]::AwayFromZero) }
            $dTr = [double]([int64]$d.DiskTransfersPersec - [int64]$p.DiskTransfersPersec)
            if ($dTr -gt 0 -and $sec -gt 0) {
                $o.DiskTransfersPerSec = [int64][math]::Round($dTr / $sec, 0, [MidpointRounding]::AwayFromZero)
                $freq = [double][int64]$d.Frequency_PerfTime
                if ($freq -gt 0) {
                    $dAvg = [double]([int64]$d.AvgDisksecPerTransfer - [int64]$p.AvgDisksecPerTransfer)
                    if ($dAvg -ge 0) { $o.DiskAvgMs = 1000.0 * ($dAvg / $freq) / $dTr }
                }
            } elseif ($sec -gt 0) {
                $o.DiskTransfersPerSec = 0L
            }
        }
    }

    # Network: sum of all adapters (bulk counters per adapter name).
    $net = @(Get-CimSafe -ClassName Win32_PerfRawData_Tcpip_NetworkInterface -Property Name, BytesReceivedPersec, BytesSentPersec, Timestamp_Sys100NS -TimeoutSec 20)
    if ($net.Count -gt 0) {
        $map = @{}
        foreach ($a in $net) { $map[[string]$a.Name] = $a }
        $new.Net = $map
        if ($prev.ContainsKey('Net')) {
            $recv = 0.0
            $sent = 0.0
            $any = $false
            foreach ($name in $map.Keys) {
                if (-not $prev.Net.ContainsKey($name)) { continue }
                $a = $map[$name]
                $p = $prev.Net[$name]
                $sec = [double]([int64]$a.Timestamp_Sys100NS - [int64]$p.Timestamp_Sys100NS) / 1e7
                $r1 = Get-WdMonRate -Cur $a.BytesReceivedPersec -Prev $p.BytesReceivedPersec -Seconds $sec
                $r2 = Get-WdMonRate -Cur $a.BytesSentPersec -Prev $p.BytesSentPersec -Seconds $sec
                if ($null -ne $r1) { $recv += $r1; $any = $true }
                if ($null -ne $r2) { $sent += $r2; $any = $true }
            }
            if ($any) {
                $o.NetRecvBps = [int64][math]::Round($recv, 0, [MidpointRounding]::AwayFromZero)
                $o.NetSentBps = [int64][math]::Round($sent, 0, [MidpointRounding]::AwayFromZero)
            }
        }
    }

    # System: gauges + context switches (bulk).
    $sys = @(Get-CimSafe -ClassName Win32_PerfRawData_PerfOS_System -Property Processes, Threads, ProcessorQueueLength, ContextSwitchesPersec, Timestamp_Sys100NS -TimeoutSec 20)
    if ($sys.Count -gt 0) {
        $s = $sys[0]
        $new.Sys = $s
        try { $o.ProcessCount = [int64]$s.Processes; $o.ThreadCount = [int64]$s.Threads; $o.ProcQueue = [int64]$s.ProcessorQueueLength } catch { }
        if ($prev.ContainsKey('Sys')) {
            $sec = [double]([int64]$s.Timestamp_Sys100NS - [int64]$prev.Sys.Timestamp_Sys100NS) / 1e7
            $r = Get-WdMonRate -Cur $s.ContextSwitchesPersec -Prev $prev.Sys.ContextSwitchesPersec -Seconds $sec
            if ($null -ne $r) { $o.ContextSwitchesPerSec = [int64][math]::Round($r, 0, [MidpointRounding]::AwayFromZero) }
        }
    }

    # Battery (absent on desktops) and thermal zone (often absent).
    $bat = @(Get-CimSafe -ClassName Win32_Battery -Property EstimatedChargeRemaining, BatteryStatus -TimeoutSec 20)
    if ($bat.Count -gt 0) {
        try { $o.BatteryPct = [int]$bat[0].EstimatedChargeRemaining } catch { }
        $status = 0
        try { $status = [int]$bat[0].BatteryStatus } catch { $status = 0 }
        if ($status -eq 1) { $o.OnBattery = $true } elseif ($status -ge 2) { $o.OnBattery = $false }
    }
    if (-not $State.ContainsKey('ThermalUnavailable')) {
        $tz = @(Get-CimSafe -ClassName Win32_PerfFormattedData_Counters_ThermalZoneInformation -Property Name, Temperature, ThrottleReasons -TimeoutSec 20)
        if ($tz.Count -eq 0) { $State.ThermalUnavailable = $true }
        else {
            $maxT = 0.0
            $reasons = 0L
            foreach ($z in $tz) {
                $t = 0.0
                try { $t = [double]$z.Temperature } catch { $t = 0.0 }
                if ($t -gt $maxT) { $maxT = $t }
                try { $reasons = $reasons -bor [int64]$z.ThrottleReasons } catch { }
            }
            # "Temperature" is Kelvin (339 -> 65.9 C); values above 1000 come from tenths-of-Kelvin providers.
            if ($maxT -gt 1000) { $maxT = $maxT / 10.0 }
            if ($maxT -gt 200) { $o.TempC = $maxT - 273.15 }
            $o.ThrottleReasons = $reasons
        }
    }

    $State.PrevSys = $new
    return $o
}

# ---------------------------------------------------------------------------------------------
# Collection: window state (Get-Process, every 3rd sample), session idle/lock, TCP, DNS
# ---------------------------------------------------------------------------------------------
function Update-WdMonWindowInfo {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $wi = @{}
    foreach ($p in @(Get-Process -ErrorAction SilentlyContinue)) {
        $h = $false
        $priv = $null
        try { $h = ($p.MainWindowHandle -ne [IntPtr]::Zero) } catch { $h = $false }
        try { $priv = [int64]$p.PrivateMemorySize64 } catch { $priv = $null }
        $wi[[int]$p.Id] = @{ HasWindow = $h; Private = $priv }
    }
    $State.WinInfo = $wi
    $State.WinInfoSample = $State.SampleNo
}

function Get-WdMonSessionState {
    # Returns @{ IdleSeconds; Locked; LockFlag }
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [bool]$LogonUiPresent)
    $r = @{ IdleSeconds = $null; Locked = $LogonUiPresent; LockFlag = $null }
    if ($State.NativeSession) {
        try {
            $idle = [WinDebug.Session]::IdleSeconds()
            if ($idle -ge 0) { $r.IdleSeconds = [int64][math]::Floor($idle) }
        } catch { }
        try {
            $f = [WinDebug.Session]::LockFlag()
            $r.LockFlag = $f
            if ($f -eq 0) { $r.Locked = $true }
        } catch { }
    }
    return $r
}

function Update-WdMonTcp {
    # Writes first-seen connections (Established + Listen) to net.csv and updates per-process counters.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [Parameter(Mandatory = $true)][hashtable]$Snap, [string]$TsIso, [bool]$IsIdle)
    $rows = @(Get-CimSafe -Namespace 'root/StandardCimv2' -ClassName MSFT_NetTCPConnection -Filter 'State=5 OR State=2' -Property OwningProcess, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, CreationTime -TimeoutSec 20)
    if ($rows.Count -eq 0) { return 0 }
    $w = $State.Writers['net']
    $pool = @(Get-WinDebugRule -Name 'PoolPorts')
    $privateRx = [string](Get-WinDebugRule -Name 'PrivateIpRegex')
    $written = 0
    foreach ($c in $rows) {
        $procId = 0
        try { $procId = [int]$c.OwningProcess } catch { $procId = 0 }
        $key = ''
        $name = ''
        if ($Snap.PidToKey.ContainsKey($procId)) { $key = $Snap.PidToKey[$procId]; $name = $Snap.Names[$procId] }
        elseif ($State.PidNames.ContainsKey($procId)) { $name = [string]$State.PidNames[$procId] }
        if ($key -eq '') { $key = '{0}|?' -f $procId.ToString($State.Inv) }
        $connState = 0
        try { $connState = [int]$c.State } catch { $connState = 0 }
        $remote = [string]$c.RemoteAddress
        $rport = 0
        try { $rport = [int]$c.RemotePort } catch { }
        $lport = 0
        try { $lport = [int]$c.LocalPort } catch { }
        if ($connState -eq 5) {
            if ($remote -match '^(127\.|::1$|0\.0\.0\.0$|::$|fe80:)') { continue }
            $tuple = '{0}|{1}|{2}' -f $key, $remote, $rport.ToString($State.Inv)
            $stateText = 'Established'
        } else {
            $tuple = '{0}|L|{1}' -f $key, $lport.ToString($State.Inv)
            $stateText = 'Listen'
        }
        if (-not $State.NetSeen.Add($tuple)) { continue }
        $isPrivate = $false
        $isPool = $false
        if ($connState -eq 5) {
            $isPrivate = ($remote -match $privateRx)
            $isPool = ($pool -contains $rport)
        }
        $created = ''
        $createdDt = $null
        try { if ($null -ne $c.CreationTime) { $createdDt = [DateTime]$c.CreationTime; $created = Get-IsoTimestamp -Date $createdDt } } catch { $created = ''; $createdDt = $null }
        # Pre-existing connection (same rule as Analyze I14): it was opened before the monitor started (ConnCreated
        # earlier than the run start; without a creation time, one discovered in sample 1). It is still written to
        # net.csv - the endpoint is evidence - but it says nothing about idle-time behaviour, so it never counts
        # as "opened while idle" in procsum.json.
        $preExisting = $false
        if ($null -ne $createdDt) { $preExisting = ($createdDt -lt [DateTime]$State.Start) }
        elseif ([int]$State.SampleNo -le 1) { $preExisting = $true }
        Write-WdMonCsvRow -Writer $w -Values @($TsIso, $key, $procId, $name, $stateText, [string]$c.LocalAddress, $lport, $(if ($connState -eq 5) { $remote } else { '' }), $(if ($connState -eq 5) { $rport } else { $null }), $isPrivate, $isPool, $IsIdle, $created)
        $written++
        if ($State.Sum.ContainsKey($key)) {
            $s = $State.Sum[$key]
            if ($connState -eq 5) {
                $s.DistinctEndpoints = [int]$s.DistinctEndpoints + 1
                if (-not $State.RemoteIps.ContainsKey($key)) { $State.RemoteIps[$key] = New-Object 'System.Collections.Generic.HashSet[string]' }
                if ($State.RemoteIps[$key].Add($remote)) { $s.DistinctRemoteIPs = [int]$s.DistinctRemoteIPs + 1 }
                if (-not $isPrivate) { $s.PublicEndpoints = [int]$s.PublicEndpoints + 1 }
                if ($isPool) { $s.PortHits = [int]$s.PortHits + 1; [void]$State.Watch.Add($key) }
                if ($IsIdle -and -not $preExisting) { $s.ConnectionsWhileIdle = [int]$s.ConnectionsWhileIdle + 1 }
            } else {
                $s.ListenPorts = [int]$s.ListenPorts + 1
            }
        }
    }
    return $written
}

function Update-WdMonDns {
    # Writes first-seen (name, address) pairs of the DNS client cache to dns.csv (not attributable to a PID).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [string]$TsIso)
    $rows = @(Get-CimSafe -Namespace 'root/StandardCimv2' -ClassName MSFT_DNSClientCache -Property Entry, Data, Type, TimeToLive, Status -TimeoutSec 20)
    if ($rows.Count -eq 0) { return 0 }
    $w = $State.Writers['dns']
    $written = 0
    foreach ($r in $rows) {
        $status = 0
        try { $status = [int]$r.Status } catch { $status = 0 }
        if ($status -ne 0) { continue }
        $data = [string]$r.Data
        $entry = [string]$r.Entry
        if ([string]::IsNullOrEmpty($data) -or [string]::IsNullOrEmpty($entry)) { continue }
        $type = 0
        try { $type = [int]$r.Type } catch { $type = 0 }
        # ("continue" inside a switch would only leave the switch, so the type filter is checked afterwards.)
        $typeText = ''
        if ($type -eq 1) { $typeText = 'A' } elseif ($type -eq 28) { $typeText = 'AAAA' } elseif ($type -eq 5) { $typeText = 'CNAME' }
        if ($typeText -eq '') { continue }
        $tuple = '{0}|{1}' -f $entry.ToLowerInvariant(), $data
        if (-not $State.DnsSeen.Add($tuple)) { continue }
        $ttl = $null
        try { $ttl = [int64]$r.TimeToLive } catch { $ttl = $null }
        Write-WdMonCsvRow -Writer $w -Values @($TsIso, $entry, $data, $typeText, $ttl)
        $written++
    }
    return $written
}

# ---------------------------------------------------------------------------------------------
# Per-process cumulative summary (procsum.json). Values are strings/numbers/bools only (fast JSON).
# ---------------------------------------------------------------------------------------------
function New-WdMonSumEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Rec, [string]$TsIso, [bool]$PresentAtStart)
    return @{
        Key = $Rec.Key; Pid = $Rec.Pid; Name = $Rec.Name; Path = ''; ImageName = ''; CommandLine = ''; Flags = ''; SessionId = $null; ParentName = ''; LocationClass = ''; Owner = ''
        Started = (ConvertFrom-WdMonFileTime -FileTime $Rec.Started); FirstSeen = $TsIso; LastSeen = $TsIso; PresentAtStart = $PresentAtStart
        Samples = 0; RowsWritten = 0
        CpuSeconds = 0.0; CpuSum = 0.0; CpuMax = 0.0; CpuCoresMax = 0.0
        SamplesIdle = 0; SamplesActive = 0; CpuIdleSum = 0.0; CpuActiveSum = 0.0
        GpuSum = 0.0; GpuMax = 0.0; GpuSeconds = 0.0; GpuComputeSeconds = 0.0; Gpu3DSeconds = 0.0; GpuVideoSeconds = 0.0; GpuIdleSum = 0.0; GpuActiveSum = 0.0
        ReadBytes = 0.0; WriteBytes = 0.0
        WSMax = [int64]$Rec.WS; WSFirst = [int64]$Rec.WS; WSLast = [int64]$Rec.WS
        LowPrioSamples = 0; BasePriority = $Rec.Prio
        HasWindow = $null; HasWindowEver = $false
        Exited = $false; ExitTime = ''
        DistinctEndpoints = 0; DistinctRemoteIPs = 0; PublicEndpoints = 0; ListenPorts = 0; PortHits = 0; ConnectionsWhileIdle = 0
    }
}

function Update-WdMonSumEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Entry, [Parameter(Mandatory = $true)][hashtable]$Rec, [string]$TsIso, [double]$Seconds, [bool]$IsIdle)
    $s = $Entry
    $s.LastSeen = $TsIso
    $s.WSLast = [int64]$Rec.WS
    if ([int64]$Rec.WS -gt [int64]$s.WSMax) { $s.WSMax = [int64]$Rec.WS }
    $s.BasePriority = $Rec.Prio
    if ($null -ne $Rec.HasWindow) {
        $s.HasWindow = [bool]$Rec.HasWindow
        if ($Rec.HasWindow) { $s.HasWindowEver = $true }
    }
    if (-not $Rec.HasDelta) { return }
    $s.Samples = [int]$s.Samples + 1
    $cpu = [double]$Rec.CpuPct
    $cores = [double]$Rec.CpuCores
    $s.CpuSeconds = [double]$s.CpuSeconds + $cores * $Seconds
    $s.CpuSum = [double]$s.CpuSum + $cpu
    if ($cpu -gt [double]$s.CpuMax) { $s.CpuMax = $cpu }
    if ($cores -gt [double]$s.CpuCoresMax) { $s.CpuCoresMax = $cores }
    $gpu = 0.0
    if ($null -ne $Rec.Gpu) {
        $gpu = [double]$Rec.Gpu.Total
        $s.GpuSum = [double]$s.GpuSum + $gpu
        if ($gpu -gt [double]$s.GpuMax) { $s.GpuMax = $gpu }
        $s.GpuSeconds = [double]$s.GpuSeconds + $gpu / 100.0 * $Seconds
        $s.GpuComputeSeconds = [double]$s.GpuComputeSeconds + [double]$Rec.Gpu.Compute / 100.0 * $Seconds
        $s.Gpu3DSeconds = [double]$s.Gpu3DSeconds + [double]$Rec.Gpu.ThreeD / 100.0 * $Seconds
        $s.GpuVideoSeconds = [double]$s.GpuVideoSeconds + ([double]$Rec.Gpu.VDec + [double]$Rec.Gpu.VEnc) / 100.0 * $Seconds
    }
    if ($IsIdle) {
        $s.SamplesIdle = [int]$s.SamplesIdle + 1
        $s.CpuIdleSum = [double]$s.CpuIdleSum + $cpu
        $s.GpuIdleSum = [double]$s.GpuIdleSum + $gpu
    } else {
        $s.SamplesActive = [int]$s.SamplesActive + 1
        $s.CpuActiveSum = [double]$s.CpuActiveSum + $cpu
        $s.GpuActiveSum = [double]$s.GpuActiveSum + $gpu
    }
    if ($null -ne $Rec.ReadBps) { $s.ReadBytes = [double]$s.ReadBytes + [double]$Rec.ReadBps * $Seconds }
    if ($null -ne $Rec.WriteBps) { $s.WriteBytes = [double]$s.WriteBytes + [double]$Rec.WriteBps * $Seconds }
    if ([int]$Rec.Prio -le 6 -and [int]$Rec.Prio -gt 0) { $s.LowPrioSamples = [int]$s.LowPrioSamples + 1 }
}

function Limit-WdMonSum {
    # Keeps the in-memory summary bounded on very long runs: drop exited, unflagged, short-lived entries first.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [int]$Max = 20000)
    if ($State.Sum.Count -le $Max) { return }
    $removed = 0
    foreach ($k in @($State.Sum.Keys)) {
        $s = $State.Sum[$k]
        if ($s.Exited -and [int]$s.Samples -lt 3 -and [string]$s.Flags -eq '' -and [int]$s.PortHits -eq 0) {
            $State.Sum.Remove($k)
            if ($State.RemoteIps.ContainsKey($k)) { $State.RemoteIps.Remove($k) }
            $removed++
            if ($State.Sum.Count -le $Max) { break }
        }
    }
    Write-Log -Level Info -Message ('Summary trimmed: {0} short-lived exited processes dropped from memory (they stay in the CSV files)' -f $removed.ToString($State.Inv))
}

# ---------------------------------------------------------------------------------------------
# Metadata for new processes (procmeta.csv)
# ---------------------------------------------------------------------------------------------
function Test-WdMonSystemBinaryLocation {
    # True when the executable's directory IS one of the allowed locations (exact, case-insensitive match).
    # A plain StartsWith let every subfolder pass - C:\Windows\System32\Tasks, System32\spool\drivers\color and
    # C:\Windows\Tasks are writable by any user - and even sibling names such as C:\Windows\System32Evil.
    # An entry that ends with "\*" (or Defender's versioned "...\Windows Defender\Platform" folder) accepts exactly
    # one subfolder level below it (Platform\<version>\MsMpEng.exe), never deeper and never a sibling.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path, [AllowNull()][string[]]$Allowed)
    if ([string]::IsNullOrEmpty($Path) -or $null -eq $Allowed) { return $false }
    $dir = ''
    try { $dir = [string][IO.Path]::GetDirectoryName($Path) } catch { $dir = '' }
    if ([string]::IsNullOrEmpty($dir)) { return $false }
    $dir = $dir.TrimEnd('\')
    $parent = ''
    try { $parent = [string][IO.Path]::GetDirectoryName($dir) } catch { $parent = '' }
    if (-not [string]::IsNullOrEmpty($parent)) { $parent = $parent.TrimEnd('\') }
    foreach ($a in $Allowed) {
        if ([string]::IsNullOrWhiteSpace($a)) { continue }
        $entry = [string]$a
        $oneLevel = $false
        if ($entry.EndsWith('\*')) { $oneLevel = $true; $entry = $entry.Substring(0, $entry.Length - 2) }
        $exp = ''
        try { $exp = [Environment]::ExpandEnvironmentVariables($entry).TrimEnd('\') } catch { $exp = '' }
        if ([string]::IsNullOrEmpty($exp) -or $exp.IndexOf('%') -ge 0) { continue }   # unexpanded variable: never a match
        if ($exp -match '\\Windows Defender\\Platform$') { $oneLevel = $true }
        if ([string]::Equals($dir, $exp, [StringComparison]::OrdinalIgnoreCase)) { return $true }
        if ($oneLevel -and -not [string]::IsNullOrEmpty($parent) -and [string]::Equals($parent, $exp, [StringComparison]::OrdinalIgnoreCase)) { return $true }
    }
    return $false
}

function Get-WdMonProcFlags {
    [CmdletBinding()]
    param([string]$Name, [string]$Path, [string]$CommandLine, [string]$ParentName, [bool]$IsSelf)
    $flags = New-Object 'System.Collections.Generic.List[string]'
    if ($IsSelf) { $flags.Add('Self'); return ($flags -join ';') }
    $rules = $script:Rules
    if (-not [string]::IsNullOrEmpty($CommandLine) -and $CommandLine -match 'WinDebug\.ps1') { $flags.Add('WinDebugTool') }
    if (-not [string]::IsNullOrEmpty($Path) -and $Path -match [string]$rules['SuspiciousPathRegex']) { $flags.Add('SuspiciousPath') }
    if (-not [string]::IsNullOrEmpty($CommandLine) -and $CommandLine -match [string]$rules['MinerTokenRegex']) { $flags.Add('MinerTokens') }
    if (-not [string]::IsNullOrEmpty($Name) -and $Name -match [string]$rules['ScriptHostRegex'] -and -not [string]::IsNullOrEmpty($CommandLine)) {
        # Only the STRONG indicators (encoded command, download cradle, IEX, URL, ...) are a red flag; the WEAK
        # ones (-ExecutionPolicy Bypass, -NoProfile, -WindowStyle Hidden, -NonInteractive) are how every ordinary
        # scheduled script is launched and stay informational (ScriptHostWeakArgs; not on the watch list).
        $strongRx = [string]$rules['ScriptHostStrongArgRegex']
        if ([string]::IsNullOrEmpty($strongRx)) { $strongRx = [string]$rules['ScriptHostArgRegex'] }
        $weakRx = [string]$rules['ScriptHostWeakArgRegex']
        if ($CommandLine -match $strongRx) { $flags.Add('ScriptHostRedFlag') }
        elseif (-not [string]::IsNullOrEmpty($weakRx) -and $CommandLine -match $weakRx) { $flags.Add('ScriptHostWeakArgs') }
    }
    if (-not [string]::IsNullOrEmpty($Name)) {
        $sysNames = @($rules['SystemBinaryNames'])
        $matchName = $null
        foreach ($sn in $sysNames) { if ([string]::Equals($sn, $Name, [StringComparison]::OrdinalIgnoreCase)) { $matchName = $sn; break } }
        if ($null -ne $matchName -and -not [string]::IsNullOrEmpty($Path)) {
            $locs = $rules['SystemBinaryLocations']
            $allowed = @($locs['default'])
            if ($locs.Contains($matchName)) { $allowed = @($locs[$matchName]) }
            if (-not (Test-WdMonSystemBinaryLocation -Path $Path -Allowed $allowed)) { $flags.Add('SystemNameOutsideSystem32') }
        }
        $parents = $rules['ExpectedParents']
        $pKey = $null
        foreach ($pk in $parents.Keys) { if ([string]::Equals($pk, $Name, [StringComparison]::OrdinalIgnoreCase)) { $pKey = $pk; break } }
        if ($null -ne $pKey) {
            $allowedParents = @($parents[$pKey])
            # A parent that already exited is indeterminate (explorer's userinit always has) and is not flagged.
            if (-not ($allowedParents -contains 'any') -and $ParentName -ne '<exited>') {
                $pn = $ParentName
                if ([string]::IsNullOrEmpty($pn)) { $pn = '<none>' }
                $found = $false
                foreach ($ap in $allowedParents) { if ([string]::Equals($ap, $pn, [StringComparison]::OrdinalIgnoreCase)) { $found = $true; break } }
                if (-not $found) { $flags.Add('UnexpectedParent') }
            }
        }
    }
    return ($flags -join ';')
}

function Get-WdMonFileInfo {
    # Version info, signature and SHA256 of one executable (slow part: 12-300 ms signature, hash I/O bound).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $e = @{ Size = $null; Modified = $null; ModifiedIso = ''; CreatedIso = ''; Company = ''; Description = ''; ProductVersion = ''; OriginalFilename = '';
            SigStatus = ''; Signer = ''; IsOSBinary = ''; Sha256 = ''; Status = 'ok'; Resolved = (Get-IsoTimestamp) }
    $fi = New-Object System.IO.FileInfo($Path)
    if (-not $fi.Exists) { $e.Status = 'NotFound'; return $e }
    $e.Size = [int64]$fi.Length
    $e.Modified = [int64]$fi.LastWriteTimeUtc.Ticks
    $e.ModifiedIso = Get-IsoTimestamp -Date $fi.LastWriteTime
    $e.CreatedIso = Get-IsoTimestamp -Date $fi.CreationTime
    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        if ($null -ne $vi) {
            $e.Company = [string]$vi.CompanyName
            $e.Description = [string]$vi.FileDescription
            $e.ProductVersion = [string]$vi.ProductVersion
            $e.OriginalFilename = [string]$vi.OriginalFilename
        }
    } catch { }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        if ($null -ne $sig) {
            $e.SigStatus = [string]$sig.Status
            if ($null -ne $sig.SignerCertificate) {
                $subj = [string]$sig.SignerCertificate.Subject
                if ($subj.Length -gt 200) { $subj = $subj.Substring(0, 200) }
                $e.Signer = $subj
            }
            $e.IsOSBinary = [bool]$sig.IsOSBinary
        }
    } catch { $e.SigStatus = 'Error' }
    if ($fi.Length -gt $script:WdMonMaxHashBytes) {
        $e.Sha256 = 'SKIPPED_SIZE'
    } else {
        try { $e.Sha256 = ([string](Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash).ToLowerInvariant() } catch { $e.Sha256 = 'ERROR' }
    }
    return $e
}

function Write-WdMonMetaRow {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [Parameter(Mandatory = $true)][hashtable]$Meta, [AllowNull()][hashtable]$File)
    if ($null -ne $File) {
        $Meta.Company = [string]$File.Company
        $Meta.Description = [string]$File.Description
        $Meta.ProductVersion = [string]$File.ProductVersion
        $Meta.OriginalFilename = [string]$File.OriginalFilename
        $Meta.FileSize = $File.Size
        $Meta.FileCreated = [string]$File.CreatedIso
        $Meta.FileModified = [string]$File.ModifiedIso
        $Meta.SigStatus = [string]$File.SigStatus
        $Meta.Signer = [string]$File.Signer
        $Meta.IsOSBinary = $File.IsOSBinary
        $Meta.Sha256 = [string]$File.Sha256
        if ($File.Status -eq 'NotFound' -and [string]::IsNullOrEmpty($Meta.AccessNote)) { $Meta.AccessNote = 'file not found' }
    }
    $w = $State.Writers['procmeta']
    $values = New-Object 'System.Collections.Generic.List[object]'
    foreach ($col in $w.Columns) { $values.Add($Meta[$col]) }
    Write-WdMonCsvRow -Writer $w -Values $values.ToArray()
}

function Test-WdMonFileCacheHit {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [string]$Lower, [string]$Path)
    if (-not $State.FileCache.ContainsKey($Lower)) { return $false }
    $c = $State.FileCache[$Lower]
    try {
        $fi = New-Object System.IO.FileInfo($Path)
        # A missing image (self-deleting dropper, uninstalled program) is never a hit: the queue then records
        # Status NotFound / AccessNote "file not found" instead of copying a stale signature and hash as verified.
        if (-not $fi.Exists) { return $false }
        if ($null -eq $c.Size -or $null -eq $c.Modified) { return $false }
        return ([int64]$c.Size -eq [int64]$fi.Length -and [int64]$c.Modified -eq [int64]$fi.LastWriteTimeUtc.Ticks)
    } catch { return $false }
}

function Resolve-WdMonNewProcesses {
    # One Win32_Process batch + owner + flags for every first-seen key; writes procmeta rows (immediately, or
    # after the file info of the path has been resolved by Resolve-WdMonFileQueue). Returns the number of
    # processes whose path was not readable.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [Parameter(Mandatory = $true)][hashtable]$Snap, [Parameter(Mandatory = $true)][object[]]$NewRecs, [string]$TsIso)
    if ($NewRecs.Count -eq 0) { return 0 }
    $inv = $State.Inv
    $pids = @($NewRecs | ForEach-Object { [int]$_.Pid } | Sort-Object -Unique)
    $w32 = @{}
    $rows = @()
    $props = @('ProcessId', 'Name', 'ExecutablePath', 'CommandLine', 'ParentProcessId', 'SessionId')
    if ($pids.Count -gt 10) {
        $rows = @(Get-CimSafe -ClassName Win32_Process -Property $props -TimeoutSec 30)
    } else {
        $filter = (@($pids | ForEach-Object { 'ProcessId={0}' -f $_.ToString($inv) }) -join ' OR ')
        $rows = @(Get-CimSafe -ClassName Win32_Process -Filter $filter -Property $props -TimeoutSec 20)
    }
    foreach ($r in $rows) { try { $w32[[int]$r.ProcessId] = $r } catch { } }
    $noPath = 0
    foreach ($rec in $NewRecs) {
        $procId = [int]$rec.Pid
        $w = $null
        if ($w32.ContainsKey($procId)) { $w = $w32[$procId] }
        $path = ''
        $cmd = ''
        $image = ''
        $session = $null
        if ($null -ne $w) {
            $path = [string]$w.ExecutablePath
            $cmd = [string]$w.CommandLine
            $image = [string]$w.Name
            try { $session = [int]$w.SessionId } catch { $session = $null }
        }
        $ownerRaw = ''
        if ($State.NativeOwner) { try { $ownerRaw = [WinDebug.ProcOwner]::Get($procId) } catch { $ownerRaw = '' } }
        $owner = ''
        $ownerSid = ''
        $ownerDenied = $false
        if ($ownerRaw.StartsWith('E_')) { $ownerDenied = ($ownerRaw -match '^E_(OPEN|TOKEN)5$') }
        else {
            $bar = $ownerRaw.IndexOf('|')
            if ($bar -ge 0) { $ownerSid = $ownerRaw.Substring(0, $bar); $owner = $ownerRaw.Substring($bar + 1) } else { $ownerSid = $ownerRaw }
        }
        $access = ''
        if ($null -eq $w) { $access = 'exited before metadata' }
        elseif ([string]::IsNullOrEmpty($path) -and -not $script:IsAdmin) { $access = '(requires administrator)'; $noPath++ }
        elseif ([string]::IsNullOrEmpty($path)) { $access = 'path not available'; $noPath++ }
        elseif ($ownerDenied -and -not $script:IsAdmin) { $access = 'owner (requires administrator)' }
        if ($ownerDenied -and -not $script:IsAdmin -and $owner -eq '') { $owner = '(requires administrator)' }
        $ppid = [int]$rec.Ppid
        $parentName = ''
        $parentKey = ''
        if ($ppid -eq 0) { $parentName = '<none>' }
        elseif ($Snap.Names.ContainsKey($ppid)) { $parentName = [string]$Snap.Names[$ppid]; $parentKey = [string]$Snap.PidToKey[$ppid] }
        elseif ($State.PidNames.ContainsKey($ppid)) { $parentName = [string]$State.PidNames[$ppid] }
        else { $parentName = '<exited>' }
        $State.PidNames[$procId] = $rec.Name
        $isSelf = ($procId -eq $State.Pid)
        $loc = 'Unknown'
        if (-not [string]::IsNullOrEmpty($path)) { $loc = Get-ProcessLocationClass -Path $path }
        # Flags are matched on the ORIGINAL command line (a masked "-o pool:4444 -u <wallet>" must still count as
        # MinerTokens); only the text written to procmeta.csv / procsum.json is masked (Hide-WdSecret, lib\Common.ps1).
        $flags = Get-WdMonProcFlags -Name $rec.Name -Path $path -CommandLine $cmd -ParentName $parentName -IsSelf $isSelf
        $cmdOut = $cmd
        if (-not [string]::IsNullOrEmpty($cmd)) { try { $cmdOut = [string](Hide-WdSecret -Text $cmd) } catch { $cmdOut = $cmd } }
        if ($isSelf -or $flags -match '(^|;)WinDebugTool(;|$)') { [void]$State.ToolPids.Add($procId) }
        $meta = @{
            Key = $rec.Key; Pid = $procId; Name = $rec.Name; ImageName = $image; Path = $path; CommandLine = $cmdOut; Ppid = $ppid; ParentKey = $parentKey
            ParentName = $parentName; Started = (ConvertFrom-WdMonFileTime -FileTime $rec.Started); FirstSeen = $TsIso; SessionId = $session
            Owner = $owner; OwnerSid = $ownerSid; LocationClass = $loc; Company = ''; Description = ''; ProductVersion = ''; OriginalFilename = ''
            FileSize = $null; FileCreated = ''; FileModified = ''; SigStatus = ''; Signer = ''; IsOSBinary = $null; Sha256 = ''; Flags = $flags; AccessNote = $access
        }
        if ($State.Sum.ContainsKey($rec.Key)) {
            $s = $State.Sum[$rec.Key]
            $s.Path = $path; $s.ImageName = $image; $s.Flags = $flags; $s.SessionId = $session; $s.ParentName = $parentName; $s.LocationClass = $loc
            $s.Owner = $owner; $s.CommandLine = $(if ($cmdOut.Length -gt 300) { $cmdOut.Substring(0, 300) } else { $cmdOut })
        }
        # Watch list (row every sample): any flag except the informational ones (Self, WinDebugTool, ScriptHostWeakArgs).
        $watchFlag = $false
        foreach ($fl in $flags.Split(@(';'), [StringSplitOptions]::RemoveEmptyEntries)) {
            if ($fl -ne 'Self' -and $fl -ne 'WinDebugTool' -and $fl -ne 'ScriptHostWeakArgs') { $watchFlag = $true; break }
        }
        if ($watchFlag) { [void]$State.Watch.Add($rec.Key) }
        if ([string]::IsNullOrEmpty($path)) {
            Write-WdMonMetaRow -State $State -Meta $meta -File $null
            continue
        }
        $lower = $path.ToLowerInvariant()
        if (Test-WdMonFileCacheHit -State $State -Lower $lower -Path $path) {
            Write-WdMonMetaRow -State $State -Meta $meta -File $State.FileCache[$lower]
            continue
        }
        if (-not $State.PendingMeta.ContainsKey($lower)) { $State.PendingMeta[$lower] = New-Object 'System.Collections.Generic.List[object]' }
        $State.PendingMeta[$lower].Add($meta)
        if ($State.FileQueued.Add($lower)) { $State.FileQueue.Enqueue($path) }
    }
    return $noPath
}

function Resolve-WdMonFileQueue {
    # Resolves queued executable paths within a time budget (never stalls sampling), then writes the parked rows.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [double]$BudgetMs = 1000, [int]$MaxItems = 25)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $n = 0
    while ($State.FileQueue.Count -gt 0) {
        if ($n -gt 0 -and ($sw.ElapsedMilliseconds -ge $BudgetMs -or $n -ge $MaxItems)) { break }
        $path = $State.FileQueue.Dequeue()
        $lower = $path.ToLowerInvariant()
        [void]$State.FileQueued.Remove($lower)
        $info = Invoke-WdMonStep -State $State -Name 'FileInfo' -ScriptBlock { Get-WdMonFileInfo -Path $path } -Default $null
        if ($null -eq $info) { $info = @{ Size = $null; Modified = $null; ModifiedIso = ''; CreatedIso = ''; Company = ''; Description = ''; ProductVersion = ''; OriginalFilename = ''; SigStatus = 'Error'; Signer = ''; IsOSBinary = ''; Sha256 = 'ERROR'; Status = 'Error'; Resolved = (Get-IsoTimestamp) } }
        $State.FileCache[$lower] = $info
        $State.FileCacheDirty = $true
        if ($State.PendingMeta.ContainsKey($lower)) {
            foreach ($meta in $State.PendingMeta[$lower]) { Write-WdMonMetaRow -State $State -Meta $meta -File $info }
            $State.PendingMeta.Remove($lower)
        }
        $n++
    }
    return $n
}

function Complete-WdMonPendingMeta {
    # At stop: rows whose file info was never resolved are written with empty file columns.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $n = 0
    foreach ($lower in @($State.PendingMeta.Keys)) {
        foreach ($meta in $State.PendingMeta[$lower]) {
            if ([string]::IsNullOrEmpty($meta.AccessNote)) { $meta.AccessNote = 'file info pending at stop' }
            Write-WdMonMetaRow -State $State -Meta $meta -File $null
            $n++
        }
    }
    $State.PendingMeta.Clear()
    return $n
}

# ---------------------------------------------------------------------------------------------
# Events: monitor events and event-log polling (events.csv)
# ---------------------------------------------------------------------------------------------
function Write-WdMonEvent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$State,
        [Parameter(Mandatory = $true)][string]$Type,
        [string]$Key = '', [AllowNull()][object]$ProcessId = $null, [string]$Name = '', [string]$Detail = '',
        [string]$Source = '', [AllowNull()][object]$EventId = $null, [string]$EventTime = '', [AllowNull()][object]$RecordId = $null,
        [string]$TsIso = ''
    )
    if ($TsIso -eq '') { $TsIso = Get-IsoTimestamp }
    if ($null -ne $Detail) { $Detail = ($Detail -replace '\s*\r?\n\s*', ' | ').Trim() }
    if ($Detail.Length -gt 500) { $Detail = $Detail.Substring(0, 500) + '...' }
    Write-WdMonCsvRow -Writer $State.Writers['events'] -Values @($TsIso, $Type, $Key, $ProcessId, $Name, $Detail, $Source, $EventId, $EventTime, $RecordId)
}

function Initialize-WdMonEventLogs {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $defs = @(
        @{ Log = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1006, 1007, 1015, 1116, 1117, 1118, 1119, 5001, 5007) },
        @{ Log = 'System'; Ids = @(7045, 7040, 41, 1074, 6008) },
        @{ Log = 'Application'; Ids = @(1000, 1001, 1002) },
        @{ Log = 'Microsoft-Windows-TaskScheduler/Operational'; Ids = @(100, 106, 129, 140, 141, 200) },
        @{ Log = 'Microsoft-Windows-PowerShell/Operational'; Ids = @(4104) },
        @{ Log = 'Microsoft-Windows-WMI-Activity/Operational'; Ids = @(5861) }
    )
    foreach ($d in $defs) {
        $enabled = $false
        try {
            $info = Get-WinEvent -ListLog $d.Log -ErrorAction Stop
            if ($null -ne $info) { $enabled = [bool]$info.IsEnabled }
        } catch { $enabled = $false }
        # The bookmark starts at the newest record present at monitor start, so the poll (which queries by
        # EventRecordID, not by time) only ever returns events written after the start.
        $last = [int64]0
        if ($enabled) {
            try {
                $newest = @(Get-WinEvent -LogName $d.Log -MaxEvents 1 -ErrorAction Stop -Verbose:$false)
                if ($newest.Count -gt 0 -and $null -ne $newest[0].RecordId) { $last = [int64]$newest[0].RecordId }
            } catch {
                # Empty log ("No events were found") or unreadable: start from 0 or disable.
                $fqid = ''
                try { $fqid = [string]$_.FullyQualifiedErrorId } catch { $fqid = '' }
                if (-not ($fqid -like 'NoMatchingEventsFound*')) {
                    $enabled = $false
                    Write-Log -Level Debug -Message ('Event log {0} not readable: {1}' -f $d.Log, (($_.Exception.Message -replace '\r?\n', ' ').Trim()))
                }
            }
        }
        $State.EventLogs.Add(@{ Log = $d.Log; Ids = $d.Ids; Enabled = $enabled; Last = $last })
        if (-not $enabled) { Write-Log -Level Info -Message ('Event log not available or disabled, skipped: {0}' -f $d.Log) }
    }
    # The Security log is never polled by the monitor (it is readable only by administrators and noisy); the skip entry
    # points the reader to an elevated Inventory run for 4688/4698-style evidence.
    if (-not $script:IsAdmin) { Add-AdminSkip -Item 'Security event log (4688 process creation, 4698 task created)' -Detail 'not polled by the monitor; readable only by administrators - run Inventory elevated for security events' }
}

function Get-WdMonEventDetail {
    # Detail text for an event-log row. Everything returned passes through Hide-WdSecret: a 4104 script block can
    # carry a password literal, a 7045 service image path a token argument, an application error message a URL
    # with credentials.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Event, [string]$Log)
    $detail = Get-WdMonEventDetailRaw -Event $Event -Log $Log
    if ([string]::IsNullOrEmpty($detail)) { return $detail }
    try { return [string](Hide-WdSecret -Text $detail) } catch { return $detail }
}

function Test-WdMonScriptBlockNoise {
    # True when a PowerShell 4104 script-block event is noise for the miner hunt and must not reach events.csv:
    #   - written by this monitor (own PID) or by another win-debug mode running concurrently (a process whose
    #     procmeta Flags contain WinDebugTool / Self, tracked in $State.ToolPids), or text with win-debug markers
    #   - an auto-generated CDXML cmdlet-adapter block (Get-NetTCPConnection, Get-ScheduledTask ... compile one
    #     '$__cmdletization_*' block per call; they contain no user code)
    # Everything else is kept.
    [CmdletBinding()]
    param([AllowNull()][hashtable]$State, [int]$ProcessId = 0, [AllowNull()][AllowEmptyString()][string]$Text)
    if ($ProcessId -gt 0) {
        if ($ProcessId -eq $PID) { return $true }
        if ($null -ne $State -and $null -ne $State.ToolPids -and $State.ToolPids.Contains($ProcessId)) { return $true }
    }
    if ([string]::IsNullOrEmpty($Text)) { return $false }
    if ($Text -match 'WdMon|WinDebug|win-debug|Invoke-Safely|Get-CimSafe') { return $true }
    if ($Text.IndexOf('$__cmdletization_', [StringComparison]::Ordinal) -ge 0) { return $true }
    if ($Text.IndexOf('Microsoft.PowerShell.Cmdletization', [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    return $false
}

function Get-WdMonEventDetailRaw {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Event, [string]$Log)
    $props = @()
    try { $props = @($Event.Properties | ForEach-Object { [string]$_.Value }) } catch { $props = @() }
    $p0 = ''
    $p1 = ''
    if ($props.Count -gt 0) { $p0 = $props[0] }
    if ($props.Count -gt 1) { $p1 = $props[1] }
    $msg = ''
    try { $msg = [string]$Event.Message } catch { $msg = '' }
    if ([string]::IsNullOrWhiteSpace($msg)) { $msg = ($props -join '; ') }
    $first = ($msg -split '\r?\n')[0].Trim()
    $id = [int]$Event.Id
    if ($Log -eq 'System' -and $id -eq 7045) { return ('Service installed: "{0}" image="{1}" | {2}' -f $p0, (($p1 -split '\r?\n')[0]), $first) }
    if ($Log -like '*TaskScheduler*') { return ('Task {0} | {1}' -f $p0, $first) }
    if ($Log -like '*PowerShell*' -and $id -eq 4104) {
        $sb = ''
        if ($props.Count -gt 2) { $sb = $props[2] }
        if ($sb.Length -gt 300) { $sb = $sb.Substring(0, 300) }
        return ('ScriptBlock: {0}' -f $sb)
    }
    if ($Log -eq 'Application' -and ($id -eq 1000 -or $id -eq 1002)) { return ('{0} | app={1} module={2}' -f $first, $p0, $(if ($props.Count -gt 3) { $props[3] } else { '' })) }
    return $first
}

function Get-WdMonEventBatch {
    # The oldest unread events of one log: EventID in Ids AND EventRecordID > After, oldest first, at most Max.
    # Querying by record id (not by time window) means a batch cap can never skip events: the bookmark advances
    # to the last event of the batch and the next batch continues exactly there. Own 4104 script blocks are
    # excluded in the query so they do not consume batch slots. Returns @() for "no events"; other errors throw.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$LogName,
        [Parameter(Mandatory = $true)][int[]]$Ids,
        [int64]$After = 0,
        [int]$Max = 300,
        [switch]$ExcludeOwnProcess
    )
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $idExpr = (@($Ids | ForEach-Object { 'EventID={0}' -f ([int]$_).ToString($inv) }) -join ' or ')
    $xpath = '*[System[({0}) and EventRecordID > {1}' -f $idExpr, $After.ToString($inv)
    if ($ExcludeOwnProcess) { $xpath += (' and Execution[@ProcessID!={0}]' -f $PID.ToString($inv)) }
    $xpath += ']]'
    try {
        return @(Get-WinEvent -LogName $LogName -FilterXPath $xpath -Oldest -MaxEvents $Max -ErrorAction Stop -Verbose:$false)
    } catch {
        $fqid = ''
        try { $fqid = [string]$_.FullyQualifiedErrorId } catch { $fqid = '' }
        if ($fqid -like 'NoMatchingEventsFound*' -or $_.Exception.Message -match 'No events were found') { return @() }
        throw
    }
}

function Invoke-WdMonEventPoll {
    # Every 60 s: drains each enabled log from its RecordId bookmark in batches of 300 (at most 5 batches = 1500
    # events per log per poll, the rest follows at the next poll with a throttled warning). Nothing is dropped.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [string]$TsIso)
    $now = Get-Date
    $written = 0
    $inv = $State.Inv
    $batchSize = 300
    $maxBatches = 5
    $State.EventPollNo = [int]$State.EventPollNo + 1
    $resync = (([int]$State.EventPollNo % 10) -eq 0)
    foreach ($def in $State.EventLogs) {
        if (-not $def.Enabled) { continue }
        $logName = [string]$def.Log
        $ids = @($def.Ids)
        $isPowerShell = ($logName -like '*PowerShell*')
        if ($resync -and [int64]$def.Last -gt 0) {
            # A cleared log restarts its record ids at 1: every 10th poll compare the bookmark with the newest record.
            try {
                $newest = @(Get-WinEvent -LogName $logName -MaxEvents 1 -ErrorAction Stop -Verbose:$false)
                if ($newest.Count -gt 0 -and [int64]$newest[0].RecordId -lt [int64]$def.Last) {
                    Write-Log -Level Info -Message ('Event log {0} was cleared (newest record {1} < bookmark {2}); reading from the start.' -f $logName, ([int64]$newest[0].RecordId).ToString($inv), ([int64]$def.Last).ToString($inv))
                    $def.Last = [int64]0
                }
            } catch { }
        }
        $batches = 0
        $more = $true
        while ($more -and $batches -lt $maxBatches) {
            $batches++
            $after = [int64]$def.Last
            $events = @(Invoke-WdMonStep -State $State -Name ('Events.' + $logName) -ScriptBlock {
                ,@(Get-WdMonEventBatch -LogName $logName -Ids $ids -After $after -Max $batchSize -ExcludeOwnProcess:$isPowerShell)
            } -Default $null)
            if ($null -eq $events -or $events.Count -eq 0) { $more = $false; break }
            $more = ($events.Count -ge $batchSize)
            foreach ($e in $events) {
                $rid = [int64]$e.RecordId
                if ($rid -le [int64]$def.Last) { continue }
                $def.Last = $rid
                if ($logName -like '*TaskScheduler*') {
                    $taskPath = ''
                    try { $taskPath = [string]$e.Properties[0].Value } catch { $taskPath = '' }
                    if ($taskPath -like '\Microsoft\*') { continue }
                }
                if ($isPowerShell) {
                    # Script-block logging records win-debug's own blocks (this process, other win-debug modes) and
                    # CDXML adapter blocks: Test-WdMonScriptBlockNoise decides on the ORIGINAL text, before masking.
                    $evPid = 0
                    try { $evPid = [int]$e.ProcessId } catch { $evPid = 0 }
                    $text = ''
                    try { if ($e.Properties.Count -gt 2) { $text = [string]$e.Properties[2].Value } } catch { $text = '' }
                    if (Test-WdMonScriptBlockNoise -State $State -ProcessId $evPid -Text $text) { continue }
                }
                $detail = Get-WdMonEventDetail -Event $e -Log $logName
                $evTime = ''
                try { $evTime = Get-IsoTimestamp -Date $e.TimeCreated } catch { $evTime = '' }
                Write-WdMonEvent -State $State -Type 'EventLog' -Detail $detail -Source $logName -EventId $e.Id -EventTime $evTime -RecordId $rid -TsIso $TsIso
                $written++
            }
        }
        if ($more) {
            # Backlog left for the next poll: warn at most once per 10 occurrences per log.
            $n = 1
            if ($State.EventBacklogWarn.ContainsKey($logName)) { $n = 1 + [int]$State.EventBacklogWarn[$logName] }
            $State.EventBacklogWarn[$logName] = $n
            if ($n -eq 1 -or ($n % 10) -eq 0) {
                Write-Log -Level Warn -Message ('Event backlog in {0}: more than {1} matching events since the last poll; the rest is read at the next poll (nothing is skipped, {2}x so far).' -f $logName, ($batchSize * $maxBatches).ToString($inv), $n.ToString($inv))
            }
        }
    }
    $State.LastEventPoll = $now
    return $written
}

function Invoke-WdMonWmiDrain {
    # -TrackShortLived: drains __InstanceCreationEvent notifications (processes that lived < 1 interval).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [string]$TsIso)
    $n = 0
    $evs = @(Get-Event -SourceIdentifier $State.WmiSource -ErrorAction SilentlyContinue)
    foreach ($ev in $evs) {
        try {
            $ti = $ev.SourceEventArgs.NewEvent.TargetInstance
            $cmd = [string]$ti.CommandLine
            # Mask before truncating: a cut in the middle of "password=..." would leave the secret's head visible.
            if (-not [string]::IsNullOrEmpty($cmd)) { try { $cmd = [string](Hide-WdSecret -Text $cmd) } catch { } }
            if ($cmd.Length -gt 300) { $cmd = $cmd.Substring(0, 300) }
            $detail = 'Ppid={0}; Path={1}; Cmd={2}' -f [string]$ti.ParentProcessId, [string]$ti.ExecutablePath, $cmd
            Write-WdMonEvent -State $State -Type 'WmiProcessStart' -ProcessId $ti.ProcessId -Name ([string]$ti.Name) -Detail $detail -Source 'WMI __InstanceCreationEvent' -TsIso $TsIso
            $n++
        } catch { }
        try { Remove-Event -EventIdentifier $ev.EventIdentifier -ErrorAction SilentlyContinue } catch { }
    }
    return $n
}

# ---------------------------------------------------------------------------------------------
# One sample
# ---------------------------------------------------------------------------------------------
function Invoke-WdMonSample {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $inv = $State.Inv
    $ts = Get-Date
    $tsIso = Get-IsoTimestamp -Date $ts
    $State.SampleNo = [int]$State.SampleNo + 1
    $sampleNo = [int]$State.SampleNo
    $late = ($ts - [DateTime]$State.ScheduledTick).TotalSeconds
    $overrun = ($late -gt 1.0) -or [bool]$State.OverrunPending
    $State.OverrunPending = $false
    if ($overrun) { $State.Overruns = [int]$State.Overruns + 1 }
    $isInitial = ($null -eq $State.Prev)
    $prev = $State.Prev

    # 1. processes
    $snap = Invoke-WdMonStep -State $State -Name 'Processes' -ScriptBlock { Get-WdMonProcSnapshot -State $State } -Default $null
    if ($null -ne $snap -and ($snap.Count -eq 0 -or $null -eq $snap.Total)) { $snap = $null }
    if ($null -eq $snap -and -not $State.ContainsKey('ProcWarned')) {
        $State.ProcWarned = $true
        Write-Log -Level Warn -Message 'Process performance counters returned no data (Win32_PerfRawData_PerfProc_Process). If this persists, rebuild the counters with "lodctr /R" as administrator.'
    }

    # 2. system totals, GPU, windows, session
    $sys = Invoke-WdMonStep -State $State -Name 'SystemTotals' -ScriptBlock { Get-WdMonSystemTotals -State $State } -Default @{}
    if ($null -eq $sys) { $sys = @{} }
    $gpu = Invoke-WdMonStep -State $State -Name 'Gpu' -ScriptBlock { Get-WdMonGpuDelta -State $State } -Default $null
    $gpuMem = Invoke-WdMonStep -State $State -Name 'GpuMemory' -ScriptBlock { Get-WdMonGpuMemory -State $State } -Default $null
    if ($State.WinInfoSample -lt 0 -or ($sampleNo - [int]$State.WinInfoSample) -ge 3) {
        Invoke-WdMonStep -State $State -Name 'Windows' -ScriptBlock { Update-WdMonWindowInfo -State $State } | Out-Null
    }
    $logonUi = $false
    if ($null -ne $snap) { $logonUi = [bool]$snap.LogonUi }
    $sess = Invoke-WdMonStep -State $State -Name 'Session' -ScriptBlock { Get-WdMonSessionState -State $State -LogonUiPresent $logonUi } -Default $null
    if ($null -eq $sess) { $sess = @{ IdleSeconds = $null; Locked = $logonUi; LockFlag = $null } }
    $isIdle = $false
    if ($sess.Locked) { $isIdle = $true }
    elseif ($null -ne $sess.IdleSeconds -and [int64]$sess.IdleSeconds -ge $script:WdMonIdleThresholdSec) { $isIdle = $true }
    if ($null -eq $State.IsIdle) { $State.IsIdle = $isIdle }
    elseif ([bool]$State.IsIdle -ne $isIdle) {
        $type = 'IdleEnd'
        if ($isIdle) { $type = 'IdleStart' }
        Write-WdMonEvent -State $State -Type $type -Detail ('IdleSeconds={0}; Locked={1}' -f [string]$sess.IdleSeconds, [string]$sess.Locked) -TsIso $tsIso
        $State.IsIdle = $isIdle
    }

    # 3. per-process deltas and summary update
    $recs = New-Object 'System.Collections.Generic.List[object]'
    $newRecs = New-Object 'System.Collections.Generic.List[object]'
    $exitedRecs = New-Object 'System.Collections.Generic.List[object]'
    $sec = $null
    $dt = 0.0
    $procSum = 0.0
    $topName = ''
    $topPct = 0.0
    $ncpu = [double]$State.NCPU
    if ($null -ne $snap) {
        if ($null -ne $prev -and $null -ne $prev.Total) {
            $dt = [double]([int64]$snap.Total.Timestamp_Sys100NS - [int64]$prev.Total.Timestamp_Sys100NS)
            if ($dt -gt 0) { $sec = $dt / 1e7 }
        }
        $secForSum = 0.0
        if ($null -ne $sec) { $secForSum = $sec }
        foreach ($key in $snap.Rows.Keys) {
            $c = $snap.Rows[$key]
            $procId = [int]$c.IDProcess
            $rec = @{
                Key = $key; Pid = $procId; Name = [string]$snap.KeyNames[$key]; WS = [int64]$c.WorkingSet; WSP = [int64]$c.WorkingSetPrivate
                Threads = [int]$c.ThreadCount; Handles = [int]$c.HandleCount; Prio = [int]$c.PriorityBase; Ppid = [int]$c.CreatingProcessID
                Started = [uint64]$c.ElapsedTime; HasDelta = $false; CpuPct = $null; CpuCores = $null; ReadBps = $null; WriteBps = $null
                Gpu = $null; GpuDed = $null; GpuSh = $null; Private = $null; HasWindow = $null; New = $false; WindowChanged = $false
                IsSelf = ($procId -eq [int]$State.Pid)
            }
            if ($null -ne $sec -and $prev.Rows.ContainsKey($key)) {
                $p = $prev.Rows[$key]
                $dCpu = [double]([int64]$c.PercentProcessorTime - [int64]$p.PercentProcessorTime)
                if ($dCpu -lt 0) { $dCpu = 0.0 }
                $one = 100.0 * $dCpu / $dt
                $rec.CpuCores = $one / 100.0
                $rec.CpuPct = $one / $ncpu
                $dr = [double]([int64]$c.IOReadBytesPersec - [int64]$p.IOReadBytesPersec)
                if ($dr -lt 0) { $dr = 0.0 }
                $dw = [double]([int64]$c.IOWriteBytesPersec - [int64]$p.IOWriteBytesPersec)
                if ($dw -lt 0) { $dw = 0.0 }
                $rec.ReadBps = [int64][math]::Round($dr / $sec, 0, [MidpointRounding]::AwayFromZero)
                $rec.WriteBps = [int64][math]::Round($dw / $sec, 0, [MidpointRounding]::AwayFromZero)
                $rec.HasDelta = $true
                $procSum += [double]$rec.CpuPct
                if (-not $rec.IsSelf -and [double]$rec.CpuPct -gt $topPct) { $topPct = [double]$rec.CpuPct; $topName = $rec.Name }
            } elseif (-not $isInitial) {
                $rec.New = $true
            }
            if ($null -ne $gpu -and $gpu.Available -and $gpu.Agg.ContainsKey($procId)) { $rec.Gpu = $gpu.Agg[$procId] }
            if ($null -ne $gpuMem -and $gpuMem.PerPid.ContainsKey($procId)) { $rec.GpuDed = $gpuMem.PerPid[$procId].Dedicated; $rec.GpuSh = $gpuMem.PerPid[$procId].Shared }
            if ($State.WinInfo.ContainsKey($procId)) { $wi = $State.WinInfo[$procId]; $rec.HasWindow = [bool]$wi.HasWindow; $rec.Private = $wi.Private }
            if (-not $State.Sum.ContainsKey($key)) {
                $State.Sum[$key] = New-WdMonSumEntry -Rec $rec -TsIso $tsIso -PresentAtStart $isInitial
                $newRecs.Add($rec)
            } else {
                $s = $State.Sum[$key]
                if ($null -ne $rec.HasWindow -and $null -ne $s.HasWindow -and [bool]$s.HasWindow -ne [bool]$rec.HasWindow) { $rec.WindowChanged = $true }
            }
            Update-WdMonSumEntry -Entry $State.Sum[$key] -Rec $rec -TsIso $tsIso -Seconds $secForSum -IsIdle $isIdle
            $recs.Add($rec)
        }
        if ($null -ne $prev) {
            foreach ($key in $prev.Rows.Keys) {
                if ($snap.Rows.ContainsKey($key)) { continue }
                $exitedRecs.Add(@{ Key = $key; Pid = [int]$prev.Rows[$key].IDProcess; Name = [string]$prev.KeyNames[$key] })
            }
        }
    }

    # 4. metadata for first-seen processes
    $noPath = 0
    if ($newRecs.Count -gt 0) {
        $newArr = $newRecs.ToArray()
        $noPath = Invoke-WdMonStep -State $State -Name 'Metadata' -ScriptBlock { Resolve-WdMonNewProcesses -State $State -Snap $snap -NewRecs $newArr -TsIso $tsIso } -Default 0
        if ($null -eq $noPath) { $noPath = 0 }
    }
    if ($isInitial -and $null -ne $snap) {
        $State.InitialCount = $recs.Count
        $State.NoPathCount = [int]$noPath
        if ($script:IsAdmin) {
            Write-Log -Level Info -Message ('Elevated: full process details (path, command line, owner, signature) available for all {0} processes.' -f $recs.Count.ToString($inv))
        } else {
            Write-Log -Level Warn -Message ('Not elevated: executable path, command line, owner and signature are unknown for {0} of {1} processes (requires administrator); Security event log not readable. Per-process CPU/GPU/memory/IO are still recorded for every process.' -f ([int]$noPath).ToString($inv), $recs.Count.ToString($inv))
            Add-AdminSkip -Item ('Executable path / command line / owner / signature of {0} system processes' -f ([int]$noPath).ToString($inv)) -Detail 'Win32_Process.ExecutablePath is empty for SYSTEM, service and other-user processes when not elevated'
        }
    }

    # 5. network and DNS
    $netRows = 0
    $dnsRows = 0
    if ($null -ne $snap) {
        $netRows = Invoke-WdMonStep -State $State -Name 'Tcp' -ScriptBlock { Update-WdMonTcp -State $State -Snap $snap -TsIso $tsIso -IsIdle $isIdle } -Default 0
    }
    if (($sampleNo % 3) -eq 1) {
        $dnsRows = Invoke-WdMonStep -State $State -Name 'Dns' -ScriptBlock { Update-WdMonDns -State $State -TsIso $tsIso } -Default 0
    }

    # 6. samples row
    $gpuAvail = ($null -ne $gpu -and $gpu.Available)
    $gT = $null
    if ($gpuAvail) { $gT = $gpu.Totals }
    $gDed = $null
    $gSh = $null
    if ($null -ne $gpuMem) { $gDed = $gpuMem.Dedicated; $gSh = $gpuMem.Shared }
    $intervalSec = $null
    if ($null -ne $sec) { $intervalSec = Format-WdMonNumber -Value $sec -Decimals 1 }
    $procSumOut = $null
    if ($null -ne $sec) { $procSumOut = $procSum }
    $topOut = $null
    if ($null -ne $sec) { $topOut = $topPct }
    $sampleMs = [int64]$sw.ElapsedMilliseconds
    $wS = Get-WdMonDailyCsv -State $State -Name 'samples' -Time $ts
    Write-WdMonCsvRow -Writer $wS -Values @(
        $tsIso, $sampleNo, $intervalSec, $sampleMs, $overrun,
        $sys.CpuPct, $sys.CpuKernelPct, $sys.CpuDpcIntPct, $procSumOut,
        $sys.CpuPerfPct, $sys.CpuUtilityPct, $sys.CpuFreqMHz, $State.MemTotalMB, $sys.MemUsedMB, $sys.MemAvailMB, $sys.CommitBytes, $sys.CommitLimitBytes, $sys.CommitPct,
        $sys.PagesPerSec, $sys.PoolNonpagedBytes, $sys.DiskActivePct, $sys.DiskQueue, $sys.DiskReadBps, $sys.DiskWriteBps, $sys.DiskAvgMs, $sys.DiskTransfersPerSec,
        $sys.NetRecvBps, $sys.NetSentBps,
        $(if ($gpuAvail) { $gpu.Busiest } else { $null }), $(if ($gpuAvail) { $gT.ThreeD } else { $null }), $(if ($gpuAvail) { $gT.Compute } else { $null }),
        $(if ($gpuAvail) { $gT.Copy } else { $null }), $(if ($gpuAvail) { $gT.VDec } else { $null }), $(if ($gpuAvail) { $gT.VEnc } else { $null }), $(if ($gpuAvail) { $gT.Other } else { $null }),
        $gDed, $gSh, $sys.BatteryPct, $sys.OnBattery, (Format-WdMonNumber -Value $sys.TempC -Decimals 1), $sys.ThrottleReasons,
        $sess.IdleSeconds, [bool]$sess.Locked, $isIdle, $sys.ProcessCount, $sys.ThreadCount, $sys.ContextSwitchesPerSec, $sys.ProcQueue, $topName, $topOut
    )

    # 7. procs rows (row filter), exits, new-process events
    $rowsWritten = 0
    if ($null -ne $snap -and -not $isInitial) {
        $cpuVals = New-Object 'System.Collections.Generic.List[double]'
        $gpuVals = New-Object 'System.Collections.Generic.List[double]'
        foreach ($rec in $recs) {
            if ($rec.IsSelf) { continue }
            if ($rec.HasDelta) { $cpuVals.Add([double]$rec.CpuPct) }
            if ($null -ne $rec.Gpu) { $gpuVals.Add([double]$rec.Gpu.Total) }
        }
        $cpuThr = 0.005
        if ($cpuVals.Count -gt 15) { $cpuVals.Sort(); $t = $cpuVals[$cpuVals.Count - 15]; if ($t -gt $cpuThr) { $cpuThr = $t } }
        $gpuThr = 0.05
        if ($gpuVals.Count -gt 5) { $gpuVals.Sort(); $t = $gpuVals[$gpuVals.Count - 5]; if ($t -gt $gpuThr) { $gpuThr = $t } }
        $wP = Get-WdMonDailyCsv -State $State -Name 'procs' -Time $ts
        foreach ($rec in $recs) {
            $cpu = 0.0
            $cores = 0.0
            $io = 0L
            if ($rec.HasDelta) { $cpu = [double]$rec.CpuPct; $cores = [double]$rec.CpuCores; $io = [int64]$rec.ReadBps + [int64]$rec.WriteBps }
            $g = 0.0
            if ($null -ne $rec.Gpu) { $g = [double]$rec.Gpu.Total }
            $write = $false
            if ($rec.New -or $rec.WindowChanged) { $write = $true }
            elseif ($cpu -ge 0.5 -or $cores -ge 0.25) { $write = $true }
            elseif ($g -gt 0.5) { $write = $true }
            elseif ($io -gt 102400) { $write = $true }
            elseif ([int64]$rec.WS -ge 104857600) { $write = $true }
            elseif ($rec.HasDelta -and -not $rec.IsSelf -and $cpu -gt 0 -and $cpu -ge $cpuThr) { $write = $true }
            elseif ($g -gt 0 -and -not $rec.IsSelf -and $g -ge $gpuThr) { $write = $true }
            elseif ($State.Watch.Contains($rec.Key)) { $write = $true }
            if (-not $write) { continue }
            $flags = New-Object 'System.Collections.Generic.List[string]'
            if ($rec.New) { $flags.Add('New') }
            if ($rec.IsSelf) { $flags.Add('Self') }
            if ($rec.WindowChanged) { $flags.Add('WindowChanged') }
            $ga = $rec.Gpu
            Write-WdMonCsvRow -Writer $wP -Values @(
                $tsIso, $rec.Key, $rec.Pid, $rec.Name, $rec.CpuPct, (Format-WdMonNumber -Value $rec.CpuCores -Decimals 3),
                $(if ($null -ne $ga) { $ga.Total } else { $null }), $(if ($null -ne $ga) { $ga.ThreeD } else { $null }), $(if ($null -ne $ga) { $ga.Compute } else { $null }),
                $(if ($null -ne $ga) { $ga.Copy } else { $null }), $(if ($null -ne $ga) { $ga.VDec } else { $null }), $(if ($null -ne $ga) { $ga.VEnc } else { $null }), $(if ($null -ne $ga) { $ga.Other } else { $null }),
                $rec.GpuDed, $rec.GpuSh, $rec.ReadBps, $rec.WriteBps, $rec.WS, $rec.WSP, $rec.Private, $rec.Threads, $rec.Handles, $rec.Prio,
                $rec.HasWindow, $isIdle, ($flags -join ';')
            )
            $rowsWritten++
            $State.Sum[$rec.Key].RowsWritten = [int]$State.Sum[$rec.Key].RowsWritten + 1
        }
        foreach ($ex in $exitedRecs) {
            Write-WdMonCsvRow -Writer $wP -Values @($tsIso, $ex.Key, $ex.Pid, $ex.Name, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $null, $isIdle, 'Exited')
            $rowsWritten++
            $detail = ''
            if ($State.ToolPids.Contains([int]$ex.Pid) -and -not $snap.Names.ContainsKey([int]$ex.Pid)) { [void]$State.ToolPids.Remove([int]$ex.Pid) }
            if ($State.Sum.ContainsKey($ex.Key)) {
                $s = $State.Sum[$ex.Key]
                $s.Exited = $true
                $s.ExitTime = $tsIso
                $detail = 'Path={0}; Samples={1}; CpuSeconds={2}; FirstSeen={3}' -f [string]$s.Path, ([int]$s.Samples).ToString($inv), (Format-WdMonNumber -Value $s.CpuSeconds -Decimals 1), [string]$s.FirstSeen
            }
            Write-WdMonEvent -State $State -Type 'ProcessExited' -Key $ex.Key -ProcessId $ex.Pid -Name $ex.Name -Detail $detail -TsIso $tsIso
        }
        foreach ($rec in $newRecs) {
            $detail = ''
            if ($State.Sum.ContainsKey($rec.Key)) {
                $s = $State.Sum[$rec.Key]
                $detail = 'Path={0}; Parent={1} ({2}); Session={3}; Owner={4}; Flags={5}; Started={6}' -f [string]$s.Path, [string]$s.ParentName, ([int]$rec.Ppid).ToString($inv), [string]$s.SessionId, [string]$s.Owner, [string]$s.Flags, [string]$s.Started
            }
            Write-WdMonEvent -State $State -Type 'ProcessNew' -Key $rec.Key -ProcessId $rec.Pid -Name $rec.Name -Detail $detail -TsIso $tsIso
        }
    }
    if ($State.TrackShortLived) { Invoke-WdMonStep -State $State -Name 'WmiEvents' -ScriptBlock { Invoke-WdMonWmiDrain -State $State -TsIso $tsIso } | Out-Null }
    if ($null -ne $snap) { $State.Prev = $snap }
    $State.RowsWritten = [int]$State.RowsWritten + $rowsWritten
    # The samples row is on disk: this sample counts as completed for run.json (SamplesWritten / LastSampleTime).
    $State.SamplesWritten = [int]$State.SamplesWritten + 1
    $State.LastSampleIso = $tsIso

    # 8. diagnostics
    $sw.Stop()
    $cpuText = '-'
    if ($null -ne $sys.CpuPct) { $cpuText = Format-WdMonNumber -Value $sys.CpuPct -Decimals 1 }
    $gpuText = '-'
    if ($gpuAvail) { $gpuText = Format-WdMonNumber -Value $gpu.Busiest -Decimals 1 }
    $memText = '-'
    if ($null -ne $sys.MemAvailMB) { $memText = ([int64]$sys.MemAvailMB).ToString($inv) }
    $idleText = '-'
    if ($null -ne $sess.IdleSeconds) { $idleText = ([int64]$sess.IdleSeconds).ToString($inv) }
    Write-Log -Level Info -NoConsole -Message ('Sample {0}: {1} ms, processes={2}, rows={3}, new={4}, exited={5}, net={6}, dns={7}, cpu={8}, procsum={9}, gpu={10}, idle={11}s, locked={12}, overrun={13}, queue={14}, steps={15}' -f
        $sampleNo.ToString($inv), $sampleMs.ToString($inv), $recs.Count.ToString($inv), $rowsWritten.ToString($inv), $newRecs.Count.ToString($inv), $exitedRecs.Count.ToString($inv),
        ([int]$netRows).ToString($inv), ([int]$dnsRows).ToString($inv), $cpuText, (Format-WdMonNumber -Value $procSumOut -Decimals 1), $gpuText, $idleText, [string][bool]$sess.Locked, [string]$overrun, $State.FileQueue.Count.ToString($inv), (Format-WdMonStepTimes -State $State))
    $top = ''
    if ($topName -ne '') { $top = '{0} {1}%' -f $topName, (Format-WdMonNumber -Value $topPct -Decimals 1) }
    try {
        Write-Host ('{0} #{1,-5} CPU {2,5}%  GPU {3,5}%  free {4,6} MB  idle {5,6}s  {6}  top: {7}  ({8} ms)' -f $ts.ToString('HH:mm:ss', $inv), $sampleNo.ToString($inv), $cpuText, $gpuText, $memText, $idleText, $(if ($isIdle) { 'IDLE ' } else { 'user ' }), $top, $sampleMs.ToString($inv))
    } catch { }
}

# ---------------------------------------------------------------------------------------------
# Shutdown (also runs from finally after Ctrl+C: every step is independent and never throws)
# ---------------------------------------------------------------------------------------------
function Stop-WdMonSession {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$State, [string]$Reason)
    $inv = $State.Inv
    if ([string]::IsNullOrEmpty($Reason)) { $Reason = 'Interrupted' }
    $State.StopReason = $Reason
    $stop = Get-Date
    $State.StopIso = Get-IsoTimestamp -Date $stop
    $State.DurationSec = [math]::Round(($stop - [DateTime]$State.Start).TotalSeconds, 1, [MidpointRounding]::AwayFromZero)
    $pending = 0
    try { $pending = Complete-WdMonPendingMeta -State $State } catch { }
    try {
        if ($State.Writers.ContainsKey('events')) {
            Write-WdMonEvent -State $State -Type 'MonitorStopped' -ProcessId $State.Pid -Name 'powershell' -Detail ('Reason={0}; Samples={1}; Overruns={2}; DurationSec={3}; PendingMetaRows={4}' -f $Reason, ([int]$State.SampleNo).ToString($inv), ([int]$State.Overruns).ToString($inv), ([double]$State.DurationSec).ToString('F1', $inv), ([int]$pending).ToString($inv)) -TsIso $State.StopIso
        }
    } catch { }
    try { Write-WdMonProcSum -State $State } catch { Write-Log -Level Warn -Message ('procsum.json not written: {0}' -f $_.Exception.Message) }
    try { if ($State.FileCache.Count -gt 0) { $State.FileCacheDirty = $true }; Write-WdMonFileCache -State $State } catch { }
    try { Write-WdMonRunJson -State $State } catch { }
    try { Close-WdMonWriters -State $State } catch { }
    if ($State.TrackShortLived) {
        try { Unregister-Event -SourceIdentifier $State.WmiSource -ErrorAction SilentlyContinue } catch { }
        try { Get-Event -SourceIdentifier $State.WmiSource -ErrorAction SilentlyContinue | Remove-Event -ErrorAction SilentlyContinue } catch { }
    }
    foreach ($f in @('monitor.running', 'STOP')) {
        try {
            $p = [IO.Path]::Combine($State.OutDir, $f)
            if ([IO.File]::Exists($p)) { [IO.File]::Delete($p) }
        } catch { }
    }
    if ($State.CtrlCCaptured) { try { [Console]::TreatControlCAsInput = $false } catch { } }
    Write-Log -Level Info -Message ('Monitor stopped ({0}): {1} samples, {2} overruns, {3} process rows, {4} s. Session folder: {5}' -f $Reason, ([int]$State.SampleNo).ToString($inv), ([int]$State.Overruns).ToString($inv), ([int]$State.RowsWritten).ToString($inv), ([double]$State.DurationSec).ToString('F1', $inv), $State.OutDir)
    if ($null -ne $State.PrevLogPath) {
        $script:LogPath = $State.PrevLogPath
        Write-Log -Level Info -NoConsole -Message ('Monitor stopped ({0}) after {1} samples; details in monitor.log' -f $Reason, ([int]$State.SampleNo).ToString($inv))
    }
}

# ---------------------------------------------------------------------------------------------
# Public: Start-ProcessMonitor
# ---------------------------------------------------------------------------------------------
function Start-ProcessMonitor {
    <#
    .SYNOPSIS
        Samples processes, GPU, system totals, network and events into CSV files until stopped.
    .DESCRIPTION
        Stops on: a file named STOP in the session folder, -DurationMinutes, Ctrl+C or Q in the console.
        Throws 'A monitor is already running ...' when another live monitor exists under the same reports root.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutDir,
        [int]$IntervalSeconds = 10,
        [int]$DurationMinutes = 0,
        [switch]$TrackShortLived
    )
    $inv = Get-WdInv
    if ($IntervalSeconds -lt 5) { Write-Log -Level Warn -Message 'Interval below 5 s is not supported; using 5 s.'; $IntervalSeconds = 5 }
    if ($IntervalSeconds -gt 3600) { $IntervalSeconds = 3600 }
    # The live-monitor check runs BEFORE the session folder is created, so a refused start leaves no empty folder.
    $outputRoot = [IO.Path]::GetDirectoryName($OutDir)
    $live = @(Get-WdMonRunningSessions -OutputRoot $outputRoot | Where-Object { [int]$_.Pid -ne $PID })
    if ($live.Count -gt 0) {
        throw ('A monitor is already running (PID {0}, folder {1}). Stop it first (WinDebug.cmd -StopMonitor) or create a STOP file in that folder.' -f ([int]$live[0].Pid).ToString($inv), $live[0].Folder)
    }
    if (-not (Test-DirectoryExists -Path $OutDir)) { [void][IO.Directory]::CreateDirectory($OutDir) }

    $state = New-WdMonState -OutDir $OutDir -IntervalSeconds $IntervalSeconds -DurationMinutes $DurationMinutes
    $state.TrackShortLived = [bool]$TrackShortLived
    $state.PrevLogPath = $script:LogPath
    Write-Log -Level Info -NoConsole -Message 'Monitor session started; sampling diagnostics continue in monitor.log'
    $script:LogPath = [IO.Path]::Combine($OutDir, 'monitor.log')
    $script:CurrentMode = 'Monitor'
    $info = Get-ReportRunInfo -Mode 'Monitor'
    Write-Log -Level Info -NoConsole -Message ('win-debug {0} | monitor | user={1} | admin={2} | ps={3} | os={4} | culture={5}/{6} | interval={7}s | duration={8}min | pid={9}' -f $info['Version'], $info['User'], $info['IsAdmin'], $info['PSVersion'], $info['OSBuild'], $info['Culture'], $info['UICulture'], $IntervalSeconds.ToString($inv), $DurationMinutes.ToString($inv), $PID.ToString($inv))

    $reason = ''
    $ctrlC = $false
    try {
    # Native helpers (degrade: owner and idle/lock columns stay empty).
    $state.NativeOwner = Add-NativeType -TypeName 'WinDebug.ProcOwner' -SourcePath 'Native.cs'
    $state.NativeSession = [bool]('WinDebug.Session' -as [type])
    if (-not $state.NativeOwner) { Write-Log -Level Warn -Message 'Process owner and user-idle detection unavailable (native helper did not compile); Owner/IdleSeconds columns stay empty.' }

    # Static facts for run.json.
    $state.Gpus = @()
    Invoke-Safely -Name 'Monitor.RunInfo' -Quiet -ScriptBlock {
        $os = @(Get-CimSafe -ClassName Win32_OperatingSystem -Property TotalVisibleMemorySize -TimeoutSec 20)
        if ($os.Count -gt 0) { $state.MemTotalMB = [int64][math]::Round([double]$os[0].TotalVisibleMemorySize / 1024.0, 0, [MidpointRounding]::AwayFromZero) }
        $vc = @(Get-CimSafe -ClassName Win32_VideoController -Property Name, AdapterRAM, DriverVersion -TimeoutSec 20)
        $list = New-Object 'System.Collections.Generic.List[object]'
        foreach ($v in $vc) { $list.Add(@{ Name = [string]$v.Name; AdapterRAM = $(try { [int64]$v.AdapterRAM } catch { $null }); DriverVersion = [string]$v.DriverVersion }) }
        $state.Gpus = @($list.ToArray())
    } | Out-Null

    Write-WdMonRunningMarker -State $state
    foreach ($name in @('procmeta', 'net', 'dns', 'events')) {
        Open-WdMonCsv -State $state -Name $name -Path ([IO.Path]::Combine($OutDir, ($name + '.csv'))) -Columns $script:WdMonColumns[$name] | Out-Null
    }
    Invoke-Safely -Name 'Monitor.EventLogs' -Quiet -ScriptBlock { Initialize-WdMonEventLogs -State $state } | Out-Null
    Invoke-Safely -Name 'Monitor.FileCache' -Quiet -ScriptBlock { Import-WdMonFileCache -State $state } | Out-Null
    Invoke-Safely -Name 'Monitor.RunJson' -Quiet -ScriptBlock { Write-WdMonRunJson -State $state } | Out-Null
    Write-WdMonEvent -State $state -Type 'MonitorStarted' -ProcessId $PID -Name 'powershell' -Detail ('Interval={0}s; Duration={1}min; Elevated={2}; User={3}' -f $IntervalSeconds.ToString($inv), $DurationMinutes.ToString($inv), [string]$script:IsAdmin, [string]$info['User']) -TsIso $state.StartIso
    if ($TrackShortLived) {
        $ok = Invoke-Safely -Name 'Monitor.WmiSubscription' -ScriptBlock {
            Register-CimIndicationEvent -Query "SELECT * FROM __InstanceCreationEvent WITHIN 2 WHERE TargetInstance ISA 'Win32_Process'" -SourceIdentifier $state.WmiSource -ErrorAction Stop | Out-Null
            $true
        } -Default $false
        if (-not $ok) { $state.TrackShortLived = $false; Write-Log -Level Warn -Message 'Short-lived process tracking (WMI) could not be registered; continuing without it.' }
    }

    $inputRedirected = $true
    try { $inputRedirected = [Console]::IsInputRedirected } catch { $inputRedirected = $true }
    if (-not $inputRedirected) {
        try { [Console]::TreatControlCAsInput = $true; $ctrlC = $true } catch { $ctrlC = $false }
    }
    $state.CtrlCCaptured = $ctrlC
    Write-Host ''
    Write-Host ('Monitoring every {0} s. Stop: create a file named STOP in the session folder, run WinDebug.cmd -StopMonitor{1}.' -f $IntervalSeconds.ToString($inv), $(if ($ctrlC) { ', or press Q / Ctrl+C here' } elseif (-not $inputRedirected) { ', or press Ctrl+C' } else { '' })) -ForegroundColor Cyan
    if ($null -ne $state.Deadline) { Write-Host ('Runs until {0} (-DurationMinutes {1}).' -f (Get-IsoTimestamp -Date $state.Deadline), $DurationMinutes.ToString($inv)) -ForegroundColor Cyan }
    Write-Host ('Session folder: {0}' -f $OutDir) -ForegroundColor Cyan
    Write-Host 'Note: the monitor itself (powershell.exe, tagged Self) and WmiPrvSE.exe use a few percent CPU while sampling.' -ForegroundColor DarkGray

    $stopFile = [IO.Path]::Combine($OutDir, 'STOP')
    $next = Get-Date
    $consecutiveFailures = 0
        while ($true) {
            if ([IO.File]::Exists($stopFile)) { $reason = 'STOP file'; break }
            if ($null -ne $state.Deadline -and (Get-Date) -ge [DateTime]$state.Deadline) { $reason = 'Duration reached'; break }
            $state.ScheduledTick = $next
            try {
                Invoke-WdMonSample -State $state
                $consecutiveFailures = 0
                # After the first completed sample run.json gets its real ProcessesAtStart / ProcessesWithoutPath
                # (the copy written before sampling carries zeros); later refreshes ride on the procsum flush.
                if ([int]$state.SamplesWritten -eq 1) {
                    Invoke-WdMonStep -State $state -Name 'RunJson' -ScriptBlock { Write-WdMonRunJson -State $state } | Out-Null
                }
            } catch {
                $consecutiveFailures++
                $state.Failures = [int]$state.Failures + 1
                Write-Log -Level Error -Message ('Sample {0} failed: {1}' -f ([int]$state.SampleNo).ToString($inv), $_.Exception.Message)
                Write-Log -Level Debug -Message ([string]$_.ScriptStackTrace)
                if ($consecutiveFailures -ge 20) { $reason = 'Repeated sample failures'; break }
            }
            # Post-sample work, each step only while enough time remains before the next tick (a step that is
            # overdue by more than two minutes runs regardless, so a saturated 5 s interval still flushes).
            $tick = $next.AddSeconds($IntervalSeconds)
            $remainingMs = ($tick - (Get-Date)).TotalMilliseconds
            if ($remainingMs -gt 1800 -or $state.FileQueue.Count -gt 200) {
                # A single item (embedded signature, 64 MB hash) can take 0.3-0.5 s beyond the budget check.
                $budget = [math]::Max(300.0, [math]::Min(1500.0, $remainingMs - 1500))
                try { Resolve-WdMonFileQueue -State $state -BudgetMs $budget | Out-Null } catch { Write-Log -Level Warn -Message ('File info queue failed: {0}' -f $_.Exception.Message) }
            }
            $now = Get-Date
            $remainingMs = ($tick - $now).TotalMilliseconds
            $sinceEvents = ($now - [DateTime]$state.LastEventPoll).TotalSeconds
            if ($sinceEvents -ge 60 -and ($remainingMs -gt 1500 -or $sinceEvents -ge 180)) {
                Invoke-WdMonStep -State $state -Name 'EventPoll' -ScriptBlock { Invoke-WdMonEventPoll -State $state -TsIso (Get-IsoTimestamp -Date $now) } | Out-Null
            }
            $now = Get-Date
            $remainingMs = ($tick - $now).TotalMilliseconds
            $sinceSum = ($now - [DateTime]$state.LastSumFlush).TotalSeconds
            if ($sinceSum -ge 60 -and ($remainingMs -gt 800 -or $sinceSum -ge 180)) {
                Invoke-WdMonStep -State $state -Name 'ProcSum' -ScriptBlock { Limit-WdMonSum -State $state; Write-WdMonProcSum -State $state } | Out-Null
                Invoke-WdMonStep -State $state -Name 'RunJson' -ScriptBlock { Write-WdMonRunJson -State $state } | Out-Null
            }
            $now = Get-Date
            $remainingMs = ($tick - $now).TotalMilliseconds
            if ($state.FileCacheDirty -and ($now - [DateTime]$state.LastCacheFlush).TotalSeconds -ge 60 -and $remainingMs -gt 500) {
                Invoke-WdMonStep -State $state -Name 'FileCacheWrite' -ScriptBlock { Write-WdMonFileCache -State $state } | Out-Null
            }
            # Absolute-clock scheduling: skip missed ticks instead of catching up.
            $next = $next.AddSeconds($IntervalSeconds)
            $now = Get-Date
            if ($next -le $now) { $next = $now.AddMilliseconds(250); $state.OverrunPending = $true }
            while ((Get-Date) -lt $next) {
                if ([IO.File]::Exists($stopFile)) { $reason = 'STOP file'; break }
                if ($null -ne $state.Deadline -and (Get-Date) -ge [DateTime]$state.Deadline) { $reason = 'Duration reached'; break }
                if ($ctrlC) {
                    try {
                        while ([Console]::KeyAvailable) {
                            $k = [Console]::ReadKey($true)
                            if (($k.Modifiers -band [ConsoleModifiers]::Control) -and $k.Key -eq [ConsoleKey]::C) { $reason = 'Ctrl+C' }
                            elseif ($k.Key -eq [ConsoleKey]::Q) { $reason = 'Q key' }
                        }
                    } catch { }
                    if ($reason -ne '') { break }
                }
                $ms = [int][math]::Min(250, [math]::Max(10, ($next - (Get-Date)).TotalMilliseconds))
                Start-Sleep -Milliseconds $ms
            }
            if ($reason -ne '') { break }
        }
    } finally {
        Stop-WdMonSession -State $state -Reason $reason
    }
    return $OutDir
}

# ---------------------------------------------------------------------------------------------
# Public: Stop-ProcessMonitor
# ---------------------------------------------------------------------------------------------
function Stop-ProcessMonitor {
    <#
    .SYNOPSIS
        Creates a STOP file for every live monitor under OutputRoot and waits up to 30 s for each to finish.
    .OUTPUTS
        One string: 'Stopped' (every live monitor confirmed the stop), 'Signaled' (STOP file delivered but at least
        one monitor did not confirm within 30 s; it stops at its next check), 'None' (no live monitor found).
        The entry point turns these into its console message and exit code (0 / 0 / 3).
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$OutputRoot)
    $inv = Get-WdInv
    $live = @(Get-WdMonRunningSessions -OutputRoot $OutputRoot)
    if ($live.Count -eq 0) {
        # Log only: the entry point prints "No running monitor found." itself.
        Write-Log -Level Info -NoConsole -Message ('No running monitor found under {0} (no session folder with a live monitor.running).' -f $OutputRoot)
        return 'None'
    }
    $user = [string]$env:USERNAME
    foreach ($s in $live) {
        $stopFile = [IO.Path]::Combine($s.Folder, 'STOP')
        try {
            [IO.File]::WriteAllText($stopFile, ('stop requested {0} by {1}{2}' -f (Get-IsoTimestamp), $user, "`r`n"), (New-Object System.Text.UTF8Encoding($false)))
            Write-Log -Level Info -Message ('STOP file created for monitor PID {0}: {1}' -f ([int]$s.Pid).ToString($inv), $s.Folder)
        } catch {
            Write-Log -Level Error -Message ('Cannot create {0}: {1}' -f $stopFile, $_.Exception.Message)
        }
    }
    $deadline = (Get-Date).AddSeconds(30)
    $remaining = @($live)
    while ($remaining.Count -gt 0 -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
        $remaining = @($remaining | Where-Object { [IO.File]::Exists($_.Marker) -and (Test-WdMonPidAlive -ProcessId ([int]$_.Pid)) })
    }
    $outcome = 'Stopped'
    foreach ($s in $live) {
        $stillRunning = $false
        foreach ($r in $remaining) { if ($r.Folder -eq $s.Folder) { $stillRunning = $true } }
        if ($stillRunning) {
            $outcome = 'Signaled'
            Write-Log -Level Warn -NoConsole -Message ('Monitor PID {0} has not confirmed the stop within 30 s (it stops at its next check; the STOP file stays in place): {1}' -f ([int]$s.Pid).ToString($inv), $s.Folder)
        } else {
            Write-Log -Level Info -Message ('Monitor PID {0} stopped: {1}' -f ([int]$s.Pid).ToString($inv), $s.Folder)
        }
    }
    return $outcome
}

# ---------------------------------------------------------------------------------------------
# Public: scheduled task "WinDebug Monitor"
# ---------------------------------------------------------------------------------------------
function Get-WdMonTaskName {
    [CmdletBinding()]
    param()
    $n = ''
    try { $n = [string](Get-WinDebugRule -Name 'MonitorTaskName') } catch { $n = '' }
    if ([string]::IsNullOrEmpty($n)) { $n = 'WinDebug Monitor' }
    return $n
}

function Test-MonitorTaskInstalled {
    [CmdletBinding()]
    param()
    try {
        $t = Get-ScheduledTask -TaskName (Get-WdMonTaskName) -ErrorAction SilentlyContinue
        return ($null -ne $t)
    } catch { return $false }
}

function New-WdMonTaskDefinition {
    # Builds (does not register) the task objects. Returns @{ Task; Action; Trigger; Settings; Principal; Arguments; RunLevel }.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [int]$IntervalSeconds = 10
    )
    $inv = Get-WdInv
    if ($IntervalSeconds -lt 5) { $IntervalSeconds = 5 }
    $repo = [string]$script:RepoRoot
    $entry = [IO.Path]::Combine($repo, 'WinDebug.ps1')
    if ($repo.StartsWith('\\')) { throw 'The task cannot point to a network (UNC) folder; copy win-debug to a local folder first.' }
    if (-not [IO.File]::Exists($entry)) { throw ('WinDebug.ps1 not found at {0}' -f $entry) }
    $root = Resolve-PathSafe -Path $OutputRoot
    $user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    # Paths are quoted with the Win32 rules (ConvertTo-CommandLineArgument): a naive "{0}" around a root that ends
    # with a backslash ("D:\reports\", "C:\") would be read by the child as D:\reports" -IntervalSeconds 10 and
    # the hidden task would fail at every logon without any visible sign.
    $arguments = '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File {0} -Mode Monitor -NoElevate -OutputRoot {1} -IntervalSeconds {2}' -f (ConvertTo-CommandLineArgument -Text $entry), (ConvertTo-CommandLineArgument -Text $root), $IntervalSeconds.ToString($inv)
    $runLevel = 'Limited'
    if ($script:IsAdmin) { $runLevel = 'Highest' }
    $hostExe = Get-WdMonPowerShellPath
    $action = New-ScheduledTaskAction -Execute $hostExe -Argument $arguments -WorkingDirectory $repo
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
    $trigger.Delay = 'PT1M'
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel $runLevel
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description 'win-debug background process monitor (read-only diagnostics). Remove with WinDebug.cmd -UninstallTask.'
    return @{ Task = $task; Action = $action; Trigger = $trigger; Settings = $settings; Principal = $principal; Arguments = $arguments; RunLevel = $runLevel; User = $user; Execute = $hostExe }
}

function Get-WdMonPowerShellPath {
    # Fully qualified Windows PowerShell 5.1 host for the task action (never a bare "powershell.exe" resolved through PATH).
    [CmdletBinding()]
    param()
    $p = ''
    try { $p = [IO.Path]::Combine([string]$PSHOME, 'powershell.exe') } catch { $p = '' }
    if ([string]::IsNullOrEmpty($p) -or -not [IO.File]::Exists($p)) {
        $p = [IO.Path]::Combine([Environment]::GetFolderPath([Environment+SpecialFolder]::System), 'WindowsPowerShell\v1.0\powershell.exe')
    }
    return $p
}

function Install-MonitorTask {
    <#
    .SYNOPSIS
        Registers the per-user logon task "WinDebug Monitor" (RunLevel Highest only when the installing session is elevated).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [int]$IntervalSeconds = 10
    )
    $name = Get-WdMonTaskName
    try {
        $def = New-WdMonTaskDefinition -OutputRoot $OutputRoot -IntervalSeconds $IntervalSeconds
        Write-Log -Level Info -Message ('Registering task "{0}" for {1} (RunLevel {2}, AtLogOn + 1 min): "{3}" {4}' -f $name, $def.User, $def.RunLevel, $def.Execute, $def.Arguments)
        Register-ScheduledTask -TaskName $name -InputObject $def.Task -Force -ErrorAction Stop | Out-Null
        if (Test-MonitorTaskInstalled) {
            Write-Log -Level Info -Message ('Task "{0}" registered. It starts the monitor one minute after each logon of {1}; stop it with WinDebug.cmd -StopMonitor, remove it with -UninstallTask.' -f $name, $def.User)
            return $true
        }
        Write-Log -Level Error -Message ('Task "{0}" was not found after registration.' -f $name)
        return $false
    } catch {
        $msg = $_.Exception.Message
        # Culture-neutral first (the message is localized on a Russian-UI Windows): exception type, HRESULT
        # 0x80070005 (E_ACCESSDENIED), CIM error id; the English text is only a fallback.
        $ex = $_.Exception
        $hresult = 0
        try { $hresult = [int]$ex.HResult } catch { $hresult = 0 }
        $fqid = ''
        try { $fqid = [string]$_.FullyQualifiedErrorId } catch { $fqid = '' }
        $denied = ($ex -is [System.UnauthorizedAccessException]) -or ($hresult -eq -2147024891) -or ($fqid -match 'AccessDenied|UnauthorizedAccess|HRESULT 0x80070005') -or ($msg -match 'Access is denied|denied')
        if ($denied -and -not $script:IsAdmin) { $msg = $msg + ' (requires administrator for this option; a standard user can register the task only with RunLevel Limited)' }
        Write-Log -Level Error -Message ('Task "{0}" installation failed: {1}' -f $name, $msg)
        return $false
    }
}

function Uninstall-MonitorTask {
    <#
    .SYNOPSIS
        Removes the logon task "WinDebug Monitor". Returns $false when it does not exist or removal failed.
    #>
    [CmdletBinding()]
    param()
    $name = Get-WdMonTaskName
    if (-not (Test-MonitorTaskInstalled)) {
        Write-Log -Level Warn -Message ('Task "{0}" is not registered.' -f $name)
        return $false
    }
    try {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
        if (Test-MonitorTaskInstalled) {
            Write-Log -Level Error -Message ('Task "{0}" still exists after removal.' -f $name)
            return $false
        }
        Write-Log -Level Info -Message ('Task "{0}" removed.' -f $name)
        return $true
    } catch {
        Write-Log -Level Error -Message ('Task "{0}" removal failed: {1}' -f $name, $_.Exception.Message)
        return $false
    }
}
