# lib\Analyze.ps1 - Analyze mode of win-debug: turns a recorded monitor session into report.md (miner hunt).
# Dot-sourced by WinDebug.ps1 after lib\Common.ps1 (same script scope). Windows PowerShell 5.1 only.
#
# Public:  Invoke-MonitorAnalysis -SessionPath <folder> [-TopN 50]  -> path of report.md
# Private: *-WdAn* helpers (CSV streaming, aggregation, scoring, rendering).
# Input:   a monitor session folder as documented in docs\monitor-format.md (samples_*.csv, procs_*.csv,
#          procmeta.csv, procsum.json, net.csv, dns.csv, events.csv, run.json). Files may be missing or truncated;
#          CSV files are streamed line by line (never Import-Csv), rows with a wrong field count are skipped and counted.
# Output:  report.md, analysis.json, suspects.csv, process-summary.csv written INTO the session folder (plus analyze.log).
# Scoring: docs\analyze-scoring.md. Rule data (regexes, pool ports, trusted signers, known heavy processes) comes
#          from $script:Rules in lib\Common.ps1 and is never duplicated here.
# Read-only: nothing on the machine is touched; the analysis only reads the session folder and writes into it.
# Privacy: the report repeats data from the session (paths, command lines, remote addresses); nothing is uploaded.
#          VirusTotal links are plain URLs for the reader to open manually.

Set-StrictMode -Off

$script:WdAnSuspiciousThreshold = 8      # score >= 8  -> Suspicious
$script:WdAnHighThreshold       = 15     # score >= 15 -> Highly suspicious
$script:WdAnIdleMinSamples      = 20     # samples needed in BOTH states for an idle-vs-active comparison
$script:WdAnAdminText           = '(requires administrator)'
$script:WdAnVtUrl               = 'https://www.virustotal.com/gui/file/'
$script:WdAnWeakScriptHostPoints = 2     # cap for WEAK script-host evidence (I11 launch options, 4104 window hiding); never near-certain
$script:WdAnWindowHideRegex     = '-w(indowstyle)?\s+h(idden)?\b'   # window-hiding launch option: WEAK evidence in 4104 script blocks
$script:WdAnMaxColumns          = 60     # timeline width (buckets are merged above this)
$script:WdAnBlocks              = [char[]]@(0x2581, 0x2582, 0x2583, 0x2584, 0x2585, 0x2586, 0x2587, 0x2588)
$script:WdAnSuspiciousLocations = @('Temp', 'RecycleBin', 'Public', 'AppData', 'ProgramData', 'Downloads', 'Removable', 'UserProfile')
$script:WdAnTrustedLocations    = @('System32', 'Windows', 'ProgramFiles')
# Sub-folders of %windir% that ordinary users can write to (classic non-admin drop folders). Get-ProcessLocationClass
# classifies them as Windows/System32; a file there is NOT in a trusted location for I5/I8/I9/I12/I16/I17 and damping.
$script:WdAnWritableWindowsRegex = '^(tasks|tracing|temp|debug\\wia|registration\\crmlog|servicing\\packages|system32\\tasks|syswow64\\tasks|system32\\spool\\drivers\\color|system32\\spool\\printers|system32\\microsoft\\crypto\\rsa\\machinekeys|system32\\com\\dmp|syswow64\\com\\dmp)\\'
$script:WdAnMaxErrorTextLength  = 200    # JSON parse errors echo the whole input in PS 5.1; keep only the reason

# ---------------------------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------------------------
function Get-WdAnDateTime {
    # ISO 8601 with offset -> local DateTime, or $null.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $dto = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($Text.Trim(), (Get-WdInv), [Globalization.DateTimeStyles]::AssumeLocal, [ref]$dto)) { return $dto.LocalDateTime }
    return $null
}

function Format-WdAnNum {
    [CmdletBinding()]
    param([AllowNull()][object]$Value, [int]$Decimals = 1)
    if ($null -eq $Value) { return '' }
    $d = 0.0
    try { $d = [double]$Value } catch { return '' }
    if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return '' }
    return ([math]::Round($d, $Decimals, [MidpointRounding]::AwayFromZero)).ToString('F' + $Decimals.ToString((Get-WdInv)), (Get-WdInv))
}

function Format-WdAnInt {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    try { return ([int64][math]::Round([double]$Value, 0, [MidpointRounding]::AwayFromZero)).ToString((Get-WdInv)) } catch { return '' }
}

function Format-WdAnPath {
    # Shortens a long path for a markdown cell (the CSV files keep the full path).
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path, [int]$Max = 90)
    if ([string]::IsNullOrEmpty($Path)) { return '' }
    if ($Path.Length -le $Max) { return $Path }
    $tail = $Path.Substring($Path.Length - ($Max - 6))
    return ($Path.Substring(0, 3) + '...' + $tail)
}

function Get-WdAnDisplayName {
    [CmdletBinding()]
    param([AllowNull()][hashtable]$Subject)
    if ($null -eq $Subject) { return '' }
    $n = [string]$Subject['ImageName']
    if ([string]::IsNullOrEmpty($n)) { $n = [string]$Subject['Name'] }
    if ([string]::IsNullOrEmpty($n)) { $n = '?' }
    return $n
}

function Get-WdAnVtLink {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Sha256)
    if ([string]::IsNullOrEmpty($Sha256)) { return '' }
    if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$') { return '' }
    return ('[VT](' + $script:WdAnVtUrl + $Sha256.ToLowerInvariant() + ')')
}

function Get-WdAnNameEntropy {
    # Shannon entropy (bits) of the lower-case base name without extension.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Name)
    if ([string]::IsNullOrEmpty($Name)) { return 0.0 }
    $s = $Name
    try { $s = [IO.Path]::GetFileNameWithoutExtension($Name) } catch { $s = $Name }
    if ([string]::IsNullOrEmpty($s)) { return 0.0 }
    $s = $s.ToLowerInvariant()
    $f = @{}
    foreach ($c in $s.ToCharArray()) { $f[$c] = 1 + [int]$f[$c] }
    $e = 0.0
    foreach ($v in $f.Values) { $p = [double]$v / $s.Length; $e -= $p * [math]::Log($p, 2) }
    return [math]::Round($e, 2)
}

function Get-WdAnLevenshtein {
    [CmdletBinding()]
    param([string]$A, [string]$B)
    if ($null -eq $A) { $A = '' }
    if ($null -eq $B) { $B = '' }
    $n = $A.Length; $m = $B.Length
    if ($n -eq 0) { return $m }
    if ($m -eq 0) { return $n }
    $prev = New-Object 'int[]' ($m + 1)
    $cur = New-Object 'int[]' ($m + 1)
    for ($j = 0; $j -le $m; $j++) { $prev[$j] = $j }
    for ($i = 1; $i -le $n; $i++) {
        $cur[0] = $i
        for ($j = 1; $j -le $m; $j++) {
            $cost = 1
            if ($A[$i - 1] -eq $B[$j - 1]) { $cost = 0 }
            $v = $prev[$j] + 1
            if ($cur[$j - 1] + 1 -lt $v) { $v = $cur[$j - 1] + 1 }
            if ($prev[$j - 1] + $cost -lt $v) { $v = $prev[$j - 1] + $cost }
            $cur[$j] = $v
        }
        $tmp = $prev; $prev = $cur; $cur = $tmp
    }
    return $prev[$m]
}

function Test-WdAnWritableWindowsPath {
    # True when the executable lives in a user-writable sub-folder of %windir% (C:\Windows\Tasks, \Tracing,
    # \System32\Tasks, \Registration\CRMLog, ...): classified Windows/System32 by Get-ProcessLocationClass but not trusted.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $win = Get-WdFolderPrefix -Value ([string]$env:windir)
    if ([string]::IsNullOrEmpty($win)) { $win = 'c:\windows\' }
    $l = $Path.Trim('"').ToLowerInvariant()
    if (-not $l.StartsWith($win)) { return $false }
    return ($l.Substring($win.Length) -match $script:WdAnWritableWindowsRegex)
}

function Get-WdAnUnknownPathText {
    # Location/path cell for a subject without a readable path. The '(requires administrator)' marker is reserved for
    # data that is missing because of missing rights (never for processes that exited early or kernel/protected ones).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$S)
    if ($S.NeedsAdmin) { return ('unknown ' + $script:WdAnAdminText) }
    $note = [string]$S.AccessNote
    if ($note -eq 'exited before metadata') { return 'unknown (exited before metadata)' }
    if ($note -eq 'path not available') { return 'unknown (kernel/protected process)' }
    return 'unknown'
}

function Test-WdAnNameInList {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Name, [AllowNull()][object[]]$List)
    if ([string]::IsNullOrEmpty($Name) -or $null -eq $List) { return $false }
    $base = $Name
    if ($base -match '\.exe$') { $base = $base.Substring(0, $base.Length - 4) }
    foreach ($item in $List) { if ([string]::Equals([string]$item, $base, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
    return $false
}

# ---------------------------------------------------------------------------------------------
# CSV streaming (StreamReader, header map, FileShare.ReadWrite so a live session can be read)
# ---------------------------------------------------------------------------------------------
function Split-WdAnCsvLine {
    # Full CSV parser for lines that contain quotes ("" = literal quote). Lines without quotes use String.Split.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Line)
    $fields = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $Line) { return $fields.ToArray() }
    $sb = New-Object System.Text.StringBuilder
    $inQ = $false
    $n = $Line.Length
    $i = 0
    while ($i -lt $n) {
        $c = $Line[$i]
        if ($inQ) {
            if ($c -eq '"') {
                if (($i + 1) -lt $n -and $Line[$i + 1] -eq '"') { [void]$sb.Append('"'); $i++ } else { $inQ = $false }
            } else { [void]$sb.Append($c) }
        } else {
            if ($c -eq ',') { $fields.Add($sb.ToString()); [void]$sb.Clear() }
            elseif ($c -eq '"') { $inQ = $true }
            else { [void]$sb.Append($c) }
        }
        $i++
    }
    $fields.Add($sb.ToString())
    return $fields.ToArray()
}

function Open-WdAnCsvReader {
    # Returns @{ Reader; Columns; Index; Count; Path } or $null (empty file). Caller must Close() the reader.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $fs = New-Object System.IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    $sr = New-Object System.IO.StreamReader($fs, (New-Object System.Text.UTF8Encoding($false)), $true)
    $header = $sr.ReadLine()
    if ($null -eq $header) { $sr.Close(); return $null }
    $header = $header.TrimStart([char]0xFEFF)
    if ($header.IndexOf('"') -ge 0) { $cols = @(Split-WdAnCsvLine -Line $header) } else { $cols = @($header.Split(',')) }
    $index = @{}
    for ($i = 0; $i -lt $cols.Count; $i++) { $index[[string]$cols[$i]] = $i }
    return @{ Reader = $sr; Columns = $cols; Index = $index; Count = $cols.Count; Path = $Path }
}

function Get-WdAnColumn {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Reader, [Parameter(Mandatory = $true)][string]$Name)
    if ($Reader.Index.ContainsKey($Name)) { return [int]$Reader.Index[$Name] }
    return -1
}

function Get-WdAnField {
    [CmdletBinding()]
    param([AllowNull()][string[]]$Fields, [int]$Index)
    if ($Index -lt 0 -or $null -eq $Fields -or $Index -ge $Fields.Length) { return '' }
    return [string]$Fields[$Index]
}

function Read-WdAnCsvRows {
    # Generic streaming reader for the small files (procmeta, net, dns, events): one hashtable per row.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [hashtable]$Stats, [string]$StatName = 'Rows')
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if (-not (Test-FileExists -Path $Path)) { return $rows.ToArray() }
    $rd = $null
    $skipped = 0
    try {
        $rd = Open-WdAnCsvReader -Path $Path
        if ($null -eq $rd) { return $rows.ToArray() }
        $cols = $rd.Columns
        $ncol = $rd.Count
        $r = $rd.Reader
        while ($null -ne ($line = $r.ReadLine())) {
            if ($line.Length -eq 0) { continue }
            if ($line.IndexOf('"') -ge 0) { $f = @(Split-WdAnCsvLine -Line $line) } else { $f = $line.Split(',') }
            if ($f.Length -ne $ncol) { $skipped++; continue }
            $row = @{}
            for ($i = 0; $i -lt $ncol; $i++) { $row[[string]$cols[$i]] = [string]$f[$i] }
            $rows.Add($row)
        }
    } finally {
        if ($null -ne $rd -and $null -ne $rd.Reader) { $rd.Reader.Close() }
    }
    if ($null -ne $Stats) {
        $Stats[$StatName] = [int]$Stats[$StatName] + $rows.Count
        $Stats['SkippedRows'] = [int]$Stats['SkippedRows'] + $skipped
        if ($skipped -gt 0) { $Stats['SkippedFiles'] = [string]$Stats['SkippedFiles'] + ('{0}: {1}; ' -f [IO.Path]::GetFileName($Path), $skipped) }
    }
    return $rows.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Session files
# ---------------------------------------------------------------------------------------------
function Get-WdAnSessionFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SessionPath)
    $samples = @()
    $procs = @()
    try { $samples = @([IO.Directory]::GetFiles($SessionPath, 'samples_*.csv') | Sort-Object) } catch { $samples = @() }
    try { $procs = @([IO.Directory]::GetFiles($SessionPath, 'procs_*.csv') | Sort-Object) } catch { $procs = @() }
    $one = {
        param([string]$Name)
        $p = [IO.Path]::Combine($SessionPath, $Name)
        if (Test-FileExists -Path $p) { return $p }
        return ''
    }
    return @{
        Samples  = $samples
        Procs    = $procs
        ProcMeta = (& $one 'procmeta.csv')
        ProcSum  = (& $one 'procsum.json')
        Net      = (& $one 'net.csv')
        Dns      = (& $one 'dns.csv')
        Events   = (& $one 'events.csv')
        RunJson  = (& $one 'run.json')
        Running  = (& $one 'monitor.running')
    }
}

function ConvertFrom-WdAnJsonText {
    # ConvertFrom-Json with a short error: in PS 5.1 the JavaScriptSerializer message is '<reason> (<offset>): <whole input>',
    # which would otherwise flood the console, analyze.log and CollectionErrors with the entire (corrupt) file.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text, [AllowNull()][AllowEmptyString()][string]$Path)
    try {
        return (ConvertFrom-Json -InputObject $Text)
    } catch {
        $m = [string]$_.Exception.Message
        if ([string]::IsNullOrEmpty($m)) { $m = [string]$_ }
        $cut = $m.IndexOf('): ')
        if ($cut -gt 0) { $m = $m.Substring(0, $cut + 1) }
        $m = ($m -replace '\r\n|\r|\n', ' ').Trim()
        if ($m.Length -gt $script:WdAnMaxErrorTextLength) { $m = $m.Substring(0, $script:WdAnMaxErrorTextLength) + '...' }
        $name = 'JSON text'
        if (-not [string]::IsNullOrEmpty($Path)) { try { $name = [IO.Path]::GetFileName($Path) } catch { $name = $Path } }
        throw ('{0} is not valid JSON ({1} chars): {2}' -f $name, $Text.Length.ToString((Get-WdInv)), $m)
    }
}

function Read-WdAnRunInfo {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrEmpty($Path) -or -not (Test-FileExists -Path $Path)) { return $null }
    $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return (ConvertFrom-WdAnJsonText -Text $text -Path $Path)
}

function Read-WdAnProcSum {
    # procsum.json -> @{ Meta; Processes (hashtable Key -> PSCustomObject); Count }
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrEmpty($Path) -or -not (Test-FileExists -Path $Path)) { return $null }
    $text = [IO.File]::ReadAllText($Path, [Text.Encoding]::UTF8)
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $obj = ConvertFrom-WdAnJsonText -Text $text -Path $Path
    $result = @{ Meta = $obj.Meta; Processes = @{}; Count = 0; PathKeys = @{} }
    if ($null -ne $obj.Processes) {
        foreach ($p in $obj.Processes.PSObject.Properties) {
            $k = [string]$p.Name
            $result.Processes[$k] = $p.Value
            $result.Count++
            $procPath = [string]$p.Value.Path   # not $path: same variable as the $Path parameter in PowerShell
            if (-not [string]::IsNullOrEmpty($procPath)) {
                $pl = $procPath.ToLowerInvariant()
                if (-not $result.PathKeys.ContainsKey($pl)) { $result.PathKeys[$pl] = New-Object 'System.Collections.Generic.List[string]' }
                $result.PathKeys[$pl].Add($k)
            }
        }
    }
    return $result
}


# ---------------------------------------------------------------------------------------------
# samples_*.csv -> system totals, per-sample idle map, 10-minute buckets
# Bucket layout (double[16]): 0 CpuSum, 1 N, 2 CpuMax, 3 GpuSum, 4 GpuMax, 5 MemSum, 6 MemMax, 7 DiskSum, 8 DiskMax,
#   9 NetSum, 10 NetMax, 11 IdleN, 12 GpuCompSum, 13 DiskBpsSum, 14 DiskBpsMax, 15 RateN (samples with rate values)
# ---------------------------------------------------------------------------------------------
function Read-WdAnSamples {
    [CmdletBinding()]
    param([AllowNull()][string[]]$Files, [hashtable]$Stats)
    $inv = Get-WdInv
    $ns = [Globalization.NumberStyles]::Float
    $S = @{
        Rows = 0; Skipped = 0; Files = 0
        Ts = New-Object 'System.Collections.Generic.List[string]'
        Idle = New-Object 'System.Collections.Generic.List[bool]'
        TsIndex = @{}; Interval = @{}
        CumIdle = $null
        IdleN = 0; ActiveN = 0; LockedN = 0; Overruns = 0
        IntervalSum = 0.0; IntervalN = 0; IntervalMax = 0.0
        CpuSum = 0.0; CpuN = 0; CpuMax = -1.0; CpuMaxTs = ''; CpuMaxTop = ''
        KernelSum = 0.0; DpcSum = 0.0; GapSum = 0.0; GapN = 0; PerfLowN = 0; PerfSum = 0.0; PerfN = 0
        GpuSum = 0.0; GpuN = 0; GpuMax = -1.0; GpuMaxTs = ''; GpuCompSum = 0.0; GpuCompMax = -1.0
        MemTotal = 0.0; MemSum = 0.0; MemN = 0; MemMax = -1.0; MemMaxTs = ''; CommitMax = -1.0; PagesSum = 0.0; PagesN = 0
        PoolFirst = -1.0; PoolLast = -1.0
        DiskSum = 0.0; DiskN = 0; DiskMax = -1.0; DiskMaxTs = ''; DiskBpsSum = 0.0; DiskBpsMax = -1.0; DiskBpsMaxTs = ''; DiskQueueMax = 0.0
        NetSum = 0.0; NetN = 0; NetMax = -1.0; NetMaxTs = ''
        TempMax = -1.0; TempN = 0; ThrottleN = 0; BatteryN = 0; OnBatteryN = 0; BatteryMin = -1.0
        ProcCountMin = -1; ProcCountMax = -1; ProcCountLast = -1
        TopCpu = @{}
        Buckets = @{}
        First = ''; Last = ''
    }
    if ($null -eq $Files) { $Files = @() }
    foreach ($file in $Files) {
        $rd = $null
        try {
            $rd = Open-WdAnCsvReader -Path $file
            if ($null -eq $rd) { continue }
            $S.Files++
            $iTs = Get-WdAnColumn -Reader $rd -Name 'Timestamp'
            $iIdle = Get-WdAnColumn -Reader $rd -Name 'IsIdle'
            if ($iTs -lt 0) { Write-Log -Level Warn -Message ('{0}: no Timestamp column, file skipped' -f [IO.Path]::GetFileName($file)); continue }
            $iInt = Get-WdAnColumn -Reader $rd -Name 'IntervalSec'
            $iOver = Get-WdAnColumn -Reader $rd -Name 'Overrun'
            $iCpu = Get-WdAnColumn -Reader $rd -Name 'CpuPct'
            $iKern = Get-WdAnColumn -Reader $rd -Name 'CpuKernelPct'
            $iDpc = Get-WdAnColumn -Reader $rd -Name 'CpuDpcIntPct'
            $iPSum = Get-WdAnColumn -Reader $rd -Name 'CpuProcSumPct'
            $iPerf = Get-WdAnColumn -Reader $rd -Name 'CpuPerfPct'
            $iMemT = Get-WdAnColumn -Reader $rd -Name 'MemTotalMB'
            $iMemU = Get-WdAnColumn -Reader $rd -Name 'MemUsedMB'
            $iCommit = Get-WdAnColumn -Reader $rd -Name 'CommitPct'
            $iPages = Get-WdAnColumn -Reader $rd -Name 'PagesPerSec'
            $iPool = Get-WdAnColumn -Reader $rd -Name 'PoolNonpagedBytes'
            $iDisk = Get-WdAnColumn -Reader $rd -Name 'DiskActivePct'
            $iDq = Get-WdAnColumn -Reader $rd -Name 'DiskQueue'
            $iDr = Get-WdAnColumn -Reader $rd -Name 'DiskReadBps'
            $iDw = Get-WdAnColumn -Reader $rd -Name 'DiskWriteBps'
            $iNr = Get-WdAnColumn -Reader $rd -Name 'NetRecvBps'
            $iNsent = Get-WdAnColumn -Reader $rd -Name 'NetSentBps'
            $iGpu = Get-WdAnColumn -Reader $rd -Name 'GpuPct'
            $iGComp = Get-WdAnColumn -Reader $rd -Name 'GpuComputePct'
            $iBat = Get-WdAnColumn -Reader $rd -Name 'BatteryPct'
            $iOnBat = Get-WdAnColumn -Reader $rd -Name 'OnBattery'
            $iTemp = Get-WdAnColumn -Reader $rd -Name 'TempC'
            $iThr = Get-WdAnColumn -Reader $rd -Name 'ThrottleReasons'
            $iLock = Get-WdAnColumn -Reader $rd -Name 'SessionLocked'
            $iPc = Get-WdAnColumn -Reader $rd -Name 'ProcessCount'
            $iTopN = Get-WdAnColumn -Reader $rd -Name 'TopCpuName'
            $iTopP = Get-WdAnColumn -Reader $rd -Name 'TopCpuPct'
            $ncol = $rd.Count
            $r = $rd.Reader
            $d = 0.0
            $d2 = 0.0
            while ($null -ne ($line = $r.ReadLine())) {
                if ($line.Length -eq 0) { continue }
                if ($line.IndexOf('"') -ge 0) { $f = @(Split-WdAnCsvLine -Line $line) } else { $f = $line.Split(',') }
                if ($f.Length -ne $ncol) { $S.Skipped++; continue }
                $ts = $f[$iTs]
                if ($ts.Length -lt 19) { $S.Skipped++; continue }
                if ($S.TsIndex.ContainsKey($ts)) { continue }
                $S.TsIndex[$ts] = $S.Ts.Count
                $S.Ts.Add($ts)
                $isIdle = $false
                if ($iIdle -ge 0) { $isIdle = ($f[$iIdle] -eq 'True') }
                $S.Idle.Add($isIdle)
                if ($isIdle) { $S.IdleN++ } else { $S.ActiveN++ }
                if ($S.First -eq '') { $S.First = $ts }
                $S.Last = $ts
                $S.Rows++
                if ($iLock -ge 0 -and $f[$iLock] -eq 'True') { $S.LockedN++ }
                if ($iOver -ge 0 -and $f[$iOver] -eq 'True') { $S.Overruns++ }
                if ($iInt -ge 0 -and [double]::TryParse($f[$iInt], $ns, $inv, [ref]$d)) {
                    $S.Interval[$ts] = $d
                    $S.IntervalSum += $d; $S.IntervalN++
                    if ($d -gt $S.IntervalMax) { $S.IntervalMax = $d }
                }
                $bk = $ts.Substring(0, 16)
                $b = $S.Buckets[$bk]
                if ($null -eq $b) {
                    $b = New-Object 'double[]' 16
                    $b[2] = -1.0; $b[4] = -1.0; $b[6] = -1.0; $b[8] = -1.0; $b[10] = -1.0; $b[14] = -1.0
                    $S.Buckets[$bk] = $b
                }
                $b[1] += 1.0
                if ($isIdle) { $b[11] += 1.0 }
                $cpuVal = -1.0
                if ($iCpu -ge 0 -and [double]::TryParse($f[$iCpu], $ns, $inv, [ref]$d)) {
                    $cpuVal = $d
                    $S.CpuSum += $d; $S.CpuN++
                    if ($d -gt $S.CpuMax) {
                        $S.CpuMax = $d; $S.CpuMaxTs = $ts
                        if ($iTopN -ge 0) { $S.CpuMaxTop = $f[$iTopN] + ' ' + (Get-WdAnField -Fields $f -Index $iTopP) }
                    }
                    $b[0] += $d; $b[15] += 1.0
                    if ($d -gt $b[2]) { $b[2] = $d }
                    if ($iKern -ge 0 -and [double]::TryParse($f[$iKern], $ns, $inv, [ref]$d2)) { $S.KernelSum += $d2 }
                    if ($iDpc -ge 0 -and [double]::TryParse($f[$iDpc], $ns, $inv, [ref]$d2)) { $S.DpcSum += $d2 }
                    if ($iPSum -ge 0 -and [double]::TryParse($f[$iPSum], $ns, $inv, [ref]$d2)) { $S.GapSum += ($cpuVal - $d2); $S.GapN++ }
                    if ($iPerf -ge 0 -and [double]::TryParse($f[$iPerf], $ns, $inv, [ref]$d2)) {
                        $S.PerfSum += $d2; $S.PerfN++
                        if ($d2 -lt 70.0 -and $cpuVal -gt 50.0) { $S.PerfLowN++ }
                    }
                    if ($iTopN -ge 0) {
                        $tn = $f[$iTopN]
                        if ($tn.Length -gt 0) { $S.TopCpu[$tn] = 1 + [int]$S.TopCpu[$tn] }
                    }
                }
                if ($iGpu -ge 0 -and [double]::TryParse($f[$iGpu], $ns, $inv, [ref]$d)) {
                    $S.GpuSum += $d; $S.GpuN++
                    if ($d -gt $S.GpuMax) { $S.GpuMax = $d; $S.GpuMaxTs = $ts }
                    $b[3] += $d
                    if ($d -gt $b[4]) { $b[4] = $d }
                }
                if ($iGComp -ge 0 -and [double]::TryParse($f[$iGComp], $ns, $inv, [ref]$d)) {
                    $S.GpuCompSum += $d
                    if ($d -gt $S.GpuCompMax) { $S.GpuCompMax = $d }
                    $b[12] += $d
                }
                if ($iMemT -ge 0 -and $S.MemTotal -le 0 -and [double]::TryParse($f[$iMemT], $ns, $inv, [ref]$d)) { $S.MemTotal = $d }
                if ($iMemU -ge 0 -and [double]::TryParse($f[$iMemU], $ns, $inv, [ref]$d)) {
                    $S.MemSum += $d; $S.MemN++
                    if ($d -gt $S.MemMax) { $S.MemMax = $d; $S.MemMaxTs = $ts }
                    $b[5] += $d
                    if ($d -gt $b[6]) { $b[6] = $d }
                }
                if ($iCommit -ge 0 -and [double]::TryParse($f[$iCommit], $ns, $inv, [ref]$d)) { if ($d -gt $S.CommitMax) { $S.CommitMax = $d } }
                if ($iPages -ge 0 -and [double]::TryParse($f[$iPages], $ns, $inv, [ref]$d)) { $S.PagesSum += $d; $S.PagesN++ }
                if ($iPool -ge 0 -and [double]::TryParse($f[$iPool], $ns, $inv, [ref]$d)) { if ($S.PoolFirst -lt 0) { $S.PoolFirst = $d }; $S.PoolLast = $d }
                if ($iDisk -ge 0 -and [double]::TryParse($f[$iDisk], $ns, $inv, [ref]$d)) {
                    $S.DiskSum += $d; $S.DiskN++
                    if ($d -gt $S.DiskMax) { $S.DiskMax = $d; $S.DiskMaxTs = $ts }
                    $b[7] += $d
                    if ($d -gt $b[8]) { $b[8] = $d }
                }
                if ($iDq -ge 0 -and [double]::TryParse($f[$iDq], $ns, $inv, [ref]$d)) { if ($d -gt $S.DiskQueueMax) { $S.DiskQueueMax = $d } }
                $bps = -1.0
                if ($iDr -ge 0 -and [double]::TryParse($f[$iDr], $ns, $inv, [ref]$d)) { $bps = $d }
                if ($iDw -ge 0 -and [double]::TryParse($f[$iDw], $ns, $inv, [ref]$d)) { if ($bps -lt 0) { $bps = $d } else { $bps += $d } }
                if ($bps -ge 0) {
                    $S.DiskBpsSum += $bps
                    if ($bps -gt $S.DiskBpsMax) { $S.DiskBpsMax = $bps; $S.DiskBpsMaxTs = $ts }
                    $b[13] += $bps
                    if ($bps -gt $b[14]) { $b[14] = $bps }
                }
                $bps = -1.0
                if ($iNr -ge 0 -and [double]::TryParse($f[$iNr], $ns, $inv, [ref]$d)) { $bps = $d }
                if ($iNsent -ge 0 -and [double]::TryParse($f[$iNsent], $ns, $inv, [ref]$d)) { if ($bps -lt 0) { $bps = $d } else { $bps += $d } }
                if ($bps -ge 0) {
                    $S.NetSum += $bps; $S.NetN++
                    if ($bps -gt $S.NetMax) { $S.NetMax = $bps; $S.NetMaxTs = $ts }
                    $b[9] += $bps
                    if ($bps -gt $b[10]) { $b[10] = $bps }
                }
                if ($iBat -ge 0 -and [double]::TryParse($f[$iBat], $ns, $inv, [ref]$d)) { $S.BatteryN++; if ($S.BatteryMin -lt 0 -or $d -lt $S.BatteryMin) { $S.BatteryMin = $d } }
                if ($iOnBat -ge 0 -and $f[$iOnBat] -eq 'True') { $S.OnBatteryN++ }
                if ($iTemp -ge 0 -and [double]::TryParse($f[$iTemp], $ns, $inv, [ref]$d)) { $S.TempN++; if ($d -gt $S.TempMax) { $S.TempMax = $d } }
                if ($iThr -ge 0 -and [double]::TryParse($f[$iThr], $ns, $inv, [ref]$d)) { if ($d -ne 0) { $S.ThrottleN++ } }
                if ($iPc -ge 0 -and [double]::TryParse($f[$iPc], $ns, $inv, [ref]$d)) {
                    $pc = [int]$d
                    if ($S.ProcCountMin -lt 0 -or $pc -lt $S.ProcCountMin) { $S.ProcCountMin = $pc }
                    if ($pc -gt $S.ProcCountMax) { $S.ProcCountMax = $pc }
                    $S.ProcCountLast = $pc
                }
            }
        } finally {
            if ($null -ne $rd -and $null -ne $rd.Reader) { $rd.Reader.Close() }
        }
    }
    # Cumulative idle counts for range queries (CSV-only processes: idle/active sample counts between first and last sight).
    $cum = New-Object 'int[]' ($S.Ts.Count)
    $c = 0
    for ($i = 0; $i -lt $S.Ts.Count; $i++) { if ($S.Idle[$i]) { $c++ }; $cum[$i] = $c }
    $S.CumIdle = $cum
    if ($null -ne $Stats) {
        $Stats['SampleRows'] = $S.Rows
        $Stats['SkippedRows'] = [int]$Stats['SkippedRows'] + $S.Skipped
        if ($S.Skipped -gt 0) { $Stats['SkippedFiles'] = [string]$Stats['SkippedFiles'] + ('samples: {0}; ' -f $S.Skipped) }
    }
    return $S
}

# ---------------------------------------------------------------------------------------------
# procs_*.csv -> per-Key accumulators (hot loop: no function calls per row, TryParse instead of ConvertTo-Double)
# ---------------------------------------------------------------------------------------------
function Read-WdAnProcs {
    [CmdletBinding()]
    param(
        [AllowNull()][string[]]$Files,
        [AllowNull()][hashtable]$Samples,
        [AllowNull()][object]$Interesting,
        [double]$NominalInterval = 10.0,
        [int]$BucketKeyLength = 16,
        [hashtable]$Stats
    )
    $inv = Get-WdInv
    $ns = [Globalization.NumberStyles]::Float
    if ($BucketKeyLength -ne 13) { $BucketKeyLength = 16 }
    # Invoke-Safely enumerates a returned HashSet into a string[]; rebuild the set from whatever arrived.
    if ($null -ne $Interesting -and -not ($Interesting -is [System.Collections.Generic.HashSet[string]])) {
        $set = New-Object 'System.Collections.Generic.HashSet[string]'
        foreach ($k in @($Interesting)) { if ($null -ne $k) { [void]$set.Add([string]$k) } }
        $Interesting = $set
    }
    $accs = @{}
    $rows = 0
    $skipped = 0
    $selfRows = 0
    $fileCount = 0
    $intervals = $null
    if ($null -ne $Samples) { $intervals = $Samples.Interval }
    if ($null -eq $intervals) { $intervals = @{} }
    $allKeys = ($null -eq $Interesting)
    if ($null -eq $Files) { $Files = @() }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    foreach ($file in $Files) {
        $rd = $null
        try {
            $rd = Open-WdAnCsvReader -Path $file
            if ($null -eq $rd) { continue }
            $fileCount++
            $iTs = Get-WdAnColumn -Reader $rd -Name 'Timestamp'
            $iKey = Get-WdAnColumn -Reader $rd -Name 'Key'
            $iPid = Get-WdAnColumn -Reader $rd -Name 'Pid'
            $iName = Get-WdAnColumn -Reader $rd -Name 'Name'
            if ($iTs -lt 0 -or $iKey -lt 0 -or $iName -lt 0) { Write-Log -Level Warn -Message ('{0}: Timestamp/Key/Name columns missing, file skipped' -f [IO.Path]::GetFileName($file)); continue }
            $iCpu = Get-WdAnColumn -Reader $rd -Name 'CpuPct'
            $iCores = Get-WdAnColumn -Reader $rd -Name 'CpuCores'
            $iGpu = Get-WdAnColumn -Reader $rd -Name 'GpuPct'
            $iG3d = Get-WdAnColumn -Reader $rd -Name 'Gpu3D'
            $iGc = Get-WdAnColumn -Reader $rd -Name 'GpuCompute'
            $iGvd = Get-WdAnColumn -Reader $rd -Name 'GpuVideoDecode'
            $iGve = Get-WdAnColumn -Reader $rd -Name 'GpuVideoEncode'
            $iRb = Get-WdAnColumn -Reader $rd -Name 'ReadBps'
            $iWb = Get-WdAnColumn -Reader $rd -Name 'WriteBps'
            $iWs = Get-WdAnColumn -Reader $rd -Name 'WorkingSet'
            $iPrio = Get-WdAnColumn -Reader $rd -Name 'BasePriority'
            $iWin = Get-WdAnColumn -Reader $rd -Name 'HasWindow'
            $iIdle = Get-WdAnColumn -Reader $rd -Name 'IsIdle'
            $iFlags = Get-WdAnColumn -Reader $rd -Name 'Flags'
            $ncol = $rd.Count
            $r = $rd.Reader
            $d = 0.0
            $cores = 0.0
            while ($null -ne ($line = $r.ReadLine())) {
                if ($line.Length -eq 0) { continue }
                if ($line.IndexOf('"') -ge 0) { $f = @(Split-WdAnCsvLine -Line $line) } else { $f = $line.Split(',') }
                if ($f.Length -ne $ncol) { $skipped++; continue }
                # Same rule as Read-WdAnSamples: the bucket keys below take Substring(0, 13|16) of the timestamp.
                if ($f[$iTs].Length -lt 19) { $skipped++; continue }
                $rows++
                if (($rows % 250000) -eq 0) { Write-Log -Level Debug -Message ('procs: {0} rows read ({1:F0} s)' -f $rows, $sw.Elapsed.TotalSeconds) }
                $flags = ''
                if ($iFlags -ge 0) { $flags = $f[$iFlags] }
                if ($flags.Length -gt 0 -and $flags.IndexOf('Self') -ge 0) { $selfRows++; continue }
                $key = $f[$iKey]
                $ts = $f[$iTs]
                $acc = $accs[$key]
                if ($null -eq $acc) {
                    $acc = @{
                        Name = $f[$iName]; Pid = (Get-WdAnField -Fields $f -Index $iPid)
                        Rows = 0; CpuRows = 0; CpuSum = 0.0; CpuMax = 0.0; CoresMax = 0.0; CpuSec = 0.0
                        IdleN = 0; ActN = 0; IdleCpu = 0.0; ActCpu = 0.0
                        GpuSum = 0.0; GpuMax = 0.0; GpuSec = 0.0; GpuCompSec = 0.0; Gpu3DSec = 0.0; GpuVidSec = 0.0
                        GpuCompIdle = 0.0; GpuCompAct = 0.0; GpuIdle = 0.0; GpuAct = 0.0
                        ReadB = 0.0; WriteB = 0.0; WsMax = 0.0; WsFirst = -1.0; WsLast = 0.0
                        LowPrioN = 0; Prio = 0; WinEver = $false; WinLast = ''
                        FirstTs = $ts; LastTs = $ts; New = $false; Exited = $false; ExitTs = ''
                        Flat = @{}; Buckets = $null
                    }
                    $accs[$key] = $acc
                }
                $acc.Rows++
                $acc.LastTs = $ts
                if ($flags.Length -gt 0) {
                    if ($flags.IndexOf('New') -ge 0) { $acc.New = $true }
                    if ($flags.IndexOf('Exited') -ge 0) { $acc.Exited = $true; $acc.ExitTs = $ts; continue }
                }
                $isIdle = $false
                if ($iIdle -ge 0) { $isIdle = ($f[$iIdle] -eq 'True') }
                $dt = $intervals[$ts]
                if ($null -eq $dt) { $dt = $NominalInterval }
                $hasCpu = $false
                if ($iCpu -ge 0 -and [double]::TryParse($f[$iCpu], $ns, $inv, [ref]$d)) {
                    $hasCpu = $true
                    $acc.CpuRows++
                    $acc.CpuSum += $d
                    if ($d -gt $acc.CpuMax) { $acc.CpuMax = $d }
                    if ($isIdle) { $acc.IdleN++; $acc.IdleCpu += $d } else { $acc.ActN++; $acc.ActCpu += $d }
                    $cpuVal = $d
                    if ($iCores -ge 0 -and [double]::TryParse($f[$iCores], $ns, $inv, [ref]$cores)) {
                        $acc.CpuSec += $cores * $dt
                        if ($cores -gt $acc.CoresMax) { $acc.CoresMax = $cores }
                        $rc = [math]::Round($cores, 0, [MidpointRounding]::AwayFromZero)
                        if ($rc -ge 1.0 -and [math]::Abs($cores - $rc) -le (0.1 * $rc)) { $ri = [int]$rc; $acc.Flat[$ri] = 1 + [int]$acc.Flat[$ri] }
                    }
                    if ($allKeys -or $Interesting.Contains($key)) {
                        $bk = $ts.Substring(0, $BucketKeyLength)
                        if ($null -eq $acc.Buckets) { $acc.Buckets = @{} }
                        $bb = $acc.Buckets[$bk]
                        if ($null -eq $bb) { $bb = New-Object 'double[]' 4; $acc.Buckets[$bk] = $bb }
                        $bb[0] += $cpuVal; $bb[1] += 1.0
                        if ($cpuVal -gt $bb[2]) { $bb[2] = $cpuVal }
                    }
                }
                if ($iGpu -ge 0 -and [double]::TryParse($f[$iGpu], $ns, $inv, [ref]$d)) {
                    $acc.GpuSum += $d
                    if ($d -gt $acc.GpuMax) { $acc.GpuMax = $d }
                    $acc.GpuSec += $d / 100.0 * $dt
                    if ($isIdle) { $acc.GpuIdle += $d } else { $acc.GpuAct += $d }
                    if ($null -ne $acc.Buckets) { $bb = $acc.Buckets[$ts.Substring(0, $BucketKeyLength)]; if ($null -ne $bb) { $bb[3] += $d } }
                }
                if ($iGc -ge 0 -and [double]::TryParse($f[$iGc], $ns, $inv, [ref]$d)) {
                    $acc.GpuCompSec += $d / 100.0 * $dt
                    if ($isIdle) { $acc.GpuCompIdle += $d } else { $acc.GpuCompAct += $d }
                }
                if ($iG3d -ge 0 -and [double]::TryParse($f[$iG3d], $ns, $inv, [ref]$d)) { $acc.Gpu3DSec += $d / 100.0 * $dt }
                if ($iGvd -ge 0 -and [double]::TryParse($f[$iGvd], $ns, $inv, [ref]$d)) { $acc.GpuVidSec += $d / 100.0 * $dt }
                if ($iGve -ge 0 -and [double]::TryParse($f[$iGve], $ns, $inv, [ref]$d)) { $acc.GpuVidSec += $d / 100.0 * $dt }
                if ($iRb -ge 0 -and [double]::TryParse($f[$iRb], $ns, $inv, [ref]$d)) { $acc.ReadB += $d * $dt }
                if ($iWb -ge 0 -and [double]::TryParse($f[$iWb], $ns, $inv, [ref]$d)) { $acc.WriteB += $d * $dt }
                if ($iWs -ge 0 -and [double]::TryParse($f[$iWs], $ns, $inv, [ref]$d)) {
                    if ($acc.WsFirst -lt 0) { $acc.WsFirst = $d }
                    $acc.WsLast = $d
                    if ($d -gt $acc.WsMax) { $acc.WsMax = $d }
                }
                if ($iPrio -ge 0 -and [double]::TryParse($f[$iPrio], $ns, $inv, [ref]$d)) {
                    $acc.Prio = [int]$d
                    if ($hasCpu -and $d -le 6 -and $d -gt 0) { $acc.LowPrioN++ }
                }
                if ($iWin -ge 0) {
                    $w = $f[$iWin]
                    if ($w.Length -gt 0) { $acc.WinLast = $w; if ($w -eq 'True') { $acc.WinEver = $true } }
                }
            }
        } finally {
            if ($null -ne $rd -and $null -ne $rd.Reader) { $rd.Reader.Close() }
        }
    }
    $sw.Stop()
    if ($null -ne $Stats) {
        $Stats['ProcRows'] = $rows
        $Stats['ProcFiles'] = $fileCount
        $Stats['SelfRows'] = $selfRows
        $Stats['ProcKeys'] = $accs.Count
        $Stats['ProcReadSeconds'] = [math]::Round($sw.Elapsed.TotalSeconds, 1, [MidpointRounding]::AwayFromZero)
        $Stats['SkippedRows'] = [int]$Stats['SkippedRows'] + $skipped
        if ($skipped -gt 0) { $Stats['SkippedFiles'] = [string]$Stats['SkippedFiles'] + ('procs: {0}; ' -f $skipped) }
    }
    Write-Log -Level Info -Message ([string]::Format($inv, 'procs: {0} rows from {1} file(s) in {2:F1} s, {3} process keys, {4} rows skipped (wrong field count or bad timestamp), {5} rows of the monitor itself ignored', $rows, $fileCount, $sw.Elapsed.TotalSeconds, $accs.Count, $skipped, $selfRows))
    return $accs
}


# ---------------------------------------------------------------------------------------------
# procmeta.csv, dns.csv, net.csv, events.csv
# ---------------------------------------------------------------------------------------------
function Read-WdAnProcMeta {
    # -> hashtable Key -> row hashtable (last row wins for a duplicated Key)
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path, [hashtable]$Stats)
    $meta = @{}
    if ([string]::IsNullOrEmpty($Path)) { return $meta }
    foreach ($row in @(Read-WdAnCsvRows -Path $Path -Stats $Stats -StatName 'MetaRows')) {
        $k = [string]$row['Key']
        if ([string]::IsNullOrEmpty($k)) { continue }
        $meta[$k] = $row
    }
    return $meta
}

function Read-WdAnDns {
    # -> hashtable lower-case address -> List[string] of names (A/AAAA records)
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path, [hashtable]$Stats)
    $map = @{}
    if ([string]::IsNullOrEmpty($Path)) { return $map }
    foreach ($row in @(Read-WdAnCsvRows -Path $Path -Stats $Stats -StatName 'DnsRows')) {
        $type = [string]$row['Type']
        if ($type -ne 'A' -and $type -ne 'AAAA') { continue }
        $addr = ([string]$row['Data']).Trim().ToLowerInvariant()
        $name = ([string]$row['Name']).Trim()
        if ($addr -eq '' -or $name -eq '') { continue }
        if (-not $map.ContainsKey($addr)) { $map[$addr] = New-Object 'System.Collections.Generic.List[string]' }
        if (-not $map[$addr].Contains($name)) { $map[$addr].Add($name) }
    }
    return $map
}

function Read-WdAnNet {
    # -> @{ ByKey = (Key -> @{ Endpoints; RemoteIps; PublicIps; PoolPorts; RawNoDns; IdlePublic; Listen }); Established; Listen; PublicIps; PreExisting }
    # IdlePublic counts only public connections OPENED during the run while the user was idle: a connection whose
    # ConnCreated lies before the first sample (or, without ConnCreated, one first seen in sample 1) was merely
    # discovered at monitor start and says nothing about idle-time behaviour (indicator I14).
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path, [AllowNull()][hashtable]$Dns, [hashtable]$Stats, [AllowNull()][AllowEmptyString()][string]$RunStart)
    $result = @{ ByKey = @{}; Established = 0; Listen = 0; PublicIps = (New-Object 'System.Collections.Generic.HashSet[string]'); PoolRows = 0; Rows = 0; PreExisting = 0 }
    if ([string]::IsNullOrEmpty($Path)) { return $result }
    if ($null -eq $Dns) { $Dns = @{} }
    $privateRx = [string](Get-WinDebugRule -Name 'PrivateIpRegex')
    $poolPorts = @(Get-WinDebugRule -Name 'PoolPorts')
    $runStartDt = $null
    if (-not [string]::IsNullOrEmpty($RunStart)) { $runStartDt = Get-WdAnDateTime -Text $RunStart }
    $port = 0
    foreach ($row in @(Read-WdAnCsvRows -Path $Path -Stats $Stats -StatName 'NetRows')) {
        $result.Rows++
        $key = [string]$row['Key']
        if ([string]::IsNullOrEmpty($key)) { continue }
        $e = $result.ByKey[$key]
        if ($null -eq $e) {
            $e = @{
                Endpoints = New-Object 'System.Collections.Generic.List[object]'
                RemoteIps = New-Object 'System.Collections.Generic.HashSet[string]'
                PublicIps = New-Object 'System.Collections.Generic.HashSet[string]'
                PoolPorts = New-Object 'System.Collections.Generic.HashSet[int]'
                Listen = New-Object 'System.Collections.Generic.List[string]'
                RawNoDns = 0; IdlePublic = 0; Name = [string]$row['Name']; Pid = [string]$row['Pid']
            }
            $result.ByKey[$key] = $e
        }
        $state = [string]$row['State']
        if ($state -eq 'Listen') {
            $result.Listen++
            $e.Listen.Add([string]$row['LocalPort'])
            continue
        }
        $remote = ([string]$row['RemoteAddress']).Trim()
        if ($remote -eq '') { continue }
        $result.Established++
        $isPrivate = ([string]$row['IsPrivate'] -eq 'True')
        if (-not $isPrivate -and $remote -match $privateRx) { $isPrivate = $true }
        $portText = [string]$row['RemotePort']
        $port = 0
        [void][int]::TryParse($portText, [ref]$port)
        $isPool = ([string]$row['PoolPort'] -eq 'True')
        if (-not $isPool -and $port -gt 0 -and ($poolPorts -contains $port)) { $isPool = $true }
        $isIdle = ([string]$row['IsIdle'] -eq 'True')
        $ts = [string]$row['Timestamp']
        $createdText = [string]$row['ConnCreated']
        $preExisting = $false
        if ($null -ne $runStartDt) {
            $created = Get-WdAnDateTime -Text $createdText
            if ($null -ne $created) { $preExisting = ($created -lt $runStartDt) }
            elseif ($ts -eq $RunStart) { $preExisting = $true }
        }
        if ($preExisting) { $result.PreExisting++ }
        $openedIdle = ($isIdle -and -not $preExisting)
        $dnsName = ''
        $dl = $Dns[$remote.ToLowerInvariant()]
        if ($null -ne $dl -and $dl.Count -gt 0) { $dnsName = (@($dl | Select-Object -First 2) -join ', ') }
        [void]$e.RemoteIps.Add($remote)
        if (-not $isPrivate) {
            [void]$e.PublicIps.Add($remote)
            [void]$result.PublicIps.Add($remote)
            if ($dnsName -eq '') { $e.RawNoDns++ }
            if ($openedIdle) { $e.IdlePublic++ }
        }
        if ($isPool) { [void]$e.PoolPorts.Add($port); $result.PoolRows++ }
        $e.Endpoints.Add(@{ Key = $key; Name = [string]$row['Name']; Pid = [string]$row['Pid']; Remote = $remote; Port = $port; Pool = $isPool; Idle = $openedIdle; PreExisting = $preExisting; Private = $isPrivate; Dns = $dnsName; Ts = $ts; Created = $createdText })
    }
    return $result
}

function Read-WdAnEvents {
    # -> @{ All = list of row hashtables; ByType = type -> count; NewPathByKey = Key -> Path }
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path, [hashtable]$Stats)
    $result = @{ All = @(); ByType = @{}; NewPathByKey = @{}; EventLog = @() }
    if ([string]::IsNullOrEmpty($Path)) { return $result }
    $all = @(Read-WdAnCsvRows -Path $Path -Stats $Stats -StatName 'EventRows')
    $logRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($row in $all) {
        $t = [string]$row['Type']
        $result.ByType[$t] = 1 + [int]$result.ByType[$t]
        if ($t -eq 'ProcessNew') {
            $k = [string]$row['Key']
            $detail = [string]$row['Detail']
            $m = [regex]::Match($detail, '(?i)Path=([^;]*)')
            if ($m.Success -and -not [string]::IsNullOrEmpty($k)) { $result.NewPathByKey[$k] = $m.Groups[1].Value.Trim() }
        } elseif ($t -eq 'EventLog') {
            $logRows.Add($row)
        }
    }
    $result.All = $all
    $result.EventLog = $logRows.ToArray()
    return $result
}

# ---------------------------------------------------------------------------------------------
# Which keys get a per-process timeline (memory bound): top consumers plus everything flagged
# ---------------------------------------------------------------------------------------------
function Get-WdAnInterestingKeys {
    [CmdletBinding()]
    param([AllowNull()][hashtable]$ProcSum, [AllowNull()][hashtable]$Meta, [int]$TopN = 50)
    if ($null -eq $ProcSum -or $null -eq $ProcSum.Processes -or $ProcSum.Processes.Count -eq 0) { return $null }
    $set = New-Object 'System.Collections.Generic.HashSet[string]'
    $all = @($ProcSum.Processes.Values)
    $n = [math]::Max(15, $TopN)
    foreach ($prop in @('CpuSeconds', 'GpuSeconds', 'WSMax')) {
        $sorted = @($all | Sort-Object -Property @{ Expression = { [double]$_.$prop }; Descending = $true } | Select-Object -First $n)
        foreach ($p in $sorted) { [void]$set.Add([string]$p.Key) }
    }
    $sorted = @($all | Sort-Object -Property @{ Expression = { [double]$_.ReadBytes + [double]$_.WriteBytes }; Descending = $true } | Select-Object -First $n)
    foreach ($p in $sorted) { [void]$set.Add([string]$p.Key) }
    foreach ($p in $all) {
        $flags = [string]$p.Flags
        if ($flags -ne '' -and $flags -ne 'Self') { [void]$set.Add([string]$p.Key); continue }
        if ([int]$p.PortHits -gt 0) { [void]$set.Add([string]$p.Key); continue }
        $lc = [string]$p.LocationClass
        if ($lc -ne '' -and ($script:WdAnSuspiciousLocations -contains $lc)) { [void]$set.Add([string]$p.Key); continue }
        if (Test-WdAnWritableWindowsPath -Path ([string]$p.Path)) { [void]$set.Add([string]$p.Key); continue }
        if ([double]$p.GpuComputeSeconds -gt 0) { [void]$set.Add([string]$p.Key); continue }
    }
    if ($null -ne $Meta) {
        foreach ($k in $Meta.Keys) {
            $m = $Meta[$k]
            $sig = [string]$m['SigStatus']
            if ($sig -ne '' -and $sig -ne 'Valid') { [void]$set.Add($k); continue }
            $flags = [string]$m['Flags']
            if ($flags -ne '' -and $flags -ne 'Self') { [void]$set.Add($k) }
        }
    }
    # All instances of a selected path (a subject aggregates by path).
    foreach ($k in @($set)) {
        $p = $ProcSum.Processes[$k]
        if ($null -eq $p) { continue }
        $path = [string]$p.Path
        if ($path -eq '') { continue }
        $sib = $ProcSum.PathKeys[$path.ToLowerInvariant()]
        if ($null -ne $sib) { foreach ($s in $sib) { [void]$set.Add($s) } }
    }
    return $set
}

# ---------------------------------------------------------------------------------------------
# Merge procsum + CSV accumulators + procmeta into one entry per Key
# ---------------------------------------------------------------------------------------------
function Merge-WdAnProcesses {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Ctx)
    $entries = @{}
    $ps = $Ctx.ProcSum
    $agg = $Ctx.ProcAgg
    $meta = $Ctx.Meta
    $SM = $Ctx.Samples
    $events = $Ctx.Events
    if ($null -eq $agg) { $agg = @{} }
    if ($null -eq $meta) { $meta = @{} }
    $newPaths = @{}
    if ($null -ne $events -and $null -ne $events.NewPathByKey) { $newPaths = $events.NewPathByKey }
    $keys = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($null -ne $ps) { foreach ($k in $ps.Processes.Keys) { [void]$keys.Add($k) } }
    foreach ($k in $agg.Keys) { [void]$keys.Add($k) }
    foreach ($k in $meta.Keys) { [void]$keys.Add($k) }
    $broken = 0
    foreach ($key in $keys) {
        $p = $null
        if ($null -ne $ps) { $p = $ps.Processes[$key] }
        $a = $agg[$key]
        $m = $meta[$key]
        $e = @{
            Key = $key; Pid = ''; Name = ''; Path = ''; ImageName = ''; CommandLine = ''; Flags = ''; SessionId = $null; ParentName = ''
            LocationClass = ''; Owner = ''; Started = ''; FirstSeen = ''; LastSeen = ''; PresentAtStart = $false; AccessNote = ''
            Samples = 0; SamplesIdle = 0; SamplesActive = 0; CpuRows = 0
            CpuSeconds = 0.0; CpuSum = 0.0; CpuMax = 0.0; CpuCoresMax = 0.0; CpuIdleSum = 0.0; CpuActiveSum = 0.0
            GpuSum = 0.0; GpuMax = 0.0; GpuSeconds = 0.0; GpuComputeSeconds = 0.0; Gpu3DSeconds = 0.0; GpuVideoSeconds = 0.0
            GpuIdleSum = 0.0; GpuActiveSum = 0.0; GpuCompIdleSum = 0.0; GpuCompActiveSum = 0.0; HasGpuSplit = $false
            ReadBytes = 0.0; WriteBytes = 0.0; WSMax = 0.0; WSFirst = 0.0; WSLast = 0.0
            LowPrioSamples = 0; BasePriority = 0; HasWindowEver = $false; Exited = $false; ExitTime = ''
            Source = ''; Flat = $null; Buckets = $null; Meta = $m; IsSelf = $false; IsTool = $false
        }
        try {
            if ($null -ne $p) {
                $e.Source = 'procsum'
                $e.Pid = [string]$p.Pid; $e.Name = [string]$p.Name; $e.Path = [string]$p.Path; $e.ImageName = [string]$p.ImageName
                $e.CommandLine = [string]$p.CommandLine; $e.Flags = [string]$p.Flags; $e.ParentName = [string]$p.ParentName
                $e.LocationClass = [string]$p.LocationClass; $e.Owner = [string]$p.Owner
                if ($null -ne $p.SessionId -and [string]$p.SessionId -ne '') { $e.SessionId = [int]$p.SessionId }
                $e.Started = [string]$p.Started; $e.FirstSeen = [string]$p.FirstSeen; $e.LastSeen = [string]$p.LastSeen
                $e.PresentAtStart = [bool]$p.PresentAtStart
                $e.Samples = [int]$p.Samples; $e.SamplesIdle = [int]$p.SamplesIdle; $e.SamplesActive = [int]$p.SamplesActive
                $e.CpuSeconds = [double]$p.CpuSeconds; $e.CpuSum = [double]$p.CpuSum; $e.CpuMax = [double]$p.CpuMax; $e.CpuCoresMax = [double]$p.CpuCoresMax
                $e.CpuIdleSum = [double]$p.CpuIdleSum; $e.CpuActiveSum = [double]$p.CpuActiveSum
                $e.GpuSum = [double]$p.GpuSum; $e.GpuMax = [double]$p.GpuMax; $e.GpuSeconds = [double]$p.GpuSeconds
                $e.GpuComputeSeconds = [double]$p.GpuComputeSeconds; $e.Gpu3DSeconds = [double]$p.Gpu3DSeconds; $e.GpuVideoSeconds = [double]$p.GpuVideoSeconds
                $e.GpuIdleSum = [double]$p.GpuIdleSum; $e.GpuActiveSum = [double]$p.GpuActiveSum
                $e.ReadBytes = [double]$p.ReadBytes; $e.WriteBytes = [double]$p.WriteBytes
                $e.WSMax = [double]$p.WSMax; $e.WSFirst = [double]$p.WSFirst; $e.WSLast = [double]$p.WSLast
                $e.LowPrioSamples = [int]$p.LowPrioSamples; $e.BasePriority = [int]$p.BasePriority
                $e.HasWindowEver = [bool]$p.HasWindowEver; $e.Exited = [bool]$p.Exited; $e.ExitTime = [string]$p.ExitTime
            } elseif ($null -ne $a) {
                $e.Source = 'csv'
                $e.Pid = [string]$a.Pid; $e.Name = [string]$a.Name
                $e.FirstSeen = [string]$a.FirstTs; $e.LastSeen = [string]$a.LastTs
                $e.PresentAtStart = (-not $a.New)
                $e.CpuSeconds = $a.CpuSec; $e.CpuSum = $a.CpuSum; $e.CpuMax = $a.CpuMax; $e.CpuCoresMax = $a.CoresMax
                $e.CpuIdleSum = $a.IdleCpu; $e.CpuActiveSum = $a.ActCpu
                $e.GpuSum = $a.GpuSum; $e.GpuMax = $a.GpuMax; $e.GpuSeconds = $a.GpuSec; $e.GpuComputeSeconds = $a.GpuCompSec
                $e.Gpu3DSeconds = $a.Gpu3DSec; $e.GpuVideoSeconds = $a.GpuVidSec; $e.GpuIdleSum = $a.GpuIdle; $e.GpuActiveSum = $a.GpuAct
                $e.ReadBytes = $a.ReadB; $e.WriteBytes = $a.WriteB
                $e.WSMax = $a.WsMax; $e.WSFirst = [math]::Max(0.0, $a.WsFirst); $e.WSLast = $a.WsLast
                $e.LowPrioSamples = $a.LowPrioN; $e.BasePriority = $a.Prio; $e.HasWindowEver = $a.WinEver
                $e.Exited = $a.Exited; $e.ExitTime = [string]$a.ExitTs
                # Sample counts: every session sample between first and last sight (rows are filtered, a missing row = quiet).
                $e.Samples = $a.CpuRows; $e.SamplesIdle = $a.IdleN; $e.SamplesActive = $a.ActN
                if ($null -ne $SM -and $null -ne $SM.TsIndex) {
                    $fi = $SM.TsIndex[[string]$a.FirstTs]
                    $li = $SM.TsIndex[[string]$a.LastTs]
                    if ($null -ne $fi -and $null -ne $li) {
                        $fi = [int]$fi; $li = [int]$li
                        if ($a.New) { $fi++ }
                        if ($a.Exited) { $li-- }
                        if ($li -ge $fi) {
                            $tot = $li - $fi + 1
                            $idle = [int]$SM.CumIdle[$li]
                            if ($fi -gt 0) { $idle -= [int]$SM.CumIdle[$fi - 1] }
                            $e.Samples = [math]::Max($tot, $a.CpuRows); $e.SamplesIdle = [math]::Max($idle, $a.IdleN); $e.SamplesActive = [math]::Max($tot - $idle, $a.ActN)
                        }
                    }
                }
            } else {
                $e.Source = 'meta'
            }
            if ($null -ne $a) {
                $e.CpuRows = $a.CpuRows
                $e.Flat = $a.Flat
                $e.Buckets = $a.Buckets
                $e.GpuCompIdleSum = $a.GpuCompIdle; $e.GpuCompActiveSum = $a.GpuCompAct; $e.HasGpuSplit = $true
                if ($a.WinEver) { $e.HasWindowEver = $true }
                if ($e.WSFirst -le 0 -and $a.WsFirst -gt 0) { $e.WSFirst = $a.WsFirst }
                if ($e.Exited -eq $false -and $a.Exited) { $e.Exited = $true; $e.ExitTime = [string]$a.ExitTs }
                if ($e.Name -eq '') { $e.Name = [string]$a.Name }
                if ($e.Pid -eq '') { $e.Pid = [string]$a.Pid }
            }
            if ($null -ne $m) {
                if ($e.Name -eq '') { $e.Name = [string]$m['Name'] }
                if ($e.Pid -eq '') { $e.Pid = [string]$m['Pid'] }
                if ($e.Path -eq '') { $e.Path = [string]$m['Path'] }
                if ($e.ImageName -eq '') { $e.ImageName = [string]$m['ImageName'] }
                if ($e.CommandLine -eq '') { $e.CommandLine = [string]$m['CommandLine'] }
                if ($e.ParentName -eq '') { $e.ParentName = [string]$m['ParentName'] }
                if ($e.LocationClass -eq '') { $e.LocationClass = [string]$m['LocationClass'] }
                if ($e.Owner -eq '') { $e.Owner = [string]$m['Owner'] }
                if ($e.Started -eq '') { $e.Started = [string]$m['Started'] }
                if ($e.FirstSeen -eq '') { $e.FirstSeen = [string]$m['FirstSeen'] }
                if ($null -eq $e.SessionId) { $sid = 0; if ([int]::TryParse([string]$m['SessionId'], [ref]$sid)) { $e.SessionId = $sid } }
                $e.AccessNote = [string]$m['AccessNote']
                $mf = [string]$m['Flags']
                if ($mf -ne '') {
                    $set = New-Object 'System.Collections.Generic.List[string]'
                    foreach ($x in ($e.Flags + ';' + $mf).Split(@(';'), [StringSplitOptions]::RemoveEmptyEntries)) { if (-not $set.Contains($x)) { $set.Add($x) } }
                    $e.Flags = ($set -join ';')
                }
            }
            if ($e.Path -eq '' -and $newPaths.ContainsKey($key)) { $e.Path = [string]$newPaths[$key] }
            if ($e.Path -ne '' -and ($e.LocationClass -eq '' -or $e.LocationClass -eq 'Unknown')) { $e.LocationClass = Get-ProcessLocationClass -Path $e.Path }
            if ($e.Path -eq '' -and $e.LocationClass -eq '') { $e.LocationClass = 'Unknown' }
            if ($e.ImageName -eq '' -and $e.Path -ne '') { try { $e.ImageName = [IO.Path]::GetFileName($e.Path) } catch { } }
            $e.IsSelf = ($e.Flags -match '(^|;)Self(;|$)')
            $e.IsTool = ($e.Flags -match '(^|;)WinDebugTool(;|$)')
            $entries[$key] = $e
        } catch {
            $broken++
            Write-Log -Level Debug -Message ('Merge: entry {0} skipped: {1}' -f $key, $_.Exception.Message)
        }
    }
    $Ctx.Stats['BrokenEntries'] = $broken
    $Ctx.Stats['Entries'] = $entries.Count
    return $entries
}


# ---------------------------------------------------------------------------------------------
# Subjects: one row per executable path (fallback: name; system names without a path stay per instance)
# ---------------------------------------------------------------------------------------------
function Get-WdAnSubjectKey {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Entry, [AllowNull()][object[]]$SystemNames)
    if ($Entry.IsTool) { return ('t|' + $Entry.Key) }
    if ($Entry.Path -ne '') { return ('p|' + $Entry.Path.ToLowerInvariant()) }
    $name = [string]$Entry.Name
    if ($name -eq '') { $name = '?' }
    if (Test-WdAnNameInList -Name $name -List $SystemNames) { return ('k|' + $Entry.Key) }
    return ('n|' + $name.ToLowerInvariant())
}

function Group-WdAnSubjects {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Ctx)
    $entries = $Ctx.Entries
    if ($null -eq $entries) { return @() }
    $net = $Ctx.Net
    $sysNames = @(Get-WinDebugRule -Name 'SystemBinaryNames')
    $subjects = @{}
    $selfKeys = 0
    foreach ($e in $entries.Values) {
        if ($e.IsSelf) { $selfKeys++; continue }
        $skey = Get-WdAnSubjectKey -Entry $e -SystemNames $sysNames
        $s = $subjects[$skey]
        if ($null -eq $s) {
            $s = @{
                SubjectKey = $skey; Name = $e.Name; ImageName = $e.ImageName; Path = $e.Path; LocationClass = $e.LocationClass
                CommandLine = ''; ParentName = ''; SessionId = $null; Owner = ''; AccessNote = ''; Flags = ''
                Company = ''; Description = ''; OriginalFilename = ''; FileCreated = ''; SigStatus = ''; Signer = ''; IsOSBinary = $false; Sha256 = ''
                Instances = New-Object 'System.Collections.Generic.List[object]'
                Keys = New-Object 'System.Collections.Generic.List[string]'
                Pids = New-Object 'System.Collections.Generic.List[string]'
                Names = New-Object 'System.Collections.Generic.List[string]'
                Sources = New-Object 'System.Collections.Generic.List[string]'
                Started = ''; FirstSeen = ''; LastSeen = ''; PresentAtStart = $false; Starts = 0; Exits = 0; QuickRestarts = 0; MaxConcurrent = 1
                Samples = 0; SamplesIdle = 0; SamplesActive = 0; CpuRows = 0
                CpuSeconds = 0.0; CpuSum = 0.0; CpuMax = 0.0; CpuCoresMax = 0.0; CpuIdleSum = 0.0; CpuActiveSum = 0.0
                GpuSum = 0.0; GpuMax = 0.0; GpuSeconds = 0.0; GpuComputeSeconds = 0.0; Gpu3DSeconds = 0.0; GpuVideoSeconds = 0.0
                GpuIdleSum = 0.0; GpuActiveSum = 0.0; GpuCompIdleSum = 0.0; GpuCompActiveSum = 0.0; HasGpuSplit = $false
                ReadBytes = 0.0; WriteBytes = 0.0; WSMax = 0.0; WSFirst = 0.0; WSLast = 0.0; WSFirstTs = ''; WSLastTs = ''
                LowPrioSamples = 0; BasePriority = 0; HasWindowEver = $false; IsTool = $false; PathKnown = ($e.Path -ne ''); NeedsAdmin = $false
                Flat = @{}; Buckets = @{}
                Endpoints = New-Object 'System.Collections.Generic.List[object]'
                RemoteIps = New-Object 'System.Collections.Generic.HashSet[string]'
                PublicIps = New-Object 'System.Collections.Generic.HashSet[string]'
                PoolPorts = New-Object 'System.Collections.Generic.HashSet[int]'
                ListenPorts = New-Object 'System.Collections.Generic.HashSet[string]'
                RawNoDns = 0; IdlePublic = 0
                Indicators = @(); RawScore = 0; Score = 0; Class = ''; Damping = @(); Notes = New-Object 'System.Collections.Generic.List[string]'
                DefenderDetections = 0; ExclusionChanges = 0; PersistenceEvents = 0; EventTexts = New-Object 'System.Collections.Generic.List[string]'
            }
            $subjects[$skey] = $s
        }
        $s.Instances.Add($e)
        $s.Keys.Add($e.Key)
        if ($e.Pid -ne '' -and -not $s.Pids.Contains($e.Pid)) { $s.Pids.Add($e.Pid) }
        if ($e.Name -ne '' -and -not $s.Names.Contains($e.Name)) { $s.Names.Add($e.Name) }
        if (-not $s.Sources.Contains($e.Source)) { $s.Sources.Add($e.Source) }
        if ($e.IsTool) { $s.IsTool = $true }
        if ($e.PresentAtStart) { $s.PresentAtStart = $true } else { $s.Starts++ }
        if ($e.Exited) { $s.Exits++ }
        if ($e.Started -ne '' -and ($s.Started -eq '' -or [string]::CompareOrdinal($e.Started, $s.Started) -lt 0)) { $s.Started = $e.Started }
        if ($e.FirstSeen -ne '' -and ($s.FirstSeen -eq '' -or [string]::CompareOrdinal($e.FirstSeen, $s.FirstSeen) -lt 0)) { $s.FirstSeen = $e.FirstSeen }
        if ($e.LastSeen -ne '' -and ($s.LastSeen -eq '' -or [string]::CompareOrdinal($e.LastSeen, $s.LastSeen) -gt 0)) { $s.LastSeen = $e.LastSeen }
        $s.Samples += $e.Samples; $s.SamplesIdle += $e.SamplesIdle; $s.SamplesActive += $e.SamplesActive; $s.CpuRows += $e.CpuRows
        $s.CpuSeconds += $e.CpuSeconds; $s.CpuSum += $e.CpuSum; $s.CpuIdleSum += $e.CpuIdleSum; $s.CpuActiveSum += $e.CpuActiveSum
        if ($e.CpuMax -gt $s.CpuMax) { $s.CpuMax = $e.CpuMax }
        if ($e.CpuCoresMax -gt $s.CpuCoresMax) { $s.CpuCoresMax = $e.CpuCoresMax }
        $s.GpuSum += $e.GpuSum; $s.GpuSeconds += $e.GpuSeconds; $s.GpuComputeSeconds += $e.GpuComputeSeconds; $s.Gpu3DSeconds += $e.Gpu3DSeconds; $s.GpuVideoSeconds += $e.GpuVideoSeconds
        $s.GpuIdleSum += $e.GpuIdleSum; $s.GpuActiveSum += $e.GpuActiveSum; $s.GpuCompIdleSum += $e.GpuCompIdleSum; $s.GpuCompActiveSum += $e.GpuCompActiveSum
        if ($e.HasGpuSplit) { $s.HasGpuSplit = $true }
        if ($e.GpuMax -gt $s.GpuMax) { $s.GpuMax = $e.GpuMax }
        $s.ReadBytes += $e.ReadBytes; $s.WriteBytes += $e.WriteBytes
        # Working set: Peak, First, Last and Growth all describe the SAME instance (the one with the peak), so the
        # growth is a real per-process trend; concurrent helpers would otherwise mix values of unrelated processes.
        if ($e.WSMax -gt $s.WSMax -or ($s.WSMax -le 0 -and $s.WSFirst -le 0 -and $e.WSFirst -gt 0)) {
            $s.WSMax = [math]::Max($s.WSMax, $e.WSMax); $s.WSFirst = $e.WSFirst; $s.WSLast = $e.WSLast; $s.WSFirstTs = $e.FirstSeen; $s.WSLastTs = $e.LastSeen
        }
        $s.LowPrioSamples += $e.LowPrioSamples
        if ($e.BasePriority -gt 0) { $s.BasePriority = $e.BasePriority }
        if ($e.HasWindowEver) { $s.HasWindowEver = $true }
        if ($null -ne $e.SessionId -and $null -eq $s.SessionId) { $s.SessionId = $e.SessionId }
        if ($e.Flags -ne '') {
            $set = New-Object 'System.Collections.Generic.List[string]'
            foreach ($x in ($s.Flags + ';' + $e.Flags).Split(@(';'), [StringSplitOptions]::RemoveEmptyEntries)) { if (-not $set.Contains($x)) { $set.Add($x) } }
            $s.Flags = ($set -join ';')
        }
        if ($null -ne $e.Flat) { foreach ($fk in $e.Flat.Keys) { $s.Flat[$fk] = [int]$s.Flat[$fk] + [int]$e.Flat[$fk] } }
        if ($null -ne $e.Buckets) {
            foreach ($bk in $e.Buckets.Keys) {
                $src = $e.Buckets[$bk]
                $dst = $s.Buckets[$bk]
                if ($null -eq $dst) { $dst = New-Object 'double[]' 4; $s.Buckets[$bk] = $dst }
                $dst[0] += $src[0]; $dst[1] += $src[1]; $dst[3] += $src[3]
                if ($src[2] -gt $dst[2]) { $dst[2] = $src[2] }
            }
        }
        # Metadata: prefer the instance with complete file facts.
        $m = $e.Meta
        $betterMeta = ($null -ne $m -and ($s.SigStatus -eq '' -or ([string]$m['SigStatus'] -ne '' -and $s.CommandLine -eq '')))
        if ($null -ne $m -and ($betterMeta -or $s.CommandLine -eq '')) {
            if ([string]$m['CommandLine'] -ne '' -or $s.CommandLine -eq '') { $s.CommandLine = [string]$m['CommandLine'] }
            if ([string]$m['ParentName'] -ne '') { $s.ParentName = [string]$m['ParentName'] }
            if ([string]$m['Owner'] -ne '') { $s.Owner = [string]$m['Owner'] }
            if ([string]$m['AccessNote'] -ne '' -or $s.AccessNote -eq '') { $s.AccessNote = [string]$m['AccessNote'] }
            if ([string]$m['SigStatus'] -ne '') {
                $s.Company = [string]$m['Company']; $s.Description = [string]$m['Description']; $s.OriginalFilename = [string]$m['OriginalFilename']
                $s.FileCreated = [string]$m['FileCreated']; $s.SigStatus = [string]$m['SigStatus']; $s.Signer = [string]$m['Signer']
                $s.IsOSBinary = ([string]$m['IsOSBinary'] -eq 'True'); $s.Sha256 = [string]$m['Sha256']
            }
        }
        if ($s.CommandLine -eq '' -and $e.CommandLine -ne '') { $s.CommandLine = $e.CommandLine }
        if ($s.ParentName -eq '' -and $e.ParentName -ne '') { $s.ParentName = $e.ParentName }
        if ($s.Owner -eq '' -and $e.Owner -ne '') { $s.Owner = $e.Owner }
        if ($s.ImageName -eq '' -and $e.ImageName -ne '') { $s.ImageName = $e.ImageName }
        if ($s.LocationClass -eq '' -or $s.LocationClass -eq 'Unknown') { if ($e.LocationClass -ne '') { $s.LocationClass = $e.LocationClass } }
        # Network (per key)
        if ($null -ne $net -and $null -ne $net.ByKey) {
            $n = $net.ByKey[$e.Key]
            if ($null -ne $n) {
                foreach ($ep in $n.Endpoints) { $s.Endpoints.Add($ep) }
                foreach ($ip in $n.RemoteIps) { [void]$s.RemoteIps.Add($ip) }
                foreach ($ip in $n.PublicIps) { [void]$s.PublicIps.Add($ip) }
                foreach ($pp in $n.PoolPorts) { [void]$s.PoolPorts.Add($pp) }
                foreach ($lp in $n.Listen) { [void]$s.ListenPorts.Add($lp) }
                $s.RawNoDns += $n.RawNoDns; $s.IdlePublic += $n.IdlePublic
            }
        }
    }
    $Ctx.Stats['SelfKeys'] = $selfKeys
    # Derived values per subject.
    $elevated = $false
    if ($null -ne $Ctx.Run) { try { $elevated = [bool]$Ctx.Run.IsElevated } catch { $elevated = $false } }
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $subjects.Values) {
        # NeedsAdmin = the path is unknown BECAUSE of missing rights. 'exited before metadata' and 'path not available'
        # (kernel/protected processes) are produced regardless of elevation, and an elevated run had all the rights it needs.
        $s.NeedsAdmin = (-not $s.PathKnown) -and (-not $elevated) -and ($s.AccessNote -match 'requires administrator' -or ($s.Owner -match 'requires administrator') -or $s.AccessNote -eq '')
        if ($s.PathKnown) { $s.NeedsAdmin = $false }
        if ($s.Path -eq '' -and $s.LocationClass -eq '') { $s.LocationClass = 'Unknown' }
        # One-line command line for every consumer (procsum.json keeps the raw WMI value, which may contain CR/LF).
        if ($s.CommandLine -ne '') { $s.CommandLine = (($s.CommandLine -replace '\r\n|\r|\n', ' ') -replace '\s{2,}', ' ').Trim() }
        # Restarts: an instance that starts within 300 s after another instance of the same path exited.
        if ($s.Instances.Count -gt 1) {
            $exits = New-Object 'System.Collections.Generic.List[DateTime]'
            $startsList = New-Object 'System.Collections.Generic.List[DateTime]'
            foreach ($i in $s.Instances) {
                if ($i.Exited -and $i.ExitTime -ne '') { $x = Get-WdAnDateTime -Text $i.ExitTime; if ($null -ne $x) { $exits.Add($x) } }
                if (-not $i.PresentAtStart) { $st = Get-WdAnDateTime -Text $(if ($i.Started -ne '') { $i.Started } else { $i.FirstSeen }); if ($null -ne $st) { $startsList.Add($st) } }
            }
            foreach ($st in $startsList) {
                foreach ($x in $exits) {
                    $gap = ($st - $x).TotalSeconds
                    if ($gap -ge 0 -and $gap -lt 300) { $s.QuickRestarts++; break }
                }
            }
            # Max concurrent instances (by FirstSeen/LastSeen ordering).
            $ev = New-Object 'System.Collections.Generic.List[object]'
            foreach ($i in $s.Instances) {
                $a = Get-WdAnDateTime -Text $i.FirstSeen
                $b = Get-WdAnDateTime -Text $i.LastSeen
                if ($null -ne $a -and $null -ne $b) { $ev.Add(@{ T = $a; D = 1 }); $ev.Add(@{ T = $b.AddMilliseconds(1); D = -1 }) }
            }
            $cur = 0; $max = 0
            foreach ($x in @($ev | Sort-Object -Property @{ Expression = { $_.T } })) { $cur += $x.D; if ($cur -gt $max) { $max = $cur } }
            if ($max -gt 1) { $s.MaxConcurrent = $max }
        }
        $list.Add($s)
    }
    return $list.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Rule evaluation helpers (rule data from $script:Rules)
# ---------------------------------------------------------------------------------------------
function Get-WdAnMinerTokens {
    # -> @{ Strong = string[]; Weak = string[] }. Weak tokens (pool, --algo, -o host:port) also occur in dev tools;
    # stratum URLs (--url=stratum..., -o stratum...) are strong. Electron '--url=https://...' no longer matches at all.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$CommandLine)
    $strong = New-Object 'System.Collections.Generic.List[string]'
    $weak = New-Object 'System.Collections.Generic.List[string]'
    if ([string]::IsNullOrEmpty($CommandLine)) { return @{ Strong = @(); Weak = @() } }
    $rx = [string](Get-WinDebugRule -Name 'MinerTokenRegex')
    foreach ($m in [regex]::Matches($CommandLine, $rx, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
        $v = $m.Value.Trim()
        if ($v -eq '') { continue }
        $isWeak = ($v -match '^(pool|--algo)$') -or ($v -match '^-o\s' -and $v -notmatch '(?i)stratum')
        if ($isWeak) { if (-not $weak.Contains($v)) { $weak.Add($v) } }
        else { if (-not $strong.Contains($v)) { $strong.Add($v) } }
    }
    return @{ Strong = @($strong.ToArray()); Weak = @($weak.ToArray()) }
}

function Get-WdAnScriptHostTokens {
    # -> @{ Strong = string[]; Weak = string[] } of matched argument tokens (both empty when the name is not a script host).
    # STRONG (ScriptHostStrongArgRegex: encoded commands, download cradles, IEX, base64, URLs, LOLBin decoding) is a red
    # flag; WEAK (ScriptHostWeakArgRegex: -ExecutionPolicy Bypass, -NoProfile, -WindowStyle Hidden, -NonInteractive) is
    # informational only: IDE/agent shells, scheduled scripts and installers use these launch options all the time.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Name, [AllowNull()][AllowEmptyString()][string]$CommandLine)
    $none = @{ Strong = @(); Weak = @() }
    if ([string]::IsNullOrEmpty($Name) -or [string]::IsNullOrEmpty($CommandLine)) { return $none }
    $base = $Name
    if ($base -match '\.exe$') { $base = $base.Substring(0, $base.Length - 4) }
    if ($base -notmatch [string](Get-WinDebugRule -Name 'ScriptHostRegex')) { return $none }
    $rxStrong = [string](Get-WinDebugRule -Name 'ScriptHostStrongArgRegex')
    if ([string]::IsNullOrEmpty($rxStrong)) { $rxStrong = [string](Get-WinDebugRule -Name 'ScriptHostArgRegex') }
    $rxWeak = [string](Get-WinDebugRule -Name 'ScriptHostWeakArgRegex')
    $strong = New-Object 'System.Collections.Generic.List[string]'
    $weak = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrEmpty($rxStrong)) {
        foreach ($m in [regex]::Matches($CommandLine, $rxStrong, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $v = $m.Value.Trim().ToLowerInvariant()
            if ($v.Length -gt 60) { $v = $v.Substring(0, 60) + '...' }
            if ($v -ne '' -and -not $strong.Contains($v)) { $strong.Add($v) }
        }
    }
    if (-not [string]::IsNullOrEmpty($rxWeak)) {
        foreach ($m in [regex]::Matches($CommandLine, $rxWeak, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $v = ($m.Value.Trim() -replace '\s+', ' ').ToLowerInvariant()
            if ($v -ne '' -and -not $weak.Contains($v)) { $weak.Add($v) }
        }
    }
    return @{ Strong = @($strong.ToArray()); Weak = @($weak.ToArray()) }
}

function Get-WdAnScriptBlockEvidence {
    # Classifies the text of a PowerShell 4104 script block for the Events section: 'Strong' when the shared
    # ScriptHostStrongArgRegex matches (encoded command, download cradle, IEX, FromBase64String, URL, LOLBin decoding),
    # 'Weak' when only a window-hiding launch option (-WindowStyle Hidden / -w hidden) is present, '' otherwise.
    # The former inline pattern contained the bare word "hidden", which listed every CDXML module block (they declare
    # an -IncludeHidden parameter) as a red flag. Weak evidence is informational only and never scores more than 2.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $rxStrong = [string](Get-WinDebugRule -Name 'ScriptHostStrongArgRegex')
    if ([string]::IsNullOrEmpty($rxStrong)) { $rxStrong = [string](Get-WinDebugRule -Name 'ScriptHostArgRegex') }
    if (-not [string]::IsNullOrEmpty($rxStrong) -and [regex]::IsMatch($Text, $rxStrong, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) { return 'Strong' }
    if ([regex]::IsMatch($Text, $script:WdAnWindowHideRegex, [Text.RegularExpressions.RegexOptions]::IgnoreCase)) { return 'Weak' }
    return ''
}

function Test-WdAnTrustedSigner {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Subject)
    if ($Subject.SigStatus -ne 'Valid') { return $false }
    if ($Subject.IsOSBinary) { return $true }
    if ([string]::IsNullOrEmpty($Subject.Signer)) { return $false }
    return ($Subject.Signer -match [string](Get-WinDebugRule -Name 'TrustedSignerRegex'))
}

function Get-WdAnLookAlike {
    # Returns the system binary name within Levenshtein distance 1-2 of the given base name, or ''.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Name, [AllowNull()][object[]]$SystemNames)
    if ([string]::IsNullOrEmpty($Name) -or $null -eq $SystemNames) { return '' }
    $base = $Name.ToLowerInvariant()
    if ($base -match '\.exe$') { $base = $base.Substring(0, $base.Length - 4) }
    if ($base.Length -lt 5) { return '' }
    foreach ($sn in $SystemNames) {
        $t = ([string]$sn).ToLowerInvariant()
        if ($t.Length -lt 5) { continue }
        if ($t -eq $base) { return '' }
        if ([math]::Abs($t.Length - $base.Length) -gt 2) { continue }
        $d = Get-WdAnLevenshtein -A $base -B $t
        if ($d -ge 1 -and $d -le 2) { return [string]$sn }
    }
    return ''
}


# ---------------------------------------------------------------------------------------------
# Scoring (docs\analyze-scoring.md). One indicator list per subject; points are capped per indicator.
# Groups: Resource (I1-I4, I18: damped for known heavy processes), Protected (I7, I10 strong, I19: never damped), Other.
# ---------------------------------------------------------------------------------------------
function Add-WdAnIndicator {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$List, [string]$Id, [int]$Points, [string]$Text, [string]$Group = 'Other')
    $List.Add(@{ Id = $Id; Points = $Points; Text = $Text; Group = $Group })
}

function Add-WdAnEventAttribution {
    # Counts Defender detections / exclusion changes / persistence events whose text names the subject's path or image.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Subject, [AllowNull()][object[]]$EventLogRows)
    if ($null -eq $EventLogRows -or $EventLogRows.Count -eq 0) { return }
    $path = [string]$Subject.Path
    $img = [string]$Subject.ImageName
    if ($path -eq '' -and $img -eq '') { return }
    $dir = ''
    if ($path -ne '') { try { $dir = [IO.Path]::GetDirectoryName($path) } catch { $dir = '' } }
    foreach ($ev in $EventLogRows) {
        $detail = [string]$ev['Detail']
        if ($detail -eq '') { continue }
        $hitPath = ($path -ne '' -and $detail.IndexOf($path, [StringComparison]::OrdinalIgnoreCase) -ge 0)
        $hitDir = ($dir -ne '' -and $dir.Length -gt 3 -and $detail.IndexOf($dir, [StringComparison]::OrdinalIgnoreCase) -ge 0)
        $hitImg = ($img -ne '' -and $img.Length -gt 4 -and $detail.IndexOf($img, [StringComparison]::OrdinalIgnoreCase) -ge 0)
        $id = 0
        [void][int]::TryParse([string]$ev['EventId'], [ref]$id)
        $src = [string]$ev['Source']
        if ($src -match 'Defender') {
            if (($id -eq 1116 -or $id -eq 1117 -or $id -eq 1006 -or $id -eq 1007 -or $id -eq 1015 -or $id -eq 1118 -or $id -eq 1119) -and ($hitPath -or $hitImg)) {
                $Subject.DefenderDetections++
                $Subject.EventTexts.Add(('Defender {0}: {1}' -f $id, $detail))
            } elseif ($id -eq 5007 -and $detail -match 'Exclusions' -and ($hitPath -or $hitDir)) {
                $Subject.ExclusionChanges++
                $Subject.EventTexts.Add(('Defender 5007: {0}' -f $detail))
            }
        } elseif (($id -eq 7045 -and $src -eq 'System') -or ($id -eq 106 -and $src -match 'TaskScheduler') -or ($id -eq 5861 -and $src -match 'WMI')) {
            if ($hitPath -or $hitImg) {
                $Subject.PersistenceEvents++
                $Subject.EventTexts.Add(('{0} {1}: {2}' -f $src, $id, $detail))
            }
        }
    }
}

function Get-WdAnIndicators {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$S, [Parameter(Mandatory = $true)][hashtable]$Ctx)
    $inv = Get-WdInv
    $L = New-Object 'System.Collections.Generic.List[object]'
    $rules = $script:Rules
    $sysNames = @($rules['SystemBinaryNames'])
    $totalSamples = 0
    if ($null -ne $Ctx.Samples) { $totalSamples = [int]$Ctx.Samples.Rows }
    $meanInterval = [double]$Ctx.NominalInterval
    if ($null -ne $Ctx.Samples -and [int]$Ctx.Samples.IntervalN -gt 0) { $meanInterval = [double]$Ctx.Samples.IntervalSum / [int]$Ctx.Samples.IntervalN }
    if ($meanInterval -le 0) { $meanInterval = 10.0 }
    $runStart = $null
    if ($null -ne $Ctx.Samples -and $Ctx.Samples.First -ne '') { $runStart = Get-WdAnDateTime -Text $Ctx.Samples.First }
    if ($null -eq $runStart) { $runStart = Get-Date }

    # Effective sample counts: a path with N concurrent instances has N x the session samples; cap at the session totals
    # so averages mean "CPU of this program per sample" (sequential restarts keep their summed counts).
    $totalDelta = [math]::Max(0, $totalSamples - 1)
    $samples = [int]$S.Samples
    if ($totalDelta -gt 0 -and $samples -gt $totalDelta) { $samples = $totalDelta }
    $sIdle = [int]$S.SamplesIdle
    $sAct = [int]$S.SamplesActive
    if ($null -ne $Ctx.Samples) {
        if ($sIdle -gt [int]$Ctx.Samples.IdleN) { $sIdle = [int]$Ctx.Samples.IdleN }
        if ($sAct -gt [int]$Ctx.Samples.ActiveN) { $sAct = [int]$Ctx.Samples.ActiveN }
    }
    $S.EffSamples = $samples; $S.EffSamplesIdle = $sIdle; $S.EffSamplesActive = $sAct
    $cpuAvg = 0.0
    if ($samples -gt 0) { $cpuAvg = $S.CpuSum / $samples }
    $cpuIdleAvg = $null
    if ($sIdle -gt 0) { $cpuIdleAvg = $S.CpuIdleSum / $sIdle }
    $cpuActAvg = $null
    if ($sAct -gt 0) { $cpuActAvg = $S.CpuActiveSum / $sAct }
    $enoughIdle = ($sIdle -ge $script:WdAnIdleMinSamples)
    $enoughAct = ($sAct -ge $script:WdAnIdleMinSamples)
    $S.CpuAvg = $cpuAvg; $S.CpuIdleAvg = $cpuIdleAvg; $S.CpuActiveAvg = $cpuActAvg
    $presence = 0.0
    if ($totalSamples -gt 1) { $presence = [math]::Min(1.0, $samples / [double]($totalSamples - 1)) }
    $S.Presence = $presence
    $gpuCompAvg = 0.0
    if ($samples -gt 0) { $gpuCompAvg = $S.GpuComputeSeconds / ($samples * $meanInterval) * 100.0 }
    $S.GpuComputeAvg = $gpuCompAvg
    $gpuIdleAvg = $null; $gpuActAvg = $null
    if ($sIdle -gt 0) { $gpuIdleAvg = $S.GpuIdleSum / $sIdle }
    if ($sAct -gt 0) { $gpuActAvg = $S.GpuActiveSum / $sAct }
    $S.GpuIdleAvg = $gpuIdleAvg; $S.GpuActiveAvg = $gpuActAvg
    $gpuCompIdleAvg = $gpuIdleAvg; $gpuCompActAvg = $gpuActAvg
    if ($S.HasGpuSplit) {
        if ($sIdle -gt 0) { $gpuCompIdleAvg = $S.GpuCompIdleSum / $sIdle }
        if ($sAct -gt 0) { $gpuCompActAvg = $S.GpuCompActiveSum / $sAct }
    }
    $isTrusted = Test-WdAnTrustedSigner -Subject $S
    $S.IsTrustedSigner = $isTrusted
    $isKnownHeavy = Test-WdAnNameInList -Name $S.Name -List @($rules['KnownHeavyProcesses'])
    if (-not $isKnownHeavy -and $S.ImageName -ne '') { $isKnownHeavy = Test-WdAnNameInList -Name $S.ImageName -List @($rules['KnownHeavyProcesses']) }
    $S.IsKnownHeavy = $isKnownHeavy
    $pathKnown = ($S.Path -ne '')
    # C:\Windows\Tasks, \Tracing, \System32\Tasks ... are classified Windows/System32 but are user-writable drop folders.
    $writableWin = ($pathKnown -and (Test-WdAnWritableWindowsPath -Path $S.Path))
    $inTrustedLocation = ($script:WdAnTrustedLocations -contains $S.LocationClass) -and -not $writableWin
    $S.InTrustedLocation = $inTrustedLocation
    $S.InWritableWindowsFolder = $writableWin
    $flags = [string]$S.Flags
    # A very short all-idle run (no active sample, fewer than 20 idle samples) cannot say anything about idle behaviour.
    $shortIdleOnlyRun = ($null -ne $Ctx.Samples -and [int]$Ctx.Samples.ActiveN -eq 0 -and [int]$Ctx.Samples.IdleN -lt $script:WdAnIdleMinSamples)

    if ($S.IsTool) { $S.Notes.Add('win-debug tool process (WinDebugTool): not scored') ; return @() }

    # I1 CPU while the user is idle
    if ($enoughIdle -and $null -ne $cpuIdleAvg -and $cpuIdleAvg -ge 5.0) {
        if ($enoughAct) {
            $base = [math]::Max(0.5, [double]$cpuActAvg)
            if ($cpuIdleAvg -ge 2.0 * $base) {
                $pts = 6
                if ($cpuIdleAvg -ge 25.0) { $pts += 2 }
                Add-WdAnIndicator -List $L -Id 'I1' -Points $pts -Group 'Resource' -Text ([string]::Format($inv, 'CPU {0:F1} % while the user was idle vs {1:F1} % while active ({2} / {3} samples)', $cpuIdleAvg, $cpuActAvg, $sIdle, $sAct))
            }
        } else {
            Add-WdAnIndicator -List $L -Id 'I1' -Points 3 -Group 'Resource' -Text ([string]::Format($inv, 'CPU {0:F1} % over {1} idle samples; no active-time baseline (user never active during the run)', $cpuIdleAvg, $sIdle))
        }
    }
    # I2 GPU compute engine
    if ($samples -ge 30 -and $gpuCompAvg -ge 10.0) {
        $pts = 6
        $t = [string]::Format($inv, 'GPU Compute engine {0:F1} % average over {1} samples', $gpuCompAvg, $samples)
        if (-not $S.HasWindowEver) { $pts += 3; $t += ', no window' }
        if ($enoughIdle -and $enoughAct -and $null -ne $gpuCompIdleAvg -and $null -ne $gpuCompActAvg -and $gpuCompIdleAvg -gt $gpuCompActAvg) { $pts += 2; $t += [string]::Format($inv, ', higher while idle ({0:F1} % vs {1:F1} %)', $gpuCompIdleAvg, $gpuCompActAvg) }
        Add-WdAnIndicator -List $L -Id 'I2' -Points $pts -Group 'Resource' -Text $t
    }
    # I3 windowless interactive process with sustained CPU
    if (-not $S.HasWindowEver -and $null -ne $S.SessionId -and [int]$S.SessionId -ge 1 -and $cpuAvg -ge 10.0 -and $presence -ge 0.5) {
        Add-WdAnIndicator -List $L -Id 'I3' -Points 4 -Group 'Resource' -Text ([string]::Format($inv, 'no window, interactive session, CPU {0:F1} % average, present in {1:F0} % of samples', $cpuAvg, $presence * 100))
    }
    # I4 flat integer number of cores
    if ($S.CpuRows -ge 10 -and $S.Flat.Count -gt 0) {
        $bestN = 0; $bestC = 0
        foreach ($fk in $S.Flat.Keys) { if ([int]$S.Flat[$fk] -gt $bestC) { $bestC = [int]$S.Flat[$fk]; $bestN = [int]$fk } }
        $frac = $bestC / [double]$S.CpuRows
        $spanMin = 0.0
        $a = Get-WdAnDateTime -Text $S.FirstSeen; $b = Get-WdAnDateTime -Text $S.LastSeen
        if ($null -ne $a -and $null -ne $b) { $spanMin = ($b - $a).TotalMinutes }
        $covered = 0.0
        if ($samples -gt 0) { $covered = $S.CpuRows / [double]$samples }
        if ($frac -ge 0.8 -and $spanMin -ge 10 -and $covered -ge 0.8) {
            Add-WdAnIndicator -List $L -Id 'I4' -Points 3 -Group 'Resource' -Text ([string]::Format($inv, 'flat load of about {0} core(s) in {1:F0} % of {2} samples over {3:F0} min (fixed thread count)', $bestN, $frac * 100, $S.CpuRows, $spanMin))
        }
    }
    # I18 low base priority with real CPU use
    if ($samples -gt 0 -and $S.LowPrioSamples -ge 0.5 * $samples -and $cpuAvg -ge 5.0) {
        Add-WdAnIndicator -List $L -Id 'I18' -Points 3 -Group 'Resource' -Text ([string]::Format($inv, 'base priority {0} (Idle/BelowNormal) in {1} of {2} samples with CPU {3:F1} %', $S.BasePriority, $S.LowPrioSamples, $samples, $cpuAvg))
    }

    if ($pathKnown) {
        # I5 location
        $lc = [string]$S.LocationClass
        $lp = 0
        switch ($lc) {
            'Temp' { $lp = 5 } 'RecycleBin' { $lp = 5 } 'Public' { $lp = 5 }
            'AppData' { $lp = 3 } 'ProgramData' { $lp = 3 } 'Downloads' { $lp = 3 } 'Removable' { $lp = 3 }
            'UserProfile' { $lp = 2 }
        }
        if ($writableWin) {
            $sub = ''
            try { $sub = [IO.Path]::GetDirectoryName($S.Path) } catch { $sub = '' }
            Add-WdAnIndicator -List $L -Id 'I5' -Points 3 -Text ('runs from a user-writable Windows folder (' + $sub + ')')
        } elseif ($lp -gt 0) { Add-WdAnIndicator -List $L -Id 'I5' -Points $lp -Text ('runs from ' + $lc) }
        # I6 signature
        switch ($S.SigStatus) {
            'NotSigned' { Add-WdAnIndicator -List $L -Id 'I6' -Points 2 -Text 'not signed' }
            'HashMismatch' { Add-WdAnIndicator -List $L -Id 'I6' -Points 5 -Text 'signature hash mismatch (file modified after signing)' }
            'NotTrusted' { Add-WdAnIndicator -List $L -Id 'I6' -Points 5 -Text 'signature not trusted' }
            'UnknownError' { Add-WdAnIndicator -List $L -Id 'I6' -Points 2 -Text 'signature could not be verified' }
            'Error' { Add-WdAnIndicator -List $L -Id 'I6' -Points 2 -Text 'signature check failed' }
        }
        # I7 masquerade
        $i7 = 0
        $i7t = New-Object 'System.Collections.Generic.List[string]'
        if ($flags -match '(^|;)SystemNameOutsideSystem32(;|$)') { $i7 = 8; $i7t.Add(('system binary name "{0}" outside its Windows location' -f $S.Name)) }
        if ($flags -match '(^|;)UnexpectedParent(;|$)') { $i7 = 8; $i7t.Add(('unexpected parent "{0}"' -f $S.ParentName)) }
        if ($S.Name -match '^svchost(\.exe)?$' -and $S.CommandLine -ne '' -and $S.CommandLine -notmatch '^"?[^"]*svchost\.exe"?\s+-k\s') { $i7 = 8; $i7t.Add('svchost without a "-k <group>" command line') }
        if ($i7 -gt 0) { Add-WdAnIndicator -List $L -Id 'I7' -Points $i7 -Group 'Protected' -Text ('masquerade: ' + ($i7t -join '; ')) }
        # I8 look-alike name
        if (-not $inTrustedLocation -and -not $isTrusted) {
            $la = Get-WdAnLookAlike -Name $S.Name -SystemNames $sysNames
            if ($la -ne '') { Add-WdAnIndicator -List $L -Id 'I8' -Points 5 -Text ('name "{0}" looks like the system binary "{1}"' -f $S.Name, $la) }
        }
        # I9 random-looking name
        if (($writableWin -or ($lc -ne 'System32' -and $lc -ne 'Windows')) -and $S.SigStatus -ne 'Valid') {
            $base = $S.Name
            try { $base = [IO.Path]::GetFileNameWithoutExtension($S.ImageName) } catch { }
            if ([string]::IsNullOrEmpty($base)) { $base = $S.Name }
            $digits = ([regex]::Matches($base, '\d')).Count
            $ent = Get-WdAnNameEntropy -Name $base
            $rnd = $false
            if ($base -match '^[a-z0-9]{10,}$' -and $digits -ge 2) { $rnd = $true }
            elseif ($base -match '^[0-9a-f]{8,}$' -and $digits -ge 1) { $rnd = $true }
            elseif ($ent -ge 3.3 -and $base.Length -ge 8 -and $base.Length -le 16 -and $S.Company -eq '' -and $S.Description -eq '') { $rnd = $true }
            if ($rnd) { Add-WdAnIndicator -List $L -Id 'I9' -Points 3 -Text ([string]::Format($inv, 'random-looking name "{0}" (entropy {1:F2}, no version info)', $base, $ent)) }
        }
        # I12 parent chain
        $pn = $S.ParentName.ToLowerInvariant()
        $nameBase = $S.Name.ToLowerInvariant()
        if ($pn -ne '' -and $pn -ne '<exited>' -and $pn -ne '<none>') {
            $officeParents = @('winword', 'excel', 'outlook', 'powerpnt', 'acrord32', 'acrobat', 'wordpad', 'onenote')
            $scriptParents = @('wscript', 'cscript', 'mshta', 'regsvr32', 'rundll32')
            $servicing = @('svchost', 'services', 'wmiprvse', 'taskeng', 'taskhostw')
            if (($nameBase -match [string]$rules['ScriptHostRegex']) -and ($officeParents -contains $pn)) { Add-WdAnIndicator -List $L -Id 'I12' -Points 5 -Text ('script host started by an Office/PDF application ({0})' -f $S.ParentName) }
            elseif ($scriptParents -contains $pn) { Add-WdAnIndicator -List $L -Id 'I12' -Points 5 -Text ('started by a script host ({0})' -f $S.ParentName) }
            elseif ((($script:WdAnSuspiciousLocations -contains $lc) -and $lc -ne 'UserProfile' -or $writableWin) -and ($servicing -contains $pn)) {
                $lcText = $lc
                if ($writableWin) { $lcText = 'user-writable Windows folder' }
                Add-WdAnIndicator -List $L -Id 'I12' -Points 5 -Text ('{0} executable started by {1} (scheduled task, service or WMI consumer)' -f $lcText, $S.ParentName)
            }
        }
        # I17 very long uptime, background, user location
        if (-not $inTrustedLocation -and -not $S.HasWindowEver -and $S.Started -ne '') {
            $st = Get-WdAnDateTime -Text $S.Started
            if ($null -ne $st -and ($runStart - $st).TotalDays -ge 7) { Add-WdAnIndicator -List $L -Id 'I17' -Points 1 -Text ([string]::Format($inv, 'background process running for {0:F0} days from {1}', ($runStart - $st).TotalDays, $lc)) }
        }
        # I21 no version info and a young file
        if ($S.SigStatus -ne '' -and $S.Company -eq '' -and $S.Description -eq '' -and $S.FileCreated -ne '') {
            $fc = Get-WdAnDateTime -Text $S.FileCreated
            if ($null -ne $fc -and ($runStart - $fc).TotalDays -le 30) { Add-WdAnIndicator -List $L -Id 'I21' -Points 2 -Text ([string]::Format($inv, 'no company/description in version info and file created {0:F0} day(s) ago', ($runStart - $fc).TotalDays)) }
        }
        # I22 renamed binary
        if ($S.OriginalFilename -ne '' -and $S.SigStatus -ne 'Valid' -and $S.SigStatus -ne '') {
            $orig = $S.OriginalFilename.ToLowerInvariant()
            $orig = $orig -replace '\.mui$', ''
            $orig = $orig -replace '\.(exe|dll|tmp)$', ''
            $actual = $S.ImageName.ToLowerInvariant() -replace '\.(exe|tmp)$', ''
            if ($actual -eq '') { $actual = $S.Name.ToLowerInvariant() }
            if ($orig -ne '' -and $actual -ne '' -and $orig -ne $actual -and $orig.IndexOf($actual) -lt 0 -and $actual.IndexOf($orig) -lt 0 -and $orig -ne 'electron') {
                Add-WdAnIndicator -List $L -Id 'I22' -Points 6 -Text ('renamed binary: OriginalFilename "{0}" but runs as "{1}"' -f $S.OriginalFilename, $S.ImageName)
            }
        }
    }
    # I10 miner tokens (command line known)
    if ($S.CommandLine -ne '') {
        $tok = Get-WdAnMinerTokens -CommandLine $S.CommandLine
        if ($tok.Strong.Count -gt 0) {
            Add-WdAnIndicator -List $L -Id 'I10' -Points 20 -Group 'Protected' -Text ('miner tokens in the command line: ' + ($tok.Strong -join ', '))
        } elseif ($tok.Weak.Count -gt 0) {
            if ($S.CommandLine -match '--type=' -or $isTrusted) { $S.Notes.Add(('weak miner-like token(s) {0} ignored: Chromium/Electron child process or trusted signer' -f ($tok.Weak -join ', '))) }
            else { Add-WdAnIndicator -List $L -Id 'I10' -Points 3 -Text ('weak miner-like token(s) in the command line: ' + ($tok.Weak -join ', ')) }
        }
        # I11 script host arguments: STRONG tokens are red flags (6), WEAK launch options are informational only (max 2).
        # The analyzer's own match on the recorded command line wins over the monitor's flags: sessions recorded by
        # older monitors carry ScriptHostRedFlag for mere launch options (-ExecutionPolicy Bypass).
        $sh = Get-WdAnScriptHostTokens -Name $S.Name -CommandLine $S.CommandLine
        if ($sh.Strong.Count -gt 0) {
            Add-WdAnIndicator -List $L -Id 'I11' -Points 6 -Text ('script host with red-flag arguments: ' + ($sh.Strong -join ', '))
        } elseif ($sh.Weak.Count -gt 0) {
            Add-WdAnIndicator -List $L -Id 'I11' -Points $script:WdAnWeakScriptHostPoints -Text ('script host started with launch options {0} (informational: common for IDE/agent shells, scheduled scripts and installers)' -f ($sh.Weak -join ', '))
        } elseif ($flags -match '(^|;)ScriptHostRedFlag(;|$)') {
            $S.Notes.Add('monitor flag ScriptHostRedFlag not reproduced from the recorded command line (older monitors flagged launch options); not scored')
        }
    } elseif ($flags -match '(^|;)ScriptHostRedFlag(;|$)') {
        Add-WdAnIndicator -List $L -Id 'I11' -Points $script:WdAnWeakScriptHostPoints -Text 'script host flagged by the monitor (ScriptHostRedFlag; command line not recorded, so the red flag cannot be verified)'
    } elseif ($flags -match '(^|;)ScriptHostWeakArgs(;|$)') {
        Add-WdAnIndicator -List $L -Id 'I11' -Points $script:WdAnWeakScriptHostPoints -Text 'script host started with launch options (monitor flag ScriptHostWeakArgs; command line not recorded; informational)'
    }
    # I13 pool ports
    if ($S.PoolPorts.Count -gt 0) {
        $pts = [math]::Min(8, 4 * $S.PoolPorts.Count)
        $raw = $false
        foreach ($ep in $S.Endpoints) { if ($ep.Pool -and -not $ep.Private -and $ep.Dns -eq '') { $raw = $true } }
        $t = 'connection(s) to mining pool port(s) ' + (@($S.PoolPorts | Sort-Object) -join ', ')
        if ($raw) { $pts += 4; $t += ' at a raw public IP without a DNS name' }
        Add-WdAnIndicator -List $L -Id 'I13' -Points $pts -Text $t
    }
    # I14 connections opened while idle (connections that already existed at monitor start are not counted; see Read-WdAnNet)
    if ($S.IdlePublic -gt 0 -and -not $isKnownHeavy -and -not $isTrusted -and -not $shortIdleOnlyRun) {
        $skip = ((-not $pathKnown) -and (Test-WdAnNameInList -Name $S.Name -List $sysNames))
        if (-not $skip) { Add-WdAnIndicator -List $L -Id 'I14' -Points 2 -Text ([string]::Format($inv, '{0} connection(s) to public addresses opened while the user was idle', $S.IdlePublic)) }
    }
    # I15 many endpoints
    if ($S.RemoteIps.Count -ge 30 -and -not $S.HasWindowEver -and -not $isKnownHeavy) {
        Add-WdAnIndicator -List $L -Id 'I15' -Points 3 -Text ([string]::Format($inv, '{0} distinct remote addresses without a window', $S.RemoteIps.Count))
    }
    # I16 watchdog restarts
    if ($S.Starts -ge 3 -and $S.QuickRestarts -ge 2 -and -not ($inTrustedLocation -and $S.SigStatus -eq 'Valid')) {
        Add-WdAnIndicator -List $L -Id 'I16' -Points 4 -Text ([string]::Format($inv, 'started {0} times during the run, {1} time(s) within 5 min after a previous instance exited', $S.Starts, $S.QuickRestarts))
    }
    # I19 Defender, I20 persistence
    if ($S.DefenderDetections -gt 0) { Add-WdAnIndicator -List $L -Id 'I19' -Points 15 -Group 'Protected' -Text ([string]::Format($inv, 'Microsoft Defender reported {0} detection(s) naming this file', $S.DefenderDetections)) }
    if ($S.ExclusionChanges -gt 0) { Add-WdAnIndicator -List $L -Id 'I19' -Points 8 -Group 'Protected' -Text ([string]::Format($inv, 'Defender exclusion changed for this folder during the run ({0} event(s))', $S.ExclusionChanges)) }
    if ($S.PersistenceEvents -gt 0) { Add-WdAnIndicator -List $L -Id 'I20' -Points 5 -Text ([string]::Format($inv, 'persistence created during the run ({0} service/task/WMI event(s) naming this file)', $S.PersistenceEvents)) }
    return $L.ToArray()
}

function Set-WdAnScore {
    # Sums the indicators, applies damping and classifies the subject.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$S, [AllowNull()][object[]]$Indicators)
    if ($null -eq $Indicators) { $Indicators = @() }
    $S.Indicators = $Indicators
    $protected = 0; $resource = 0; $other = 0
    foreach ($i in $Indicators) {
        switch ([string]$i.Group) {
            'Protected' { $protected += [int]$i.Points }
            'Resource' { $resource += [int]$i.Points }
            default { $other += [int]$i.Points }
        }
    }
    $raw = $protected + $resource + $other
    $S.RawScore = $raw
    $damp = New-Object 'System.Collections.Generic.List[string]'
    if ($S.IsKnownHeavy -and ($S.SigStatus -eq 'Valid' -or -not $S.PathKnown) -and $resource -gt 0) {
        $resource = [math]::Max(0, $resource - 4)
        $damp.Add('known heavy/legitimate background process: -4 on resource indicators')
    }
    $rest = $resource + $other
    $trustedLocation = $S.InTrustedLocation
    if ($null -eq $trustedLocation) { $trustedLocation = ($script:WdAnTrustedLocations -contains $S.LocationClass) }
    if ($S.IsTrustedSigner -and $trustedLocation -and $rest -gt 0) {
        $rest = [math]::Max(0, $rest - 6)
        $damp.Add('valid signature of a well-known vendor in a system/program location: -6')
    } elseif ($S.IsTrustedSigner -and $S.SigStatus -eq 'Valid' -and ($S.LocationClass -eq 'AppData' -or $S.LocationClass -eq 'ProgramData') -and $rest -gt 0) {
        # Zoom/OneDrive/Edge/Spotify/Discord updaters: trusted-signed AppData/ProgramData binaries launched by the Task
        # Scheduler collect I5 + I12 (= 8) by design of those rules; the raw score stays visible in suspects.csv.
        $rest = [math]::Max(0, $rest - 4)
        $damp.Add('valid signature of a well-known vendor in a per-user/program-data location: -4')
    }
    $S.Damping = @($damp.ToArray())
    $S.Score = $protected + $rest
    $S.HasStrongIndicator = $false
    foreach ($i in $Indicators) { if (($i.Id -eq 'I10' -and [int]$i.Points -ge 20) -or ($i.Id -eq 'I19' -and [int]$i.Points -ge 15)) { $S.HasStrongIndicator = $true } }
    if ($S.Score -ge $script:WdAnHighThreshold) { $S.Class = 'Highly suspicious' }
    elseif ($S.Score -ge $script:WdAnSuspiciousThreshold) { $S.Class = 'Suspicious' }
    elseif ($S.Score -gt 0) { $S.Class = 'Below threshold' }
    else { $S.Class = 'Clean' }
    $S.NeedsElevatedCheck = $false
    if ($S.NeedsAdmin) {
        foreach ($i in $Indicators) { if ($i.Group -eq 'Resource') { $S.NeedsElevatedCheck = $true } }
    }
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($i in $Indicators) { $parts.Add(('{0} +{1}: {2}' -f $i.Id, $i.Points, $i.Text)) }
    $S.Reasons = ($parts -join '; ')
}


# ---------------------------------------------------------------------------------------------
# Timeline buckets and sparklines (glyphs built from char codes; source stays ASCII)
# ---------------------------------------------------------------------------------------------
function Get-WdAnBucketMode {
    [CmdletBinding()]
    param([double]$SpanHours)
    if ($SpanHours -le 1) { return '1min' }
    if ($SpanHours -le 6) { return '10min' }
    if ($SpanHours -le 60) { return 'hour' }
    if ($SpanHours -le 24 * 8) { return '3h' }
    if ($SpanHours -le 24 * 16) { return '6h' }
    if ($SpanHours -le 24 * 32) { return '12h' }
    return 'day'
}

function Get-WdAnBucketGroupKey {
    # Bucket key 'yyyy-MM-ddTHH:mm' (16 chars; 13-char hour keys for long runs) -> group key for the display mode.
    [CmdletBinding()]
    param([string]$Key, [string]$Mode)
    if ($null -eq $Key -or $Key.Length -lt 13) { return $Key }
    switch ($Mode) {
        '1min' { return $Key }
        '10min' { if ($Key.Length -ge 15) { return ($Key.Substring(0, 15) + '0') } else { return $Key } }
        'hour' { return $Key.Substring(0, 13) }
        'day' { return $Key.Substring(0, 10) }
        default {
            $h = 0
            [void][int]::TryParse($Key.Substring(11, 2), [ref]$h)
            $n = 1
            [void][int]::TryParse($Mode.TrimEnd('h'), [ref]$n)
            if ($n -lt 1) { $n = 1 }
            $g = [int][math]::Floor($h / $n) * $n
            return ($Key.Substring(0, 10) + 'T' + $g.ToString('00', (Get-WdInv)))
        }
    }
}

function Get-WdAnBucketLabel {
    [CmdletBinding()]
    param([string]$GroupKey, [string]$Mode)
    if ([string]::IsNullOrEmpty($GroupKey)) { return '' }
    switch ($Mode) {
        '1min' { if ($GroupKey.Length -ge 16) { return $GroupKey.Substring(11, 5) } else { return $GroupKey } }
        '10min' { if ($GroupKey.Length -ge 16) { return $GroupKey.Substring(11, 5) } else { return $GroupKey } }
        'day' { return $GroupKey.Substring(5) }
        default { if ($GroupKey.Length -ge 13) { return ($GroupKey.Substring(5, 5) + ' ' + $GroupKey.Substring(11, 2) + ':00') } else { return $GroupKey } }
    }
}

function Get-WdAnGroupedBuckets {
    # Merges 15-char buckets into group keys. Even/sum indexes are added, MaxIndexes take the maximum.
    [CmdletBinding()]
    param([AllowNull()][hashtable]$Buckets, [string]$Mode, [int]$Width, [int[]]$MaxIndexes)
    $out = @{}
    if ($null -eq $Buckets) { return $out }
    if ($null -eq $MaxIndexes) { $MaxIndexes = @() }
    foreach ($k in $Buckets.Keys) {
        $g = Get-WdAnBucketGroupKey -Key $k -Mode $Mode
        $src = $Buckets[$k]
        $dst = $out[$g]
        if ($null -eq $dst) {
            $dst = New-Object 'double[]' $Width
            foreach ($mi in $MaxIndexes) { $dst[$mi] = -1.0 }
            $out[$g] = $dst
        }
        for ($i = 0; $i -lt $Width -and $i -lt $src.Length; $i++) {
            if ($MaxIndexes -contains $i) { if ($src[$i] -gt $dst[$i]) { $dst[$i] = $src[$i] } }
            else { $dst[$i] += $src[$i] }
        }
    }
    return $out
}

function Get-WdAnSparkline {
    # Values < 0 mean "no data" and render as a dot. Max <= 0 -> per-series maximum.
    [CmdletBinding()]
    param([AllowNull()][double[]]$Values, [double]$Max = -1.0)
    if ($null -eq $Values -or $Values.Count -eq 0) { return '' }
    if ($Max -le 0) { foreach ($v in $Values) { if ($v -gt $Max) { $Max = $v } } }
    $sb = New-Object System.Text.StringBuilder
    foreach ($v in $Values) {
        if ($v -lt 0) { [void]$sb.Append([char]0x00B7); continue }
        if ($Max -le 0) { [void]$sb.Append($script:WdAnBlocks[0]); continue }
        $idx = [int][math]::Min(7, [math]::Floor($v / $Max * 7.999))
        if ($idx -lt 0) { $idx = 0 }
        [void]$sb.Append($script:WdAnBlocks[$idx])
    }
    return $sb.ToString()
}

function Get-WdAnTimeline {
    # System timeline from the samples buckets: group keys, labels, per-metric series and peaks.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Ctx)
    $SM = $Ctx.Samples
    $TL = @{ Mode = ''; Groups = @(); Labels = @(); Series = @{}; IdleLine = ''; RateN = @(); SpanHours = 0.0; Peaks = @() }
    if ($null -eq $SM -or $SM.Rows -eq 0) { return $TL }
    $a = Get-WdAnDateTime -Text $SM.First
    $b = Get-WdAnDateTime -Text $SM.Last
    $span = 0.0
    if ($null -ne $a -and $null -ne $b) { $span = ($b - $a).TotalHours }
    $TL.SpanHours = $span
    $mode = Get-WdAnBucketMode -SpanHours $span
    $grouped = Get-WdAnGroupedBuckets -Buckets $SM.Buckets -Mode $mode -Width 16 -MaxIndexes @(2, 4, 6, 8, 10, 14)
    $groups = @($grouped.Keys | Sort-Object)
    # Too many columns: step up the mode until it fits.
    $modes = @('1min', '10min', 'hour', '3h', '6h', '12h', 'day')
    $mi = [array]::IndexOf($modes, $mode)
    while ($groups.Count -gt $script:WdAnMaxColumns -and $mi -lt ($modes.Count - 1)) {
        $mi++
        $mode = $modes[$mi]
        $grouped = Get-WdAnGroupedBuckets -Buckets $SM.Buckets -Mode $mode -Width 16 -MaxIndexes @(2, 4, 6, 8, 10, 14)
        $groups = @($grouped.Keys | Sort-Object)
    }
    $TL.Mode = $mode
    $TL.Groups = $groups
    $labels = @()
    foreach ($g in $groups) { $labels += (Get-WdAnBucketLabel -GroupKey $g -Mode $mode) }
    $TL.Labels = $labels
    $n = $groups.Count
    $cpu = New-Object 'double[]' $n; $gpu = New-Object 'double[]' $n; $mem = New-Object 'double[]' $n; $disk = New-Object 'double[]' $n
    $dbps = New-Object 'double[]' $n; $net = New-Object 'double[]' $n; $rateN = New-Object 'double[]' $n; $gcomp = New-Object 'double[]' $n
    $idleSb = New-Object System.Text.StringBuilder
    $memTotal = [double]$SM.MemTotal
    for ($i = 0; $i -lt $n; $i++) {
        $g = $grouped[$groups[$i]]
        $rn = $g[15]; $all = $g[1]
        $rateN[$i] = $rn
        if ($rn -gt 0) { $cpu[$i] = $g[0] / $rn; $gpu[$i] = $g[3] / $rn; $disk[$i] = $g[7] / $rn; $dbps[$i] = $g[13] / $rn; $net[$i] = $g[9] / $rn; $gcomp[$i] = $g[12] / $rn }
        else { $cpu[$i] = -1; $gpu[$i] = -1; $disk[$i] = -1; $dbps[$i] = -1; $net[$i] = -1; $gcomp[$i] = -1 }
        if ($all -gt 0) { if ($memTotal -gt 0) { $mem[$i] = ($g[5] / $all) / $memTotal * 100.0 } else { $mem[$i] = $g[5] / $all } } else { $mem[$i] = -1 }
        if ($all -le 0) { [void]$idleSb.Append(' ') } elseif (($g[11] / $all) -ge 0.5) { [void]$idleSb.Append('_') } else { [void]$idleSb.Append('.') }
    }
    $TL.Series = @{ Cpu = $cpu; Gpu = $gpu; GpuCompute = $gcomp; Mem = $mem; Disk = $disk; DiskBps = $dbps; Net = $net }
    $TL.RateN = $rateN
    $TL.IdleLine = $idleSb.ToString()
    return $TL
}

function Get-WdAnSubjectSeries {
    # Average CpuPct per display bucket for one subject (missing rows count as 0 because the row filter dropped quiet samples).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Subject, [Parameter(Mandatory = $true)][hashtable]$Timeline, [switch]$Gpu)
    $n = $Timeline.Groups.Count
    $out = New-Object 'double[]' $n
    if ($n -eq 0) { return ,$out }
    $grouped = Get-WdAnGroupedBuckets -Buckets $Subject.Buckets -Mode $Timeline.Mode -Width 4 -MaxIndexes @(2)
    for ($i = 0; $i -lt $n; $i++) {
        $rn = [double]$Timeline.RateN[$i]
        if ($rn -le 0) { $out[$i] = -1; continue }
        $g = $grouped[$Timeline.Groups[$i]]
        if ($null -eq $g) { $out[$i] = 0; continue }
        if ($Gpu) { $out[$i] = $g[3] / $rn } else { $out[$i] = $g[0] / $rn }
    }
    return ,$out
}

# ---------------------------------------------------------------------------------------------
# Verdict and recommendations
# ---------------------------------------------------------------------------------------------
function Get-WdAnVerdict {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Ctx)
    $inv = Get-WdInv
    $subjects = @($Ctx.Subjects)
    $suspects = @($subjects | Where-Object { $_.Score -ge $script:WdAnSuspiciousThreshold } | Sort-Object -Property @{ Expression = { $_.Score }; Descending = $true }, @{ Expression = { $_.CpuSeconds }; Descending = $true })
    # Missing observations or failed readers/scoring cannot support a clean verdict. Keep any detected suspects.
    $hasTelemetry = ([int]$Ctx.Stats['ProcRows'] -gt [int]$Ctx.Stats['SelfRows']) -or ($null -ne $Ctx.ProcSum -and $Ctx.ProcSum.Count -gt 0)
    $incomplete = (-not $hasTelemetry) -or $subjects.Count -eq 0 -or $script:CollectionErrors.Count -gt 0 -or [int]$Ctx.Stats['BrokenEntries'] -gt 0
    $inconclusive = ($suspects.Count -eq 0 -and $incomplete)
    $VD = @{ Suspects = $suspects; Top = @($suspects | Select-Object -First 3); Clean = ($suspects.Count -eq 0 -and -not $inconclusive); Inconclusive = $inconclusive; Reasons = @(); Warnings = @() }
    if (-not $hasTelemetry -or $subjects.Count -eq 0) { $VD.Warnings += 'No usable process observations were available; record a monitor session before drawing conclusions.' }
    if ($script:CollectionErrors.Count -gt 0 -or [int]$Ctx.Stats['BrokenEntries'] -gt 0) { $VD.Warnings += 'Some session data could not be read or scored; see Collection errors and the appendix before drawing conclusions.' }
    $SM = $Ctx.Samples
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    $strong = @($subjects | Where-Object { $_.HasStrongIndicator })
    $idleHeavy = @($subjects | Where-Object { @($_.Indicators | Where-Object { $_.Id -eq 'I1' -and [int]$_.Points -ge 6 }).Count -gt 0 })
    $compute = @($subjects | Where-Object { @($_.Indicators | Where-Object { $_.Id -eq 'I2' }).Count -gt 0 })
    $masq = @($subjects | Where-Object { @($_.Indicators | Where-Object { $_.Id -eq 'I7' -or $_.Id -eq 'I8' }).Count -gt 0 })
    $pool = @($subjects | Where-Object { $_.PoolPorts.Count -gt 0 })
    $defender = 0
    if ($null -ne $Ctx.Events) { foreach ($ev in @($Ctx.Events.EventLog)) { if ([string]$ev['Source'] -match 'Defender' -and [string]$ev['EventId'] -match '^(1006|1007|1015|1116|1117|1118|1119)$') { $defender++ } } }
    if ($VD.Inconclusive) {
        $reasons.Add('the available data is insufficient for a clean verdict; record a new session or resolve the collection errors')
    } elseif ($VD.Clean) {
        if ($strong.Count -eq 0) { $reasons.Add('no miner tokens in any recorded command line and no Defender detection during the run') }
        if ($idleHeavy.Count -eq 0) {
            if ($null -ne $SM -and $SM.IdleN -ge $script:WdAnIdleMinSamples -and $SM.ActiveN -ge $script:WdAnIdleMinSamples) { $reasons.Add('no process consumed CPU mainly while the user was idle') }
            else { $reasons.Add('idle-vs-active behaviour could not be compared (the run needs at least 20 samples in each state; record a longer session that includes both work and idle time)') }
        }
        if ($compute.Count -eq 0) { $reasons.Add('no sustained GPU Compute engine use (3D/Video use by browsers, games and the desktop is normal)') }
        if ($masq.Count -eq 0) { $reasons.Add('no system binary name running from a wrong location or with a wrong parent') }
        if ($pool.Count -eq 0) { $reasons.Add('no connection to a known mining pool port') }
        $best = @($subjects | Where-Object { $_.Score -gt 0 } | Sort-Object -Property @{ Expression = { $_.Score }; Descending = $true } | Select-Object -First 3)
        if ($best.Count -gt 0) {
            $names = @()
            foreach ($b in $best) { $names += ('{0} ({1} points)' -f (Get-WdAnDisplayName -Subject $b), $b.Score) }
            $reasons.Add('highest scores stayed below the Suspicious threshold of ' + $script:WdAnSuspiciousThreshold + ': ' + ($names -join ', '))
        }
    } else {
        foreach ($t in $VD.Top) { $reasons.Add(('{0}: score {1} ({2})' -f (Get-WdAnDisplayName -Subject $t), $t.Score, $t.Class)) }
    }
    if ($defender -gt 0) { $VD.Warnings += ('Microsoft Defender recorded {0} detection event(s) during the run (see Events)' -f $defender) }
    if ($null -ne $SM) {
        if ($SM.PerfLowN -gt 0 -and $SM.CpuN -gt 0 -and ($SM.PerfLowN / [double]$SM.CpuN) -ge 0.1) { $VD.Warnings += ([string]::Format($inv, 'CPU throttling: processor performance below 70 % while busy in {0} of {1} samples (cooling / power plan problem, not a rogue process)', $SM.PerfLowN, $SM.CpuN)) }
        if ($SM.ThrottleN -gt 0) { $VD.Warnings += ([string]::Format($inv, 'thermal throttling reasons reported in {0} sample(s)', $SM.ThrottleN)) }
        if ($SM.MemTotal -gt 0 -and $SM.MemMax -gt 0 -and ($SM.MemMax / $SM.MemTotal) -ge 0.9) { $VD.Warnings += ([string]::Format($inv, 'memory pressure: used memory peaked at {0:F0} % of {1:F0} MB', $SM.MemMax / $SM.MemTotal * 100, $SM.MemTotal)) }
        if ($SM.CommitMax -ge 90) { $VD.Warnings += ([string]::Format($inv, 'commit charge peaked at {0:F0} % of the commit limit', $SM.CommitMax)) }
    }
    $VD.Reasons = @($reasons.ToArray())
    return $VD
}

function Get-WdAnRecommendations {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Ctx)
    $inv = Get-WdInv
    $R = New-Object 'System.Collections.Generic.List[string]'
    $VD = $Ctx.Verdict
    $SM = $Ctx.Samples
    $run = $Ctx.Run
    $elevated = $false
    if ($null -ne $run) { $elevated = [bool]$run.IsElevated }
    if ($null -eq $VD -or $VD.Inconclusive) {
        $R.Add('The analysis is inconclusive. Check monitor.log and Collection errors, then record a new session including normal work and idle time.')
    } elseif ($VD.Suspects.Count -gt 0) {
        $R.Add('Do not delete anything yet. For each suspect: open the VirusTotal link (the report only links the SHA256; nothing was uploaded), check the path, signer and command line, and search the file name together with "miner".')
        $R.Add('Find how it starts: run the Inventory mode (autostart entries, scheduled tasks, services, WMI subscriptions, Defender exclusions) and look for the same path. Miners are usually re-launched by a scheduled task or a service with a watchdog.')
        $R.Add('Run a full Microsoft Defender scan (or a second-opinion scanner) with the PC disconnected from the network; if Defender exclusions were added without your knowledge, remove them first.')
        $R.Add('If a file is confirmed malicious: stop the process, disable its autostart/task/service, then quarantine the file. Change passwords afterwards if the machine was compromised.')
    } else {
        $R.Add('Nothing points to a miner in this session. If the PC still feels slow, look at the top consumers above and at the system timeline peaks.')
    }
    $needsElevated = @($Ctx.Subjects | Where-Object { $_.NeedsElevatedCheck })
    if (-not $elevated) {
        if ($needsElevated.Count -gt 0) { $R.Add(('Record the monitor session again with administrator rights: {0} system process(es) consumed noticeable resources but their path, command line and signature were not readable (requires administrator).' -f $needsElevated.Count)) }
        else { $R.Add('The monitor ran without administrator rights: paths, command lines and signatures of SYSTEM/service processes were not recorded. A miner installed as a service would only show its resource use here; re-run elevated for a complete picture.') }
    }
    if ($null -ne $SM) {
        if ($SM.IdleN -lt $script:WdAnIdleMinSamples -or $SM.ActiveN -lt $script:WdAnIdleMinSamples) { $R.Add('Record a longer session (several hours including normal work AND idle time, ideally overnight) so idle-vs-active behaviour can be compared - the strongest miner signal.') }
        if ($SM.PerfLowN -gt 0 -and $SM.CpuN -gt 0 -and ($SM.PerfLowN / [double]$SM.CpuN) -ge 0.1) { $R.Add('The CPU was throttled while busy: clean fans and vents, check the power plan and (on a laptop) use the original power adapter. This makes everything slow without any rogue process.') }
        if ($SM.MemTotal -gt 0 -and $SM.MemMax -gt 0 -and ($SM.MemMax / $SM.MemTotal) -ge 0.9) { $R.Add('Memory was nearly full: close or remove the largest memory consumers listed above, or add RAM.') }
        if ($SM.PagesN -gt 0 -and ($SM.PagesSum / $SM.PagesN) -gt 500) { $R.Add([string]::Format($inv, 'Hard page faults averaged {0:F0}/s: the system was swapping; more RAM or fewer background programs would help.', $SM.PagesSum / $SM.PagesN)) }
    }
    $growth = @($Ctx.Subjects | Where-Object { $_.WSFirst -gt 0 -and $_.WSLast -gt 0 -and $_.WSLast -ge 2 * $_.WSFirst -and $_.WSLast -ge 500MB -and $_.Samples -ge 30 })
    if ($growth.Count -gt 0) {
        $names = @()
        foreach ($g in @($growth | Select-Object -First 3)) { $names += ('{0} ({1} -> {2})' -f (Get-WdAnDisplayName -Subject $g), (Format-Bytes -Bytes $g.WSFirst), (Format-Bytes -Bytes $g.WSLast)) }
        $R.Add('Working set of these processes grew steadily (possible leak): ' + ($names -join ', ') + '. Restart them or update the program.')
    }
    return $R.ToArray()
}


# ---------------------------------------------------------------------------------------------
# report.md
# ---------------------------------------------------------------------------------------------
function Get-WdAnSessionSummary {
    # Session facts for the report and analysis.json (run.json first, samples as fallback/measurement).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Ctx)
    $inv = Get-WdInv
    $run = $Ctx.Run
    $SM = $Ctx.Samples
    $o = [ordered]@{
        SessionPath = $Ctx.SessionPath; Computer = ''; User = ''; MonitorVersion = ''; FormatVersion = ''; IsElevated = $null; NCPU = $null; MemTotalMB = $null
        GPUs = @(); GpuCounterMode = ''; IntervalSeconds = $null; MeasuredIntervalSec = $null; Start = ''; Stop = ''; StopReason = ''; DurationSec = $null
        Samples = 0; Overruns = 0; IdleSamples = 0; ActiveSamples = 0; IdleSharePct = $null; LockedSamples = 0
        ProcessesAtStart = $null; ProcessesWithoutPath = $null; ProcessKeys = 0; StillRunning = $false; TrackShortLived = $false
    }
    if ($null -ne $run) {
        $o.Computer = [string]$run.Computer; $o.User = [string]$run.User; $o.MonitorVersion = [string]$run.Version; $o.FormatVersion = [string]$run.FormatVersion
        $o.IsElevated = [bool]$run.IsElevated; $o.NCPU = $run.NCPU; $o.MemTotalMB = $run.MemTotalMB; $o.GpuCounterMode = [string]$run.GpuCounterMode
        $o.IntervalSeconds = $run.IntervalSeconds; $o.Start = [string]$run.Start; $o.Stop = [string]$run.Stop; $o.StopReason = [string]$run.StopReason
        $o.TrackShortLived = [bool]$run.TrackShortLived
        if ($null -ne $run.DurationSec -and [string]$run.DurationSec -ne '' -and [double]$run.DurationSec -gt 0) { $o.DurationSec = [double]$run.DurationSec }
        $o.ProcessesAtStart = $run.ProcessesAtStart; $o.ProcessesWithoutPath = $run.ProcessesWithoutPath
        $g = @()
        if ($null -ne $run.GPUs) { foreach ($x in @($run.GPUs)) { $g += [string]$x.Name } }
        $o.GPUs = $g
    }
    # run.json is rewritten after the first completed sample and at every 60 s summary flush; a session killed before
    # its first refresh still carries ProcessesWithoutPath = 0, so fall back to counting the procmeta rows with the marker.
    $noPath = 0
    if ($null -ne $o.ProcessesWithoutPath) { try { $noPath = [int]$o.ProcessesWithoutPath } catch { $noPath = 0 } }
    if ($noPath -le 0 -and $null -ne $Ctx.Meta -and $Ctx.Meta.Count -gt 0) {
        $n = 0
        foreach ($m in $Ctx.Meta.Values) {
            if ([string]$m['Path'] -ne '') { continue }
            if (([string]$m['AccessNote']).IndexOf($script:WdAnAdminText, [StringComparison]::OrdinalIgnoreCase) -ge 0 -or ([string]$m['Owner']).IndexOf($script:WdAnAdminText, [StringComparison]::OrdinalIgnoreCase) -ge 0) { $n++ }
        }
        if ($n -gt 0) { $o.ProcessesWithoutPath = $n }
    }
    if ($null -ne $SM) {
        $o.Samples = $SM.Rows; $o.Overruns = $SM.Overruns; $o.IdleSamples = $SM.IdleN; $o.ActiveSamples = $SM.ActiveN; $o.LockedSamples = $SM.LockedN
        if ($SM.Rows -gt 0) { $o.IdleSharePct = [math]::Round($SM.IdleN * 100.0 / $SM.Rows, 1, [MidpointRounding]::AwayFromZero) }
        if ($SM.IntervalN -gt 0) { $o.MeasuredIntervalSec = [math]::Round($SM.IntervalSum / $SM.IntervalN, 1, [MidpointRounding]::AwayFromZero) }
        if ($null -eq $o.DurationSec -and $SM.First -ne '' -and $SM.Last -ne '') {
            $a = Get-WdAnDateTime -Text $SM.First; $b = Get-WdAnDateTime -Text $SM.Last
            if ($null -ne $a -and $null -ne $b) { $o.DurationSec = [math]::Round(($b - $a).TotalSeconds, 1, [MidpointRounding]::AwayFromZero) }
        }
        if ($o.Start -eq '') { $o.Start = $SM.First }
        if ($o.Stop -eq '' -and $SM.Last -ne '') { $o.Stop = $SM.Last }
    }
    if ($null -eq $o.DurationSec) { $o.DurationSec = 0.0 }
    if ($null -ne $Ctx.Entries) { $o.ProcessKeys = $Ctx.Entries.Count }
    if (-not [string]::IsNullOrEmpty($Ctx.Files.Running)) { $o.StillRunning = $true }
    return $o
}

function Format-WdAnDuration {
    [CmdletBinding()]
    param([double]$Seconds)
    $inv = Get-WdInv
    if ($Seconds -lt 120) { return ([string]::Format($inv, '{0:F0} s', $Seconds)) }
    if ($Seconds -lt 7200) { return ([string]::Format($inv, '{0:F0} min', $Seconds / 60)) }
    if ($Seconds -lt 172800) { return ([string]::Format($inv, '{0:F1} h', $Seconds / 3600)) }
    return ([string]::Format($inv, '{0:F1} days', $Seconds / 86400))
}

function Get-WdAnSubjectRow {
    # Common columns for the consumer tables.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$S, [Parameter(Mandatory = $true)][hashtable]$Ctx)
    $inv = Get-WdInv
    $loc = [string]$S.LocationClass
    if ($S.Path -eq '') { $loc = Get-WdAnUnknownPathText -S $S }
    $idleAct = ''
    if ($null -ne $S.CpuIdleAvg -and $null -ne $S.CpuActiveAvg) { $idleAct = [string]::Format($inv, '{0:F1} / {1:F1}', $S.CpuIdleAvg, $S.CpuActiveAvg) }
    elseif ($null -ne $S.CpuIdleAvg) { $idleAct = [string]::Format($inv, '{0:F1} / -', $S.CpuIdleAvg) }
    elseif ($null -ne $S.CpuActiveAvg) { $idleAct = [string]::Format($inv, '- / {0:F1}', $S.CpuActiveAvg) }
    $win = 'no'
    if ($S.HasWindowEver) { $win = 'yes' }
    $name = Get-WdAnDisplayName -Subject $S
    if ($S.Instances.Count -gt 1) { $name += (' (x{0})' -f $S.Instances.Count) }
    if ($S.IsTool) { $name += ' (win-debug)' }
    return [ordered]@{
        Process = $name; Location = $loc; CpuSeconds = (Format-WdAnNum -Value $S.CpuSeconds -Decimals 1); AvgPct = (Format-WdAnNum -Value $S.CpuAvg -Decimals 2)
        MaxPct = (Format-WdAnNum -Value $S.CpuMax -Decimals 1); Presence = ([string]::Format($inv, '{0:F0} %', $S.Presence * 100)); IdleActive = $idleAct; Window = $win
        Timeline = ''
    }
}

function Get-WdAnReportLines {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Ctx)
    $inv = Get-WdInv
    $L = New-Object 'System.Collections.Generic.List[string]'
    $sum = $Ctx.Summary
    $SM = $Ctx.Samples
    $TL = $Ctx.Timeline
    $VD = $Ctx.Verdict
    $subjects = @($Ctx.Subjects)
    $topRows = [math]::Min(15, [math]::Max(5, $Ctx.TopN))

    $L.Add('# win-debug monitor analysis')
    $L.Add('')
    foreach ($x in @(Get-RunInfoSectionLines -DurationSeconds $Ctx.DurationSeconds -Mode 'Analyze')) { $L.Add($x) }
    $L.Add('### Monitor session')
    $L.Add('')
    $L.Add(('- Session folder: {0}' -f $Ctx.SessionPath))
    $L.Add(('- Recorded on: {0} by {1}; monitor {2}; format {3}' -f $sum.Computer, $sum.User, $sum.MonitorVersion, $sum.FormatVersion))
    $elev = 'unknown'
    if ($null -ne $sum.IsElevated) { if ($sum.IsElevated) { $elev = 'yes' } else { $elev = 'no - paths, command lines and signatures of SYSTEM/service processes are missing ' + $script:WdAnAdminText } }
    $L.Add(('- Monitor ran elevated: {0}' -f $elev))
    $L.Add(('- Start: {0}; stop: {1} ({2}); duration {3}' -f $sum.Start, $(if ($sum.Stop -ne '') { $sum.Stop } else { 'still running / not stopped cleanly' }), $(if ($sum.StopReason -ne '') { $sum.StopReason } else { 'no stop reason recorded' }), (Format-WdAnDuration -Seconds ([double]$sum.DurationSec))))
    $L.Add(('- Samples: {0} (interval {1} s configured, {2} s measured, {3} overruns); {4} CPUs, {5} MB RAM, GPU: {6} (counters: {7})' -f $sum.Samples, $sum.IntervalSeconds, $sum.MeasuredIntervalSec, $sum.Overruns, $sum.NCPU, $sum.MemTotalMB, $(if ($sum.GPUs.Count -gt 0) { ($sum.GPUs -join ', ') } else { 'none' }), $sum.GpuCounterMode))
    $L.Add(('- User idle in {0} of {1} samples ({2} %; idle = no input for 300 s or session locked, {3} locked); active in {4}' -f $sum.IdleSamples, $sum.Samples, $sum.IdleSharePct, $sum.LockedSamples, $sum.ActiveSamples))
    $noPathText = ''
    if ($null -ne $sum.ProcessesWithoutPath -and [int]$sum.ProcessesWithoutPath -gt 0) {
        # In an elevated run the count holds kernel/protected processes (System, Registry, ...), not a rights problem.
        if ($null -ne $sum.IsElevated -and $sum.IsElevated) { $noPathText = (', {0} without a readable path (kernel/protected processes)' -f $sum.ProcessesWithoutPath) }
        else { $noPathText = (', {0} without readable path {1}' -f $sum.ProcessesWithoutPath, $script:WdAnAdminText) }
    }
    $L.Add(('- Processes: {0} at start, {1} distinct during the run{2}' -f $sum.ProcessesAtStart, $sum.ProcessKeys, $noPathText))
    if ($sum.StillRunning) { $L.Add('- Note: monitor.running exists - the session is still being recorded or was not stopped cleanly; the analysis covers the data written so far.') }
    $L.Add('')

    # Verdict
    $L.Add('## Verdict')
    $L.Add('')
    if ($null -eq $VD) { $L.Add('_verdict unavailable (scoring failed, see Collection errors)_') }
    elseif ($VD.Inconclusive) {
        $L.Add('**Inconclusive** (insufficient or unreadable process data; a clean verdict cannot be established).')
        $L.Add('')
        foreach ($r in $VD.Reasons) { $L.Add('- ' + $r) }
    }
    elseif ($VD.Clean) {
        $L.Add(('**Nothing suspicious found** (no process reached the Suspicious threshold of {0} points).' -f $script:WdAnSuspiciousThreshold))
        $L.Add('')
        foreach ($r in $VD.Reasons) { $L.Add('- ' + $r) }
    } else {
        $L.Add(('**{0} suspicious process(es)**; top {1}:' -f $VD.Suspects.Count, $VD.Top.Count))
        $L.Add('')
        $i = 0
        foreach ($t in $VD.Top) {
            $i++
            $L.Add(('{0}. **{1}** - score {2} ({3}){4}' -f $i, (Get-WdAnDisplayName -Subject $t), $t.Score, $t.Class, $(if ($t.HasStrongIndicator) { ', near-certain indicator fired' } else { '' })))
            $L.Add(('   - path: {0}' -f $(if ($t.Path -ne '') { $t.Path } else { Get-WdAnUnknownPathText -S $t })))
            foreach ($ind in $t.Indicators) { $L.Add(('   - {0} +{1}: {2}' -f $ind.Id, $ind.Points, $ind.Text)) }
        }
    }
    if ($null -ne $VD -and $VD.Warnings.Count -gt 0) {
        $L.Add('')
        $L.Add('System-level warnings:')
        $L.Add('')
        foreach ($w in $VD.Warnings) { $L.Add('- ' + $w) }
    }
    $L.Add('')

    # System timeline
    $L.Add('## System timeline')
    $L.Add('')
    if ($null -eq $SM -or $SM.Rows -eq 0 -or $null -eq $TL -or $TL.Groups.Count -eq 0) {
        $L.Add('_no samples_')
    } else {
        $modeText = @{ '1min' = '1 minute'; '10min' = '10 minutes'; 'hour' = '1 hour'; '3h' = '3 hours'; '6h' = '6 hours'; '12h' = '12 hours'; 'day' = '1 day' }[$TL.Mode]
        $L.Add(('One character per {0}, {1} buckets from {2} to {3}. Percent rows are scaled 0-100; rate rows are scaled to their own maximum; `' -f $modeText, $TL.Groups.Count, $TL.Labels[0], $TL.Labels[$TL.Labels.Count - 1]) + [string][char]0x00B7 + '` = no data.')
        $L.Add('')
        $rows = New-Object 'System.Collections.Generic.List[object]'
        $addRow = {
            param([string]$Metric, [double[]]$Series, [double]$Max, [string]$Avg, [string]$MaxText, [string]$MaxAt)
            $rows.Add([ordered]@{ Metric = $Metric; Timeline = (Get-WdAnSparkline -Values $Series -Max $Max); Avg = $Avg; Max = $MaxText; MaxAt = $MaxAt })
        }
        $cpuAvg = ''; if ($SM.CpuN -gt 0) { $cpuAvg = Format-WdAnNum -Value ($SM.CpuSum / $SM.CpuN) -Decimals 1 }
        & $addRow 'CPU %' $TL.Series.Cpu 100 $cpuAvg (Format-WdAnNum -Value $SM.CpuMax -Decimals 1) ('{0} (top: {1})' -f $SM.CpuMaxTs, $SM.CpuMaxTop)
        $gpuAvg = ''; if ($SM.GpuN -gt 0) { $gpuAvg = Format-WdAnNum -Value ($SM.GpuSum / $SM.GpuN) -Decimals 1 }
        & $addRow 'GPU % (busiest engine)' $TL.Series.Gpu 100 $gpuAvg (Format-WdAnNum -Value $SM.GpuMax -Decimals 1) $SM.GpuMaxTs
        $gcAvg = ''; if ($SM.GpuN -gt 0) { $gcAvg = Format-WdAnNum -Value ($SM.GpuCompSum / $SM.GpuN) -Decimals 1 }
        & $addRow 'GPU Compute engine %' $TL.Series.GpuCompute 100 $gcAvg (Format-WdAnNum -Value ([math]::Max(0.0, $SM.GpuCompMax)) -Decimals 1) ''
        $memAvg = ''; $memMax = ''
        if ($SM.MemN -gt 0 -and $SM.MemTotal -gt 0) { $memAvg = Format-WdAnNum -Value ($SM.MemSum / $SM.MemN / $SM.MemTotal * 100) -Decimals 1; $memMax = [string]::Format($inv, '{0:F1} ({1:F0} MB)', $SM.MemMax / $SM.MemTotal * 100, $SM.MemMax) }
        & $addRow 'Memory used %' $TL.Series.Mem 100 $memAvg $memMax $SM.MemMaxTs
        $dAvg = ''; if ($SM.DiskN -gt 0) { $dAvg = Format-WdAnNum -Value ($SM.DiskSum / $SM.DiskN) -Decimals 1 }
        & $addRow 'Disk active %' $TL.Series.Disk 100 $dAvg (Format-WdAnNum -Value $SM.DiskMax -Decimals 1) $SM.DiskMaxTs
        $dbAvg = ''; if ($SM.DiskN -gt 0) { $dbAvg = Format-Bytes -Bytes ($SM.DiskBpsSum / $SM.DiskN) }
        & $addRow 'Disk read+write /s' $TL.Series.DiskBps -1 $dbAvg (Format-Bytes -Bytes ([math]::Max(0.0, $SM.DiskBpsMax))) $SM.DiskBpsMaxTs
        $nAvg = ''; if ($SM.NetN -gt 0) { $nAvg = Format-Bytes -Bytes ($SM.NetSum / $SM.NetN) }
        & $addRow 'Network in+out /s' $TL.Series.Net -1 $nAvg (Format-Bytes -Bytes ([math]::Max(0.0, $SM.NetMax))) $SM.NetMaxTs
        $rows.Add([ordered]@{ Metric = 'User idle (_) / active (.)'; Timeline = $TL.IdleLine; Avg = ('{0} % idle' -f $sum.IdleSharePct); Max = ''; MaxAt = '' })
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Metric', 'Timeline', 'Avg', 'Max', 'MaxAt') -Headers @('Metric', 'Timeline', 'Avg', 'Max', 'Max at'))) { $L.Add($x) }
        $L.Add('')
        $facts = New-Object 'System.Collections.Generic.List[string]'
        if ($SM.CpuN -gt 0) { $facts.Add([string]::Format($inv, 'kernel time {0:F1} %, DPC/interrupts {1:F1} % of the CPU average', $SM.KernelSum / $SM.CpuN, $SM.DpcSum / $SM.CpuN)) }
        if ($SM.GapN -gt 0) { $facts.Add([string]::Format($inv, 'CPU not attributable to any process (kernel/idle accounting gap): {0:F1} points on average', $SM.GapSum / $SM.GapN)) }
        if ($SM.PerfN -gt 0) { $facts.Add([string]::Format($inv, 'processor performance {0:F0} % of nominal on average (>100 = turbo); throttled while busy in {1} sample(s)', $SM.PerfSum / $SM.PerfN, $SM.PerfLowN)) }
        if ($SM.PagesN -gt 0) { $facts.Add([string]::Format($inv, 'hard page faults {0:F0}/s on average; commit charge peak {1:F0} %', $SM.PagesSum / $SM.PagesN, [math]::Max(0.0, $SM.CommitMax))) }
        if ($SM.PoolFirst -gt 0 -and $SM.PoolLast -gt 0) { $facts.Add(('non-paged pool {0} -> {1}' -f (Format-Bytes -Bytes $SM.PoolFirst), (Format-Bytes -Bytes $SM.PoolLast))) }
        if ($SM.TempN -gt 0) { $facts.Add([string]::Format($inv, 'hottest thermal zone {0:F1} C; throttle reasons set in {1} sample(s)', $SM.TempMax, $SM.ThrottleN)) }
        if ($SM.BatteryN -gt 0) { $facts.Add([string]::Format($inv, 'battery present, lowest charge {0:F0} %, on battery in {1} sample(s)', $SM.BatteryMin, $SM.OnBatteryN)) }
        if ($SM.ProcCountMax -ge 0) { $facts.Add(('process count {0}-{1}' -f $SM.ProcCountMin, $SM.ProcCountMax)) }
        if ($SM.TopCpu.Count -gt 0) {
            $tops = @($SM.TopCpu.GetEnumerator() | Sort-Object -Property @{ Expression = { $_.Value }; Descending = $true } | Select-Object -First 3)
            $tt = @(); foreach ($t in $tops) { $tt += ('{0} ({1}x)' -f $t.Key, $t.Value) }
            $facts.Add('most often the top CPU process: ' + ($tt -join ', '))
        }
        foreach ($f in $facts) { $L.Add('- ' + $f) }
        $L.Add('')
    }

    # Top consumers
    $L.Add('## Top consumers')
    $L.Add('')
    $L.Add('Aggregated per executable path across restarts (instance count in brackets). Averages are over all samples the process existed in; `Idle / Active` are average CPU % while the user was idle / active. The monitor itself (powershell.exe tagged Self) is excluded.')
    $L.Add('')
    $L.Add('### By CPU time')
    $L.Add('')
    $byCpu = @($subjects | Where-Object { $_.CpuSeconds -gt 0 } | Sort-Object -Property @{ Expression = { $_.CpuSeconds }; Descending = $true } | Select-Object -First $topRows)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $byCpu) {
        $r = Get-WdAnSubjectRow -S $s -Ctx $Ctx
        if ($null -ne $TL -and $TL.Groups.Count -gt 0) {
            $ser = Get-WdAnSubjectSeries -Subject $s -Timeline $TL
            $mx = 0.0; foreach ($v in $ser) { if ($v -gt $mx) { $mx = $v } }
            $r.Timeline = (Get-WdAnSparkline -Values $ser -Max $mx) + [string]::Format($inv, ' max {0:F1}', $mx)
        }
        $rows.Add($r)
    }
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Process', 'Location', 'CpuSeconds', 'AvgPct', 'MaxPct', 'Presence', 'IdleActive', 'Window', 'Timeline') -Headers @('Process', 'Location', 'CPU s', 'Avg %', 'Max %', 'Present', 'Idle / Active %', 'Window', 'Timeline (avg % per bucket)'))) { $L.Add($x) }
    $L.Add('')
    $L.Add('### By GPU time')
    $L.Add('')
    $byGpu = @($subjects | Where-Object { $_.GpuSeconds -gt 0 } | Sort-Object -Property @{ Expression = { $_.GpuSeconds }; Descending = $true } | Select-Object -First $topRows)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $byGpu) {
        $ia = ''
        if ($null -ne $s.GpuIdleAvg -and $null -ne $s.GpuActiveAvg) { $ia = [string]::Format($inv, '{0:F1} / {1:F1}', $s.GpuIdleAvg, $s.GpuActiveAvg) }
        elseif ($null -ne $s.GpuIdleAvg) { $ia = [string]::Format($inv, '{0:F1} / -', $s.GpuIdleAvg) }
        elseif ($null -ne $s.GpuActiveAvg) { $ia = [string]::Format($inv, '- / {0:F1}', $s.GpuActiveAvg) }
        $rows.Add([ordered]@{
            Process = (Get-WdAnDisplayName -Subject $s); GpuSeconds = (Format-WdAnNum -Value $s.GpuSeconds -Decimals 1); Compute = (Format-WdAnNum -Value $s.GpuComputeSeconds -Decimals 1)
            ThreeD = (Format-WdAnNum -Value $s.Gpu3DSeconds -Decimals 1); Video = (Format-WdAnNum -Value $s.GpuVideoSeconds -Decimals 1); MaxPct = (Format-WdAnNum -Value $s.GpuMax -Decimals 1)
            IdleActive = $ia; Window = $(if ($s.HasWindowEver) { 'yes' } else { 'no' })
        })
    }
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Process', 'GpuSeconds', 'Compute', 'ThreeD', 'Video', 'MaxPct', 'IdleActive', 'Window') -Headers @('Process', 'GPU s', 'Compute s', '3D s', 'Video s', 'Max %', 'Idle / Active %', 'Window'))) { $L.Add($x) }
    $L.Add('')
    $L.Add('GPU seconds = engine-% / 100 x interval, summed. Compute/CUDA engine use by a windowless process is the miner signal; 3D and Video use by browsers, games and the desktop is normal.')
    $L.Add('')
    $L.Add('### By memory (working set)')
    $L.Add('')
    $byMem = @($subjects | Where-Object { $_.WSMax -gt 0 } | Sort-Object -Property @{ Expression = { $_.WSMax }; Descending = $true } | Select-Object -First $topRows)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $byMem) {
        $growth = ''
        if ($s.WSFirst -gt 0 -and $s.WSLast -gt 0) { $growth = Format-Bytes -Bytes ($s.WSLast - $s.WSFirst); if ($s.WSLast -lt $s.WSFirst) { $growth = '-' + (Format-Bytes -Bytes ($s.WSFirst - $s.WSLast)) } }
        $rows.Add([ordered]@{ Process = (Get-WdAnDisplayName -Subject $s); Peak = (Format-Bytes -Bytes $s.WSMax); First = (Format-Bytes -Bytes $s.WSFirst); Last = (Format-Bytes -Bytes $s.WSLast); Growth = $growth; Instances = $s.Instances.Count })
    }
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Process', 'Peak', 'First', 'Last', 'Growth', 'Instances') -Headers @('Process', 'Peak WS', 'First WS', 'Last WS', 'Growth', 'Instances'))) { $L.Add($x) }
    $L.Add('')
    $L.Add('Peak, First, Last and Growth describe the same instance (the one with the peak working set), so Growth is a per-process trend even for programs with many helper processes.')
    $L.Add('')
    $L.Add('### By IO')
    $L.Add('')
    $byIo = @($subjects | Where-Object { ($_.ReadBytes + $_.WriteBytes) -gt 0 } | Sort-Object -Property @{ Expression = { $_.ReadBytes + $_.WriteBytes }; Descending = $true } | Select-Object -First $topRows)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $byIo) { $rows.Add([ordered]@{ Process = (Get-WdAnDisplayName -Subject $s); Read = (Format-Bytes -Bytes $s.ReadBytes); Write = (Format-Bytes -Bytes $s.WriteBytes); Total = (Format-Bytes -Bytes ($s.ReadBytes + $s.WriteBytes)) }) }
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Process', 'Read', 'Write', 'Total'))) { $L.Add($x) }
    $L.Add('')
    $L.Add('IO bytes include all I/O of the process (files, network, pipes).')
    $L.Add('')

    # Idle vs active
    $L.Add('## Idle vs active')
    $L.Add('')
    if ($null -eq $SM -or $SM.IdleN -lt $script:WdAnIdleMinSamples -or $SM.ActiveN -lt $script:WdAnIdleMinSamples) {
        $L.Add(('_insufficient data_: the comparison needs at least {0} samples in both states; this run has {1} idle and {2} active samples. A process that works mainly while nobody uses the PC is the strongest miner signal, so record a longer session covering work and idle time.' -f $script:WdAnIdleMinSamples, $(if ($null -ne $SM) { $SM.IdleN } else { 0 }), $(if ($null -ne $SM) { $SM.ActiveN } else { 0 })))
        $L.Add('')
        $idleOnly = @($subjects | Where-Object { $null -ne $_.CpuIdleAvg -and [int]$_.EffSamplesIdle -ge $script:WdAnIdleMinSamples -and $_.CpuIdleAvg -ge 1 } | Sort-Object -Property @{ Expression = { $_.CpuIdleAvg }; Descending = $true } | Select-Object -First $topRows)
        if ($idleOnly.Count -gt 0) {
            $L.Add('Processes with the highest CPU while the user was idle (no active baseline available):')
            $L.Add('')
            $rows = New-Object 'System.Collections.Generic.List[object]'
            foreach ($s in $idleOnly) { $rows.Add([ordered]@{ Process = (Get-WdAnDisplayName -Subject $s); IdleAvg = (Format-WdAnNum -Value $s.CpuIdleAvg -Decimals 2); IdleSamples = $s.EffSamplesIdle; Window = $(if ($s.HasWindowEver) { 'yes' } else { 'no' }); Location = $s.LocationClass }) }
            foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Process', 'IdleAvg', 'IdleSamples', 'Window', 'Location') -Headers @('Process', 'CPU % while idle', 'Idle samples', 'Window', 'Location'))) { $L.Add($x) }
            $L.Add('')
        }
    } else {
        $both = @($subjects | Where-Object { [int]$_.EffSamplesIdle -ge $script:WdAnIdleMinSamples -and [int]$_.EffSamplesActive -ge $script:WdAnIdleMinSamples -and $null -ne $_.CpuIdleAvg -and $null -ne $_.CpuActiveAvg -and ($_.CpuIdleAvg -ge 1 -or $_.CpuActiveAvg -ge 1 -or ($null -ne $_.GpuIdleAvg -and $_.GpuIdleAvg -ge 1) -or ($null -ne $_.GpuActiveAvg -and $_.GpuActiveAvg -ge 1)) })
        $both = @($both | Sort-Object -Property @{ Expression = { $_.CpuIdleAvg / [math]::Max(0.5, $_.CpuActiveAvg) }; Descending = $true } | Select-Object -First $topRows)
        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($s in $both) {
            $ratio = $s.CpuIdleAvg / [math]::Max(0.5, $s.CpuActiveAvg)
            $note = ''
            if ($ratio -ge 2 -and $s.CpuIdleAvg -ge 5) { $note = 'works mainly while idle' }
            if ($s.IsKnownHeavy) { if ($note -ne '') { $note += '; ' }; $note += 'on the known heavy/legitimate list' }
            $rows.Add([ordered]@{
                Process = (Get-WdAnDisplayName -Subject $s); IdleAvg = (Format-WdAnNum -Value $s.CpuIdleAvg -Decimals 2); ActiveAvg = (Format-WdAnNum -Value $s.CpuActiveAvg -Decimals 2); Ratio = (Format-WdAnNum -Value $ratio -Decimals 1)
                GpuIdle = (Format-WdAnNum -Value $s.GpuIdleAvg -Decimals 1); GpuActive = (Format-WdAnNum -Value $s.GpuActiveAvg -Decimals 1); Window = $(if ($s.HasWindowEver) { 'yes' } else { 'no' }); Note = $note
            })
        }
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Process', 'IdleAvg', 'ActiveAvg', 'Ratio', 'GpuIdle', 'GpuActive', 'Window', 'Note') -Headers @('Process', 'CPU % idle', 'CPU % active', 'Ratio', 'GPU % idle', 'GPU % active', 'Window', 'Note'))) { $L.Add($x) }
        $L.Add('')
        $L.Add('Ratio = idle average / max(0.5, active average). A ratio of 2 or more with at least 5 % idle CPU scores indicator I1. Legitimate idle-time workers (Defender scans, Search indexer, Windows Update, OneDrive, photo indexing) also appear here; they are damped when signed.')
        $L.Add('')
    }
    return $L.ToArray()
}


function Get-WdAnReportLines2 {
    # Second half of report.md: suspects, network, restarts, events, recommendations, appendix.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Ctx)
    $inv = Get-WdInv
    $L = New-Object 'System.Collections.Generic.List[string]'
    $sum = $Ctx.Summary
    $SM = $Ctx.Samples
    $subjects = @($Ctx.Subjects)
    $topRows = [math]::Min(20, [math]::Max(5, $Ctx.TopN))

    # Suspicious processes
    $L.Add('## Suspicious processes')
    $L.Add('')
    $L.Add(('Score = sum of indicator points after damping (see `docs\analyze-scoring.md`). {0}+ = Suspicious, {1}+ = Highly suspicious. `?` = could not be evaluated because the path is unknown {2}.' -f $script:WdAnSuspiciousThreshold, $script:WdAnHighThreshold, $script:WdAnAdminText))
    $L.Add('')
    $scored = @($subjects | Where-Object { $_.Score -ge $script:WdAnSuspiciousThreshold } | Sort-Object -Property @{ Expression = { $_.Score }; Descending = $true }, @{ Expression = { $_.CpuSeconds }; Descending = $true } | Select-Object -First $topRows)
    $belowNote = $false
    if ($scored.Count -eq 0) {
        $scored = @($subjects | Where-Object { $_.Score -gt 0 } | Sort-Object -Property @{ Expression = { $_.Score }; Descending = $true }, @{ Expression = { $_.CpuSeconds }; Descending = $true } | Select-Object -First 5)
        $belowNote = $true
        if ($scored.Count -gt 0) { $L.Add('No process reached the threshold. The highest scores (all **below** the Suspicious threshold) are listed for transparency:'); $L.Add('') }
    }
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $scored) {
        $reasons = New-Object 'System.Collections.Generic.List[string]'
        foreach ($i in $s.Indicators) { $reasons.Add(('{0} +{1} {2}' -f $i.Id, $i.Points, $i.Text)) }
        foreach ($d in $s.Damping) { $reasons.Add('damping: ' + $d) }
        if ($s.NeedsAdmin) { $reasons.Add('path/signature/command line: ? ' + $script:WdAnAdminText) }
        $sig = $s.SigStatus
        if ($s.Signer -ne '') {
            # X.500 subjects quote values that contain a comma: CN="Zoom Communications, Inc.", O=...
            $m = [regex]::Match($s.Signer, '(?i)(?:^|,\s*)(?:CN|O)=(?:"([^"]*)"|((?:[^,\\]|\\.)+))')
            if ($m.Success) {
                $v = ''
                if ($m.Groups[1].Success) { $v = $m.Groups[1].Value } else { $v = $m.Groups[2].Value -replace '\\(.)', '$1' }
                $v = $v.Trim().Trim('"')
                if ($v -ne '') { $sig += ' (' + $v + ')' }
            }
        }
        if ($sig -eq '' -and $s.NeedsAdmin) { $sig = '? ' + $script:WdAnAdminText }
        $sha = ''
        if ($s.Sha256 -match '^[0-9a-fA-F]{64}$') { $sha = $s.Sha256.Substring(0, 16) + '... ' + (Get-WdAnVtLink -Sha256 $s.Sha256) } elseif ($s.Sha256 -ne '') { $sha = $s.Sha256 }
        $rows.Add([ordered]@{
            Score = ('{0} ({1})' -f $s.Score, $s.Class); Process = (Get-WdAnDisplayName -Subject $s); Reasons = ($reasons -join '; ')
            Path = $(if ($s.Path -ne '') { Format-WdAnPath -Path $s.Path -Max 120 } else { Get-WdAnUnknownPathText -S $s }); Signer = $sig; Sha = $sha
            FirstSeen = $s.FirstSeen; LastSeen = $s.LastSeen
        })
    }
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Score', 'Process', 'Reasons', 'Path', 'Signer', 'Sha', 'FirstSeen', 'LastSeen') -Headers @('Score', 'Process', 'Reasons', 'Path', 'Signature', 'SHA256 / VirusTotal', 'First seen', 'Last seen'))) { $L.Add($x) }
    $L.Add('')
    if ($scored.Count -gt 0) {
        $L.Add('Details of the listed processes:')
        $L.Add('')
        foreach ($s in $scored) {
            $L.Add(('- **{0}** (score {1}, raw {2}; {3} instance(s), PID(s) {4}){5}' -f (Get-WdAnDisplayName -Subject $s), $s.Score, $s.RawScore, $s.Instances.Count, (@($s.Pids | Select-Object -First 6) -join ', '), $(if ($belowNote) { ' - below threshold' } else { '' })))
            if ($s.CommandLine -ne '') {
                # Flatten first, cut the flattened string (cutting by the ORIGINAL length threw after CR/LF removal).
                # Secrets are masked for the report only; scoring used the original text.
                $cl = (((Hide-WdSecret -Text $s.CommandLine) -replace '`', "'") -replace '\r\n|\r|\n', ' ')
                if ($cl.Length -gt 300) { $cl = $cl.Substring(0, 300) + '...' }
                $L.Add(('  - command line: `{0}`' -f $cl))
            }
            $L.Add(('  - parent: {0}; owner: {1}; session {2}; started {3}; location {4}' -f $(if ($s.ParentName -ne '') { $s.ParentName } else { '?' }), $(if ($s.Owner -ne '') { $s.Owner } else { '?' }), $(if ($null -ne $s.SessionId) { $s.SessionId } else { '?' }), $s.Started, $s.LocationClass))
            $L.Add(('  - CPU {0} s (avg {1} %, max {2} %), GPU {3} s (compute {4} s), peak working set {5}, {6} remote address(es), {7} pool-port hit(s)' -f (Format-WdAnNum -Value $s.CpuSeconds -Decimals 1), (Format-WdAnNum -Value $s.CpuAvg -Decimals 2), (Format-WdAnNum -Value $s.CpuMax -Decimals 1), (Format-WdAnNum -Value $s.GpuSeconds -Decimals 1), (Format-WdAnNum -Value $s.GpuComputeSeconds -Decimals 1), (Format-Bytes -Bytes $s.WSMax), $s.RemoteIps.Count, $s.PoolPorts.Count))
            if ($s.Sha256 -match '^[0-9a-fA-F]{64}$') { $L.Add(('  - SHA256 `{0}` - {1} (manual lookup only; nothing was uploaded)' -f $s.Sha256, (Get-WdAnVtLink -Sha256 $s.Sha256))) }
            foreach ($n in $s.Notes) { $L.Add('  - note: ' + $n) }
            foreach ($t in @($s.EventTexts | Select-Object -First 3)) { $L.Add('  - event: ' + (Hide-WdSecret -Text $t)) }
        }
        $L.Add('')
    }
    $needsElevated = @($subjects | Where-Object { $_.NeedsElevatedCheck } | Sort-Object -Property @{ Expression = { $_.CpuSeconds }; Descending = $true } | Select-Object -First 10)
    if ($needsElevated.Count -gt 0) {
        $L.Add(('Re-run the monitor elevated to inspect these processes: their resource use triggered indicators but path, command line and signature were not readable {0}:' -f $script:WdAnAdminText))
        $L.Add('')
        foreach ($s in $needsElevated) { $L.Add(('- {0} (PID {1}): {2}' -f (Get-WdAnDisplayName -Subject $s), (@($s.Pids | Select-Object -First 4) -join ', '), $s.Reasons)) }
        $L.Add('')
    }
    $damped = @($subjects | Where-Object { $_.Notes.Count -gt 0 -and -not $_.IsTool } | Select-Object -First 8)
    if ($damped.Count -gt 0) {
        $L.Add('Rule hits that were treated as known false positives:')
        $L.Add('')
        foreach ($s in $damped) { foreach ($n in $s.Notes) { $L.Add(('- {0}: {1}' -f (Get-WdAnDisplayName -Subject $s), $n)) } }
        $L.Add('')
    }

    # Network
    $L.Add('## Network endpoints of interest')
    $L.Add('')
    $net = $Ctx.Net
    if ($null -eq $net -or $net.Rows -eq 0) {
        $L.Add('_no net.csv data_')
    } else {
        $L.Add(('{0} established connection(s) to {1} distinct public address(es) and {2} listening port entries were recorded (first sight per process and endpoint). DNS names come from the local DNS cache and cannot be attributed to a process.' -f $net.Established, $net.PublicIps.Count, $net.Listen))
        $L.Add('')
        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($s in @($subjects | Sort-Object -Property @{ Expression = { $_.Score }; Descending = $true })) {
            if ($s.Endpoints.Count -eq 0) { continue }
            $interesting = ($s.PoolPorts.Count -gt 0 -or $s.Score -ge $script:WdAnSuspiciousThreshold -or ($s.RawNoDns -gt 0 -and -not $s.IsKnownHeavy -and -not $s.IsTrustedSigner -and $s.PathKnown) -or $s.RemoteIps.Count -ge 30)
            if (-not $interesting) { continue }
            $seen = New-Object 'System.Collections.Generic.HashSet[string]'
            foreach ($ep in @($s.Endpoints | Where-Object { -not $_.Private } | Sort-Object -Property @{ Expression = { $_.Pool }; Descending = $true }, @{ Expression = { $_.Ts } })) {
                if (-not $seen.Add($ep.Remote + ':' + $ep.Port)) { continue }
                if ($seen.Count -gt 6) { break }
                $why = @()
                if ($ep.Pool) { $why += 'pool port' }
                if ($ep.Dns -eq '') { $why += 'no DNS name' }
                if ($ep.Idle) { $why += 'while idle' }
                if ($s.RemoteIps.Count -ge 30) { $why += ('{0} addresses' -f $s.RemoteIps.Count) }
                $rows.Add([ordered]@{ Process = (Get-WdAnDisplayName -Subject $s); Remote = $ep.Remote; Port = $ep.Port; Dns = $ep.Dns; Why = ($why -join ', '); FirstSeen = $ep.Ts })
            }
            if ($rows.Count -ge 60) { break }
        }
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Process', 'Remote', 'Port', 'Dns', 'Why', 'FirstSeen') -Headers @('Process', 'Remote address', 'Port', 'DNS name (cache)', 'Why listed', 'First seen'))) { $L.Add($x) }
        $L.Add('')
        $L.Add('Listed: connections to mining-pool ports, raw public IPs without a cached DNS name for unsigned/unknown programs, processes with 30+ remote addresses, and all public endpoints of scored processes. Browsers, updaters and cloud clients normally talk to many raw IPs (CDNs) and are not listed.')
        $L.Add('')
    }

    # New / short-lived / restarts
    $L.Add('## New, short-lived and restarted processes')
    $L.Add('')
    $entries = @()
    if ($null -ne $Ctx.Entries) { $entries = @($Ctx.Entries.Values | Where-Object { -not $_.IsSelf }) }
    $newE = @($entries | Where-Object { -not $_.PresentAtStart })
    $exitedE = @($entries | Where-Object { $_.Exited })
    $shortE = @($newE | Where-Object { $_.Exited -and $_.FirstSeen -ne '' -and $_.ExitTime -ne '' } | Where-Object { $a = Get-WdAnDateTime -Text $_.FirstSeen; $b = Get-WdAnDateTime -Text $_.ExitTime; ($null -ne $a -and $null -ne $b -and ($b - $a).TotalSeconds -lt 60) })
    $L.Add(('{0} process(es) started during the run, {1} exited, {2} lived less than 60 s (the monitor sees a process only if it survives one sampling interval; short-lived helpers are under-reported unless -TrackShortLived was used).' -f $newE.Count, $exitedE.Count, $shortE.Count))
    $L.Add('')
    $restarts = @($subjects | Where-Object { $_.Starts -ge 2 } | Sort-Object -Property @{ Expression = { $_.QuickRestarts }; Descending = $true }, @{ Expression = { $_.Starts }; Descending = $true } | Select-Object -First $topRows)
    if ($restarts.Count -gt 0) {
        $L.Add('Executables started more than once:')
        $L.Add('')
        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($s in $restarts) {
            $rows.Add([ordered]@{ Process = (Get-WdAnDisplayName -Subject $s); Starts = $s.Starts; Exits = $s.Exits; Quick = $s.QuickRestarts; Concurrent = $s.MaxConcurrent; Location = $s.LocationClass; Signature = $s.SigStatus; Parent = $s.ParentName })
        }
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Process', 'Starts', 'Exits', 'Quick', 'Concurrent', 'Location', 'Signature', 'Parent') -Headers @('Process', 'Starts', 'Exits', 'Restart < 5 min after exit', 'Max concurrent', 'Location', 'Signature', 'Parent'))) { $L.Add($x) }
        $L.Add('')
        $L.Add('Many short starts of the same tool (git, conhost, cmd, compilers) are normal in a developer session; a watchdog pattern is one instance at a time that is restarted shortly after it exits.')
        $L.Add('')
    }
    $newSusp = @($newE | Where-Object { ($script:WdAnSuspiciousLocations -contains $_.LocationClass) } | Select-Object -First 15)
    if ($newSusp.Count -gt 0) {
        $L.Add('New processes from user-writable locations:')
        $L.Add('')
        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($e in $newSusp) {
            $sig = ''
            if ($null -ne $e.Meta) { $sig = [string]$e.Meta['SigStatus'] }
            $rows.Add([ordered]@{ Process = $e.Name; Path = (Format-WdAnPath -Path $e.Path -Max 100); Location = $e.LocationClass; Parent = $e.ParentName; Started = $e.Started; Signature = $sig })
        }
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows.ToArray() -Columns @('Process', 'Path', 'Location', 'Parent', 'Started', 'Signature'))) { $L.Add($x) }
        $L.Add('')
    }
    $wmi = 0
    if ($null -ne $Ctx.Events) { $wmi = [int]$Ctx.Events.ByType['WmiProcessStart'] }
    if ($wmi -gt 0) { $L.Add(('{0} process start(s) were captured by the WMI creation-event subscription (-TrackShortLived); see events.csv type WmiProcessStart.' -f $wmi)); $L.Add('') }

    # Events
    $L.Add('## Events')
    $L.Add('')
    $ev = $Ctx.Events
    if ($null -eq $ev -or $ev.All.Count -eq 0) {
        $L.Add('_no events.csv data_')
    } else {
        $logRows = @($ev.EventLog)
        $defRows = @($logRows | Where-Object { [string]$_['Source'] -match 'Defender' })
        $sysRows = @($logRows | Where-Object { [string]$_['Source'] -eq 'System' })
        $appRows = @($logRows | Where-Object { [string]$_['Source'] -eq 'Application' })
        $taskRows = @($logRows | Where-Object { [string]$_['Source'] -match 'TaskScheduler' })
        $psRows = @($logRows | Where-Object { [string]$_['Source'] -match 'PowerShell' })
        $wmiRows = @($logRows | Where-Object { [string]$_['Source'] -match 'WMI' })
        $idleTrans = [int]$ev.ByType['IdleStart'] + [int]$ev.ByType['IdleEnd']
        $L.Add(('Event-log hits during the run: Defender {0}, System {1}, Application {2}, Task Scheduler {3}, PowerShell script blocks {4}, WMI activity {5}; {6} idle/active transition(s).' -f $defRows.Count, $sysRows.Count, $appRows.Count, $taskRows.Count, $psRows.Count, $wmiRows.Count, $idleTrans))
        $L.Add('')
        $mkRows = {
            param([object[]]$Rows, [int]$Max)
            $out = New-Object 'System.Collections.Generic.List[object]'
            foreach ($r in @($Rows | Sort-Object -Property @{ Expression = { [string]$_['EventTime'] } } | Select-Object -First $Max)) {
                $d = Hide-WdSecret -Text ([string]$r['Detail'])   # masked for the report only; attribution used the original
                if ($d.Length -gt 180) { $d = $d.Substring(0, 179) + [string][char]0x2026 }
                $row = [ordered]@{ Time = [string]$r['EventTime']; Log = ([string]$r['Source'] -replace '^Microsoft-Windows-', ''); Id = [string]$r['EventId']; Detail = $d }
                if ($r.ContainsKey('WdAnEvidence')) { $row['Evidence'] = [string]$r['WdAnEvidence'] }
                $out.Add($row)
            }
            return $out.ToArray()
        }
        if ($defRows.Count -gt 0) {
            $L.Add('### Microsoft Defender')
            $L.Add('')
            $L.Add('1006/1116 = malware detected, 1007/1117 = action taken, 1015/1118/1119 = suspicious behaviour / action failed, 5001 = real-time protection disabled, 5007 = configuration change (exclusions!).')
            $L.Add('')
            foreach ($x in @(ConvertTo-MarkdownTable -InputObject @(& $mkRows $defRows 30) -Columns @('Time', 'Log', 'Id', 'Detail'))) { $L.Add($x) }
            $L.Add('')
        }
        $persist = @($sysRows | Where-Object { [string]$_['EventId'] -eq '7045' -or [string]$_['EventId'] -eq '7040' }) + @($taskRows) + @($wmiRows)
        if ($persist.Count -gt 0) {
            $L.Add('### Services, scheduled tasks and WMI (persistence)')
            $L.Add('')
            $L.Add('7045 = new service installed, 7040 = service start type changed, TaskScheduler 106 = task registered, 100/129/200 = task or action started, 140/141 = task updated/deleted, WMI 5861 = permanent event consumer registered.')
            $L.Add('')
            foreach ($x in @(ConvertTo-MarkdownTable -InputObject @(& $mkRows $persist 40) -Columns @('Time', 'Log', 'Id', 'Detail'))) { $L.Add($x) }
            $L.Add('')
        }
        $crash = @($appRows) + @($sysRows | Where-Object { [string]$_['EventId'] -match '^(41|1074|6008)$' })
        if ($crash.Count -gt 0) {
            $L.Add('### Crashes, hangs and shutdowns')
            $L.Add('')
            $L.Add('Application 1000 = crash, 1001 = Windows Error Reporting, 1002 = hang; System 41 = unexpected reboot, 6008 = unexpected shutdown, 1074 = shutdown/restart requested.')
            $L.Add('')
            foreach ($x in @(ConvertTo-MarkdownTable -InputObject @(& $mkRows $crash 30) -Columns @('Time', 'Log', 'Id', 'Detail'))) { $L.Add($x) }
            $L.Add('')
        }
        if ($psRows.Count -gt 0) {
            $L.Add(('### PowerShell script blocks (4104): {0}' -f $psRows.Count))
            $L.Add('')
            $L.Add('The first 300 characters of each script block are in events.csv. Encoded commands (`-EncodedCommand`, `FromBase64String`) and download cradles are the patterns to look for; IDE/agent tooling also produces many of these. Only script blocks of other PowerShell processes are recorded (the monitor filters its own).')
            $L.Add('')
            # Shared STRONG regex (red flag) or a window-hiding option (WEAK, informational). The old inline pattern
            # matched the bare word "hidden" and listed every CDXML module block (-IncludeHidden parameter).
            $susp = New-Object 'System.Collections.Generic.List[object]'
            foreach ($r in $psRows) {
                $evidence = Get-WdAnScriptBlockEvidence -Text ([string]$r['Detail'])
                if ($evidence -eq '') { continue }
                $copy = @{}
                foreach ($k in $r.Keys) { $copy[$k] = $r[$k] }
                $copy['WdAnEvidence'] = $(if ($evidence -eq 'Strong') { 'red flag' } else { 'weak (window hiding; max {0} points)' -f $script:WdAnWeakScriptHostPoints })
                $susp.Add($copy)
            }
            $suspStrong = @($susp | Where-Object { [string]$_['WdAnEvidence'] -eq 'red flag' } | Select-Object -First 10)
            $weakSlots = 10 - $suspStrong.Count
            $suspWeak = @()
            if ($weakSlots -gt 0) { $suspWeak = @($susp | Where-Object { [string]$_['WdAnEvidence'] -ne 'red flag' } | Select-Object -First $weakSlots) }
            $suspAll = @($suspStrong) + @($suspWeak)
            if ($suspAll.Count -gt 0) {
                $L.Add(('Script blocks with red-flag patterns ({0} strong, {1} weak of {2} listed; weak = window-hiding option only, informational):' -f $suspStrong.Count, $suspWeak.Count, $suspAll.Count))
                $L.Add('')
                foreach ($x in @(ConvertTo-MarkdownTable -InputObject @(& $mkRows $suspAll 10) -Columns @('Time', 'Log', 'Id', 'Evidence', 'Detail'))) { $L.Add($x) }
                $L.Add('')
            }
        }
        if ($defRows.Count -eq 0 -and $persist.Count -eq 0 -and $crash.Count -eq 0 -and $psRows.Count -eq 0) { $L.Add('No Defender, service, task, WMI or crash events were recorded during the run.'); $L.Add('') }
        if ($null -eq $sum.IsElevated -or -not $sum.IsElevated) { $L.Add(('The Security log (process creation 4688, task creation 4698) was not read by the monitor {0}.' -f $script:WdAnAdminText)); $L.Add('') }
    }

    # Recommendations
    $L.Add('## Recommendations')
    $L.Add('')
    $i = 0
    foreach ($r in @($Ctx.Recommendations)) { $i++; $L.Add(('{0}. {1}' -f $i, $r)) }
    if ($i -eq 0) { $L.Add('_none_') }
    $L.Add('')

    # Appendix
    $L.Add('## Appendix')
    $L.Add('')
    $L.Add('### Methodology')
    $L.Add('')
    $L.Add('- Per-process totals come from `procsum.json` (every sample, unaffected by the row filter); time-resolved views, flat-core detection and processes missing from procsum come from `procs_*.csv`, streamed line by line and joined to `samples_*.csv` by timestamp.')
    $L.Add('- Processes are aggregated per executable path across restarts (fallback: name; system-named processes without a readable path stay separate). Metadata (path, signature, SHA256, parent, owner) comes from `procmeta.csv`; connections from `net.csv` (first sight per endpoint), DNS names from `dns.csv`, events from `events.csv`.')
    $L.Add(('- Scoring: 22 indicators with capped points (`docs\analyze-scoring.md`): resource behaviour (CPU/GPU while idle, windowless load, flat core count, low priority), file facts (location, signature, name masquerade/look-alike/random, renamed binary, missing version info), command line (miner tokens, script-host red flags), parent chain, network (pool ports, raw IPs, idle connections, endpoint count), restarts and events. Thresholds: {0} Suspicious, {1} Highly suspicious. Miner tokens and Defender detections are near-certain and never damped.' -f $script:WdAnSuspiciousThreshold, $script:WdAnHighThreshold))
    $L.Add('- Damping: valid signature of a well-known vendor in System32/Windows/Program Files = -6; the same signature in AppData/ProgramData (updaters started by the Task Scheduler) = -4; known heavy/legitimate background process (Defender, Search, Update, OneDrive, browsers, WSL, GPU vendor services) = -4 on resource indicators. User-writable Windows folders (C:\Windows\Tasks, \Tracing, \System32\Tasks, ...) are never a trusted location. The raw score is kept in suspects.csv.')
    $L.Add('- Idle = no keyboard/mouse input for 300 s or a locked session, as recorded by the monitor; idle-vs-active comparisons need 20 samples in each state.')
    $L.Add('- VirusTotal links are built from the SHA256 recorded by the monitor; nothing is uploaded or queried by the tool.')
    $L.Add('')
    $L.Add('### False-positive notes')
    $L.Add('')
    $L.Add('- Browsers, Electron apps (VS Code, Discord, Telegram, Spotify, Yandex Browser) and games use the 3D/Video GPU engines and shared GPU memory, even minimised; their crashpad/utility children carry `--url=https://...`, which does not match the miner rule (only `--url=stratum...` does); the weak tokens `pool`, `--algo` and `-o host:port` are ignored for `--type=` child processes.')
    $L.Add('- Legitimate idle-time workers: MsMpEng (Defender scans), SearchIndexer/SearchProtocolHost, TiWorker/TrustedInstaller/MoUsoCoreWorker/UsoClient (Windows Update), CompatTelRunner, OneDrive, Microsoft.Photos (ML tagging uses GPU compute), backgroundTaskHost, RuntimeBroker, dwm (GPU 3D always), vmmemWSL/vmmem (WSL/Hyper-V), GPU vendor containers, Adobe/Google/Edge updaters, Steam/Epic helpers, Ollama/LM Studio/python with torch (user-installed compute!), ffmpeg/HandBrake/OBS encoders.')
    $L.Add('- Launch options such as `-ExecutionPolicy Bypass`, `-NoProfile`, `-WindowStyle Hidden` or `-NonInteractive` (IDE and agent shells, scheduled scripts, installers, win-debug itself) are informational only and score at most 2 points; the 6-point red flag needs payload delivery (`-EncodedCommand`, `DownloadString`, `IEX`, `FromBase64String`, URLs, `certutil -decode`, ...).')
    $L.Add('- Unsigned but legitimate: indie games, Python/Node tooling, portable apps, self-built tools. A svchost with high idle CPU is usually the Update/Search/BITS/Delivery Optimization host; its `-k <group>` is printed when the command line is known.')
    $L.Add('- Antimalware/backup software reads all files at idle (high IO, high idle CPU). Thermal throttling makes everything slow without any rogue process and is reported separately above. "No window" also applies to tray-only and minimised-to-tray programs.')
    $L.Add('')
    $L.Add('### Data gaps')
    $L.Add('')
    $st = $Ctx.Stats
    if ($null -eq $sum.IsElevated -or -not $sum.IsElevated) {
        $cnt = 'the'
        if ($null -ne $sum.ProcessesWithoutPath -and [int]$sum.ProcessesWithoutPath -gt 0) { $cnt = [string]$sum.ProcessesWithoutPath }
        $L.Add(('- The monitor ran without administrator rights: executable path, command line, owner, signature and SHA256 are unknown for {0} process(es) of SYSTEM, services and other users; their CPU/GPU/memory/IO/TCP were still recorded. Indicators I5-I12, I17, I21, I22 cannot be evaluated for them; the Security event log was not read {1}.' -f $cnt, $script:WdAnAdminText))
    } else { $L.Add('- The monitor ran elevated: file facts were readable for all processes (kernel/protected processes such as System or Registry have no image path by design).') }
    $L.Add(('- Files read: {0} samples file(s) with {1} rows, {2} procs file(s) with {3} rows ({4} s), procmeta {5} rows, net {6} rows, dns {7} rows, events {8} rows; {9} row(s) skipped because of a wrong field count{10}.' -f $(if ($null -ne $SM) { $SM.Files } else { 0 }), [int]$st['SampleRows'], [int]$st['ProcFiles'], [int]$st['ProcRows'], $st['ProcReadSeconds'], [int]$st['MetaRows'], [int]$st['NetRows'], [int]$st['DnsRows'], [int]$st['EventRows'], [int]$st['SkippedRows'], $(if ([string]$st['SkippedFiles'] -ne '') { ' (' + ([string]$st['SkippedFiles']).TrimEnd(' ', ';') + ')' } else { '' })))
    if ($null -eq $Ctx.ProcSum) { $L.Add('- procsum.json was missing or unreadable: totals were rebuilt from the filtered procs rows (quiet samples below the row filter count as 0; averages are exact only for processes that always exceeded the filter).') }
    else {
        $csvOnly = 0
        if ($null -ne $Ctx.Entries) { $csvOnly = @($Ctx.Entries.Values | Where-Object { $_.Source -eq 'csv' }).Count }
        if ($csvOnly -gt 0) { $L.Add(('- {0} process(es) appear in procs_*.csv but not in procsum.json (written every 60 s; the monitor may have been killed before the last rewrite): their totals come from the filtered CSV rows.' -f $csvOnly)) }
        $metaOnly = 0
        if ($null -ne $Ctx.Entries) { $metaOnly = @($Ctx.Entries.Values | Where-Object { $_.Source -eq 'meta' }).Count }
        if ($metaOnly -gt 0) { $L.Add(('- {0} process(es) have metadata but no samples (exited before the first delta).' -f $metaOnly)) }
    }
    if ([int]$st['BrokenEntries'] -gt 0) { $L.Add(('- {0} procsum entries could not be parsed and were skipped.' -f [int]$st['BrokenEntries'])) }
    $pending = 0
    if ($null -ne $Ctx.Meta) { $pending = @($Ctx.Meta.Values | Where-Object { [string]$_['AccessNote'] -eq 'file info pending at stop' }).Count }
    if ($pending -gt 0) { $L.Add(('- {0} process(es) have no signature/SHA256 because the monitor stopped before its file-info queue drained (AccessNote "file info pending at stop").' -f $pending)) }
    if ($null -ne $SM -and $SM.Rows -gt 0 -and ($SM.IdleN -lt $script:WdAnIdleMinSamples -or $SM.ActiveN -lt $script:WdAnIdleMinSamples)) {
        $na = 'I1 full, I2 idle bonus'
        if ($SM.ActiveN -eq 0 -and $SM.IdleN -lt $script:WdAnIdleMinSamples) { $na += ', I14 (all-idle run shorter than 20 samples)' }
        $L.Add(('- Idle-vs-active indicators ({0}) were not available: the run lacks 20 samples in one of the states.' -f $na))
    }
    if ($null -ne $Ctx.Net -and [int]$Ctx.Net.PreExisting -gt 0) { $L.Add(('- {0} connection(s) already existed when the monitor started (discovered in sample 1); they are listed as endpoints but do not count as "opened while idle" (I14).' -f [int]$Ctx.Net.PreExisting)) }
    $L.Add(('- The monitor''s own footprint is in the data: its powershell.exe is tagged Self and excluded here ({0} rows); WmiPrvSE.exe (WMI provider host, 1-2 % CPU at a 10 s interval) is caused by the sampling itself and is not tagged. Processes tagged WinDebugTool are other win-debug runs and are not scored.' -f [int]$st['SelfRows']))
    $L.Add('- Sample 1 is a baseline without rates; `New` processes get their first values one sample later; HasWindow and private bytes refresh every 3rd sample; procmeta rows are written when file facts are known (not in time order).')
    $L.Add('')
    foreach ($x in @(Get-SummaryFooterLines)) { $L.Add($x) }
    return $L.ToArray()
}


# ---------------------------------------------------------------------------------------------
# Machine-readable outputs
# ---------------------------------------------------------------------------------------------
function Get-WdAnSubjectRecord {
    # Flat record for process-summary.csv / suspects.csv / analysis.json.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$S, [switch]$WithIndicators)
    $r = [ordered]@{
        Process = (Get-WdAnDisplayName -Subject $S); Name = $S.Name; Path = $S.Path; LocationClass = $S.LocationClass; Instances = $S.Instances.Count
        Pids = (@($S.Pids) -join ';'); Score = $S.Score; RawScore = $S.RawScore; Class = $S.Class; Reasons = $S.Reasons; Damping = (@($S.Damping) -join '; ')
        NeedsAdmin = $S.NeedsAdmin; Samples = $S.Samples; SamplesIdle = $S.SamplesIdle; SamplesActive = $S.SamplesActive; EffectiveSamples = $S.EffSamples; EffectiveSamplesIdle = $S.EffSamplesIdle; EffectiveSamplesActive = $S.EffSamplesActive
        CpuSeconds = [math]::Round($S.CpuSeconds, 2, [MidpointRounding]::AwayFromZero); CpuAvgPct = [math]::Round([double]$S.CpuAvg, 3, [MidpointRounding]::AwayFromZero); CpuMaxPct = [math]::Round($S.CpuMax, 2, [MidpointRounding]::AwayFromZero)
        CpuCoresMax = [math]::Round($S.CpuCoresMax, 3, [MidpointRounding]::AwayFromZero)
        CpuIdleAvgPct = $(if ($null -ne $S.CpuIdleAvg) { [math]::Round([double]$S.CpuIdleAvg, 3, [MidpointRounding]::AwayFromZero) } else { $null })
        CpuActiveAvgPct = $(if ($null -ne $S.CpuActiveAvg) { [math]::Round([double]$S.CpuActiveAvg, 3, [MidpointRounding]::AwayFromZero) } else { $null })
        GpuSeconds = [math]::Round($S.GpuSeconds, 2, [MidpointRounding]::AwayFromZero); GpuComputeSeconds = [math]::Round($S.GpuComputeSeconds, 2, [MidpointRounding]::AwayFromZero)
        Gpu3DSeconds = [math]::Round($S.Gpu3DSeconds, 2, [MidpointRounding]::AwayFromZero); GpuVideoSeconds = [math]::Round($S.GpuVideoSeconds, 2, [MidpointRounding]::AwayFromZero)
        GpuMaxPct = [math]::Round($S.GpuMax, 2, [MidpointRounding]::AwayFromZero); GpuComputeAvgPct = [math]::Round([double]$S.GpuComputeAvg, 3, [MidpointRounding]::AwayFromZero)
        ReadBytes = [int64]$S.ReadBytes; WriteBytes = [int64]$S.WriteBytes; WSMaxBytes = [int64]$S.WSMax; WSFirstBytes = [int64]$S.WSFirst; WSLastBytes = [int64]$S.WSLast
        HasWindowEver = $S.HasWindowEver; SessionId = $S.SessionId; BasePriority = $S.BasePriority; LowPrioSamples = $S.LowPrioSamples
        Started = $S.Started; FirstSeen = $S.FirstSeen; LastSeen = $S.LastSeen; PresentAtStart = $S.PresentAtStart; Starts = $S.Starts; Exits = $S.Exits; QuickRestarts = $S.QuickRestarts; MaxConcurrent = $S.MaxConcurrent
        RemoteIps = $S.RemoteIps.Count; PublicIps = $S.PublicIps.Count; PoolPorts = (@($S.PoolPorts | Sort-Object) -join ';'); RawIpNoDns = $S.RawNoDns; IdlePublicConnections = $S.IdlePublic; ListenPorts = $S.ListenPorts.Count
        DefenderDetections = $S.DefenderDetections; ExclusionChanges = $S.ExclusionChanges; PersistenceEvents = $S.PersistenceEvents
        ParentName = $S.ParentName; Owner = $S.Owner; Company = $S.Company; Description = $S.Description; OriginalFilename = $S.OriginalFilename
        SigStatus = $S.SigStatus; Signer = $S.Signer; IsOSBinary = $S.IsOSBinary; Sha256 = $S.Sha256; VirusTotal = $(if ($S.Sha256 -match '^[0-9a-fA-F]{64}$') { $script:WdAnVtUrl + $S.Sha256.ToLowerInvariant() } else { '' })
        # CommandLine is masked (Hide-WdSecret) in every output file; scoring used the original text.
        Flags = $S.Flags; AccessNote = $S.AccessNote; CommandLine = (Hide-WdSecret -Text $S.CommandLine); Sources = (@($S.Sources) -join ';'); IsTool = $S.IsTool
    }
    if ($WithIndicators) {
        $inds = @()
        foreach ($i in $S.Indicators) { $inds += [ordered]@{ Id = $i.Id; Points = $i.Points; Text = $i.Text; Group = $i.Group } }
        $r['Indicators'] = $inds
        $r['Notes'] = @($S.Notes)
        $r['Endpoints'] = @($S.Endpoints | Where-Object { -not $_.Private } | Select-Object -First 50 | ForEach-Object { [ordered]@{ Remote = $_.Remote; Port = $_.Port; Pool = $_.Pool; Idle = $_.Idle; Dns = $_.Dns; FirstSeen = $_.Ts } })
    }
    return $r
}

function Export-WdAnOutputs {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$Ctx)
    $exportErrorStart = $script:CollectionErrors.Count
    $dir = $Ctx.SessionPath
    $subjects = @($Ctx.Subjects)
    $sorted = @($subjects | Sort-Object -Property @{ Expression = { $_.Score }; Descending = $true }, @{ Expression = { $_.CpuSeconds }; Descending = $true })
    # process-summary.csv: every subject
    Invoke-Safely -Name 'Analyze.Write.ProcessSummary' -ScriptBlock {
        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($s in $sorted) { $rows.Add([pscustomobject](Get-WdAnSubjectRecord -S $s)) }
        Export-CsvInvariant -InputObject $rows.ToArray() -Path ([IO.Path]::Combine($dir, 'process-summary.csv'))
    } | Out-Null
    # suspects.csv: everything with a score > 0
    Invoke-Safely -Name 'Analyze.Write.Suspects' -ScriptBlock {
        $rows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($s in @($sorted | Where-Object { $_.Score -gt 0 -or $_.RawScore -gt 0 })) { $rows.Add([pscustomobject](Get-WdAnSubjectRecord -S $s)) }
        Export-CsvInvariant -InputObject $rows.ToArray() -Path ([IO.Path]::Combine($dir, 'suspects.csv'))
    } | Out-Null
    # analysis.json
    Invoke-Safely -Name 'Analyze.Write.Json' -ScriptBlock {
        $TL = $Ctx.Timeline
        $SM = $Ctx.Samples
        $timeline = [ordered]@{ Mode = ''; Labels = @(); Groups = @(); Cpu = @(); Gpu = @(); GpuCompute = @(); MemUsedPct = @(); DiskActivePct = @(); DiskBps = @(); NetBps = @(); IdleLine = '' }
        if ($null -ne $TL -and $TL.Groups.Count -gt 0) {
            $rd = { param([double[]]$a) $o = @(); foreach ($v in $a) { if ($v -lt 0) { $o += $null } else { $o += [math]::Round($v, 2, [MidpointRounding]::AwayFromZero) } }; return ,$o }
            $timeline = [ordered]@{
                Mode = $TL.Mode; Labels = @($TL.Labels); Groups = @($TL.Groups); Cpu = (& $rd $TL.Series.Cpu); Gpu = (& $rd $TL.Series.Gpu); GpuCompute = (& $rd $TL.Series.GpuCompute)
                MemUsedPct = (& $rd $TL.Series.Mem); DiskActivePct = (& $rd $TL.Series.Disk); DiskBps = (& $rd $TL.Series.DiskBps); NetBps = (& $rd $TL.Series.Net); IdleLine = $TL.IdleLine
            }
        }
        $peaks = [ordered]@{}
        if ($null -ne $SM) {
            $peaks = [ordered]@{
                CpuMaxPct = $SM.CpuMax; CpuMaxAt = $SM.CpuMaxTs; CpuMaxTopProcess = $SM.CpuMaxTop; CpuAvgPct = $(if ($SM.CpuN -gt 0) { $SM.CpuSum / $SM.CpuN } else { $null })
                GpuMaxPct = $SM.GpuMax; GpuMaxAt = $SM.GpuMaxTs; MemUsedMaxMB = $SM.MemMax; MemUsedMaxAt = $SM.MemMaxTs; MemTotalMB = $SM.MemTotal; CommitMaxPct = $SM.CommitMax
                DiskActiveMaxPct = $SM.DiskMax; DiskActiveMaxAt = $SM.DiskMaxTs; DiskBpsMax = $SM.DiskBpsMax; DiskBpsMaxAt = $SM.DiskBpsMaxTs; NetBpsMax = $SM.NetMax; NetBpsMaxAt = $SM.NetMaxTs
                TempMaxC = $(if ($SM.TempN -gt 0) { $SM.TempMax } else { $null }); ThrottleSamples = $SM.ThrottleN; PerfLowSamples = $SM.PerfLowN
                PagesPerSecAvg = $(if ($SM.PagesN -gt 0) { $SM.PagesSum / $SM.PagesN } else { $null }); PoolNonpagedFirst = $SM.PoolFirst; PoolNonpagedLast = $SM.PoolLast
                ProcSumGapPoints = $(if ($SM.GapN -gt 0) { $SM.GapSum / $SM.GapN } else { $null }); TopCpuCounts = $SM.TopCpu
            }
        }
        $top = [ordered]@{
            ByCpuSeconds = @($subjects | Where-Object { $_.CpuSeconds -gt 0 } | Sort-Object -Property @{ Expression = { $_.CpuSeconds }; Descending = $true } | Select-Object -First $Ctx.TopN | ForEach-Object { Get-WdAnSubjectRecord -S $_ })
            ByGpuSeconds = @($subjects | Where-Object { $_.GpuSeconds -gt 0 } | Sort-Object -Property @{ Expression = { $_.GpuSeconds }; Descending = $true } | Select-Object -First $Ctx.TopN | ForEach-Object { Get-WdAnSubjectRecord -S $_ })
            ByWorkingSet = @($subjects | Where-Object { $_.WSMax -gt 0 } | Sort-Object -Property @{ Expression = { $_.WSMax }; Descending = $true } | Select-Object -First $Ctx.TopN | ForEach-Object { Get-WdAnSubjectRecord -S $_ })
            ByIo = @($subjects | Where-Object { ($_.ReadBytes + $_.WriteBytes) -gt 0 } | Sort-Object -Property @{ Expression = { $_.ReadBytes + $_.WriteBytes }; Descending = $true } | Select-Object -First $Ctx.TopN | ForEach-Object { Get-WdAnSubjectRecord -S $_ })
        }
        $VD = $Ctx.Verdict
        $verdict = [ordered]@{ Clean = $false; Inconclusive = $true; Reasons = @('scoring failed; see Collection errors'); Warnings = @(); Suspects = @() }
        if ($null -ne $VD) {
            $verdict = [ordered]@{ Clean = $VD.Clean; Inconclusive = $VD.Inconclusive; Reasons = @($VD.Reasons); Warnings = @($VD.Warnings); Suspects = @($VD.Suspects | ForEach-Object { Get-WdAnSubjectRecord -S $_ -WithIndicators }) }
        }
        $events = [ordered]@{ ByType = @{}; EventLog = @() }
        if ($null -ne $Ctx.Events) {
            $events = [ordered]@{
                ByType = $Ctx.Events.ByType
                EventLog = @($Ctx.Events.EventLog | Select-Object -First 500 | ForEach-Object { [ordered]@{ Time = [string]$_['EventTime']; Log = [string]$_['Source']; Id = [string]$_['EventId']; Detail = (Hide-WdSecret -Text ([string]$_['Detail'])); RecordId = [string]$_['RecordId'] } })
            }
        }
        $doc = [ordered]@{
            Meta = (Get-ReportRunInfo -Mode 'Analyze')
            AnalyzeDurationSeconds = $Ctx.DurationSeconds
            Thresholds = [ordered]@{ Suspicious = $script:WdAnSuspiciousThreshold; HighlySuspicious = $script:WdAnHighThreshold; IdleMinSamples = $script:WdAnIdleMinSamples }
            Session = $Ctx.Summary
            Stats = $Ctx.Stats
            Verdict = $verdict
            Timeline = $timeline
            Peaks = $peaks
            TopConsumers = $top
            Scored = @($sorted | Where-Object { $_.RawScore -gt 0 } | ForEach-Object { Get-WdAnSubjectRecord -S $_ -WithIndicators })
            NeedsElevatedCheck = @($subjects | Where-Object { $_.NeedsElevatedCheck } | ForEach-Object { Get-WdAnSubjectRecord -S $_ })
            Recommendations = @($Ctx.Recommendations)
            AdminSkips = @(Get-AdminSkips)
            CollectionErrors = @($script:CollectionErrors.ToArray())
        }
        Export-Json -Object $doc -Path ([IO.Path]::Combine($dir, 'analysis.json')) -Depth 8
    } | Out-Null
    # report.md (last, so the footer includes any write error above). A rendering error degrades one half of the
    # report to a note instead of losing the whole file (the error is also logged and listed under Collection errors).
    $reportPath = [IO.Path]::Combine($dir, 'report.md')
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $fallback1 = @('# win-debug monitor analysis', '', '_The first half of the report (run info, verdict, timeline, top consumers) could not be rendered; see analyze.log and the Collection errors section below. analysis.json and the CSV files hold the same data._', '')
    $fallback2 = @('## Suspicious processes', '', '_The second half of the report (suspects, network, restarts, events, recommendations, appendix) could not be rendered; see analyze.log. suspects.csv and analysis.json hold the same data._', '')
    foreach ($x in @(Invoke-Safely -Name 'Analyze.Write.Report1' -Default $fallback1 -ScriptBlock { Get-WdAnReportLines -Ctx $Ctx })) { $lines.Add([string]$x) }
    foreach ($x in @(Invoke-Safely -Name 'Analyze.Write.Report2' -Default $fallback2 -ScriptBlock { Get-WdAnReportLines2 -Ctx $Ctx })) { $lines.Add([string]$x) }
    if (-not $lines.Contains('## Collection errors')) { foreach ($x in @(Get-SummaryFooterLines)) { $lines.Add([string]$x) } }
    Write-MarkdownFile -Path $reportPath -Lines $lines.ToArray()
    Confirm-WdReportExport -ErrorStart $exportErrorStart
    return $reportPath
}

# ---------------------------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------------------------
function Invoke-MonitorAnalysis {
    <#
    .SYNOPSIS
        Analyze mode: reads a monitor session folder and writes report.md, analysis.json, suspects.csv and
        process-summary.csv into it. Returns the path of report.md.
    .PARAMETER SessionPath
        A monitor session folder (<OutputRoot>\<PC>_<yyyyMMdd-HHmmss>_monitor). May still be recording.
    .PARAMETER TopN
        Number of rows in the machine-readable top lists (markdown tables show at most 15-20 rows).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$SessionPath,
        [ValidateRange(1, 1000)][int]$TopN = 50
    )
    $inv = Get-WdInv
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $SessionPath = Resolve-PathSafe -Path $SessionPath
    if (-not (Test-DirectoryExists -Path $SessionPath)) { throw ('Session folder not found: {0}' -f $SessionPath) }
    $SessionPath = $SessionPath.TrimEnd('\')
    if ([string]::IsNullOrEmpty($script:LogPath)) { $script:LogPath = [IO.Path]::Combine($SessionPath, 'analyze.log') }
    $script:ReportDir = $SessionPath
    $script:CurrentMode = 'Analyze'
    if ($null -eq $script:RunStart) { $script:RunStart = Get-Date }
    $ctx = @{
        SessionPath = $SessionPath; TopN = $TopN; NominalInterval = 10.0
        Stats = @{ SampleRows = 0; ProcRows = 0; ProcFiles = 0; SkippedRows = 0; SkippedFiles = ''; SelfRows = 0; MetaRows = 0; NetRows = 0; DnsRows = 0; EventRows = 0; ProcKeys = 0; ProcReadSeconds = 0.0; Entries = 0; BrokenEntries = 0; SelfKeys = 0 }
        Run = $null; Samples = $null; ProcSum = $null; Meta = $null; Dns = $null; Net = $null; Events = $null; ProcAgg = $null; Entries = $null
        Subjects = @(); Timeline = $null; Verdict = $null; Recommendations = @(); Summary = $null; DurationSeconds = 0.0
    }
    Write-SectionHeader -Title 'Analyze: reading the session'
    $ctx.Files = Get-WdAnSessionFiles -SessionPath $SessionPath
    if ($ctx.Files.Samples.Count -eq 0 -and $ctx.Files.Procs.Count -eq 0 -and [string]::IsNullOrEmpty($ctx.Files.ProcSum)) {
        throw ('Not a monitor session (no samples_*.csv, procs_*.csv or procsum.json): {0}' -f $SessionPath)
    }
    Write-Log -Level Info -Message ('Session: {0} ({1} samples file(s), {2} procs file(s){3})' -f $SessionPath, $ctx.Files.Samples.Count, $ctx.Files.Procs.Count, $(if ($ctx.Files.Running -ne '') { ', monitor.running present' } else { '' }))
    $ctx.Run = Measure-Step -Name 'Analyze.RunJson' -ScriptBlock { Invoke-Safely -Name 'Analyze.RunJson' -Default $null -ScriptBlock { Read-WdAnRunInfo -Path $ctx.Files.RunJson } }
    if ($null -ne $ctx.Run -and $null -ne $ctx.Run.IntervalSeconds) { try { $ctx.NominalInterval = [double]$ctx.Run.IntervalSeconds } catch { } }
    if ($ctx.NominalInterval -le 0) { $ctx.NominalInterval = 10.0 }
    $ctx.Samples = Measure-Step -Name 'Analyze.Samples' -ScriptBlock { Invoke-Safely -Name 'Analyze.Samples' -Default $null -ScriptBlock { Read-WdAnSamples -Files $ctx.Files.Samples -Stats $ctx.Stats } }
    if ($null -ne $ctx.Samples) { Write-Log -Level Info -Message ('samples: {0} rows, {1} idle / {2} active, {3} overruns, {4} skipped' -f $ctx.Samples.Rows, $ctx.Samples.IdleN, $ctx.Samples.ActiveN, $ctx.Samples.Overruns, $ctx.Samples.Skipped) }
    $ctx.ProcSum = Measure-Step -Name 'Analyze.ProcSum' -ScriptBlock { Invoke-Safely -Name 'Analyze.ProcSum' -Default $null -ScriptBlock { Read-WdAnProcSum -Path $ctx.Files.ProcSum } }
    if ($null -ne $ctx.ProcSum) { Write-Log -Level Info -Message ('procsum.json: {0} processes' -f $ctx.ProcSum.Count) } else { Write-Log -Level Warn -Message 'procsum.json missing or unreadable: totals will be rebuilt from procs_*.csv (filtered rows)' }
    $ctx.Meta = Measure-Step -Name 'Analyze.ProcMeta' -ScriptBlock { Invoke-Safely -Name 'Analyze.ProcMeta' -Default @{} -ScriptBlock { Read-WdAnProcMeta -Path $ctx.Files.ProcMeta -Stats $ctx.Stats } }
    $ctx.Dns = Measure-Step -Name 'Analyze.Dns' -ScriptBlock { Invoke-Safely -Name 'Analyze.Dns' -Default @{} -ScriptBlock { Read-WdAnDns -Path $ctx.Files.Dns -Stats $ctx.Stats } }
    $runStartTs = ''
    if ($null -ne $ctx.Samples) { $runStartTs = [string]$ctx.Samples.First }
    $ctx.Net = Measure-Step -Name 'Analyze.Net' -ScriptBlock { Invoke-Safely -Name 'Analyze.Net' -Default $null -ScriptBlock { Read-WdAnNet -Path $ctx.Files.Net -Dns $ctx.Dns -Stats $ctx.Stats -RunStart $runStartTs } }
    $ctx.Events = Measure-Step -Name 'Analyze.Events' -ScriptBlock { Invoke-Safely -Name 'Analyze.Events' -Default $null -ScriptBlock { Read-WdAnEvents -Path $ctx.Files.Events -Stats $ctx.Stats } }
    $interesting = Invoke-Safely -Name 'Analyze.InterestingKeys' -Default $null -ScriptBlock { Get-WdAnInterestingKeys -ProcSum $ctx.ProcSum -Meta $ctx.Meta -TopN $TopN }
    $bucketLen = 16
    if ($null -ne $ctx.Samples -and $ctx.Samples.First -ne '' -and $ctx.Samples.Last -ne '') {
        $sa = Get-WdAnDateTime -Text $ctx.Samples.First
        $sb = Get-WdAnDateTime -Text $ctx.Samples.Last
        if ($null -ne $sa -and $null -ne $sb -and ($sb - $sa).TotalHours -gt 6) { $bucketLen = 13 }
    }
    $ctx.ProcAgg = Measure-Step -Name 'Analyze.Procs' -ScriptBlock { Invoke-Safely -Name 'Analyze.Procs' -Default @{} -ScriptBlock { Read-WdAnProcs -Files $ctx.Files.Procs -Samples $ctx.Samples -Interesting $interesting -NominalInterval $ctx.NominalInterval -BucketKeyLength $bucketLen -Stats $ctx.Stats } }

    Write-SectionHeader -Title 'Analyze: aggregating and scoring'
    $ctx.Entries = Measure-Step -Name 'Analyze.Merge' -ScriptBlock { Invoke-Safely -Name 'Analyze.Merge' -Default @{} -ScriptBlock { Merge-WdAnProcesses -Ctx $ctx } }
    $ctx.Subjects = @(Measure-Step -Name 'Analyze.Subjects' -ScriptBlock { Invoke-Safely -Name 'Analyze.Subjects' -Default @() -ScriptBlock { Group-WdAnSubjects -Ctx $ctx } })
    Write-Log -Level Info -Message ('{0} process keys -> {1} subjects (aggregated by path)' -f $ctx.Stats['Entries'], $ctx.Subjects.Count)
    Measure-Step -Name 'Analyze.Score' -ScriptBlock {
        $logRows = @()
        if ($null -ne $ctx.Events) { $logRows = @($ctx.Events.EventLog) }
        foreach ($s in $ctx.Subjects) {
            Invoke-Safely -Name ('Analyze.Score.' + $s.Name) -Quiet -ScriptBlock {
                Add-WdAnEventAttribution -Subject $s -EventLogRows $logRows
                $ind = @(Get-WdAnIndicators -S $s -Ctx $ctx)
                Set-WdAnScore -S $s -Indicators $ind
            } | Out-Null
            if ($null -eq $s.Class -or $s.Class -eq '') { Set-WdAnScore -S $s -Indicators @() }
        }
    } | Out-Null
    $ctx.Timeline = Measure-Step -Name 'Analyze.Timeline' -ScriptBlock { Invoke-Safely -Name 'Analyze.Timeline' -Default $null -ScriptBlock { Get-WdAnTimeline -Ctx $ctx } }
    $ctx.Verdict = Invoke-Safely -Name 'Analyze.Verdict' -Default $null -ScriptBlock { Get-WdAnVerdict -Ctx $ctx }
    $ctx.Recommendations = @(Invoke-Safely -Name 'Analyze.Recommendations' -Default @() -ScriptBlock { Get-WdAnRecommendations -Ctx $ctx })
    $ctx.Summary = Invoke-Safely -Name 'Analyze.Summary' -Default ([ordered]@{}) -ScriptBlock { Get-WdAnSessionSummary -Ctx $ctx }
    if ($null -ne $ctx.Run -and -not [bool]$ctx.Run.IsElevated) {
        # run.json carries the count only after a clean stop; the summary falls back to counting procmeta rows.
        $noPath = $null
        try { $noPath = $ctx.Summary.ProcessesWithoutPath } catch { $noPath = $null }
        $noPathText = 'system/service processes'
        if ($null -ne $noPath -and [int]$noPath -gt 0) { $noPathText = ('{0} system/service processes' -f ([int]$noPath).ToString($inv)) }
        Add-AdminSkip -Item ('Executable path, command line, owner, signature and SHA256 of ' + $noPathText) -Detail 'the monitor session was recorded without administrator rights'
        Add-AdminSkip -Item 'Security event log (4688 process creation, 4698 task created)' -Detail 'not read by the monitor without administrator rights'
    }
    $suspects = 0
    if ($null -ne $ctx.Verdict) { $suspects = $ctx.Verdict.Suspects.Count }
    foreach ($s in @($ctx.Subjects | Where-Object { $_.Score -ge $script:WdAnSuspiciousThreshold } | Sort-Object -Property @{ Expression = { $_.Score }; Descending = $true })) {
        $sev = 'Warning'
        if ($s.Score -ge $script:WdAnHighThreshold) { $sev = 'Critical' }
        Add-Finding -Severity $sev -Category 'Process' -RuleId 'AN-SUSPECT' -Title ('{0}: {1} (score {2})' -f $s.Class, (Get-WdAnDisplayName -Subject $s), $s.Score) -Detail $s.Reasons -Recommendation 'See report.md, section Suspicious processes.'
    }

    Write-SectionHeader -Title 'Analyze: writing the report'
    # DurationSeconds (report.md run info, analysis.json AnalyzeDurationSeconds) = reading + scoring only: the JSON
    # cannot contain the time of its own write. The console total below includes writing the outputs.
    $analysisSeconds = $sw.Elapsed.TotalSeconds
    $ctx.DurationSeconds = [math]::Round($analysisSeconds, 1, [MidpointRounding]::AwayFromZero)
    $reportPath = Measure-Step -Name 'Analyze.Write' -ScriptBlock { Export-WdAnOutputs -Ctx $ctx }
    $sw.Stop()
    Write-Log -Level Info -Message ([string]::Format($inv, 'Analysis finished in {0:F1} s (reading and scoring {1:F1} s, writing the outputs {2:F1} s): {3} samples, {4} procs rows, {5} subjects, {6} suspicious. Report: {7}', $sw.Elapsed.TotalSeconds, $analysisSeconds, $sw.Elapsed.TotalSeconds - $analysisSeconds, [int]$ctx.Stats['SampleRows'], [int]$ctx.Stats['ProcRows'], $ctx.Subjects.Count, $suspects, $reportPath))
    return $reportPath
}
