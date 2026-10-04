# lib\DiskUsage.ps1 - Disk mode of win-debug: what occupies each volume and what could be freed (report only).
# Dot-sourced by WinDebug.ps1 after lib\Common.ps1 (same script scope). Windows PowerShell 5.1 only.
#
# Public:  Invoke-DiskScan -OutDir <dir> [-Drives C,D] [-TopN 50] [-Deep]
# Private: *-WdDisk* helpers (walker, volumes, profiles, cleanup catalog, installed apps, outputs).
# Native:  lib\native\FastWalker.cs (WinDebug.FastWalker) loaded via Add-NativeType; when compilation fails the
#          module falls back to .NET DirectoryInfo recursion (slower, allocated sizes approximate).
# Read-only: nothing is deleted or changed; the module only measures and reports. No cleanmgr/DISM execution.
#
# Outputs in -OutDir: summary.md, disk-usage.json, volumes.csv, top-folders.csv, top-files.csv,
#                     cleanup-candidates.csv, user-profiles.csv (plus run.log written by Write-Log).
# All byte values are allocated-on-disk [int64] unless a column is named LogicalBytes.

Set-StrictMode -Off

$script:WdDiskWalkerSource   = 'FastWalker.cs'   # resolved by Add-NativeType under lib\native; test hook: bogus path forces the fallback
$script:WdDiskWalkerMode     = $null             # 'Native' or 'Fallback' after Initialize-WdDiskWalker
$script:WdDiskLargeFileBytes = [int64]500MB
$script:WdDiskScans          = New-Object 'System.Collections.Generic.List[object]'   # volume scans (size cache for Get-WdDiskDirSize)
$script:WdDiskCandidates     = New-Object 'System.Collections.Generic.List[object]'
$script:WdDiskRemotePaths    = New-Object 'System.Collections.Generic.List[string]'   # candidate paths on network/non-fixed drives (not measured)
$script:WdDiskAdminText      = '(requires administrator)'
$script:WdDiskRemoteText     = 'not on a local fixed drive, not measured'

# ---------------------------------------------------------------------------------------------
# Walker: native P/Invoke type or .NET fallback
# ---------------------------------------------------------------------------------------------
function Initialize-WdDiskWalker {
    [CmdletBinding()]
    param(
        [string]$SourcePath,
        [switch]$Force
    )
    if (-not $Force -and -not [string]::IsNullOrEmpty($script:WdDiskWalkerMode)) { return $script:WdDiskWalkerMode }
    if ([string]::IsNullOrEmpty($SourcePath)) { $SourcePath = $script:WdDiskWalkerSource }
    $ok = $false
    try { $ok = [bool](Add-NativeType -TypeName 'WinDebug.FastWalker' -SourcePath $SourcePath) } catch { $ok = $false }
    if ($ok) {
        $script:WdDiskWalkerMode = 'Native'
        Write-Log -Level Info -Message 'Directory walker: native (FindFirstFileExW via Add-Type)'
    } else {
        $script:WdDiskWalkerMode = 'Fallback'
        Write-Log -Level Warn -Message 'Directory walker: .NET fallback (slower; allocated size of compressed/sparse files is approximate)'
    }
    return $script:WdDiskWalkerMode
}

function Get-WdDiskNormalizedPath {
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path.Trim()
    if ($p.StartsWith('\\?\UNC\', [StringComparison]::OrdinalIgnoreCase)) { $p = '\\' + $p.Substring(8) }
    elseif ($p.StartsWith('\\?\')) { $p = $p.Substring(4) }
    $p = $p.TrimEnd('\')
    if ($p.Length -eq 2 -and $p.EndsWith(':')) { $p += '\' }
    return $p
}

function Test-WdDiskLocalPath {
    # $true when the path lies on a local fixed drive (the only kind the Disk report is about). UNC paths (folder
    # redirection to \\server\share, WSL \\wsl.localhost), mapped network drives, removable media and optical drives
    # return $false: they are never walked (slow over SMB, and their bytes do not belong to a local volume).
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    $p = Get-WdDiskNormalizedPath -Path $Path
    if ($null -eq $p) { return $false }
    if ($p.StartsWith('\\')) { return $false }
    if ($p.Length -lt 2 -or $p[1] -ne ':') { return $false }
    try {
        $di = New-Object System.IO.DriveInfo($p.Substring(0, 1))
        return ($di.DriveType -eq [IO.DriveType]::Fixed)
    } catch { return $false }
}

function Add-WdDiskRemotePath {
    # Remembers a candidate path that was skipped because it is not on a local fixed drive (for the note/finding).
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    if ($null -eq $script:WdDiskRemotePaths) { $script:WdDiskRemotePaths = New-Object 'System.Collections.Generic.List[string]' }
    $null = Add-WdDiskUniquePath -List $script:WdDiskRemotePaths -Path $Path
    Write-Log -Level Debug -Message ('Path skipped ({0}): {1}' -f $script:WdDiskRemoteText, $Path)
}

function Add-WdDiskUniquePath {
    # Adds $Path to a List[string] unless an equal path is already there (OrdinalIgnoreCase, like NTFS). Returns $true when added.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$List,
        [AllowNull()][AllowEmptyString()][string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    foreach ($x in $List) { if ($x.Equals($Path, [StringComparison]::OrdinalIgnoreCase)) { return $false } }
    $List.Add($Path)
    return $true
}

function Get-WdDiskCimRawInt {
    # Raw numeric value of a CIM property. Once the Storage module is loaded (Inventory does that in -Mode All / Menu),
    # its types.ps1xml turns MSFT_* enum properties such as MediaType into display strings ('SSD'), so the adapted
    # property can no longer be cast to [int]; CimInstanceProperties still holds the UInt16. -1 when unavailable.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Instance, [Parameter(Mandatory = $true)][string]$Name)
    try {
        $p = $Instance.CimInstanceProperties[$Name]
        if ($null -ne $p -and $null -ne $p.Value) { return [int]$p.Value }
    } catch { }
    try { return [int]$Instance.$Name } catch { }
    return -1
}

function Get-WdDiskLongPath {
    # 8.3 segments (e.g. %TEMP% = C:\Users\SOMEUS~1\AppData\Local\Temp) expanded to the long form when the native helper is available.
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    if ($Path -notmatch '~') { return $Path }
    if ('WinDebug.FastWalker' -as [type]) {
        try { return [WinDebug.FastWalker]::GetLongPath($Path) } catch { return $Path }
    }
    try {
        $fso = New-Object -ComObject Scripting.FileSystemObject
        if ($fso.FolderExists($Path)) { return [string]$fso.GetFolder($Path).Path }
    } catch { }
    return $Path
}

function New-WdDiskFallbackEntry {
    [CmdletBinding()]
    param([string]$Path, [int]$Depth, [AllowNull()][object]$Parent)
    return @{ Path = $Path; Depth = $Depth; Bytes = [int64]0; Alloc = [int64]0; Files = [int64]0; Dirs = [int64]0; Denied = 0; CloudFiles = [int64]0; CloudBytes = [int64]0; Parent = $Parent }
}

function Get-WdDiskFallbackScan {
    # Research method 2: DirectoryInfo.EnumerateFileSystemInfos recursion (iterative, explicit stack), links skipped by
    # LinkType (Get-Item), cloud placeholders (RecallOnDataAccess/Offline) counted as 0 bytes allocated.
    # Returns a hashtable with the same member names as WinDebug.ScanResult.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$MaxDepth = 0,
        [int64]$LargeFileThreshold = [int64]::MaxValue,
        [int]$OldDays = 0
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $root = Get-WdDiskNormalizedPath -Path $Path
    $cutoff = $null
    if ($OldDays -gt 0) { $cutoff = [DateTime]::UtcNow.AddDays(-$OldDays) }
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $index   = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([StringComparer]::OrdinalIgnoreCase)
    $stack   = New-Object 'System.Collections.Generic.Stack[object]'
    $large   = New-Object 'System.Collections.Generic.List[object]'
    $deniedPaths = New-Object 'System.Collections.Generic.List[string]'
    $r = @{ Root = $root; MaxDepth = $MaxDepth; Files = [int64]0; Dirs = [int64]0; Bytes = [int64]0; Alloc = [int64]0
            CloudOnlyFiles = [int64]0; CloudOnlyBytes = [int64]0; OldFiles = [int64]0; OldBytes = [int64]0
            Denied = 0; SkippedLinks = 0; Errors = 0; DeepestLevel = 0; ElapsedMs = 0.0
            Directories = $null; LargeFiles = $null; DeniedPaths = $null; Index = $index }
    $rootEntry = New-WdDiskFallbackEntry -Path $root -Depth 0 -Parent $null
    $entries.Add($rootEntry)
    $index[$root] = $rootEntry
    $stack.Push($rootEntry)
    while ($stack.Count -gt 0) {
        $e = $stack.Pop()
        $depth = [int]$e['Depth']
        if ($depth -gt $r['DeepestLevel']) { $r['DeepestLevel'] = $depth }
        try {
            $di = New-Object System.IO.DirectoryInfo($e['Path'])
            foreach ($it in $di.EnumerateFileSystemInfos()) {
                $attr = [int]$it.Attributes
                if (($attr -band 0x10) -ne 0) {
                    if (($attr -band 0x400) -ne 0) {
                        $link = $null
                        try { $link = Get-Item -LiteralPath $it.FullName -Force -ErrorAction Stop } catch { $link = $null }
                        if ($null -ne $link -and ($link.LinkType -eq 'Junction' -or $link.LinkType -eq 'SymbolicLink')) { $r['SkippedLinks']++; continue }
                    }
                    $e['Dirs']++
                    if ($depth -ge 512) { $r['Errors']++; continue }
                    $child = New-WdDiskFallbackEntry -Path $it.FullName -Depth ($depth + 1) -Parent $e
                    $entries.Add($child)
                    $index[$it.FullName] = $child
                    $stack.Push($child)
                } else {
                    $size = [int64]0
                    try { $size = [int64]$it.Length } catch { $size = [int64]0 }
                    $alloc = $size
                    if (($attr -band 0x400000) -ne 0 -or ($attr -band 0x1000) -ne 0) {
                        $alloc = [int64]0
                        $e['CloudFiles']++
                        $e['CloudBytes'] += $size
                        $r['CloudOnlyFiles']++
                        $r['CloudOnlyBytes'] += $size
                    }
                    $e['Files']++
                    $e['Bytes'] += $size
                    $e['Alloc'] += $alloc
                    if ($null -ne $cutoff -and $it.LastWriteTimeUtc -lt $cutoff) { $r['OldFiles']++; $r['OldBytes'] += $alloc }
                    if ($size -ge $LargeFileThreshold) {
                        $large.Add(@{ Path = $it.FullName; Bytes = $size; Alloc = $alloc; LastWriteUtc = $it.LastWriteTimeUtc; CreatedUtc = $it.CreationTimeUtc; Attributes = [uint32]($attr -band 0xFFFFFFFF); CloudOnly = (($attr -band 0x400000) -ne 0) })
                    }
                }
            }
        } catch [System.UnauthorizedAccessException] {
            $e['Denied']++
            $r['Denied']++
            if ($deniedPaths.Count -lt 200) { $deniedPaths.Add([string]$e['Path']) }
        } catch {
            $r['Errors']++
        }
    }
    # Roll up: reverse pre-order processes every descendant before its ancestor.
    for ($i = $entries.Count - 1; $i -ge 1; $i--) {
        $c = $entries[$i]
        $p = $c['Parent']
        if ($null -eq $p) { continue }
        $p['Bytes'] += $c['Bytes']; $p['Alloc'] += $c['Alloc']; $p['Files'] += $c['Files']; $p['Dirs'] += $c['Dirs']
        $p['Denied'] += $c['Denied']; $p['CloudFiles'] += $c['CloudFiles']; $p['CloudBytes'] += $c['CloudBytes']
    }
    $dirs = New-Object 'System.Collections.Generic.List[object]'
    foreach ($en in $entries) { if ([int]$en['Depth'] -le $MaxDepth) { $dirs.Add($en) } }
    $r['Files'] = [int64]$rootEntry['Files']; $r['Dirs'] = [int64]$rootEntry['Dirs']; $r['Bytes'] = [int64]$rootEntry['Bytes']; $r['Alloc'] = [int64]$rootEntry['Alloc']
    $r['Directories'] = $dirs
    $r['LargeFiles'] = $large
    $r['DeniedPaths'] = $deniedPaths
    $sw.Stop()
    $r['ElapsedMs'] = $sw.Elapsed.TotalMilliseconds
    return $r
}

function Get-WdDiskScan {
    # One pass over a directory tree with either walker. Returns $null when the path does not exist.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$MaxDepth = 0,
        [int64]$LargeFileThreshold = [int64]::MaxValue,
        [int]$OldDays = 0
    )
    if (-not (Test-DirectoryExists -Path $Path)) { return $null }
    $mode = Initialize-WdDiskWalker
    $raw = $null
    $interrupted = $false
    if ($mode -eq 'Native') {
        # Scan() is one synchronous call: PowerShell cannot stop a pipeline inside it. The native helper listens for
        # Ctrl+C itself (Console.CancelKeyPress sets FastWalker.Cancel, the walk unwinds within milliseconds, the
        # console host then stops the pipeline at the next statement as usual).
        try { [WinDebug.FastWalker]::HookCancel() } catch { }
        try {
            $raw = [WinDebug.FastWalker]::Scan($Path, $MaxDepth, $LargeFileThreshold, $OldDays)
        } finally {
            try { [WinDebug.FastWalker]::UnhookCancel() } catch { }
        }
        try { $interrupted = [bool]$raw.Cancelled } catch { $interrupted = $false }
    } else {
        $raw = Get-WdDiskFallbackScan -Path $Path -MaxDepth $MaxDepth -LargeFileThreshold $LargeFileThreshold -OldDays $OldDays
    }
    if ($null -eq $raw) { return $null }
    if ($interrupted) { Write-Log -Level Warn -Message ('Scan of {0} interrupted (Ctrl+C): totals are partial' -f $Path) }
    return [pscustomobject]@{
        Mode           = $mode
        Interrupted    = $interrupted
        Root           = [string]$raw.Root
        Files          = [int64]$raw.Files
        Dirs           = [int64]$raw.Dirs
        Bytes          = [int64]$raw.Bytes
        Alloc          = [int64]$raw.Alloc
        CloudOnlyFiles = [int64]$raw.CloudOnlyFiles
        CloudOnlyBytes = [int64]$raw.CloudOnlyBytes
        OldFiles       = [int64]$raw.OldFiles
        OldBytes       = [int64]$raw.OldBytes
        Denied         = [int]$raw.Denied
        SkippedLinks   = [int]$raw.SkippedLinks
        Errors         = [int]$raw.Errors
        DeepestLevel   = [int]$raw.DeepestLevel
        DeniedPaths    = @($raw.DeniedPaths)
        ElapsedSeconds = [math]::Round(([double]$raw.ElapsedMs) / 1000.0, 2, [MidpointRounding]::AwayFromZero)
        Raw            = $raw
    }
}

function ConvertTo-WdDiskFolderRow {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Entry, [string]$Volume = '')
    $cloudBytes = [int64]0
    if ($Entry -is [System.Collections.IDictionary]) {
        $cloudFiles = [int64]$Entry['CloudFiles']; $cloudBytes = [int64]$Entry['CloudBytes']
    } else {
        $cloudFiles = [int64]$Entry.CloudOnlyFiles; $cloudBytes = [int64]$Entry.CloudOnlyBytes
    }
    return [ordered]@{
        Volume         = $Volume
        Depth          = [int]$Entry.Depth
        Path           = [string]$Entry.Path
        Bytes          = [int64]$Entry.Alloc
        Files          = [int64]$Entry.Files
        Dirs           = [int64]$Entry.Dirs
        Inaccessible   = [int]$Entry.Denied
        LogicalBytes   = [int64]$Entry.Bytes
        CloudOnlyFiles = $cloudFiles
        CloudOnlyBytes = $cloudBytes
    }
}

function Get-WdDiskScanTopFolders {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Scan, [int]$Depth = 1, [int]$Top = 50, [string]$Volume = '')
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if ($Scan.Mode -eq 'Native') {
        foreach ($d in @($Scan.Raw.TopDirectories($Depth, $Top))) { $rows.Add((ConvertTo-WdDiskFolderRow -Entry $d -Volume $Volume)) }
    } else {
        $sel = @($Scan.Raw['Directories'] | Where-Object { [int]$_['Depth'] -eq $Depth } | Sort-Object -Property @{ Expression = { [int64]$_['Alloc'] }; Descending = $true }, @{ Expression = { [string]$_['Path'] } } | Select-Object -First $Top)
        foreach ($d in $sel) { $rows.Add((ConvertTo-WdDiskFolderRow -Entry $d -Volume $Volume)) }
    }
    return $rows.ToArray()
}

function Get-WdDiskScanTopFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Scan, [int]$Top = 50, [string]$Volume = '')
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $items = @()
    if ($Scan.Mode -eq 'Native') {
        $items = @($Scan.Raw.TopFiles($Top))
    } else {
        $items = @($Scan.Raw['LargeFiles'] | Sort-Object -Property @{ Expression = { [int64]$_['Alloc'] }; Descending = $true }, @{ Expression = { [int64]$_['Bytes'] }; Descending = $true } | Select-Object -First $Top)
    }
    foreach ($f in $items) {
        $path = [string]$f.Path
        $ext = ''
        try { $ext = [IO.Path]::GetExtension($path).ToLowerInvariant() } catch { $ext = '' }
        $modified = $null
        $created = $null
        try { if ($f.LastWriteUtc -gt [DateTime]::MinValue) { $modified = ([DateTime]$f.LastWriteUtc).ToLocalTime() } } catch { }
        try { if ($f.CreatedUtc -gt [DateTime]::MinValue) { $created = ([DateTime]$f.CreatedUtc).ToLocalTime() } } catch { }
        $rows.Add([ordered]@{
            Volume       = $Volume
            Path         = $path
            Bytes        = [int64]$f.Alloc
            Modified     = $modified
            Created      = $created
            Extension    = $ext
            LogicalBytes = [int64]$f.Bytes
            CloudOnly    = [bool]$f.CloudOnly
        })
    }
    return $rows.ToArray()
}

function Get-WdDiskScanEntry {
    # Per-directory totals recorded by a scan (depth <= MaxDepth), or $null.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Scan, [Parameter(Mandatory = $true)][string]$Path)
    $key = Get-WdDiskNormalizedPath -Path $Path
    if ($null -eq $key) { return $null }
    $e = $null
    if ($Scan.Mode -eq 'Native') {
        $e = $Scan.Raw.Find($key)
    } else {
        $idx = $Scan.Raw['Index']
        if ($null -ne $idx -and $idx.ContainsKey($key)) { $e = $idx[$key] }
    }
    if ($null -eq $e) { return $null }
    return (ConvertTo-WdDiskFolderRow -Entry $e)
}

function Get-WdDiskDirSize {
    # Size of one folder: from a completed volume scan when the folder is at depth <= 3 there, otherwise a direct pass.
    # Returns [ordered] Path, Bytes (allocated), LogicalBytes, Files, Dirs, Denied, CloudOnlyFiles, CloudOnlyBytes, OldBytes, OldFiles, FromCache; $null when missing.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [int]$OldDays = 0,
        [switch]$NoCache
    )
    $p = Get-WdDiskNormalizedPath -Path $Path
    if ($null -eq $p) { return $null }
    if (-not (Test-WdDiskLocalPath -Path $p)) { Add-WdDiskRemotePath -Path $p; return $null }   # never walk SMB / removable media
    if (-not (Test-DirectoryExists -Path $p)) { return $null }
    if (-not $NoCache -and $OldDays -le 0 -and $null -ne $script:WdDiskScans) {
        foreach ($scan in $script:WdDiskScans) {
            if ($null -eq $scan) { continue }
            if ($p.StartsWith([string]$scan.Root, [StringComparison]::OrdinalIgnoreCase)) {
                $row = Get-WdDiskScanEntry -Scan $scan -Path $p
                if ($null -ne $row) {
                    return [ordered]@{ Path = $p; Bytes = [int64]$row['Bytes']; LogicalBytes = [int64]$row['LogicalBytes']; Files = [int64]$row['Files']; Dirs = [int64]$row['Dirs']
                                       Denied = [int]$row['Inaccessible']; CloudOnlyFiles = [int64]$row['CloudOnlyFiles']; CloudOnlyBytes = [int64]$row['CloudOnlyBytes']
                                       OldBytes = [int64]0; OldFiles = [int64]0; FromCache = $true }
                }
            }
        }
    }
    $s = Get-WdDiskScan -Path $p -MaxDepth 0 -OldDays $OldDays
    if ($null -eq $s) { return $null }
    return [ordered]@{ Path = $p; Bytes = $s.Alloc; LogicalBytes = $s.Bytes; Files = $s.Files; Dirs = $s.Dirs; Denied = $s.Denied
                       CloudOnlyFiles = $s.CloudOnlyFiles; CloudOnlyBytes = $s.CloudOnlyBytes; OldBytes = $s.OldBytes; OldFiles = $s.OldFiles; FromCache = $false }
}

function Test-WdDiskReadable {
    # $true when the directory listing is allowed for the current user (never throws).
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    if (-not (Test-DirectoryExists -Path $Path)) { return $false }
    try {
        $en = [IO.Directory]::EnumerateFileSystemEntries($Path).GetEnumerator()
        [void]$en.MoveNext()
        return $true
    } catch { return $false }
}

function Get-WdDiskFileBytes {
    # Sum and count of files directly in a folder whose name matches a regex (no recursion).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Directory, [string]$NameRegex = '.*')
    $bytes = [int64]0
    $count = [int64]0
    $found = New-Object 'System.Collections.Generic.List[string]'
    if (-not (Test-DirectoryExists -Path $Directory)) { return [ordered]@{ Bytes = $bytes; Files = $count; Paths = @() } }
    foreach ($f in @(Get-ChildItem -LiteralPath $Directory -File -Force -ErrorAction SilentlyContinue)) {
        if ($f.Name -notmatch $NameRegex) { continue }
        $bytes += [int64]$f.Length
        $count++
        $found.Add($f.FullName)
    }
    return [ordered]@{ Bytes = $bytes; Files = $count; Paths = $found.ToArray() }
}

# ---------------------------------------------------------------------------------------------
# Volumes
# ---------------------------------------------------------------------------------------------
function Get-WdDiskVolumes {
    [CmdletBinding()]
    param([string[]]$Drives)
    $requested = @()
    if ($null -ne $Drives) {
        foreach ($d in $Drives) {
            if ($null -eq $d) { continue }
            $l = ([string]$d).Trim().TrimEnd('\').TrimEnd(':').ToUpperInvariant()
            if ($l.Length -eq 1) { $requested += $l }
        }
    }
    $sysLetter = ''
    try { $sysLetter = ([string]$env:SystemDrive).TrimEnd(':').ToUpperInvariant() } catch { $sysLetter = 'C' }
    $bitlocker = @{}
    if ($script:IsAdmin) {
        foreach ($ev in @(Get-CimSafe -ClassName Win32_EncryptableVolume -Namespace 'root/CIMV2/Security/MicrosoftVolumeEncryption')) {
            $dl = ([string]$ev.DriveLetter).TrimEnd(':').ToUpperInvariant()
            $st = 'unknown'
            switch ([int]$ev.ProtectionStatus) { 0 { $st = 'off' } 1 { $st = 'on' } }
            if ($dl.Length -eq 1) { $bitlocker[$dl] = $st }
        }
    } else {
        Add-AdminSkip -Item 'BitLocker protection status per volume' -Detail 'Win32_EncryptableVolume is readable only by administrators'
    }
    $list = New-Object 'System.Collections.Generic.List[object]'
    foreach ($v in @(Get-CimSafe -ClassName Win32_Volume -Filter 'DriveType=3')) {
        $letter = ''
        try { $letter = ([string]$v.DriveLetter).TrimEnd(':').ToUpperInvariant() } catch { $letter = '' }
        $hasLetter = ($letter.Length -eq 1)
        $cap = [int64]0; $free = [int64]0
        try { if ($null -ne $v.Capacity) { $cap = [int64]$v.Capacity } } catch { }
        try { if ($null -ne $v.FreeSpace) { $free = [int64]$v.FreeSpace } } catch { }
        $used = $cap - $free
        if ($used -lt 0) { $used = [int64]0 }
        $freePct = $null
        if ($cap -gt 0) { $freePct = [math]::Round((100.0 * $free / $cap), 1, [MidpointRounding]::AwayFromZero) }
        $fs = [string]$v.FileSystem
        # Win32_Volume returns null Capacity/FreeSpace/FileSystem for a BitLocker-locked or RAW/unformatted volume:
        # report it as 'Unknown' with n/a sizes instead of 'OK' with 0 B.
        $known = ($cap -gt 0 -and -not [string]::IsNullOrEmpty($fs))
        # A volume without a letter that is mounted in a folder (Win32_Volume.Name = 'C:\Data\') is listed but not
        # scanned: the walker skips volume mount points, and only lettered volumes are selected below.
        $mountPath = ''
        try {
            $vn = [string]$v.Name
            if (-not $hasLetter -and -not [string]::IsNullOrWhiteSpace($vn) -and -not $vn.StartsWith('\\?\') -and $vn -ne [string]$v.DeviceID) { $mountPath = $vn.TrimEnd('\') }
        } catch { $mountPath = '' }
        $scannable = $hasLetter -and $known -and ($fs -eq 'NTFS' -or $fs -eq 'ReFS')
        $selected = $scannable
        if ($requested.Count -gt 0) { $selected = $scannable -and ($requested -contains $letter) }
        $bl = ''
        if ($hasLetter) { if ($bitlocker.ContainsKey($letter)) { $bl = [string]$bitlocker[$letter] } elseif (-not $script:IsAdmin) { $bl = $script:WdDiskAdminText } }
        $status = 'OK'
        if (-not $known) {
            $status = 'Unknown'
        } elseif ($hasLetter) {
            if ($freePct -lt 5 -or $free -lt 5GB) { $status = 'Critical' }
            elseif ($freePct -lt 10 -or $free -lt 20GB) { $status = 'Warning' }
        }
        $list.Add([ordered]@{
            Letter          = $letter
            Label           = [string]$v.Label
            FileSystem      = $fs
            CapacityBytes   = $(if ($known) { $cap } else { $null })
            UsedBytes       = $(if ($known) { $used } else { $null })
            FreeBytes       = $(if ($known) { $free } else { $null })
            FreePercent     = $freePct
            Status          = $status
            IsSystem        = ($hasLetter -and $letter -eq $sysLetter)
            HasLetter       = $hasLetter
            MountPath       = $mountPath
            Selected        = $selected
            BlockSize       = $(try { [int64]$v.BlockSize } catch { $null })
            Compressed      = $(try { [bool]$v.Compressed } catch { $false })
            IndexingEnabled = $(try { [bool]$v.IndexingEnabled } catch { $null })
            PageFilePresent = $(try { [bool]$v.PageFilePresent } catch { $null })
            BitLocker       = $bl
            DeviceId        = [string]$v.DeviceID
        })
    }
    foreach ($rq in $requested) {
        $hit = $false
        foreach ($x in $list) { if ($x['Letter'] -eq $rq -and $x['Selected']) { $hit = $true } }
        if (-not $hit) { Write-Log -Level Warn -Message ('Drive {0}: is not a fixed NTFS/ReFS volume with a letter and will be skipped' -f $rq) }
    }
    return $list.ToArray()
}

function Get-WdDiskPhysicalDisks {
    [CmdletBinding()]
    param()
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($d in @(Get-CimSafe -ClassName MSFT_PhysicalDisk -Namespace 'root/Microsoft/Windows/Storage')) {
        # Raw CIM values: after Import-Module Storage (auto-loaded by Inventory in -Mode All) the adapted properties are
        # display strings ('SSD', 'NVMe', 'Healthy') and [int]$d.MediaType would throw; the string form is the fallback.
        $media = 'Unspecified'
        switch (Get-WdDiskCimRawInt -Instance $d -Name 'MediaType') { 3 { $media = 'HDD' } 4 { $media = 'SSD' } 5 { $media = 'SCM' } -1 { $media = [string]$d.MediaType } }
        $bus = [string]$d.BusType
        switch (Get-WdDiskCimRawInt -Instance $d -Name 'BusType') { 17 { $bus = 'NVMe' } 11 { $bus = 'SATA' } 7 { $bus = 'USB' } 8 { $bus = 'RAID' } 10 { $bus = 'SAS' } 3 { $bus = 'ATA' } }
        $health = [string]$d.HealthStatus
        switch (Get-WdDiskCimRawInt -Instance $d -Name 'HealthStatus') { 0 { $health = 'Healthy' } 1 { $health = 'Warning' } 2 { $health = 'Unhealthy' } }
        $rows.Add([ordered]@{ Name = [string]$d.FriendlyName; MediaType = $media; BusType = $bus; SizeBytes = $(try { [int64]$d.Size } catch { $null }); HealthStatus = $health })
    }
    return $rows.ToArray()
}

function Add-WdDiskVolumeFindings {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Volumes)
    foreach ($v in @($Volumes)) {
        if ($null -eq $v -or -not $v['HasLetter']) { continue }
        if ($v['Status'] -eq 'Unknown') {
            Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-VOL-UNKNOWN' -Title ('Volume {0}: capacity not readable (BitLocker locked or not formatted)' -f $v['Letter']) -Detail 'Win32_Volume reports no capacity or file system for this lettered volume; it was not scanned.' -Recommendation 'Unlock the drive in Explorer (BitLocker) or check it in Disk Management if it should hold data.'
            continue
        }
        $freeText = '{0} free of {1} ({2} %)' -f (Format-Bytes -Bytes $v['FreeBytes']), (Format-Bytes -Bytes $v['CapacityBytes']), (ConvertTo-InvariantString -Value $v['FreePercent'] -Decimals 1)
        $sysNote = ''
        if ($v['IsSystem']) { $sysNote = ' A nearly full system drive slows Windows down (page file growth, updates, SSD write amplification) and Windows Update fails below about 10 GB free.' }
        if ($v['Status'] -eq 'Critical') {
            Add-Finding -Severity Critical -Category 'Disk' -RuleId 'DSK-FULL-CRIT' -Title ('Volume {0}: is almost full: {1}' -f $v['Letter'], $freeText) -Detail ('Less than 5 % or 5 GB free.' + $sysNote) -Recommendation 'Free space now: see "Potential savings" below (Safe items first), then move large personal files (Downloads, videos, game libraries) to another drive.'
        } elseif ($v['Status'] -eq 'Warning') {
            Add-Finding -Severity Warning -Category 'Disk' -RuleId 'DSK-FULL-WARN' -Title ('Volume {0}: is running low on space: {1}' -f $v['Letter'], $freeText) -Detail ('Less than 10 % or 20 GB free.' + $sysNote) -Recommendation 'Review the cleanup candidates below; keep at least 10-15 % free on an SSD.'
        }
        if ($v['Compressed']) {
            Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-VOL-COMPRESSED' -Title ('Volume {0}: has NTFS compression enabled at volume level' -f $v['Letter']) -Detail 'Every write is compressed on the fly; this costs CPU time on a slow machine.' -Recommendation 'Consider disabling compression for the whole volume (drive Properties > uncheck "Compress this drive") once enough free space exists.'
        }
    }
}

function Get-WdDiskVolumeScan {
    # Full pass over one volume: statistics, sanity ratio, top folders depth 1..3 and top files.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Volume, [int]$TopN = 50)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $letter = [string]$Volume['Letter']
    $root = $letter + ':\'
    $scan = Get-WdDiskScan -Path $root -MaxDepth 3 -LargeFileThreshold $script:WdDiskLargeFileBytes
    if ($null -eq $scan) { throw ('Volume {0} could not be enumerated' -f $root) }
    # Normally the console host stops the pipeline right after Ctrl+C; if it did not (other hosts), do not report partial totals as facts.
    if ($scan.Interrupted) { throw ('Volume {0} scan interrupted by Ctrl+C; partial totals discarded' -f $root) }
    $script:WdDiskScans.Add($scan)
    $used = [int64]$Volume['UsedBytes']
    $ratio = $null
    if ($used -gt 0) { $ratio = [math]::Round(([double]$scan.Alloc / [double]$used), 3, [MidpointRounding]::AwayFromZero) }
    Write-Log -Level Info -Message ([string]::Format($inv, 'Volume {0}: scanned in {1:F1} s ({2}): {3:N0} files, {4:N0} folders, {5} allocated of {6} used (ratio {7}); {8} folders not readable, {9} links skipped, {10} cloud-only files, {11} errors',
        $root, $scan.ElapsedSeconds, $scan.Mode, $scan.Files, $scan.Dirs, (Format-Bytes -Bytes $scan.Alloc), (Format-Bytes -Bytes $used), (ConvertTo-InvariantString -Value $ratio -Decimals 3), $scan.Denied, $scan.SkippedLinks, $scan.CloudOnlyFiles, $scan.Errors))
    $folders = New-Object 'System.Collections.Generic.List[object]'
    foreach ($d in 1..3) {
        foreach ($row in @(Get-WdDiskScanTopFolders -Scan $scan -Depth $d -Top $TopN -Volume $letter)) { $folders.Add($row) }
    }
    $files = @(Get-WdDiskScanTopFiles -Scan $scan -Top $TopN -Volume $letter)
    return [ordered]@{
        Volume         = $letter
        Root           = $root
        WalkerMode     = $scan.Mode
        ElapsedSeconds = $scan.ElapsedSeconds
        Files          = $scan.Files
        Dirs           = $scan.Dirs
        AllocatedBytes = $scan.Alloc
        LogicalBytes   = $scan.Bytes
        UsedBytes      = $used
        SanityRatio    = $ratio
        CloudOnlyFiles = $scan.CloudOnlyFiles
        CloudOnlyBytes = $scan.CloudOnlyBytes
        Denied         = $scan.Denied
        DeniedSample   = @($scan.DeniedPaths | Select-Object -First 20)
        SkippedLinks   = $scan.SkippedLinks
        Errors         = $scan.Errors
        DeepestLevel   = $scan.DeepestLevel
        TopFolders     = $folders.ToArray()
        TopFiles       = $files
    }
}

# ---------------------------------------------------------------------------------------------
# User profiles
# ---------------------------------------------------------------------------------------------
function Get-WdDiskProfilesDirectory {
    [CmdletBinding()]
    param()
    $pd = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -Name 'ProfilesDirectory' -Expand
    if (-not [string]::IsNullOrWhiteSpace([string]$pd)) { return [Environment]::ExpandEnvironmentVariables([string]$pd) }
    return [IO.Path]::Combine(([string]$env:SystemDrive + '\'), 'Users')
}

function Get-WdDiskUserProfiles {
    # Win32_UserProfile (non-special) + folder date + size (from the volume scan cache when possible).
    [CmdletBinding()]
    param()
    $now = Get-Date
    $current = Get-WdDiskNormalizedPath -Path ([string]$env:USERPROFILE)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $cim = @(Get-CimSafe -ClassName Win32_UserProfile)
    foreach ($p in $cim) {
        $special = $false
        try { $special = [bool]$p.Special } catch { $special = $false }
        if ($special) { continue }
        $path = Get-WdDiskNormalizedPath -Path ([string]$p.LocalPath)
        if ($null -eq $path) { continue }
        [void]$seen.Add($path)
        $lastUse = $null
        try { if ($null -ne $p.LastUseTime) { $lastUse = [DateTime]$p.LastUseTime } } catch { $lastUse = $null }
        $loaded = $false
        try { $loaded = [bool]$p.Loaded } catch { }
        $rows.Add((New-WdDiskProfileRow -Path $path -Sid ([string]$p.SID) -Loaded $loaded -LastUseTime $lastUse -Current $current -Now $now -Source 'Win32_UserProfile'))
    }
    # Fallback / complement: profile folders without a Win32_UserProfile entry (orphaned folders).
    $usersDir = Get-WdDiskProfilesDirectory
    if (Test-DirectoryExists -Path $usersDir) {
        foreach ($d in @(Get-ChildItem -LiteralPath $usersDir -Directory -Force -ErrorAction SilentlyContinue)) {
            if (([int]$d.Attributes -band 0x400) -ne 0) { continue }   # junctions such as "All Users", "Default User"
            if ($d.Name -eq 'Public' -or $d.Name -eq 'Default') { continue }
            $path = Get-WdDiskNormalizedPath -Path $d.FullName
            if ($seen.Contains($path)) { continue }
            [void]$seen.Add($path)
            $rows.Add((New-WdDiskProfileRow -Path $path -Sid '' -Loaded $false -LastUseTime $null -Current $current -Now $now -Source 'folder only (no profile entry)'))
        }
        $pub = [IO.Path]::Combine($usersDir, 'Public')
        if (Test-DirectoryExists -Path $pub) { $rows.Add((New-WdDiskProfileRow -Path $pub -Sid '' -Loaded $true -LastUseTime $null -Current $current -Now $now -Source 'shared folder')) }
    }
    $unreadable = 0
    foreach ($r in $rows) { if (-not $r['Readable']) { $unreadable++ } }
    if ($unreadable -gt 0 -and -not $script:IsAdmin) {
        Add-AdminSkip -Item ('{0} user profile folder(s) of other users' -f $unreadable) -Detail 'their sizes and caches are only readable by administrators'
    }
    return $rows.ToArray()
}

function New-WdDiskProfileRow {
    [CmdletBinding()]
    param(
        [string]$Path, [string]$Sid, [bool]$Loaded, [AllowNull()][object]$LastUseTime,
        [AllowNull()][string]$Current, [DateTime]$Now, [string]$Source
    )
    $name = ''
    try { $name = [IO.Path]::GetFileName($Path.TrimEnd('\')) } catch { $name = $Path }
    $exists = Test-DirectoryExists -Path $Path
    $readable = Test-WdDiskReadable -Path $Path
    $folderWrite = $null
    if ($exists) { try { $folderWrite = (New-Object System.IO.DirectoryInfo($Path)).LastWriteTime } catch { $folderWrite = $null } }
    $size = $null
    if ($exists) { $size = Get-WdDiskDirSize -Path $Path }
    # A folder whose listing is denied comes back as Bytes=0/Denied=1 from the walker: that is "unknown", not 0.
    $measured = ($null -ne $size -and $readable)
    $ageDays = $null
    $ref = $null
    if ($null -ne $LastUseTime) { $ref = [DateTime]$LastUseTime } elseif ($null -ne $folderWrite) { $ref = [DateTime]$folderWrite }
    if ($null -ne $ref) { $ageDays = [int][math]::Floor(($Now - $ref).TotalDays); if ($ageDays -lt 0) { $ageDays = 0 } }
    $isCurrent = ($null -ne $Current -and $Path.Equals($Current, [StringComparison]::OrdinalIgnoreCase))
    $old = ((-not $Loaded) -and (-not $isCurrent) -and $null -ne $ageDays -and $ageDays -gt 90 -and $Source -ne 'shared folder')
    return [ordered]@{
        Name            = $name
        Path            = $Path
        SID             = $Sid
        Loaded          = $Loaded
        IsCurrent       = $isCurrent
        LastUseTime     = $LastUseTime
        FolderLastWrite = $folderWrite
        AgeDays         = $ageDays
        Bytes           = $(if ($measured) { [int64]$size['Bytes'] } else { $null })
        Files           = $(if ($measured) { [int64]$size['Files'] } else { $null })
        Inaccessible    = $(if ($null -ne $size) { [int]$size['Denied'] } else { $null })
        Readable        = $readable
        OldProfile      = $old
        Source          = $Source
        LocalAppData    = $(if ($isCurrent -and -not [string]::IsNullOrEmpty($env:LOCALAPPDATA)) { [string]$env:LOCALAPPDATA } else { [IO.Path]::Combine($Path, 'AppData\Local') })
        RoamingAppData  = $(if ($isCurrent -and -not [string]::IsNullOrEmpty($env:APPDATA)) { [string]$env:APPDATA } else { [IO.Path]::Combine($Path, 'AppData\Roaming') })
    }
}

# ---------------------------------------------------------------------------------------------
# Cleanup candidates (catalog framework)
# ---------------------------------------------------------------------------------------------
function Add-WdDiskCandidate {
    # Measures the given paths (files or folders) and records one cleanup candidate. Returns the record.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [AllowNull()][AllowEmptyCollection()][string[]]$Paths,
        [Parameter(Mandatory = $true)][ValidateSet('Safe', 'Review', 'Risky')][string]$SafetyClass,
        [string]$HowToClean = '',
        [string]$Note = '',
        [switch]$AdminOnly,                 # a denied path here is expected without admin: record an admin skip
        [switch]$ReportOnly,                # never reclaimable (informational size)
        [int]$OldDays = 0,                  # reclaimable = bytes of files older than N days
        [Nullable[int64]]$Bytes,            # pre-measured size (paths are not walked)
        [Nullable[int64]]$Files,
        [Nullable[int64]]$Reclaimable,
        [AllowNull()][hashtable]$PathBytes,  # pre-measured: allocated bytes per path (lets Get-WdDiskSavings count nested paths once)
        [switch]$NoCache
    )
    # Locals must not differ from a parameter only by case ($Files vs $files): PowerShell variable names are
    # case-insensitive, so such a local would overwrite the parameter.
    $total = [int64]0; $logical = [int64]0; $fileCount = [int64]0; $dirs = [int64]0; $denied = 0; $old = [int64]0; $cloudFiles = [int64]0; $cloudBytes = [int64]0
    $existing = New-Object 'System.Collections.Generic.List[string]'
    $deniedList = New-Object 'System.Collections.Generic.List[string]'
    $remote = New-Object 'System.Collections.Generic.List[string]'
    $sizes = New-Object 'System.Collections.Generic.List[object]'   # [ordered] Path, Bytes per path when known
    $sizesKnown = $true
    $measured = $false
    if ($null -ne $Bytes) {
        $total = [int64]$Bytes
        $logical = $total
        if ($null -ne $Files) { $fileCount = [int64]$Files }
        $measured = $true
        foreach ($p in @($Paths)) {
            $np = Get-WdDiskNormalizedPath -Path $p
            if ($null -eq $np) { continue }
            if (-not (Test-WdDiskLocalPath -Path $np)) { Add-WdDiskRemotePath -Path $np; $null = Add-WdDiskUniquePath -List $remote -Path $np; continue }
            if (-not (Add-WdDiskUniquePath -List $existing -Path $np)) { continue }
            if ($null -eq $PathBytes) { continue }
            $pb = $null
            foreach ($k in $PathBytes.Keys) { if (([string]$k).TrimEnd('\').Equals($np, [StringComparison]::OrdinalIgnoreCase)) { $pb = $PathBytes[$k]; break } }
            if ($null -ne $pb) { $sizes.Add([ordered]@{ Path = $np; Bytes = [int64]$pb }) } else { $sizesKnown = $false }
        }
        if ($null -eq $PathBytes) {
            if ($existing.Count -eq 1) { $sizes.Add([ordered]@{ Path = $existing[0]; Bytes = $total }) } else { $sizesKnown = $false }
        }
    } else {
        foreach ($p in @($Paths)) {
            if ([string]::IsNullOrWhiteSpace($p)) { continue }
            $np = Get-WdDiskNormalizedPath -Path $p
            if ($null -eq $np) { continue }
            $dup = $false
            foreach ($seenPath in $existing) { if ($seenPath.Equals($np, [StringComparison]::OrdinalIgnoreCase)) { $dup = $true; break } }
            if ($dup) { continue }
            if (-not (Test-WdDiskLocalPath -Path $np)) {
                if ((Test-FileExists -Path $np) -or (Test-DirectoryExists -Path $np)) { Add-WdDiskRemotePath -Path $np; $null = Add-WdDiskUniquePath -List $remote -Path $np }
                continue
            }
            if (Test-FileExists -Path $np) {
                $fb = Get-FileSizeSafe -Path $np
                if ($null -ne $fb) { $total += [int64]$fb; $logical += [int64]$fb; $fileCount++; $existing.Add($np); $measured = $true; $sizes.Add([ordered]@{ Path = $np; Bytes = [int64]$fb }) }
                continue
            }
            if (-not (Test-DirectoryExists -Path $np)) { continue }
            $s = Get-WdDiskDirSize -Path $np -OldDays $OldDays -NoCache:$NoCache
            if ($null -eq $s) { continue }
            $measured = $true
            $existing.Add($np)
            $sizes.Add([ordered]@{ Path = $np; Bytes = [int64]$s['Bytes'] })
            $total += [int64]$s['Bytes']; $logical += [int64]$s['LogicalBytes']; $fileCount += [int64]$s['Files']; $dirs += [int64]$s['Dirs']
            $old += [int64]$s['OldBytes']; $cloudFiles += [int64]$s['CloudOnlyFiles']; $cloudBytes += [int64]$s['CloudOnlyBytes']
            if ([int]$s['Denied'] -gt 0) { $denied += [int]$s['Denied']; $deniedList.Add($np) }
        }
    }
    $needsAdmin = ($denied -gt 0 -and -not $script:IsAdmin)
    $recl = [int64]0
    if ($ReportOnly) { $recl = [int64]0 }
    elseif ($null -ne $Reclaimable) { $recl = [int64]$Reclaimable }
    elseif ($OldDays -gt 0) { $recl = $old }
    else { $recl = $total }
    if ($needsAdmin -and $AdminOnly) {
        Add-AdminSkip -Item ('Cleanup candidate "{0}"' -f $Category) -Detail ('not readable: ' + ($deniedList.ToArray() -join '; '))
    }
    $noteText = $Note
    if ($needsAdmin) {
        $extra = ('{0} folder(s) not readable {1}' -f $denied, $script:WdDiskAdminText)
        if ([string]::IsNullOrEmpty($noteText)) { $noteText = $extra } else { $noteText = $noteText + '. ' + $extra }
    }
    if ($remote.Count -gt 0) {
        $extra = ('{0}: {1}' -f $script:WdDiskRemoteText, ($remote.ToArray() -join '; '))
        if ([string]::IsNullOrEmpty($noteText)) { $noteText = $extra } else { $noteText = $noteText + '. ' + $extra }
    }
    $item = [ordered]@{
        Category       = $Category
        SafetyClass    = $SafetyClass
        Bytes          = $total
        LogicalBytes   = $logical
        Files          = $fileCount
        Dirs           = $dirs
        Inaccessible   = $denied
        Reclaimable    = $recl
        ReportOnly     = [bool]$ReportOnly
        NeedsAdmin     = $needsAdmin
        Exists         = ($existing.Count -gt 0)
        Paths          = $existing.ToArray()
        Path           = ($existing.ToArray() -join '; ')
        HowToClean     = $HowToClean
        Note           = $noteText
        OldBytes       = $old
        CloudOnlyFiles = $cloudFiles
        CloudOnlyBytes = $cloudBytes
        Measured       = $measured
        RemotePaths    = $remote.ToArray()
        PathSizes      = $(if ($sizesKnown) { $sizes.ToArray() } else { $null })   # $null = per-path split unknown
        OverlapBytes   = [int64]0                                                    # set by Get-WdDiskSavings
        OverlapsWith   = ''
    }
    $script:WdDiskCandidates.Add($item)
    return $item
}

function Get-WdDiskProfilePaths {
    # Expands a relative pattern for every readable profile: 'Local\...' (LOCALAPPDATA), 'Roaming\...' (APPDATA) or 'Profile\...'.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowNull()][AllowEmptyCollection()][object[]]$Profiles, [Parameter(Mandatory = $true)][string[]]$Patterns)
    $out = New-Object 'System.Collections.Generic.List[string]'
    foreach ($pr in @($Profiles)) {
        if ($null -eq $pr -or -not $pr['Readable'] -or $pr['Source'] -eq 'shared folder') { continue }
        foreach ($pat in $Patterns) {
            $p = $null
            if ($pat.StartsWith('Local\')) { $p = [IO.Path]::Combine([string]$pr['LocalAppData'], $pat.Substring(6)) }
            elseif ($pat.StartsWith('Roaming\')) { $p = [IO.Path]::Combine([string]$pr['RoamingAppData'], $pat.Substring(8)) }
            elseif ($pat.StartsWith('Profile\')) { $p = [IO.Path]::Combine([string]$pr['Path'], $pat.Substring(8)) }
            elseif ($pat -eq 'Profile') { $p = [string]$pr['Path'] }
            if ($null -ne $p) { $null = Add-WdDiskUniquePath -List $out -Path $p }
        }
    }
    return $out.ToArray()
}

function Get-WdDiskExistingPaths {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][string[]]$Paths)
    $out = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in @($Paths)) {
        if ([string]::IsNullOrWhiteSpace($p)) { continue }
        if ((Test-DirectoryExists -Path $p) -or (Test-FileExists -Path $p)) { $null = Add-WdDiskUniquePath -List $out -Path $p }
    }
    return $out.ToArray()
}

function Get-WdDiskCasedPath {
    # On-disk spelling of an existing path (registry values such as Steam's SteamPath are lower-case); input when missing.
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    try {
        $full = [IO.Path]::GetFullPath($Path.Trim())
        if (-not (Test-DirectoryExists -Path $full) -and -not (Test-FileExists -Path $full)) { return $full.TrimEnd('\') }
        $root = [IO.Path]::GetPathRoot($full)
        $cur = $root
        if ($root.Length -eq 3 -and $root[1] -eq ':') { $cur = $root.ToUpperInvariant() }
        $rest = $full.Substring($root.Length).Trim('\')
        if ($rest.Length -eq 0) { return $cur }
        foreach ($seg in $rest.Split('\')) {
            if ($seg.Length -eq 0) { continue }
            $hits = @()
            try { $hits = @([IO.Directory]::GetFileSystemEntries($cur, $seg)) } catch { $hits = @() }   # FindFirstFile returns the on-disk name
            if ($hits.Count -eq 1) { $cur = [string]$hits[0] } else { $cur = [IO.Path]::Combine($cur, $seg) }
        }
        return $cur
    } catch { return $Path }
}

function Get-WdDiskSubfolders {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [string]$NameRegex = '.*')
    $out = New-Object 'System.Collections.Generic.List[string]'
    if (-not (Test-DirectoryExists -Path $Path)) { return $out.ToArray() }
    foreach ($d in @(Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($d.Name -match $NameRegex) { $out.Add($d.FullName) }
    }
    return $out.ToArray()
}

function Get-WdDiskChromiumProfileNames {
    # Profile directory -> display name from "Local State" (must be read as UTF-8).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$UserDataRoot)
    $map = @{}
    $ls = [IO.Path]::Combine($UserDataRoot, 'Local State')
    if (-not (Test-FileExists -Path $ls)) { return $map }
    try {
        $json = Get-Content -LiteralPath $ls -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $cache = $json.profile.info_cache
        if ($null -ne $cache) {
            foreach ($prop in $cache.PSObject.Properties) {
                $n = ''
                try { $n = [string]$prop.Value.name } catch { $n = '' }
                if (-not [string]::IsNullOrEmpty($n)) { $map[[string]$prop.Name] = $n }
            }
        }
    } catch { }
    return $map
}

# ---------------------------------------------------------------------------------------------
# Cleanup catalog - system side (research section B)
# ---------------------------------------------------------------------------------------------
function Get-WdDiskPageFileInfo {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Volumes)
    $ramBytes = $null
    foreach ($os in @(Get-CimSafe -ClassName Win32_OperatingSystem -Property @('TotalVisibleMemorySize'))) { try { $ramBytes = [int64]$os.TotalVisibleMemorySize * 1024 } catch { } }
    $auto = $null
    foreach ($cs in @(Get-CimSafe -ClassName Win32_ComputerSystem -Property @('AutomaticManagedPagefile'))) { try { $auto = [bool]$cs.AutomaticManagedPagefile } catch { } }
    $usage = New-Object 'System.Collections.Generic.List[object]'
    foreach ($u in @(Get-CimSafe -ClassName Win32_PageFileUsage)) {
        $usage.Add([ordered]@{ Name = [string]$u.Name; AllocatedBytes = $(try { [int64]$u.AllocatedBaseSize * 1MB } catch { $null }); CurrentUsageBytes = $(try { [int64]$u.CurrentUsage * 1MB } catch { $null }); PeakUsageBytes = $(try { [int64]$u.PeakUsage * 1MB } catch { $null }) })
    }
    $files = New-Object 'System.Collections.Generic.List[object]'
    foreach ($v in @($Volumes)) {
        if ($null -eq $v -or -not $v['HasLetter']) { continue }
        foreach ($n in @('pagefile.sys', 'swapfile.sys', 'hiberfil.sys')) {
            $p = '{0}:\{1}' -f $v['Letter'], $n
            $b = Get-FileSizeSafe -Path $p
            if ($null -ne $b) { $files.Add([ordered]@{ Path = $p; Bytes = [int64]$b; Kind = $n }) }
        }
    }
    $hiberboot = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled' -Default $null
    $hiberEnabled = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled' -Default $null
    $hiberType = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HiberFileType' -Default $null
    $pagingSetting = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management' -Name 'PagingFiles' -Default $null
    return [ordered]@{
        RamBytes                 = $ramBytes
        AutomaticManagedPagefile = $auto
        PagingFilesSetting       = @($pagingSetting)
        Usage                    = $usage.ToArray()
        Files                    = $files.ToArray()
        FastStartupEnabled       = $(if ($null -eq $hiberboot) { $true } else { ([int]$hiberboot -ne 0) })   # absent = default on
        HibernateEnabledRegistry = $hiberEnabled
        HiberFileType            = $hiberType
    }
}

function Add-WdDiskSystemCandidates {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Volumes, [AllowNull()][object[]]$Profiles, [int]$TopN = 50)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $win = [string]$env:windir
    if ([string]::IsNullOrEmpty($win)) { $win = 'C:\Windows' }
    $pd = [string]$env:ProgramData
    if ([string]::IsNullOrEmpty($pd)) { $pd = 'C:\ProgramData' }
    $sysRoot = ([string]$env:SystemDrive).TrimEnd('\') + '\'
    $lettered = @($Volumes | Where-Object { $null -ne $_ -and $_['HasLetter'] })
    $extra = [ordered]@{}

    # 1. Recycle Bin (per volume; other users' SID folders are denied without admin)
    $null = Invoke-Safely -Name 'Disk.Cleanup.RecycleBin' -ScriptBlock {
        $paths = @()
        foreach ($v in $lettered) { $paths += ('{0}:\$Recycle.Bin' -f $v['Letter']) }
        $note = ''
        try {
            $shell = New-Object -ComObject Shell.Application
            $items = $shell.NameSpace(0xA).Items()
            $note = ('{0} item(s) in the current user''s Recycle Bin' -f ([int]$items.Count).ToString($inv))
        } catch { $note = '' }
        Add-WdDiskCandidate -Category 'Recycle Bin' -Paths $paths -SafetyClass Safe -Note $note -HowToClean 'Right-click Recycle Bin > Empty Recycle Bin; Storage Sense; cleanmgr "Recycle Bin"' | Out-Null
    }

    # 2-3. Temp folders
    $null = Invoke-Safely -Name 'Disk.Cleanup.UserTemp' -ScriptBlock {
        $paths = @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\Temp'))
        $envTemp = Get-WdDiskNormalizedPath -Path (Get-WdDiskLongPath -Path ([string]$env:TEMP))
        if ($null -ne $envTemp -and -not ($paths -contains $envTemp)) { $paths += $envTemp }
        $unreadable = @($Profiles | Where-Object { $null -ne $_ -and -not $_['Readable'] }).Count
        $note = 'Reclaimable = files older than 1 day (files in use are skipped by the cleanup tools)'
        if ($unreadable -gt 0 -and -not $script:IsAdmin) { $note += ('; {0} profile(s) not readable {1}' -f $unreadable, $script:WdDiskAdminText) }
        Add-WdDiskCandidate -Category 'User temp folders (%TEMP%)' -Paths $paths -SafetyClass Safe -OldDays 1 -NoCache -Note $note -HowToClean 'Settings > System > Storage > Temporary files; Storage Sense; cleanmgr "Temporary files"' | Out-Null
    }
    $null = Invoke-Safely -Name 'Disk.Cleanup.SystemTemp' -ScriptBlock {
        Add-WdDiskCandidate -Category 'System temp (Windows\Temp, SystemTemp)' -Paths @("$win\Temp", "$win\SystemTemp") -SafetyClass Safe -AdminOnly -OldDays 1 -NoCache -HowToClean 'cleanmgr "Temporary files" started as administrator; Storage Sense' | Out-Null
    }

    # 4. Windows Update download cache (+ DataStore report only)
    $null = Invoke-Safely -Name 'Disk.Cleanup.WindowsUpdate' -ScriptBlock {
        Add-WdDiskCandidate -Category 'Windows Update download cache' -Paths @("$win\SoftwareDistribution\Download") -SafetyClass Risky -HowToClean 'Settings > Storage > Temporary files > "Windows Update Cleanup"; cleanmgr; Windows re-downloads what it needs' -Note 'Do not delete SoftwareDistribution\DataStore (update history database)' | Out-Null
        Add-WdDiskCandidate -Category 'Windows Update history database (DataStore)' -Paths @("$win\SoftwareDistribution\DataStore") -SafetyClass Risky -ReportOnly -HowToClean 'Report only: keep it' | Out-Null
    }

    # 5. Delivery Optimization
    $null = Invoke-Safely -Name 'Disk.Cleanup.DeliveryOptimization' -ScriptBlock {
        $paths = @("$win\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache", "$pd\Microsoft\Windows\DeliveryOptimization\Cache")
        $snapBytes = $null
        if (Get-Command -Name 'Get-DeliveryOptimizationPerfSnap' -ErrorAction SilentlyContinue) {
            $snap = Invoke-Safely -Name 'Disk.Cleanup.DeliveryOptimization.Snap' -Quiet -ScriptBlock { Get-DeliveryOptimizationPerfSnap -WarningAction SilentlyContinue -ErrorAction Stop }
            if ($null -ne $snap) { try { $snapBytes = [int64]$snap.CacheSizeBytes } catch { $snapBytes = $null } }
        }
        $c = Add-WdDiskCandidate -Category 'Delivery Optimization cache' -Paths $paths -SafetyClass Risky -AdminOnly -HowToClean 'Delete-DeliveryOptimizationCache (administrator PowerShell); cleanmgr "Delivery Optimization Files"'
        if ($null -ne $snapBytes) {
            $c['Note'] = ('Cache size reported by Delivery Optimization: {0}' -f (Format-Bytes -Bytes $snapBytes)) + $(if ($c['Note']) { '. ' + $c['Note'] } else { '' })
            if ($snapBytes -gt $c['Bytes']) { $c['Bytes'] = $snapBytes; $c['LogicalBytes'] = $snapBytes; $c['Reclaimable'] = $snapBytes }
        }
    }

    # 6-7. Previous installation and setup folders
    $null = Invoke-Safely -Name 'Disk.Cleanup.WindowsOld' -ScriptBlock {
        $c = Add-WdDiskCandidate -Category 'Previous Windows installation (Windows.old)' -Paths @([IO.Path]::Combine($sysRoot, 'Windows.old')) -SafetyClass Risky -HowToClean 'Settings > Storage > Temporary files > "Previous Windows installation(s)"; cleanmgr; removed automatically after 10 days' -Note 'Needed only to roll back the last feature update'
        if ($c['Exists'] -and $c['Bytes'] -gt 0) {
            Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-WINDOWS-OLD' -Title ('Windows.old occupies {0}' -f (Format-Bytes -Bytes $c['Bytes'])) -Detail 'The previous Windows installation is kept for 10 days to allow a rollback.' -Recommendation 'If the current Windows works fine: Settings > System > Storage > Temporary files > "Previous Windows installation(s)".'
        }
    }
    $null = Invoke-Safely -Name 'Disk.Cleanup.SetupFolders' -ScriptBlock {
        $names = @('$WINDOWS.~BT', '$Windows.~WS', '$SysReset', 'ESD', '$GetCurrent', 'OneDriveTemp')
        $paths = @()
        foreach ($n in $names) { $paths += [IO.Path]::Combine($sysRoot, $n) }
        Add-WdDiskCandidate -Category 'Windows setup working folders ($WINDOWS.~BT, ~WS, ESD, $SysReset, $GetCurrent)' -Paths $paths -SafetyClass Risky -HowToClean 'cleanmgr "Temporary Windows installation files" / "Windows ESD installation files"; Storage Sense' | Out-Null
        Add-WdDiskCandidate -Category 'Windows setup logs (Panther)' -Paths @("$win\Panther") -SafetyClass Review -HowToClean 'cleanmgr "Temporary files"; usually NTFS-compressed logs' | Out-Null
    }

    # 8. Windows logs
    $null = Invoke-Safely -Name 'Disk.Cleanup.WindowsLogs' -ScriptBlock {
        Add-WdDiskCandidate -Category 'Windows logs (CBS, DISM, WindowsUpdate, MoSetup, System32\LogFiles, USOShared)' -Paths @("$win\Logs\CBS", "$win\Logs\DISM", "$win\Logs\WindowsUpdate", "$win\Logs\MoSetup", "$win\System32\LogFiles", "$pd\USOShared\Logs") -SafetyClass Review -HowToClean 'cleanmgr "Temporary files" removes most of Windows\Logs; do not touch System32\winevt\Logs' | Out-Null
        Add-WdDiskCandidate -Category 'Event logs (winevt\Logs)' -Paths @("$win\System32\winevt\Logs") -SafetyClass Risky -ReportOnly -HowToClean 'Report only: clear individual logs in Event Viewer only when asked to' | Out-Null
    }

    # 9. Prefetch (do not clean)
    $null = Invoke-Safely -Name 'Disk.Cleanup.Prefetch' -ScriptBlock {
        Add-WdDiskCandidate -Category 'Prefetch (do NOT clean)' -Paths @("$win\Prefetch") -SafetyClass Risky -ReportOnly -AdminOnly -HowToClean 'Nothing: Windows trims it itself (max 128 entries). Deleting it makes application starts slower for days' | Out-Null
    }

    # 10. Windows Error Reporting
    $null = Invoke-Safely -Name 'Disk.Cleanup.WER' -ScriptBlock {
        $paths = @("$pd\Microsoft\Windows\WER\ReportQueue", "$pd\Microsoft\Windows\WER\ReportArchive", "$pd\Microsoft\Windows\WER\Temp")
        $paths += @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\Microsoft\Windows\WER\ReportQueue', 'Local\Microsoft\Windows\WER\ReportArchive', 'Local\CrashDumps'))
        Add-WdDiskCandidate -Category 'Windows Error Reporting files and crash dumps (WER, CrashDumps)' -Paths $paths -SafetyClass Safe -HowToClean 'cleanmgr "Windows Error Reporting files"; Storage Sense' -Note 'Keep them while an application crash is being investigated' | Out-Null
    }

    # 11. Kernel dumps
    $null = Invoke-Safely -Name 'Disk.Cleanup.KernelDumps' -ScriptBlock {
        $mode = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'CrashDumpEnabled' -Default $null
        $modeText = 'unknown'
        switch ([int]$mode) { 0 { $modeText = 'none' } 1 { $modeText = 'complete memory dump' } 2 { $modeText = 'kernel memory dump' } 3 { $modeText = 'small memory dump (minidump)' } 7 { $modeText = 'automatic memory dump' } }
        $dumpFile = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'DumpFile' -Default "$win\MEMORY.DMP" -Expand
        $miniDir = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl' -Name 'MinidumpDir' -Default "$win\Minidump" -Expand
        $dumpFile = [Environment]::ExpandEnvironmentVariables([string]$dumpFile)
        $miniDir = [Environment]::ExpandEnvironmentVariables([string]$miniDir)
        Add-WdDiskCandidate -Category 'Kernel crash dumps (MEMORY.DMP, Minidump)' -Paths @($dumpFile, $miniDir) -SafetyClass Review -HowToClean 'cleanmgr "System error memory dump files" / "System error minidump files"' -Note ('Crash dump setting: ' + $modeText + '. Keep the newest dump while blue screens are being investigated') | Out-Null
        Add-WdDiskCandidate -Category 'Live kernel reports (LiveKernelReports)' -Paths @("$win\LiveKernelReports") -SafetyClass Review -AdminOnly -HowToClean 'cleanmgr "System error memory dump files"; large .dmp files here record hangs, not crashes' | Out-Null
    }

    # 12-13. hiberfil / pagefile / swapfile
    $null = Invoke-Safely -Name 'Disk.Cleanup.PageFiles' -ScriptBlock {
        $pf = Get-WdDiskPageFileInfo -Volumes $Volumes
        $extra['PageFiles'] = $pf
        $hiber = @($pf['Files'] | Where-Object { $_['Kind'] -eq 'hiberfil.sys' })
        $hiberBytes = [int64]0
        foreach ($h in $hiber) { $hiberBytes += [int64]$h['Bytes'] }
        $ramText = ''
        if ($null -ne $pf['RamBytes'] -and $pf['RamBytes'] -gt 0) { $ramText = ('RAM {0}' -f (Format-Bytes -Bytes $pf['RamBytes'])) }
        if ($hiber.Count -gt 0) {
            $fast = $(if ($pf['FastStartupEnabled']) { 'on' } else { 'off' })
            $note = ('Hibernation file = {0} of RAM ({1}); Fast Startup {2}. Disabling hibernation also disables Fast Startup' -f $(if ($pf['RamBytes'] -gt 0) { ([math]::Round(100.0 * $hiberBytes / $pf['RamBytes'], 0, [MidpointRounding]::AwayFromZero)).ToString($inv) + ' %' } else { 'n/a' }), $ramText, $fast)
            Add-WdDiskCandidate -Category 'Hibernation file (hiberfil.sys)' -Paths @($hiber | ForEach-Object { $_['Path'] }) -SafetyClass Review -Note $note -HowToClean 'powercfg /h off (administrator) frees it entirely; powercfg /h /type reduced keeps Fast Startup with a smaller file' | Out-Null
        }
        $page = @($pf['Files'] | Where-Object { $_['Kind'] -ne 'hiberfil.sys' })
        if ($page.Count -gt 0) {
            $pageBytes = [int64]0
            foreach ($p in $page) { $pageBytes += [int64]$p['Bytes'] }
            $peak = [int64]0
            foreach ($u in @($pf['Usage'])) { if ($null -ne $u['PeakUsageBytes'] -and [int64]$u['PeakUsageBytes'] -gt $peak) { $peak = [int64]$u['PeakUsageBytes'] } }
            $autoText = $(if ($pf['AutomaticManagedPagefile'] -eq $true) { 'system managed' } elseif ($pf['AutomaticManagedPagefile'] -eq $false) { 'custom size' } else { 'unknown' })
            $note = ('Page file {0}, peak use since boot {1}, {2}' -f $autoText, (Format-Bytes -Bytes $peak), $ramText)
            Add-WdDiskCandidate -Category 'Page file and swap file (pagefile.sys, swapfile.sys)' -Paths @($page | ForEach-Object { $_['Path'] }) -SafetyClass Review -ReportOnly -Note $note -HowToClean 'Report only: SystemPropertiesPerformance.exe > Advanced > Virtual memory (system managed is recommended); never delete the file' | Out-Null
            if ($pageBytes -gt 8GB -and $peak -gt 0 -and $pageBytes -gt (3 * $peak) -and $null -ne $pf['RamBytes'] -and $pageBytes -gt $pf['RamBytes']) {
                Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-PAGEFILE-LARGE' -Title ('Page file is {0} while peak use since boot is {1}' -f (Format-Bytes -Bytes $pageBytes), (Format-Bytes -Bytes $peak)) -Detail ('A system-managed page file grows after memory pressure and does not shrink again. ' + $ramText) -Recommendation 'If space is tight: SystemPropertiesPerformance.exe > Advanced > Virtual memory: set an initial size of about 1.5 x RAM and let the maximum stay system managed, or keep it system managed and free space elsewhere.'
            }
        }
    }

    # 14. WinSxS (report only)
    $null = Invoke-Safely -Name 'Disk.Cleanup.WinSxS' -ScriptBlock {
        Add-WdDiskCandidate -Category 'Component store (WinSxS)' -Paths @("$win\WinSxS") -SafetyClass Risky -ReportOnly -HowToClean 'Dism /Online /Cleanup-Image /StartComponentCleanup (administrator); cleanmgr "Windows Update Cleanup"; the task \Microsoft\Windows\Servicing\StartComponentCleanup does it automatically' -Note 'Apparent size: hard links are counted more than once, the real unique size is smaller (see -Deep)' | Out-Null
    }

    # 15. Windows\Installer with orphan detection (report only)
    $null = Invoke-Safely -Name 'Disk.Cleanup.Installer' -ScriptBlock {
        $orph = Get-WdDiskInstallerOrphans -InstallerDir "$win\Installer"
        $extra['InstallerCache'] = $orph
        $note = ''
        if ($null -ne $orph) {
            $note = ('{0} .msi/.msp files; {1} not referenced by any installed product or patch ({2}) - orphan detection can have false positives (per-user installs)' -f ([int64]$orph['PackageFiles']).ToString($inv), ([int64]$orph['OrphanFiles']).ToString($inv), (Format-Bytes -Bytes $orph['OrphanBytes']))
            if ([int64]$orph['OrphanBytes'] -gt 1GB) {
                Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-MSI-ORPHANS' -Title ('Windows\Installer holds {0} of .msi/.msp files that no installed product references' -f (Format-Bytes -Bytes $orph['OrphanBytes'])) -Detail $note -Recommendation 'There is no built-in cleanup. Do not delete files here by hand: referenced packages are needed for repair and uninstall. Third-party "PatchCleaner"-style tools exist; use them only after a backup.'
            }
        }
        Add-WdDiskCandidate -Category 'Windows Installer cache (Windows\Installer)' -Paths @("$win\Installer") -SafetyClass Risky -ReportOnly -Note $note -HowToClean 'Report only: no built-in tool; deleting referenced packages breaks repair/uninstall' | Out-Null
    }

    # 18. Windows Search index
    $null = Invoke-Safely -Name 'Disk.Cleanup.SearchIndex' -ScriptBlock {
        $dataDir = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search' -Name 'DataDirectory' -Default "$pd\Microsoft\Search\Data" -Expand
        $dataDir = [Environment]::ExpandEnvironmentVariables([string]$dataDir)
        Add-WdDiskCandidate -Category 'Windows Search index' -Paths @($dataDir) -SafetyClass Risky -ReportOnly -AdminOnly -HowToClean 'Report only: Settings > Privacy & security > Searching Windows > Advanced indexing options > Rebuild, or exclude large folders; never delete the database' | Out-Null
    }

    # 20. Font caches
    $null = Invoke-Safely -Name 'Disk.Cleanup.FontCache' -ScriptBlock {
        $paths = @("$win\ServiceProfiles\LocalService\AppData\Local\FontCache")
        $paths += @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\FontCache'))
        Add-WdDiskCandidate -Category 'Font cache' -Paths $paths -SafetyClass Risky -ReportOnly -AdminOnly -HowToClean 'Report only: only for font glitches - stop the "Windows Font Cache Service", delete *.dat, start it again' | Out-Null
    }

    # 21. Defender
    $null = Invoke-Safely -Name 'Disk.Cleanup.Defender' -ScriptBlock {
        $def = "$pd\Microsoft\Windows Defender"
        Add-WdDiskCandidate -Category 'Microsoft Defender scan history and definition backups' -Paths @("$def\Scans\History", "$def\Definition Updates\Backup", "$def\Support", "$def\LocalCopy") -SafetyClass Risky -AdminOnly -HowToClean 'cleanmgr "Microsoft Defender Antivirus" handler (administrator)' | Out-Null
        Add-WdDiskCandidate -Category 'Microsoft Defender platform versions' -Paths @("$def\Platform") -SafetyClass Risky -ReportOnly -HowToClean 'Report only: Windows removes superseded platform versions itself' | Out-Null
    }

    # 33. Shadow storage / System Restore
    $null = Invoke-Safely -Name 'Disk.Cleanup.ShadowStorage' -ScriptBlock {
        $diskPct = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore\Cfg' -Name 'DiskPercent' -Default $null
        $srOn = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore' -Name 'RPSessionInterval' -Default $null
        $note = ''
        if ($null -ne $srOn) { $note = ('System Restore: {0}' -f $(if ([int]$srOn -ne 0) { 'on' } else { 'off' })) }
        if ($null -ne $diskPct) { $note += (' (max {0} % of the volume)' -f ([int]$diskPct).ToString($inv)) }
        $sviPaths = @()
        foreach ($v in $lettered) { $sviPaths += ('{0}:\System Volume Information' -f $v['Letter']) }
        if ($script:IsAdmin) {
            $usedBytes = [int64]0; $maxBytes = [int64]0; $shadowCount = 0
            foreach ($ss in @(Get-CimSafe -ClassName Win32_ShadowStorage)) { try { $usedBytes += [int64]$ss.UsedSpace; $maxBytes += [int64]$ss.MaxSpace } catch { } }
            $shadowCount = @(Get-CimSafe -ClassName Win32_ShadowCopy).Count
            $extra['ShadowStorage'] = [ordered]@{ UsedBytes = $usedBytes; MaxBytes = $maxBytes; ShadowCopies = $shadowCount; SystemRestoreOn = $srOn; DiskPercent = $diskPct }
            Add-WdDiskCandidate -Category 'System Restore points / shadow copies' -Paths $sviPaths -SafetyClass Risky -Bytes $usedBytes -Files $shadowCount -Reclaimable ([int64]0) -Note ($note + ('; {0} shadow copies, max {1}' -f $shadowCount, (Format-Bytes -Bytes $maxBytes))) -HowToClean 'SystemPropertiesProtection.exe > Configure > Max Usage; vssadmin resize shadowstorage /for=C: /on=C: /maxsize=5% (administrator); cleanmgr > More Options' | Out-Null
        } else {
            $extra['ShadowStorage'] = [ordered]@{ UsedBytes = $null; MaxBytes = $null; ShadowCopies = $null; SystemRestoreOn = $srOn; DiskPercent = $diskPct; Note = $script:WdDiskAdminText }
            Add-AdminSkip -Item 'Shadow storage size (System Restore points, Win32_ShadowStorage)' -Detail 'System Volume Information and the VSS provider are readable only by administrators'
            Add-WdDiskCandidate -Category 'System Restore points / shadow copies' -Paths $sviPaths -SafetyClass Risky -AdminOnly -ReportOnly -Note ($note + '; size ' + $script:WdDiskAdminText) -HowToClean 'SystemPropertiesProtection.exe > Configure > Max Usage; cleanmgr > More Options' | Out-Null
        }
    }

    # 34. File History / backups
    $null = Invoke-Safely -Name 'Disk.Cleanup.FileHistory' -ScriptBlock {
        $paths = @("$pd\Microsoft\Windows\Backup")
        foreach ($v in $lettered) { $paths += ('{0}:\FileHistory' -f $v['Letter']); $paths += ('{0}:\WindowsImageBackup' -f $v['Letter']) }
        $cfg = @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\Microsoft\Windows\FileHistory\Configuration\Config1.xml'))
        $configured = $false
        foreach ($c in $cfg) { if (Test-FileExists -Path $c) { $configured = $true } }
        Add-WdDiskCandidate -Category 'File History / Windows Backup data' -Paths $paths -SafetyClass Review -Note ('File History configured for a readable profile: {0}' -f $(if ($configured) { 'yes' } else { 'no' })) -HowToClean 'Control Panel > File History > Advanced settings > Clean up versions' | Out-Null
    }

    # 38. chkdsk fragments
    $null = Invoke-Safely -Name 'Disk.Cleanup.FoundFolders' -ScriptBlock {
        $paths = @()
        foreach ($v in $lettered) { $paths += @(Get-WdDiskSubfolders -Path ('{0}:\' -f $v['Letter']) -NameRegex '^found\.\d{3}$') }
        Add-WdDiskCandidate -Category 'chkdsk recovered fragments (found.000)' -Paths $paths -SafetyClass Safe -HowToClean 'cleanmgr "Old Chkdsk files"' | Out-Null
    }

    # 40. Driver store (report only)
    $null = Invoke-Safely -Name 'Disk.Cleanup.DriverStore' -ScriptBlock {
        Add-WdDiskCandidate -Category 'Driver store (DriverStore\FileRepository)' -Paths @("$win\System32\DriverStore\FileRepository") -SafetyClass Risky -ReportOnly -HowToClean 'Report only: pnputil /delete-driver oemNN.inf for superseded GPU driver packages (administrator); cleanmgr "Device driver packages"' | Out-Null
    }

    # 39. Reserved storage (registry only)
    $null = Invoke-Safely -Name 'Disk.Cleanup.ReservedStorage' -ScriptBlock {
        $shipped = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' -Name 'ShippedWithReserves' -Default $null
        $passed = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager' -Name 'PassedPolicy' -Default $null
        $extra['ReservedStorage'] = [ordered]@{ ShippedWithReserves = $shipped; PassedPolicy = $passed; Note = 'about 7 GB reserved for updates is normal; Get-WindowsReservedStorageState needs administrator' }
    }

    # 27. Hyper-V default location
    $null = Invoke-Safely -Name 'Disk.Cleanup.HyperV' -ScriptBlock {
        $paths = @()
        $def = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization' -Name 'DefaultVirtualHardDiskPath' -Default $null -Expand
        if (-not [string]::IsNullOrWhiteSpace([string]$def)) { $paths += [Environment]::ExpandEnvironmentVariables([string]$def) }
        $paths += [IO.Path]::Combine([string]$env:PUBLIC, 'Documents\Hyper-V\Virtual hard disks')
        Add-WdDiskCandidate -Category 'Hyper-V virtual hard disks' -Paths $paths -SafetyClass Review -HowToClean 'Hyper-V Manager: delete checkpoints (merges .avhdx), remove unused VMs' | Out-Null
    }

    # 28 (Risky part). Installer package caches
    $null = Invoke-Safely -Name 'Disk.Cleanup.PackageCache' -ScriptBlock {
        Add-WdDiskCandidate -Category 'Installer package caches (ProgramData\Package Cache, Visual Studio Packages)' -Paths @("$pd\Package Cache", "$pd\Microsoft\VisualStudio\Packages") -SafetyClass Risky -ReportOnly -HowToClean 'Report only: needed for repair/uninstall; Visual Studio Installer > "Disable or move the package cache"' | Out-Null
    }

    return $extra
}

function Get-WdDiskInstallerOrphans {
    # .msi/.msp files in Windows\Installer not referenced by LocalPackage of any product/patch under Installer\UserData.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$InstallerDir)
    if (-not (Test-DirectoryExists -Path $InstallerDir)) { return $null }
    $referenced = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $userData = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData'
    foreach ($sidKey in @(Get-ChildItem -LiteralPath $userData -ErrorAction SilentlyContinue)) {
        foreach ($kind in @('Products', 'Patches')) {
            $kindPath = [IO.Path]::Combine($sidKey.PSPath, $kind)
            foreach ($item in @(Get-ChildItem -LiteralPath $kindPath -ErrorAction SilentlyContinue)) {
                $lp = $null
                if ($kind -eq 'Products') {
                    $ip = [IO.Path]::Combine($item.PSPath, 'InstallProperties')
                    $k = Get-Item -LiteralPath $ip -ErrorAction SilentlyContinue
                    if ($null -ne $k) { $lp = $k.GetValue('LocalPackage') }
                } else {
                    $lp = $item.GetValue('LocalPackage')
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$lp)) { [void]$referenced.Add([string]$lp) }
            }
        }
    }
    $files = @(Get-ChildItem -LiteralPath $InstallerDir -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.Extension -eq '.msi' -or $_.Extension -eq '.msp' })
    $orphanBytes = [int64]0; $orphanFiles = [int64]0; $totalBytes = [int64]0
    $sample = New-Object 'System.Collections.Generic.List[string]'
    foreach ($f in $files) {
        $totalBytes += [int64]$f.Length
        if (-not $referenced.Contains($f.FullName)) {
            $orphanBytes += [int64]$f.Length
            $orphanFiles++
            if ($sample.Count -lt 20) { $sample.Add($f.FullName) }
        }
    }
    return [ordered]@{ PackageFiles = [int64]$files.Count; PackageBytes = $totalBytes; ReferencedPackages = [int64]$referenced.Count; OrphanFiles = $orphanFiles; OrphanBytes = $orphanBytes; OrphanSample = $sample.ToArray() }
}

# ---------------------------------------------------------------------------------------------
# Cleanup catalog - user side (browsers, app caches, cloud, games, VMs, dev caches, personal folders)
# ---------------------------------------------------------------------------------------------
function Add-WdDiskBrowserCandidates {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Profiles)
    $cacheDirs = @('Cache', 'Code Cache', 'GPUCache', 'Service Worker\CacheStorage', 'Service Worker\ScriptCache', 'DawnCache', 'DawnGraphiteCache', 'DawnWebGPUCache', 'GrShaderCache', 'ShaderCache', 'Media Cache', 'GraphiteDawnCache')
    $browsers = @(
        @{ Name = 'Google Chrome';   Root = 'Local\Google\Chrome\User Data';              RootIsProfile = $false },
        @{ Name = 'Microsoft Edge';  Root = 'Local\Microsoft\Edge\User Data';             RootIsProfile = $false },
        @{ Name = 'Yandex Browser';  Root = 'Local\Yandex\YandexBrowser\User Data';       RootIsProfile = $false },
        @{ Name = 'Brave';           Root = 'Local\BraveSoftware\Brave-Browser\User Data'; RootIsProfile = $false },
        @{ Name = 'Vivaldi';         Root = 'Local\Vivaldi\User Data';                    RootIsProfile = $false },
        @{ Name = 'Chromium';        Root = 'Local\Chromium\User Data';                   RootIsProfile = $false },
        @{ Name = 'Opera';           Root = 'Local\Opera Software\Opera Stable';          RootIsProfile = $true },
        @{ Name = 'Opera GX';        Root = 'Local\Opera Software\Opera GX Stable';       RootIsProfile = $true }
    )
    foreach ($b in $browsers) {
        $null = Invoke-Safely -Name ('Disk.Cleanup.Browser.' + $b.Name) -ScriptBlock {
            $paths = New-Object 'System.Collections.Generic.List[string]'
            $names = New-Object 'System.Collections.Generic.List[string]'
            foreach ($root in @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @($b.Root))) {
                if (-not (Test-DirectoryExists -Path $root)) { continue }
                $profileDirs = @()
                if ($b.RootIsProfile) { $profileDirs = @($root) }
                else {
                    $profileDirs = @(Get-WdDiskSubfolders -Path $root -NameRegex '^(Default|Profile \d+|Guest Profile|System Profile)$')
                    foreach ($cd in @('ShaderCache', 'GrShaderCache', 'GraphiteDawnCache')) { $p = [IO.Path]::Combine($root, $cd); if (Test-DirectoryExists -Path $p) { $paths.Add($p) } }
                    $map = Get-WdDiskChromiumProfileNames -UserDataRoot $root
                    foreach ($pdir in $profileDirs) {
                        $leaf = [IO.Path]::GetFileName($pdir)
                        if ($map.ContainsKey($leaf)) { $names.Add(('{0} ({1})' -f $leaf, $map[$leaf])) } else { $names.Add($leaf) }
                    }
                }
                foreach ($pdir in $profileDirs) {
                    foreach ($cd in $cacheDirs) { $p = [IO.Path]::Combine($pdir, $cd); if (Test-DirectoryExists -Path $p) { $paths.Add($p) } }
                }
            }
            if ($paths.Count -eq 0) { return }
            $note = ''
            if ($names.Count -gt 0) { $note = 'Profiles: ' + (($names.ToArray() | Select-Object -Unique) -join ', ') }
            $c = Add-WdDiskCandidate -Category ('Browser cache: ' + $b.Name) -Paths $paths.ToArray() -SafetyClass Safe -Note $note -HowToClean 'Close the browser, then Settings > Privacy > Clear browsing data > "Cached images and files" (never delete History or Login Data by hand)'
            $script:WdDiskBrowserBytes += [int64]$c['Bytes']
        }
    }
    $null = Invoke-Safely -Name 'Disk.Cleanup.Browser.Firefox' -ScriptBlock {
        $paths = New-Object 'System.Collections.Generic.List[string]'
        foreach ($root in @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\Mozilla\Firefox\Profiles'))) {
            foreach ($pdir in @(Get-WdDiskSubfolders -Path $root)) {
                foreach ($cd in @('cache2', 'startupCache', 'shader-cache', 'thumbnails')) { $p = [IO.Path]::Combine($pdir, $cd); if (Test-DirectoryExists -Path $p) { $paths.Add($p) } }
            }
        }
        if ($paths.Count -eq 0) { return }
        $c = Add-WdDiskCandidate -Category 'Browser cache: Firefox' -Paths $paths.ToArray() -SafetyClass Safe -HowToClean 'about:preferences#privacy > Cookies and Site Data > Clear Data > "Cached Web Content"'
        $script:WdDiskBrowserBytes += [int64]$c['Bytes']
    }
}

function Add-WdDiskAppCacheCandidates {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Profiles)
    $apps = @(
        @{ Name = 'Microsoft Teams';     Class = 'Safe';   Patterns = @('Roaming\Microsoft\Teams\Cache', 'Roaming\Microsoft\Teams\Code Cache', 'Roaming\Microsoft\Teams\GPUCache', 'Roaming\Microsoft\Teams\Service Worker', 'Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\EBWebView'); How = 'Quit Teams, then Settings > General > "Clear cache" (or delete the listed folders while Teams is closed)' },
        @{ Name = 'Discord';             Class = 'Safe';   Patterns = @('Roaming\discord\Cache', 'Roaming\discord\Code Cache', 'Roaming\discord\GPUCache'); How = 'Quit Discord, then delete the listed cache folders (they are rebuilt)' },
        @{ Name = 'Slack';               Class = 'Safe';   Patterns = @('Roaming\Slack\Cache', 'Roaming\Slack\Service Worker', 'Roaming\Slack\GPUCache'); How = 'Slack menu > Troubleshooting > "Clear cache and restart"' },
        @{ Name = 'Spotify';             Class = 'Safe';   Patterns = @('Local\Spotify\Storage', 'Local\Spotify\Data', 'Local\Packages\SpotifyAB.SpotifyMusic_zpdnekdrzrea0\LocalCache\Spotify\Data'); How = 'Spotify Settings > Storage > "Clear cache" (offline downloads are separate)' },
        @{ Name = 'Telegram Desktop';    Class = 'Review'; Patterns = @('Roaming\Telegram Desktop\tdata\user_data\cache', 'Roaming\Telegram Desktop\tdata\user_data\media_cache', 'Local\Packages\TelegramMessengerLLP.TelegramDesktop_t4vj0pshhgkwm\LocalCache'); How = 'Telegram Settings > Advanced > "Manage local storage" > Clear (media you keep offline is removed too)' },
        @{ Name = 'WhatsApp';            Class = 'Review'; Patterns = @('Local\Packages\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\LocalCache'); How = 'WhatsApp Settings > Storage and data > Manage storage' },
        @{ Name = 'Zoom';                Class = 'Safe';   Patterns = @('Roaming\Zoom\data'); How = 'Zoom Settings > Zoom Apps > "Clear" local app data; recordings are elsewhere' },
        @{ Name = 'VS Code / Cursor / Claude Desktop'; Class = 'Safe'; Patterns = @('Roaming\Code\Cache', 'Roaming\Code\CachedData', 'Roaming\Code\CachedExtensionVSIXs', 'Roaming\Code\Code Cache', 'Roaming\Code\GPUCache', 'Roaming\Code - Insiders\Cache', 'Roaming\Code - Insiders\CachedData', 'Roaming\Cursor\Cache', 'Roaming\Cursor\CachedData', 'Roaming\Cursor\Code Cache', 'Roaming\Claude\Cache', 'Roaming\Claude\Code Cache', 'Roaming\Claude\GPUCache'); How = 'Quit the app, then delete the listed cache folders (they are rebuilt)' }
    )
    foreach ($a in $apps) {
        $null = Invoke-Safely -Name ('Disk.Cleanup.AppCache.' + $a.Name) -ScriptBlock {
            $paths = @(Get-WdDiskExistingPaths -Paths @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns $a.Patterns))
            if ($paths.Count -eq 0) { return }
            Add-WdDiskCandidate -Category ('App cache: ' + $a.Name) -Paths $paths -SafetyClass $a.Class -HowToClean $a.How | Out-Null
        }
    }
    $null = Invoke-Safely -Name 'Disk.Cleanup.ShaderCache' -ScriptBlock {
        $paths = @(Get-WdDiskExistingPaths -Paths @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\D3DSCache', 'Local\NVIDIA\DXCache', 'Local\NVIDIA\GLCache', 'Local\AMD\DxCache', 'Local\AMD\DxcCache', 'Local\AMD\GLCache', 'Local\AMD\VkCache', 'Local\Intel\ShaderCache', 'Local\Steam\htmlcache')))
        if ($paths.Count -eq 0) { return }
        Add-WdDiskCandidate -Category 'GPU shader caches (D3DSCache, NVIDIA/AMD/Intel, Steam htmlcache)' -Paths $paths -SafetyClass Safe -HowToClean 'cleanmgr "DirectX Shader Cache"; rebuilt automatically (first game start is slower)' | Out-Null
    }
    $null = Invoke-Safely -Name 'Disk.Cleanup.Thumbnails' -ScriptBlock {
        $bytes = [int64]0; $files = [int64]0; $paths = @(); $perPath = @{}
        foreach ($dir in @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\Microsoft\Windows\Explorer'))) {
            $r = Get-WdDiskFileBytes -Directory $dir -NameRegex '^(thumbcache|iconcache)_.*\.db$'
            if ($r['Files'] -gt 0) { $bytes += [int64]$r['Bytes']; $files += [int64]$r['Files']; $paths += $dir; $perPath[$dir] = [int64]$r['Bytes'] }
        }
        if ($files -eq 0) { return }
        Add-WdDiskCandidate -Category 'Thumbnail and icon caches (thumbcache_*.db, iconcache_*.db)' -Paths $paths -SafetyClass Safe -Bytes $bytes -Files $files -PathBytes $perPath -HowToClean 'cleanmgr "Thumbnails"; Storage Sense; rebuilt automatically' | Out-Null
    }
    $null = Invoke-Safely -Name 'Disk.Cleanup.MiscCaches' -ScriptBlock {
        $paths = @(Get-WdDiskExistingPaths -Paths @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\Microsoft\Windows\INetCache', 'Local\Microsoft\Windows\WebCache', 'Local\Microsoft\Office\16.0\OfficeFileCache', 'Local\Microsoft\Terminal Server Client\Cache', 'Local\Microsoft\OneDrive\logs', 'Local\Microsoft\Windows\Notifications')))
        if ($paths.Count -gt 0) {
            Add-WdDiskCandidate -Category 'Misc Windows caches (INetCache, WebCache, Office file cache, RDP bitmap cache, OneDrive logs)' -Paths $paths -SafetyClass Review -HowToClean 'cleanmgr "Temporary Internet Files"; Office: File > Options > Save > "Delete cached files"' | Out-Null
        }
        $ost = [int64]0; $ostFiles = [int64]0; $ostPaths = @()
        foreach ($dir in @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\Microsoft\Outlook'))) {
            $r = Get-WdDiskFileBytes -Directory $dir -NameRegex '\.(ost|nst)$'
            if ($r['Files'] -gt 0) { $ost += [int64]$r['Bytes']; $ostFiles += [int64]$r['Files']; $ostPaths += @($r['Paths']) }
        }
        if ($ostFiles -gt 0) {
            Add-WdDiskCandidate -Category 'Outlook offline data files (.ost)' -Paths $ostPaths -SafetyClass Review -Bytes $ost -Files $ostFiles -Reclaimable ([int64]0) -HowToClean 'Outlook > Account Settings > Change > "Mail to keep offline" slider (smaller window = smaller file); the file re-syncs from the server' | Out-Null
        }
    }
}

function Add-WdDiskCloudAndGameCandidates {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Profiles, [AllowNull()][object[]]$Volumes)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $lettered = @($Volumes | Where-Object { $null -ne $_ -and $_['HasLetter'] })

    # 24. OneDrive (current user accounts from registry + environment; other users: default folder names)
    $null = Invoke-Safely -Name 'Disk.Cleanup.OneDrive' -ScriptBlock {
        $paths = New-Object 'System.Collections.Generic.List[string]'
        foreach ($acc in @(Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\OneDrive\Accounts' -ErrorAction SilentlyContinue)) {
            $uf = $acc.GetValue('UserFolder')
            if (-not [string]::IsNullOrWhiteSpace([string]$uf) -and (Test-DirectoryExists -Path ([string]$uf))) { $null = Add-WdDiskUniquePath -List $paths -Path (Get-WdDiskNormalizedPath -Path ([string]$uf)) }
        }
        foreach ($ev in @($env:OneDrive, $env:OneDriveConsumer, $env:OneDriveCommercial)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$ev) -and (Test-DirectoryExists -Path ([string]$ev))) { $null = Add-WdDiskUniquePath -List $paths -Path (Get-WdDiskNormalizedPath -Path ([string]$ev)) }
        }
        foreach ($pr in @($Profiles)) {
            if ($null -eq $pr -or $pr['IsCurrent'] -or -not $pr['Readable']) { continue }
            foreach ($d in @(Get-WdDiskSubfolders -Path ([string]$pr['Path']) -NameRegex '^OneDrive')) { $null = Add-WdDiskUniquePath -List $paths -Path $d }
        }
        if ($paths.Count -eq 0) { return }
        $c = Add-WdDiskCandidate -Category 'OneDrive local copies' -Paths $paths.ToArray() -SafetyClass Review -HowToClean 'Right-click a folder > "Free up space" (files stay in the cloud); Storage Sense "locally available cloud content"'
        $c['Note'] = ('{0} on disk of {1} logical; {2} cloud-only placeholder(s) ({3}) already take no space' -f (Format-Bytes -Bytes $c['Bytes']), (Format-Bytes -Bytes $c['LogicalBytes']), ([int64]$c['CloudOnlyFiles']).ToString('N0', $inv), (Format-Bytes -Bytes $c['CloudOnlyBytes'])) + $(if ($c['Note']) { '. ' + $c['Note'] } else { '' })
    }

    # 25. Game libraries
    $null = Invoke-Safely -Name 'Disk.Cleanup.Games.Steam' -ScriptBlock {
        $libs = New-Object 'System.Collections.Generic.List[string]'
        $steamPath = Get-RegistryValueSafe -Path 'HKCU:\Software\Valve\Steam' -Name 'SteamPath' -Default $null
        if ([string]::IsNullOrWhiteSpace([string]$steamPath)) { $steamPath = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam' -Name 'InstallPath' -Default $null }
        if ([string]::IsNullOrWhiteSpace([string]$steamPath)) { return }
        # HKCU SteamPath is lower-case with forward slashes ('c:/program files (x86)/steam') while libraryfolders.vdf
        # holds the canonical spelling: canonicalise (on-disk casing) and de-duplicate case-insensitively, or the same
        # library is walked twice and every game counted twice.
        $steamPath = Get-WdDiskCasedPath -Path (([string]$steamPath).Replace('/', '\'))
        $null = Add-WdDiskUniquePath -List $libs -Path (Get-WdDiskCasedPath -Path ([IO.Path]::Combine($steamPath, 'steamapps')))
        $vdf = [IO.Path]::Combine($steamPath, 'steamapps\libraryfolders.vdf')
        if (Test-FileExists -Path $vdf) {
            foreach ($line in @(Get-Content -LiteralPath $vdf -Encoding UTF8 -ErrorAction SilentlyContinue)) {
                if ($line -match '"path"\s+"([^"]+)"') { $null = Add-WdDiskUniquePath -List $libs -Path (Get-WdDiskCasedPath -Path ([IO.Path]::Combine($Matches[1].Replace('\\', '\').Replace('/', '\'), 'steamapps'))) }
            }
        }
        $games = New-Object 'System.Collections.Generic.List[object]'
        foreach ($lib in $libs) {
            foreach ($acf in @(Get-ChildItem -LiteralPath $lib -File -Filter 'appmanifest_*.acf' -ErrorAction SilentlyContinue)) {
                $txt = Get-Content -LiteralPath $acf.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                $n = ''; $sz = [int64]0
                if ($txt -match '"name"\s+"([^"]+)"') { $n = $Matches[1] }
                if ($txt -match '"SizeOnDisk"\s+"(\d+)"') { $sz = [int64]$Matches[1] }
                if ($n) { $games.Add([pscustomobject]@{ Name = $n; Bytes = $sz }) }
            }
        }
        $top = @($games | Sort-Object -Property Bytes -Descending | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_.Name, (Format-Bytes -Bytes $_.Bytes) })
        $note = 'Large but intentional'
        if ($top.Count -gt 0) { $note += ('; {0} game(s), largest: {1}' -f $games.Count, ($top -join ', ')) }
        Add-WdDiskCandidate -Category 'Game library: Steam' -Paths @(Get-WdDiskExistingPaths -Paths $libs.ToArray()) -SafetyClass Review -Reclaimable ([int64]0) -Note $note -HowToClean 'Uninstall games through the Steam library; Steam > Settings > Storage moves libraries to another drive' | Out-Null
    }
    $null = Invoke-Safely -Name 'Disk.Cleanup.Games.Epic' -ScriptBlock {
        $dat = [IO.Path]::Combine([string]$env:ProgramData, 'Epic\UnrealEngineLauncher\LauncherInstalled.dat')
        if (-not (Test-FileExists -Path $dat)) { return }
        $json = Get-Content -LiteralPath $dat -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        $paths = @()
        foreach ($i in @($json.InstallationList)) { if ($i.InstallLocation) { $paths += [string]$i.InstallLocation } }
        $paths = @(Get-WdDiskExistingPaths -Paths $paths)
        if ($paths.Count -eq 0) { return }
        Add-WdDiskCandidate -Category 'Game library: Epic Games' -Paths $paths -SafetyClass Review -Reclaimable ([int64]0) -Note 'Large but intentional' -HowToClean 'Uninstall through the Epic Games Launcher' | Out-Null
    }
    $null = Invoke-Safely -Name 'Disk.Cleanup.Games.Other' -ScriptBlock {
        $pf = [string]$env:ProgramFiles; $pf86 = [string]${env:ProgramFiles(x86)}
        $gog = @()
        foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\WOW6432Node\GOG.com\Games' -ErrorAction SilentlyContinue)) { $p = $k.GetValue('path'); if ($p) { $gog += [string]$p } }
        $sets = @(
            @{ Name = 'GOG Galaxy';  Paths = $gog + @([IO.Path]::Combine($pf86, 'GOG Galaxy\Games'), [IO.Path]::Combine($pf, 'GOG Galaxy\Games')) },
            @{ Name = 'EA app';      Paths = @([IO.Path]::Combine($pf, 'EA Games'), [IO.Path]::Combine($pf86, 'EA Games'), [IO.Path]::Combine($pf, 'Electronic Arts')) },
            @{ Name = 'Battle.net';  Paths = @([IO.Path]::Combine($pf86, 'Battle.net'), [IO.Path]::Combine([string]$env:ProgramData, 'Battle.net')) },
            @{ Name = 'Ubisoft Connect'; Paths = @([IO.Path]::Combine($pf86, 'Ubisoft\Ubisoft Game Launcher\games')) },
            @{ Name = 'Riot Games';  Paths = @([IO.Path]::Combine(([string]$env:SystemDrive + '\'), 'Riot Games')) }
        )
        $xbox = @()
        foreach ($v in $lettered) { $xbox += ('{0}:\XboxGames' -f $v['Letter']) }
        $sets += @{ Name = 'Xbox / Microsoft Store games (XboxGames)'; Paths = $xbox }
        foreach ($s in $sets) {
            $ex = @(Get-WdDiskExistingPaths -Paths $s.Paths)
            if ($ex.Count -eq 0) { continue }
            Add-WdDiskCandidate -Category ('Game library: ' + $s.Name) -Paths $ex -SafetyClass Review -Reclaimable ([int64]0) -Note 'Large but intentional' -HowToClean 'Uninstall through the launcher / Settings > Apps' | Out-Null
        }
    }

    # 26. WSL / Docker / other virtual disks
    $null = Invoke-Safely -Name 'Disk.Cleanup.VirtualDisks' -ScriptBlock {
        $files = New-Object 'System.Collections.Generic.List[string]'
        $notes = New-Object 'System.Collections.Generic.List[string]'
        foreach ($k in @(Get-ChildItem -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction SilentlyContinue)) {
            $bp = [string]$k.GetValue('BasePath')
            if ([string]::IsNullOrWhiteSpace($bp)) { continue }
            $bp = Get-WdDiskNormalizedPath -Path $bp
            $vhd = [IO.Path]::Combine($bp, 'ext4.vhdx')
            if (Test-FileExists -Path $vhd) {
                if (Add-WdDiskUniquePath -List $files -Path $vhd) {
                    $notes.Add(('WSL "{0}": {1}' -f [string]$k.GetValue('DistributionName'), (Format-Bytes -Bytes (Get-FileSizeSafe -Path $vhd))))
                }
            }
        }
        $roots = @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\Docker\wsl', 'Roaming\Claude\vm_bundles', 'Profile\.docker', 'Profile\.local\share\containers', 'Local\Podman'))
        foreach ($r in $roots) {
            if (-not (Test-DirectoryExists -Path $r)) { continue }
            foreach ($f in @(Get-ChildItem -LiteralPath $r -Recurse -File -Force -Depth 4 -ErrorAction SilentlyContinue | Where-Object { $_.Extension -match '^\.(vhdx|vhd|avhdx|qcow2|img)$' })) {
                if (Add-WdDiskUniquePath -List $files -Path $f.FullName) { $notes.Add(('{0}: {1}' -f $f.Name, (Format-Bytes -Bytes $f.Length))) }
            }
        }
        if ($files.Count -eq 0) { return }
        $c = Add-WdDiskCandidate -Category 'WSL / Docker virtual disks (.vhdx)' -Paths $files.ToArray() -SafetyClass Review -Reclaimable ([int64]0) -Note (($notes.ToArray() | Select-Object -First 8) -join '; ') -HowToClean 'wsl --shutdown, then Optimize-VHD (Hyper-V module, administrator) or diskpart "compact vdisk"; docker system prune; Docker Desktop > Troubleshoot > Clean / Purge data. Virtual disks never shrink by themselves'
        if ([int64]$c['Bytes'] -gt 20GB) {
            Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-VHDX-LARGE' -Title ('WSL/Docker virtual disks occupy {0}' -f (Format-Bytes -Bytes $c['Bytes'])) -Detail ($c['Note']) -Recommendation 'Delete unused distributions/images inside WSL or Docker, then compact the .vhdx (wsl --shutdown; Optimize-VHD or diskpart compact vdisk). The file does not shrink on its own.'
        }
    }
}

function Add-WdDiskDevAndPersonalCandidates {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Profiles, [int]$TopN = 50)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $extra = [ordered]@{}

    # 28. Developer caches
    $null = Invoke-Safely -Name 'Disk.Cleanup.DevCaches' -ScriptBlock {
        $safe = @(
            @{ Tool = 'pip';      Patterns = @('Local\pip\cache') },
            @{ Tool = 'npm';      Patterns = @('Local\npm-cache', 'Roaming\npm-cache') },
            @{ Tool = 'yarn';     Patterns = @('Local\Yarn\Cache') },
            @{ Tool = 'pnpm';     Patterns = @('Local\pnpm\store', 'Local\pnpm-cache') },
            @{ Tool = 'NuGet';    Patterns = @('Profile\.nuget\packages', 'Local\NuGet\v3-cache', 'Local\NuGet\Cache', 'Local\NuGet\plugins-cache') },
            @{ Tool = 'Gradle';   Patterns = @('Profile\.gradle\caches', 'Profile\.gradle\wrapper') },
            @{ Tool = 'Maven';    Patterns = @('Profile\.m2\repository') },
            @{ Tool = 'Cargo';    Patterns = @('Profile\.cargo\registry', 'Profile\.cargo\git') },
            @{ Tool = 'Go';       Patterns = @('Profile\go\pkg\mod', 'Local\go-build') },
            @{ Tool = 'conda';    Patterns = @('Profile\.conda\pkgs', 'Profile\anaconda3\pkgs', 'Profile\miniconda3\pkgs') },
            @{ Tool = 'uv';       Patterns = @('Local\uv\cache') },
            @{ Tool = 'Composer'; Patterns = @('Local\Composer') },
            # Only known re-downloadable sub-caches of ~\.cache: the folder as a whole also holds AI models
            # (huggingface, torch: Review below) and tool runtimes that are not purgeable caches.
            @{ Tool = '.cache';   Patterns = @('Profile\.cache\pip', 'Profile\.cache\uv', 'Profile\.cache\pre-commit', 'Profile\.cache\ms-playwright', 'Profile\.cache\puppeteer', 'Profile\.cache\yarn') }
        )
        $paths = @(); $parts = @(); $total = [int64]0; $fileTotal = [int64]0; $perPath = @{}
        foreach ($t in $safe) {
            $ex = @(Get-WdDiskExistingPaths -Paths @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns $t.Patterns))
            if ($ex.Count -eq 0) { continue }
            $b = [int64]0
            foreach ($p in $ex) {
                $s = Get-WdDiskDirSize -Path $p
                if ($null -eq $s) { continue }
                $b += [int64]$s['Bytes']; $fileTotal += [int64]$s['Files']; $perPath[[string]$s['Path']] = [int64]$s['Bytes']; $paths += [string]$s['Path']
            }
            $total += $b
            $parts += ('{0} {1}' -f $t.Tool, (Format-Bytes -Bytes $b))
        }
        if ($paths.Count -gt 0) {
            # Pre-measured (-Bytes/-PathBytes): the sizes above are reused instead of walking every folder a second time.
            Add-WdDiskCandidate -Category 'Developer package caches (pip, npm, yarn, pnpm, NuGet, Gradle, Maven, Cargo, Go, conda, uv, Composer, .cache\pip|uv|pre-commit|ms-playwright|puppeteer|yarn)' -Paths $paths -SafetyClass Safe -Bytes $total -Files $fileTotal -PathBytes $perPath -Note ($parts -join ', ') -HowToClean 'pip cache purge; npm cache clean --force; yarn cache clean; dotnet nuget locals all --clear; go clean -modcache; conda clean -a; uv cache clean; pre-commit clean; npx playwright uninstall --all; Gradle: stop daemons then delete .gradle\caches (everything is re-downloaded on demand)' | Out-Null
        }
        $review = @(Get-WdDiskExistingPaths -Paths @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\Android\Sdk', 'Profile\.android\avd', 'Profile\.vscode\extensions', 'Local\JetBrains', 'Local\Xamarin', 'Profile\.ollama\models', 'Profile\.cache\huggingface', 'Profile\.cache\torch', 'Local\lm-studio\models')))
        if ($review.Count -gt 0) {
            Add-WdDiskCandidate -Category 'Developer SDKs, emulators, extensions and models (Android SDK/AVD, VS Code extensions, JetBrains, Xamarin, Ollama/LM Studio/Hugging Face/torch models)' -Paths $review -SafetyClass Review -HowToClean 'Android Studio SDK Manager / Device Manager; VS Code: uninstall unused extensions; JetBrains: File > Invalidate Caches; remove unused local AI models (huggingface-cli delete-cache, ollama rm)' | Out-Null
        }
    }

    # 29. Phone backups
    $null = Invoke-Safely -Name 'Disk.Cleanup.PhoneBackups' -ScriptBlock {
        $ex = @(Get-WdDiskExistingPaths -Paths @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Profile\Apple\MobileSync\Backup', 'Roaming\Apple Computer\MobileSync\Backup', 'Profile\Documents\Samsung\SmartSwitch', 'Profile\Documents\HiSuite\backup')))
        if ($ex.Count -eq 0) { return }
        Add-WdDiskCandidate -Category 'Phone backups (iTunes/Apple Devices, Smart Switch, HiSuite)' -Paths $ex -SafetyClass Review -HowToClean 'Apple Devices / iTunes > Manage Backups > delete old device backups' | Out-Null
    }

    # 31. Downloads (per readable profile; current user via User Shell Folders)
    $null = Invoke-Safely -Name 'Disk.Cleanup.Downloads' -ScriptBlock {
        $paths = New-Object 'System.Collections.Generic.List[string]'
        $remote = New-Object 'System.Collections.Generic.List[string]'
        $dl = Get-RegistryValueSafe -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name '{374DE290-123F-4565-9164-39C4925E467B}' -Expand
        if (-not [string]::IsNullOrWhiteSpace([string]$dl)) {
            $dl = Get-WdDiskNormalizedPath -Path ([Environment]::ExpandEnvironmentVariables([string]$dl))
            # Folder Redirection (domain GPO) may point Downloads to \\server\share: listed, never walked over SMB.
            if (-not (Test-WdDiskLocalPath -Path $dl)) { Add-WdDiskRemotePath -Path $dl; $null = Add-WdDiskUniquePath -List $remote -Path $dl }
            elseif (Test-DirectoryExists -Path $dl) { $null = Add-WdDiskUniquePath -List $paths -Path $dl }
        }
        foreach ($pr in @($Profiles)) {
            if ($null -eq $pr -or -not $pr['Readable'] -or $pr['Source'] -eq 'shared folder') { continue }
            if ($pr['IsCurrent'] -and ($paths.Count -gt 0 -or $remote.Count -gt 0)) { continue }
            $p = [IO.Path]::Combine([string]$pr['Path'], 'Downloads')
            if (Test-DirectoryExists -Path $p) { $null = Add-WdDiskUniquePath -List $paths -Path $p }
        }
        if ($paths.Count -eq 0 -and $remote.Count -eq 0) { return }
        $bytes = [int64]0; $logical = [int64]0; $files = [int64]0; $old = [int64]0; $oldFiles = [int64]0; $denied = 0
        $perPath = @{}
        $top = New-Object 'System.Collections.Generic.List[object]'
        foreach ($p in $paths) {
            $s = Get-WdDiskScan -Path $p -MaxDepth 0 -LargeFileThreshold ([int64]50MB) -OldDays 365
            if ($null -eq $s) { continue }
            $bytes += $s.Alloc; $logical += $s.Bytes; $files += $s.Files; $old += $s.OldBytes; $oldFiles += $s.OldFiles; $denied += $s.Denied
            $perPath[$p] = [int64]$s.Alloc
            foreach ($f in @(Get-WdDiskScanTopFiles -Scan $s -Top $TopN)) { $top.Add($f) }
        }
        $topSorted = @($top.ToArray() | Sort-Object -Property @{ Expression = { [int64]$_['Bytes'] }; Descending = $true } | Select-Object -First $TopN)
        $extra['DownloadsTopFiles'] = $topSorted
        $note = ('{0} file(s) older than 1 year: {1}' -f $oldFiles.ToString('N0', $inv), (Format-Bytes -Bytes $old))
        $topText = @($topSorted | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f [IO.Path]::GetFileName([string]$_['Path']), (Format-Bytes -Bytes $_['Bytes']) })
        if ($topText.Count -gt 0) { $note += '; largest: ' + ($topText -join ', ') }
        Add-WdDiskCandidate -Category 'Downloads' -Paths @($paths.ToArray() + $remote.ToArray()) -SafetyClass Review -Bytes $bytes -Files $files -PathBytes $perPath -Reclaimable $old -Note $note -HowToClean 'Review and delete old installers/archives by hand; Storage Sense can remove Downloads files unchanged for N days (off by default)' | Out-Null
        if ($old -gt 5GB) {
            Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-DOWNLOADS-OLD' -Title ('Downloads contains {0} of files older than one year' -f (Format-Bytes -Bytes $old)) -Detail $note -Recommendation 'Sort Downloads by date and size; delete finished installers, archives and videos you no longer need.'
        }
    }

    # 32. Personal known folders (sizes only)
    $null = Invoke-Safely -Name 'Disk.Cleanup.KnownFolders' -ScriptBlock {
        $known = @(@{ Name = 'Desktop'; Value = 'Desktop' }, @{ Name = 'Documents'; Value = 'Personal' }, @{ Name = 'Pictures'; Value = 'My Pictures' }, @{ Name = 'Videos'; Value = 'My Video' }, @{ Name = 'Music'; Value = 'My Music' })
        $rows = New-Object 'System.Collections.Generic.List[object]'
        $paths = @(); $parts = @(); $total = [int64]0; $fileTotal = [int64]0; $perPath = @{}
        $remote = New-Object 'System.Collections.Generic.List[string]'
        foreach ($k in $known) {
            $set = New-Object 'System.Collections.Generic.List[string]'
            $cur = Get-RegistryValueSafe -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name $k.Value -Expand
            if (-not [string]::IsNullOrWhiteSpace([string]$cur)) {
                $cur = Get-WdDiskNormalizedPath -Path ([Environment]::ExpandEnvironmentVariables([string]$cur))
                # Folder Redirection (domain GPO) may point a known folder to \\server\share: listed, never walked over SMB.
                if (-not (Test-WdDiskLocalPath -Path $cur)) { Add-WdDiskRemotePath -Path $cur; $null = Add-WdDiskUniquePath -List $remote -Path $cur }
                elseif (Test-DirectoryExists -Path $cur) { $null = Add-WdDiskUniquePath -List $set -Path $cur }
            }
            foreach ($pr in @($Profiles)) {
                if ($null -eq $pr -or -not $pr['Readable'] -or $pr['IsCurrent'] -or $pr['Source'] -eq 'shared folder') { continue }
                $p = [IO.Path]::Combine([string]$pr['Path'], $k.Name)
                if (Test-DirectoryExists -Path $p) { $null = Add-WdDiskUniquePath -List $set -Path $p }
            }
            $b = [int64]0; $f = [int64]0
            foreach ($p in $set) { $s = Get-WdDiskDirSize -Path $p; if ($null -ne $s) { $b += [int64]$s['Bytes']; $f += [int64]$s['Files']; $perPath[$p] = [int64]$s['Bytes'] } }
            if ($set.Count -gt 0) { $rows.Add([ordered]@{ Folder = $k.Name; Paths = $set.ToArray(); Bytes = $b; Files = $f }); $paths += $set.ToArray(); $parts += ('{0} {1}' -f $k.Name, (Format-Bytes -Bytes $b)); $total += $b; $fileTotal += $f }
        }
        foreach ($r in $remote) { $rows.Add([ordered]@{ Folder = 'redirected'; Paths = @($r); Bytes = $null; Files = $null; Note = $script:WdDiskRemoteText }) }
        $extra['KnownFolders'] = $rows.ToArray()
        if ($paths.Count -gt 0 -or $remote.Count -gt 0) {
            Add-WdDiskCandidate -Category 'Personal folders (Desktop, Documents, Pictures, Videos, Music)' -Paths @($paths + $remote.ToArray()) -SafetyClass Review -Bytes $total -Files $fileTotal -PathBytes $perPath -Reclaimable ([int64]0) -Note ($parts -join ', ') -HowToClean 'User decides: move large media to another drive or to the cloud; folders redirected into OneDrive appear under "OneDrive local copies"' | Out-Null
        }
    }
    return $extra
}

# ---------------------------------------------------------------------------------------------
# Installed applications, Store apps, Storage Sense
# ---------------------------------------------------------------------------------------------
function Get-WdDiskInstalledApps {
    # Uninstall registry keys (never Win32 installer WMI classes). EstimatedSize is in KB.
    [CmdletBinding()]
    param()
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $roots = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'Machine (32-bit)' },
        @{ Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall'; Scope = 'User' }
    )
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    $apps = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $roots) {
        foreach ($k in @(Get-ChildItem -LiteralPath $r.Path -ErrorAction SilentlyContinue)) {
            $name = ''
            try { $name = [string]$k.GetValue('DisplayName') } catch { $name = '' }
            if ([string]::IsNullOrWhiteSpace($name)) { continue }
            $sysComp = $null
            try { $sysComp = $k.GetValue('SystemComponent') } catch { }
            if ($null -ne $sysComp -and [int]$sysComp -eq 1) { continue }
            $version = ''
            try { $version = [string]$k.GetValue('DisplayVersion') } catch { }
            $key = $name + '|' + $version
            if (-not $seen.Add($key)) { continue }
            $bytes = $null
            try { $es = $k.GetValue('EstimatedSize'); if ($null -ne $es) { $bytes = [int64]$es * 1024 } } catch { $bytes = $null }
            $installDate = ''
            try {
                $raw = [string]$k.GetValue('InstallDate')
                $dt = [DateTime]::MinValue
                if ($raw -match '^\d{8}$' -and [DateTime]::TryParseExact($raw, 'yyyyMMdd', $inv, [Globalization.DateTimeStyles]::None, [ref]$dt)) { $installDate = $dt.ToString('yyyy-MM-dd', $inv) }
                elseif (-not [string]::IsNullOrWhiteSpace($raw)) { $installDate = $raw }
            } catch { $installDate = '' }
            $apps.Add([ordered]@{
                Name            = $name
                Publisher       = $(try { [string]$k.GetValue('Publisher') } catch { '' })
                Version         = $version
                Bytes           = $bytes
                InstallDate     = $installDate
                InstallLocation = $(try { [string]$k.GetValue('InstallLocation') } catch { '' })
                Scope           = $r.Scope
            })
        }
    }
    return @($apps.ToArray() | Sort-Object -Property @{ Expression = { if ($null -eq $_['Bytes']) { [int64]-1 } else { [int64]$_['Bytes'] } }; Descending = $true }, @{ Expression = { [string]$_['Name'] } })
}

function Get-WdDiskAppxPackages {
    # Store apps of the current user with their install folder size (package folders under WindowsApps are readable).
    [CmdletBinding()]
    param([AllowNull()][object[]]$Profiles)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $pkgs = @()
    try { $pkgs = @(Get-AppxPackage -ErrorAction Stop) } catch { throw ('Get-AppxPackage failed: {0}' -f $_.Exception.Message) }
    foreach ($p in $pkgs) {
        $loc = [string]$p.InstallLocation
        $bytes = $null; $files = $null; $denied = 0
        if (-not [string]::IsNullOrWhiteSpace($loc) -and (Test-DirectoryExists -Path $loc)) {
            $s = Get-WdDiskDirSize -Path $loc
            if ($null -ne $s) {
                $denied = [int]$s['Denied']
                # A package folder that is denied as a whole (Denied > 0 and nothing counted) is unknown, not 0 bytes.
                if ($denied -eq 0 -or [int64]$s['Files'] -gt 0) { $bytes = [int64]$s['Bytes']; $files = [int64]$s['Files'] }
            }
        }
        $rows.Add([ordered]@{ Name = [string]$p.Name; Version = [string]$p.Version; Publisher = [string]$p.PublisherId; IsFramework = [bool]$p.IsFramework; InstallLocation = $loc; Bytes = $bytes; Files = $files; Inaccessible = $denied })
    }
    return @($rows.ToArray() | Sort-Object -Property @{ Expression = { if ($null -eq $_['Bytes']) { [int64]-1 } else { [int64]$_['Bytes'] } }; Descending = $true }, @{ Expression = { [string]$_['Name'] } })
}

function Add-WdDiskAppxCandidates {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Profiles, [int]$TopN = 50)
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $extra = [ordered]@{ Appx = @(); AppxTotalBytes = $null }
    $appx = @(Invoke-Safely -Name 'Disk.Appx.Packages' -Default @() -ScriptBlock { Get-WdDiskAppxPackages -Profiles $Profiles })
    $extra['Appx'] = @($appx | Select-Object -First $TopN)
    if ($appx.Count -gt 0) {
        $total = [int64]0; $fileTotal = [int64]0
        foreach ($a in $appx) { if ($null -ne $a['Bytes']) { $total += [int64]$a['Bytes'] }; if ($null -ne $a['Files']) { $fileTotal += [int64]$a['Files'] } }
        $extra['AppxTotalBytes'] = $total
        $top = @($appx | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_['Name'], (Format-Bytes -Bytes $_['Bytes']) })
        $waRoot = [IO.Path]::Combine([string]$env:ProgramFiles, 'WindowsApps')
        Add-WdDiskCandidate -Category ('Store apps of the current user ({0} packages)' -f $appx.Count.ToString($inv)) -Paths @($waRoot) -SafetyClass Review -Bytes $total -Files $fileTotal -Reclaimable ([int64]0) -Note ('Largest: ' + ($top -join ', ')) -HowToClean 'Settings > Apps > Installed apps > Uninstall; Remove-AppxPackage' | Out-Null
    }
    if (-not $script:IsAdmin) {
        Add-AdminSkip -Item 'Store apps of other users (WindowsApps root listing, Get-AppxPackage -AllUsers)' -Detail 'the WindowsApps folder itself is readable only by administrators; the current user''s packages were measured'
    }
    $null = Invoke-Safely -Name 'Disk.Appx.PackageData' -ScriptBlock {
        $pkgRoots = @(Get-WdDiskExistingPaths -Paths @(Get-WdDiskProfilePaths -Profiles $Profiles -Patterns @('Local\Packages')))
        if ($pkgRoots.Count -eq 0) { return }
        $total = [int64]0; $fileTotal = [int64]0; $tempBytes = [int64]0; $tempFiles = [int64]0; $tempPaths = @(); $perRoot = @{}; $perTemp = @{}
        $perPkg = New-Object 'System.Collections.Generic.List[object]'
        foreach ($root in $pkgRoots) {
            $rootBytes = [int64]0
            foreach ($d in @(Get-WdDiskSubfolders -Path $root)) {
                $s = Get-WdDiskDirSize -Path $d
                if ($null -eq $s) { continue }
                $total += [int64]$s['Bytes']; $fileTotal += [int64]$s['Files']; $rootBytes += [int64]$s['Bytes']
                $perPkg.Add([ordered]@{ Package = [IO.Path]::GetFileName($d); Path = $d; Bytes = [int64]$s['Bytes']; Files = [int64]$s['Files'] })
                $ts = [IO.Path]::Combine($d, 'TempState')
                if (Test-DirectoryExists -Path $ts) { $t = Get-WdDiskDirSize -Path $ts; if ($null -ne $t -and [int64]$t['Bytes'] -gt 0) { $tempBytes += [int64]$t['Bytes']; $tempFiles += [int64]$t['Files']; $tempPaths += $ts; $perTemp[$ts] = [int64]$t['Bytes'] } }
            }
            $perRoot[$root] = $rootBytes
        }
        $sorted = @($perPkg.ToArray() | Sort-Object -Property @{ Expression = { [int64]$_['Bytes'] }; Descending = $true })
        $extra['PackageData'] = @($sorted | Select-Object -First $TopN)
        $top = @($sorted | Select-Object -First 5 | ForEach-Object { '{0} ({1})' -f $_['Package'], (Format-Bytes -Bytes $_['Bytes']) })
        Add-WdDiskCandidate -Category 'Store app data (AppData\Local\Packages)' -Paths $pkgRoots -SafetyClass Review -Bytes $total -Files $fileTotal -PathBytes $perRoot -Reclaimable ([int64]0) -Note ('Largest: ' + ($top -join ', ') + '. WSL distributions installed from the Store keep their ext4.vhdx here (also listed under "WSL / Docker virtual disks")') -HowToClean 'Settings > Apps > the app > Advanced options > Reset (deletes its data); uninstall unused apps' | Out-Null
        if ($tempBytes -gt 0) {
            Add-WdDiskCandidate -Category 'Store app temporary state (Packages\*\TempState)' -Paths $tempPaths -SafetyClass Safe -Bytes $tempBytes -Files $tempFiles -PathBytes $perTemp -HowToClean 'Storage Sense / Settings > Storage > Temporary files; apps recreate it' | Out-Null
        }
    }
    return $extra
}

function Get-WdDiskStorageSense {
    # HKCU StoragePolicy values; meaning of the numeric value names is community-documented (best effort).
    [CmdletBinding()]
    param()
    $base = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
    $names = [ordered]@{ '01' = 'Enabled'; '2048' = 'Cadence'; '04' = 'DeleteTempFiles'; '08' = 'RecycleBinCleanup'; '256' = 'RecycleBinDays'; '32' = 'DownloadsCleanup'; '512' = 'DownloadsDays'; '02' = 'CloudDehydration'; '128' = 'CloudDehydrationDays' }
    $out = [ordered]@{ KeyPresent = $false }
    $present = $false
    foreach ($k in $names.Keys) {
        $v = Get-RegistryValueSafe -Path $base -Name $k -Default $null
        if ($null -ne $v) { $present = $true }
        $out[[string]$names[$k]] = $v
    }
    $out['KeyPresent'] = $present
    $cad = $out['Cadence']
    $cadText = 'unknown'
    if ($null -ne $cad) { switch ([int]$cad) { 0 { $cadText = 'when disk space is low' } 1 { $cadText = 'every day' } 7 { $cadText = 'every week' } 30 { $cadText = 'every month' } default { $cadText = [string]$cad } } }
    $out['CadenceText'] = $cadText
    $pol = [ordered]@{}
    foreach ($n in @('AllowStorageSenseGlobal', 'ConfigStorageSenseGlobalCadence', 'AllowStorageSenseTemporaryFilesCleanup', 'ConfigStorageSenseRecycleBinCleanupThreshold', 'ConfigStorageSenseDownloadsCleanupThreshold', 'ConfigStorageSenseCloudContentDehydrationThreshold')) {
        $pv = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\StorageSense' -Name $n -Default $null
        if ($null -ne $pv) { $pol[$n] = $pv }
    }
    $out['GroupPolicy'] = $pol
    $task = Invoke-Safely -Name 'Disk.StorageSense.SilentCleanupTask' -Quiet -Default $null -ScriptBlock {
        $t = Get-ScheduledTask -TaskPath '\Microsoft\Windows\DiskCleanup\' -TaskName 'SilentCleanup' -ErrorAction Stop
        [string]$t.State
    }
    $out['SilentCleanupTaskState'] = $task
    return $out
}

function Get-WdDiskCleanmgrHandlers {
    [CmdletBinding()]
    param()
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($k in @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches' -ErrorAction SilentlyContinue)) {
        $folder = $null
        try { $folder = $k.GetValue('Folder') } catch { }
        $rows.Add([ordered]@{ Handler = $k.PSChildName; Folder = $(if ($null -ne $folder) { @($folder) -join ';' } else { '' }) })
    }
    return $rows.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Savings summary and findings derived from the catalog
# ---------------------------------------------------------------------------------------------
function Get-WdDiskSavings {
    [CmdletBinding()]
    param()
    $classes = @('Safe', 'Review', 'Risky')
    $rows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($c in $classes) {
        $size = [int64]0; $recl = [int64]0; $count = 0; $admin = 0
        $overlap = Resolve-WdDiskCandidateOverlaps -SafetyClass $c
        foreach ($item in $script:WdDiskCandidates) {
            if ($item['SafetyClass'] -ne $c -or -not $item['Exists']) { continue }
            $count++
            $size += [int64]$item['Bytes']
            if (-not $item['ReportOnly']) { $recl += [int64]$item['Reclaimable'] }
            if ($item['NeedsAdmin']) { $admin++ }
        }
        $size -= $overlap
        if ($size -lt 0) { $size = [int64]0 }
        $meaning = ''
        switch ($c) {
            'Safe'   { $meaning = 'caches and temporary data; can be removed with the built-in tools named in the table (apps closed)' }
            'Review' { $meaning = 'personal or intentional data; the user decides - not counted in the headline' }
            'Risky'  { $meaning = 'system-managed; only through the named system tool (DISM, cleanmgr, powercfg), never by deleting files' }
        }
        $rows.Add([ordered]@{ SafetyClass = $c; Candidates = $count; Bytes = $size; OverlapBytes = $overlap; Reclaimable = $recl; NeedsAdminCount = $admin; Meaning = $meaning })
    }
    return $rows.ToArray()
}

function Resolve-WdDiskCandidateOverlaps {
    # Candidates of one class may nest (ext4.vhdx inside AppData\Local\Packages, OneDrive\Documents inside the OneDrive
    # root): 'Size now' must count such bytes once. Containers (shorter paths) win; a path inside an already counted
    # path is excluded and the candidate gets OverlapBytes / OverlapsWith (+ a Note). Returns the excluded bytes.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$SafetyClass)
    $entries = New-Object 'System.Collections.Generic.List[object]'
    foreach ($item in $script:WdDiskCandidates) {
        if ($item['SafetyClass'] -ne $SafetyClass -or -not $item['Exists']) { continue }
        $item['OverlapBytes'] = [int64]0
        $item['OverlapsWith'] = ''
        $known = @($item['PathSizes'])
        if ($null -ne $item['PathSizes'] -and $known.Count -gt 0) {
            foreach ($ps in $known) { $entries.Add(@{ Item = $item; Paths = @([string]$ps['Path']); Bytes = [int64]$ps['Bytes']; Key = [string]$ps['Path'] }) }
        } else {
            # Per-path split unknown: the candidate is one unit, excluded only when every path is nested.
            $all = @($item['Paths'])
            if ($all.Count -eq 0) { continue }
            $shortest = $all[0]
            foreach ($a in $all) { if ($a.Length -lt $shortest.Length) { $shortest = $a } }
            $entries.Add(@{ Item = $item; Paths = $all; Bytes = [int64]$item['Bytes']; Key = [string]$shortest })
        }
    }
    $sorted = @($entries.ToArray() | Sort-Object -Property @{ Expression = { ([string]$_['Key']).Length } }, @{ Expression = { [string]$_['Key'] } })
    $accepted = New-Object 'System.Collections.Generic.List[object]'   # @{ Path; Item }
    $excluded = [int64]0
    foreach ($e in $sorted) {
        $container = $null
        $allNested = ($e['Paths'].Count -gt 0)
        foreach ($p in $e['Paths']) {
            $np = ([string]$p).TrimEnd('\')
            $hit = $null
            foreach ($acc in $accepted) {
                if ($acc['Item'] -eq $e['Item']) { continue }
                $ap = [string]$acc['Path']
                if ($np.Equals($ap, [StringComparison]::OrdinalIgnoreCase) -or $np.StartsWith($ap + '\', [StringComparison]::OrdinalIgnoreCase)) { $hit = $acc; break }
            }
            if ($null -eq $hit) { $allNested = $false } elseif ($null -eq $container) { $container = $hit }
        }
        if ($allNested -and $null -ne $container) {
            $excluded += [int64]$e['Bytes']
            $e['Item']['OverlapBytes'] = [int64]$e['Item']['OverlapBytes'] + [int64]$e['Bytes']
            $cat = [string]$container['Item']['Category']
            $tag = 'overlaps with "' + $cat + '" (counted once in "Size now")'
            if (([string]$e['Item']['OverlapsWith']) -notmatch [regex]::Escape($cat)) {
                $e['Item']['OverlapsWith'] = $(if ([string]::IsNullOrEmpty([string]$e['Item']['OverlapsWith'])) { $cat } else { [string]$e['Item']['OverlapsWith'] + '; ' + $cat })
                $note = [string]$e['Item']['Note']
                if ($note -notmatch [regex]::Escape($tag)) { $e['Item']['Note'] = $(if ([string]::IsNullOrEmpty($note)) { $tag } else { $note + '. ' + $tag }) }
            }
            continue
        }
        foreach ($p in $e['Paths']) { $accepted.Add(@{ Path = ([string]$p).TrimEnd('\'); Item = $e['Item'] }) }
    }
    return $excluded
}

function Add-WdDiskCatalogFindings {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Savings, [AllowNull()][object[]]$Volumes, [AllowNull()][object[]]$Profiles, [AllowNull()][object]$StorageSense)
    $safe = $null
    foreach ($s in @($Savings)) { if ($s['SafetyClass'] -eq 'Safe') { $safe = $s } }
    if ($null -ne $safe -and [int64]$safe['Reclaimable'] -ge 1GB) {
        $sev = 'Info'
        if ([int64]$safe['Reclaimable'] -ge 10GB) { $sev = 'Warning' }
        Add-Finding -Severity $sev -Category 'Disk' -RuleId 'DSK-SAFE-SAVINGS' -Title ('About {0} can be freed safely (temporary files, caches, Recycle Bin)' -f (Format-Bytes -Bytes $safe['Reclaimable'])) -Detail ('{0} Safe cleanup candidates measured; see "Potential savings" and the candidate table.' -f $safe['Candidates']) -Recommendation 'Run Settings > System > Storage > Temporary files (or cleanmgr), empty the Recycle Bin and clear browser caches with the browsers closed. Nothing is deleted by this tool.'
    }
    foreach ($item in $script:WdDiskCandidates) {
        if (-not $item['Exists']) { continue }
        $b = [int64]$item['Bytes']
        switch -Wildcard ($item['Category']) {
            'Recycle Bin' { if ($b -gt 1GB) { Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-RECYCLE-BIN' -Title ('Recycle Bin holds {0}' -f (Format-Bytes -Bytes $b)) -Detail $item['Path'] -Recommendation 'Empty the Recycle Bin (right-click > Empty Recycle Bin).' } }
            'User temp folders*' { if ([int64]$item['Reclaimable'] -gt 2GB) { Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-TEMP-LARGE' -Title ('Temp folders hold {0} of files older than one day' -f (Format-Bytes -Bytes $item['Reclaimable'])) -Detail $item['Path'] -Recommendation 'Settings > System > Storage > Temporary files, or cleanmgr "Temporary files".' } }
            'Hibernation file*' {
                $sysVol = $null
                foreach ($v in @($Volumes)) { if ($v['IsSystem']) { $sysVol = $v } }
                if ($b -gt 4GB -and $null -ne $sysVol -and ($sysVol['Status'] -eq 'Critical' -or $sysVol['Status'] -eq 'Warning')) {
                    Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-HIBERFIL' -Title ('hiberfil.sys uses {0} on the nearly full system drive' -f (Format-Bytes -Bytes $b)) -Detail $item['Note'] -Recommendation 'If hibernation is not used: powercfg /h off (administrator) frees the file; this also disables Fast Startup. powercfg /h /type reduced halves it and keeps Fast Startup.'
                }
            }
        }
    }
    if ($script:WdDiskBrowserBytes -gt 2GB) {
        Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-BROWSER-CACHE' -Title ('Browser caches occupy {0}' -f (Format-Bytes -Bytes $script:WdDiskBrowserBytes)) -Detail 'All Chromium-family and Firefox profiles of readable users summed (caches only, no history or passwords).' -Recommendation 'Clear "Cached images and files" in each browser with the browser closed; the cache is rebuilt as you browse.'
    }
    $old = @($Profiles | Where-Object { $null -ne $_ -and $_['OldProfile'] })
    if ($old.Count -gt 0) {
        $names = @($old | ForEach-Object { '{0} ({1} days, {2})' -f $_['Name'], $_['AgeDays'], $(if ($_['Readable'] -and $null -ne $_['Bytes']) { Format-Bytes -Bytes $_['Bytes'] } else { 'size ' + $script:WdDiskAdminText }) })
        Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-OLD-PROFILES' -Title ('{0} user profile(s) not used for more than 90 days' -f $old.Count) -Detail ($names -join '; ') -Recommendation 'Remove unneeded profiles through System Properties > Advanced > User Profiles > Delete (administrator). Never delete the folder by hand (leaves a broken ProfileList entry).'
    }
    if ($null -ne $script:WdDiskRemotePaths -and $script:WdDiskRemotePaths.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-FOLDER-REDIRECTED' -Title ('{0} folder(s) point to a network or removable location and were not measured' -f $script:WdDiskRemotePaths.Count) -Detail (@($script:WdDiskRemotePaths | Select-Object -First 8) -join '; ') -Recommendation 'Redirected known folders (Documents, Desktop, Downloads on \\server\share) do not occupy this PC''s disks; their size is not part of this report.'
    }
    if ($null -ne $StorageSense -and $StorageSense['KeyPresent'] -and $null -ne $StorageSense['Enabled'] -and [int]$StorageSense['Enabled'] -eq 0) {
        $low = $false
        foreach ($v in @($Volumes)) { if ($v['IsSystem'] -and ($v['Status'] -eq 'Critical' -or $v['Status'] -eq 'Warning')) { $low = $true } }
        if ($low) {
            Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-STORAGESENSE-OFF' -Title 'Storage Sense is turned off while the system drive is low on space' -Detail 'Storage Sense removes temporary files and old Recycle Bin content automatically.' -Recommendation 'Settings > System > Storage > Storage Sense > On (run when disk space is low or weekly).'
        }
    }
}

function Add-WdDiskScanFindings {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Scans)
    foreach ($s in @($Scans)) {
        if ($null -eq $s) { continue }
        $ratio = $s['SanityRatio']
        if ($null -ne $ratio -and ($ratio -lt 0.7 -or $ratio -gt 1.15)) {
            Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-SCAN-RATIO' -Title ('Volume {0}: scanned {1} but the volume reports {2} used (ratio {3})' -f $s['Volume'], (Format-Bytes -Bytes $s['AllocatedBytes']), (Format-Bytes -Bytes $s['UsedBytes']), (ConvertTo-InvariantString -Value $ratio -Decimals 2)) -Detail ('{0} folders were not readable (System Volume Information with shadow copies, other users, Windows\Temp ...), {1} links and volume mount points were skipped; MFT and hard links also cause a gap.' -f $s['Denied'], $s['SkippedLinks']) -Recommendation 'Run as administrator for a complete picture; a large gap on the system volume usually means shadow copies (System Restore) - check "System Restore points / shadow copies".'
        }
        if ($s['Denied'] -gt 0 -and -not $script:IsAdmin) {
            Add-Finding -Severity Info -Category 'Disk' -RuleId 'DSK-DENIED' -Title ('Volume {0}: {1} folder(s) were not readable without administrator rights' -f $s['Volume'], $s['Denied']) -Detail ('Examples: ' + (@($s['DeniedSample'] | Select-Object -First 8) -join '; ')) -Recommendation 'Run win-debug as administrator to include System Volume Information, Windows\Temp, Prefetch, LiveKernelReports, the Search index, Defender history, other users'' profiles and Recycle Bins, and the WindowsApps root.'
        }
    }
}

# ---------------------------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------------------------
function ConvertTo-WdDiskArray {
    # Copies any enumerable into a plain object[] (avoids the PS 5.1 "Argument types do not match" binder bug of @() on generic lists).
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][object]$Value)
    $l = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Value) { return ,$l.ToArray() }
    if ($Value -is [string] -or $Value -is [System.Collections.IDictionary] -or -not ($Value -is [System.Collections.IEnumerable])) { $l.Add($Value); return ,$l.ToArray() }
    foreach ($i in $Value) { $l.Add($i) }
    return ,$l.ToArray()
}

function Get-WdDiskDateText {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    try { return ([DateTime]$Value).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture) } catch { return '' }
}

function Get-WdDiskSummaryLines {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Data,
        [int]$TopN = 50,
        [double]$DurationSeconds = 0
    )
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $L = New-Object 'System.Collections.Generic.List[string]'
    $L.Add('# Disk usage report')
    $L.Add('')
    foreach ($x in @(Get-RunInfoSectionLines -DurationSeconds $DurationSeconds -Mode 'Disk')) { $L.Add($x) }
    $L.Add(('- Directory walker: {0}; drives scanned: {1}; TopN: {2}' -f $Data['WalkerMode'], (@($Data['Scans'] | ForEach-Object { $_['Volume'] + ':' }) -join ', '), $TopN.ToString($inv)))
    $L.Add('- Sizes are allocated-on-disk bytes (OneDrive placeholders take no space; NTFS-compressed files count compressed). Nothing was deleted or changed.')
    $L.Add('- Privacy: this report and its CSV/JSON files contain personal data (user names and SIDs, file names in Downloads, browser profile display names, the Outlook .ost file name = mailbox address, game names). Review before sharing.')
    $L.Add('')

    # Findings
    $L.Add('## Findings')
    $L.Add('')
    $findings = ConvertTo-WdDiskArray -Value (Get-Findings)
    if ($findings.Count -eq 0) { $L.Add('_none_') }
    else {
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $findings -Columns @('Severity', 'Title', 'Detail', 'Recommendation'))) { $L.Add($x) }
    }
    $L.Add('')

    # Volumes
    $L.Add('## Volumes')
    $L.Add('')
    $volRows = @()
    foreach ($v in @($Data['Volumes'])) {
        $letter = $(if ($v['HasLetter']) { $v['Letter'] + ':' } elseif ($v['MountPath']) { $v['MountPath'] + '\' } else { '(no letter)' })
        $notes = @()
        if ($v['IsSystem']) { $notes += 'system' }
        if ($v['Compressed']) { $notes += 'NTFS compressed' }
        if ($v['BitLocker']) { $notes += ('BitLocker ' + $v['BitLocker']) }
        if ($v['Status'] -eq 'Unknown') { $notes += 'capacity not readable (BitLocker locked or not formatted)' }
        if (-not $v['Selected']) {
            if ($v['MountPath']) { $notes += 'mounted in a folder, not scanned (mount points are skipped by the walker)' }
            elseif (-not $v['HasLetter']) { $notes += 'no drive letter, not scanned' }
            else { $notes += 'not scanned' }
        }
        $volRows += [ordered]@{ Volume = $letter; Label = $v['Label']; FS = $v['FileSystem']; Size = (Format-Bytes -Bytes $v['CapacityBytes']); Used = (Format-Bytes -Bytes $v['UsedBytes']); Free = (Format-Bytes -Bytes $v['FreeBytes']); 'Free %' = (ConvertTo-InvariantString -Value $v['FreePercent'] -Decimals 1); Status = $v['Status']; Notes = ($notes -join ', ') }
    }
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $volRows -Columns @('Volume', 'Label', 'FS', 'Size', 'Used', 'Free', 'Free %', 'Status', 'Notes'))) { $L.Add($x) }
    $L.Add('')
    $L.Add('Thresholds: Warning below 10 % or 20 GB free, Critical below 5 % or 5 GB free.')
    $L.Add('')
    if (@($Data['PhysicalDisks']).Count -gt 0) {
        $pdRows = @($Data['PhysicalDisks'] | ForEach-Object { [ordered]@{ Disk = $_['Name']; Type = $_['MediaType']; Bus = $_['BusType']; Size = (Format-Bytes -Bytes $_['SizeBytes']); Health = $_['HealthStatus'] } })
        $L.Add('### Physical disks')
        $L.Add('')
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $pdRows -Columns @('Disk', 'Type', 'Bus', 'Size', 'Health'))) { $L.Add($x) }
        $L.Add('')
    }
    $L.Add('### Scan statistics')
    $L.Add('')
    $scanRows = @($Data['Scans'] | ForEach-Object { [ordered]@{ Volume = ($_['Volume'] + ':'); 'Scan time' = ((ConvertTo-InvariantString -Value $_['ElapsedSeconds'] -Decimals 1) + ' s'); Files = ([int64]$_['Files']).ToString('N0', $inv); Folders = ([int64]$_['Dirs']).ToString('N0', $inv); Allocated = (Format-Bytes -Bytes $_['AllocatedBytes']); Logical = (Format-Bytes -Bytes $_['LogicalBytes']); 'Scanned / used' = (ConvertTo-InvariantString -Value $_['SanityRatio'] -Decimals 2); 'Not readable' = $_['Denied']; 'Links skipped' = $_['SkippedLinks']; 'Cloud-only files' = ([int64]$_['CloudOnlyFiles']).ToString('N0', $inv) } })
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $scanRows -Columns @('Volume', 'Scan time', 'Files', 'Folders', 'Allocated', 'Logical', 'Scanned / used', 'Not readable', 'Links skipped', 'Cloud-only files'))) { $L.Add($x) }
    $L.Add('')
    $L.Add('"Scanned / used" below 1.0 means folders that could not be read (shadow copies in System Volume Information, other users, system caches) plus MFT overhead; hard links inside Windows are counted once per link (see -Deep). Junctions, symbolic links and volume mount points are never followed: a volume mounted in a folder is listed above but not measured.')
    if ($null -ne $Data['Deep']) {
        $d = $Data['Deep']
        $L.Add('')
        $L.Add(('Deep step (hard links): {0} = {1} summed, {2} unique ({3} files with more than one link, {4} duplicate links, {5} s).' -f $d['Root'], (Format-Bytes -Bytes $d['Bytes']), (Format-Bytes -Bytes $d['UniqueBytes']), ([int64]$d['LinkedFiles']).ToString('N0', $inv), ([int64]$d['DuplicateLinks']).ToString('N0', $inv), (ConvertTo-InvariantString -Value $d['ElapsedSeconds'] -Decimals 1)))
    }
    $L.Add('')

    # Savings
    $L.Add('## Potential savings by safety class')
    $L.Add('')
    $savRows = @($Data['Savings'] | ForEach-Object { [ordered]@{ 'Safety class' = $_['SafetyClass']; Candidates = $_['Candidates']; 'Size now' = (Format-Bytes -Bytes $_['Bytes']); Reclaimable = (Format-Bytes -Bytes $_['Reclaimable']); 'Need admin' = $_['NeedsAdminCount']; Meaning = $_['Meaning'] } })
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $savRows -Columns @('Safety class', 'Candidates', 'Size now', 'Reclaimable', 'Need admin', 'Meaning'))) { $L.Add($x) }
    $L.Add('')
    $safe = @($Data['Savings'] | Where-Object { $_['SafetyClass'] -eq 'Safe' })
    if ($safe.Count -gt 0) { $L.Add(('**Headline: about {0} can be freed safely.** Review items are shown but not summed; Risky items are only reclaimable through the named system tool.' -f (Format-Bytes -Bytes $safe[0]['Reclaimable']))) }
    $L.Add('')
    $overlapTotal = [int64]0
    foreach ($sv in @($Data['Savings'])) { if ($null -ne $sv['OverlapBytes']) { $overlapTotal += [int64]$sv['OverlapBytes'] } }
    $savNotes = @()
    if ($overlapTotal -gt 0) { $savNotes += ('candidates whose paths lie inside another candidate of the same class are counted once in "Size now" ({0} of overlap excluded; the Note column names the containing item)' -f (Format-Bytes -Bytes $overlapTotal)) }
    $adminTotal = 0
    foreach ($sv in @($Data['Savings'])) { $adminTotal += [int]$sv['NeedsAdminCount'] }
    if ($adminTotal -gt 0) { $savNotes += '"Need admin" candidates could not be measured completely without administrator rights, so their sizes are lower bounds' }
    if ($savNotes.Count -gt 0) { $L.Add('Notes: ' + ($savNotes -join '; ') + '.'); $L.Add('') }

    # Candidates
    $L.Add('## Cleanup candidates')
    $L.Add('')
    $order = @{ 'Safe' = 0; 'Review' = 1; 'Risky' = 2 }
    $cands = @($script:WdDiskCandidates | Where-Object { $_['Exists'] -or $_['NeedsAdmin'] } | Sort-Object -Property @{ Expression = { $order[[string]$_['SafetyClass']] } }, @{ Expression = { [int64]$_['Bytes'] }; Descending = $true })
    $candRows = @($cands | ForEach-Object {
        $sz = $(if ($_['NeedsAdmin'] -and [int64]$_['Bytes'] -eq 0) { $script:WdDiskAdminText } elseif ($_['Measured']) { Format-Bytes -Bytes $_['Bytes'] } else { $script:WdDiskAdminText })
        $rc = $(if ($_['ReportOnly']) { 'report only' } elseif ($_['NeedsAdmin'] -and [int64]$_['Bytes'] -eq 0) { $script:WdDiskAdminText } elseif (-not $_['Measured']) { $script:WdDiskAdminText } else { Format-Bytes -Bytes $_['Reclaimable'] })
        [ordered]@{ Category = $_['Category']; Safety = $_['SafetyClass']; Size = $sz; Files = $(if ($_['Files'] -gt 0) { ([int64]$_['Files']).ToString('N0', $inv) } else { '' }); Reclaimable = $rc; Admin = $(if ($_['NeedsAdmin']) { 'yes' } else { '' }); 'Path(s)' = $_['Path']; 'How to clean' = $_['HowToClean']; Note = $_['Note'] }
    })
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $candRows -Columns @('Category', 'Safety', 'Size', 'Files', 'Reclaimable', 'Admin', 'Path(s)', 'How to clean', 'Note'))) { $L.Add($x) }
    $L.Add('')
    $ss = $Data['StorageSense']
    $L.Add('### Storage Sense (HKCU StoragePolicy, best-effort interpretation)')
    $L.Add('')
    if ($null -eq $ss -or -not $ss['KeyPresent']) { $L.Add('- No Storage Sense settings found for the current user (defaults apply).') }
    else {
        $onOff = { param($v) if ($null -eq $v) { 'n/a' } elseif ([int]$v -ne 0) { 'on' } else { 'off' } }
        $L.Add(('- Storage Sense: {0}; runs {1}' -f (& $onOff $ss['Enabled']), $ss['CadenceText']))
        $L.Add(('- Delete temporary files: {0}; Recycle Bin cleanup: {1} (after {2} days); Downloads cleanup: {3} (after {4} days); cloud content dehydration: {5} (after {6} days)' -f (& $onOff $ss['DeleteTempFiles']), (& $onOff $ss['RecycleBinCleanup']), (ConvertTo-InvariantString -Value $ss['RecycleBinDays']), (& $onOff $ss['DownloadsCleanup']), (ConvertTo-InvariantString -Value $ss['DownloadsDays']), (& $onOff $ss['CloudDehydration']), (ConvertTo-InvariantString -Value $ss['CloudDehydrationDays'])))
        if ($null -ne $ss['GroupPolicy'] -and $ss['GroupPolicy'].Count -gt 0) { $L.Add(('- Group policy overrides present: ' + (ConvertTo-InvariantString -Value $ss['GroupPolicy']))) }
    }
    if ($null -ne $ss -and $ss['SilentCleanupTaskState']) { $L.Add(('- Scheduled task \Microsoft\Windows\DiskCleanup\SilentCleanup: {0}' -f $ss['SilentCleanupTaskState'])) }
    $L.Add('')

    # Top folders
    $L.Add('## Top folders')
    $L.Add('')
    foreach ($s in @($Data['Scans'])) {
        foreach ($d in 1..3) {
            $rows = @($s['TopFolders'] | Where-Object { [int]$_['Depth'] -eq $d } | ForEach-Object { [ordered]@{ Path = $_['Path']; Size = (Format-Bytes -Bytes $_['Bytes']); Files = ([int64]$_['Files']).ToString('N0', $inv); Folders = ([int64]$_['Dirs']).ToString('N0', $inv); 'Not readable' = $_['Inaccessible']; 'Cloud-only files' = $(if ([int64]$_['CloudOnlyFiles'] -gt 0) { ([int64]$_['CloudOnlyFiles']).ToString('N0', $inv) } else { '' }) } })
            $L.Add(('### {0}: depth {1} (top {2})' -f $s['Volume'], $d, $TopN.ToString($inv)))
            $L.Add('')
            foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows -Columns @('Path', 'Size', 'Files', 'Folders', 'Not readable', 'Cloud-only files'))) { $L.Add($x) }
            $L.Add('')
        }
    }

    # Top files
    $L.Add(('## Top files (>= {0}, top {1} per volume)' -f (Format-Bytes -Bytes $script:WdDiskLargeFileBytes -Decimals 0), $TopN.ToString($inv)))
    $L.Add('')
    foreach ($s in @($Data['Scans'])) {
        $rows = @($s['TopFiles'] | ForEach-Object { [ordered]@{ Path = $_['Path']; Size = (Format-Bytes -Bytes $_['Bytes']); Logical = $(if ($_['LogicalBytes'] -ne $_['Bytes']) { Format-Bytes -Bytes $_['LogicalBytes'] } else { '' }); Modified = (Get-WdDiskDateText -Value $_['Modified']); 'Cloud-only' = $(if ($_['CloudOnly']) { 'yes' } else { '' }) } })
        $L.Add(('### {0}:' -f $s['Volume']))
        $L.Add('')
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows -Columns @('Path', 'Size', 'Logical', 'Modified', 'Cloud-only'))) { $L.Add($x) }
        $L.Add('')
    }
    if (@($Data['DownloadsTopFiles']).Count -gt 0) {
        $rows = @($Data['DownloadsTopFiles'] | Select-Object -First 10 | ForEach-Object { [ordered]@{ Path = $_['Path']; Size = (Format-Bytes -Bytes $_['Bytes']); Modified = (Get-WdDiskDateText -Value $_['Modified']) } })
        $L.Add('### Largest files in Downloads')
        $L.Add('')
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $rows -Columns @('Path', 'Size', 'Modified'))) { $L.Add($x) }
        $L.Add('')
    }

    # Profiles
    $L.Add('## User profiles')
    $L.Add('')
    $profRows = @($Data['Profiles'] | ForEach-Object {
        [ordered]@{ Name = $_['Name']; Path = $_['Path']; Loaded = $(if ($_['Loaded']) { 'yes' } else { 'no' }); 'Last use' = (Get-WdDiskDateText -Value $_['LastUseTime']); 'Folder modified' = (Get-WdDiskDateText -Value $_['FolderLastWrite']); Size = $(if ($_['Readable']) { Format-Bytes -Bytes $_['Bytes'] } else { $script:WdDiskAdminText }); Files = $(if ($_['Readable'] -and $null -ne $_['Files']) { ([int64]$_['Files']).ToString('N0', $inv) } else { '' }); Old = $(if ($_['OldProfile']) { 'yes (> 90 days, not loaded)' } else { '' }); Source = $_['Source'] }
    })
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $profRows -Columns @('Name', 'Path', 'Loaded', 'Last use', 'Folder modified', 'Size', 'Files', 'Old', 'Source'))) { $L.Add($x) }
    $L.Add('')
    $L.Add('LastUseTime comes from Win32_UserProfile and is often empty for unloaded profiles on Windows 11; "Folder modified" is the fallback. Profile sizes of other users need administrator rights.')
    $L.Add('')

    # Installed apps
    $L.Add(('## Installed apps by size (top {0}, Uninstall registry EstimatedSize)' -f $TopN.ToString($inv)))
    $L.Add('')
    $appRows = @($Data['InstalledApps'] | Where-Object { $null -ne $_['Bytes'] } | Select-Object -First $TopN | ForEach-Object { [ordered]@{ Name = $_['Name']; Publisher = $_['Publisher']; Version = $_['Version']; Size = (Format-Bytes -Bytes $_['Bytes']); Installed = $_['InstallDate']; Location = $_['InstallLocation'] } })
    foreach ($x in @(ConvertTo-MarkdownTable -InputObject $appRows -Columns @('Name', 'Publisher', 'Version', 'Size', 'Installed', 'Location'))) { $L.Add($x) }
    $L.Add('')
    $noSize = @($Data['InstalledApps'] | Where-Object { $null -eq $_['Bytes'] }).Count
    $L.Add(('{0} apps found in total; {1} report no size (EstimatedSize missing).' -f @($Data['InstalledApps']).Count.ToString($inv), $noSize.ToString($inv)))
    $L.Add('')
    if (@($Data['Appx']).Count -gt 0) {
        $L.Add(('### Store apps of the current user (top {0} by install folder size)' -f $TopN.ToString($inv)))
        $L.Add('')
        $apxRows = @($Data['Appx'] | Select-Object -First $TopN | ForEach-Object { [ordered]@{ Package = $_['Name']; Version = $_['Version']; Size = (Format-Bytes -Bytes $_['Bytes']); Framework = $(if ($_['IsFramework']) { 'yes' } else { '' }); Location = $_['InstallLocation'] } })
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $apxRows -Columns @('Package', 'Version', 'Size', 'Framework', 'Location'))) { $L.Add($x) }
        $L.Add('')
    }
    if (@($Data['PackageData']).Count -gt 0) {
        $L.Add('### Store app data (AppData\Local\Packages, top 15)')
        $L.Add('')
        $pkRows = @($Data['PackageData'] | Select-Object -First 15 | ForEach-Object { [ordered]@{ Package = $_['Package']; Size = (Format-Bytes -Bytes $_['Bytes']); Files = ([int64]$_['Files']).ToString('N0', $inv) } })
        foreach ($x in @(ConvertTo-MarkdownTable -InputObject $pkRows -Columns @('Package', 'Size', 'Files'))) { $L.Add($x) }
        $L.Add('')
    }

    foreach ($x in @(Get-SummaryFooterLines)) { $L.Add($x) }
    return $L.ToArray()
}

function Export-WdDiskOutputs {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$OutDir, [Parameter(Mandatory = $true)][hashtable]$Data, [int]$TopN = 50, [double]$DurationSeconds = 0)
    # volumes.csv
    $volRows = @($Data['Volumes'] | ForEach-Object { [ordered]@{ Letter = $_['Letter']; Label = $_['Label']; FileSystem = $_['FileSystem']; CapacityBytes = $_['CapacityBytes']; UsedBytes = $_['UsedBytes']; FreeBytes = $_['FreeBytes']; FreePercent = $_['FreePercent']; Status = $_['Status']; IsSystem = $_['IsSystem']; Selected = $_['Selected']; Compressed = $_['Compressed']; BitLocker = $_['BitLocker']; BlockSize = $_['BlockSize'] } })
    Export-CsvInvariant -InputObject $volRows -Path ([IO.Path]::Combine($OutDir, 'volumes.csv'))
    # top-folders.csv
    $folderRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in @($Data['Scans'])) { foreach ($f in @($s['TopFolders'])) { $folderRows.Add([ordered]@{ Volume = $f['Volume']; Depth = $f['Depth']; Path = $f['Path']; Bytes = $f['Bytes']; Files = $f['Files']; Dirs = $f['Dirs']; Inaccessible = $f['Inaccessible'] }) } }
    Export-CsvInvariant -InputObject $folderRows.ToArray() -Path ([IO.Path]::Combine($OutDir, 'top-folders.csv'))
    # top-files.csv
    $fileRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in @($Data['Scans'])) { foreach ($f in @($s['TopFiles'])) { $fileRows.Add([ordered]@{ Path = $f['Path']; Bytes = $f['Bytes']; Modified = $f['Modified']; Created = $f['Created']; Extension = $f['Extension']; LogicalBytes = $f['LogicalBytes']; CloudOnly = $f['CloudOnly'] }) } }
    Export-CsvInvariant -InputObject $fileRows.ToArray() -Path ([IO.Path]::Combine($OutDir, 'top-files.csv'))
    # cleanup-candidates.csv
    $candRows = @($script:WdDiskCandidates | Where-Object { $_['Exists'] -or $_['NeedsAdmin'] } | ForEach-Object { [ordered]@{ Category = $_['Category']; Path = $_['Path']; Bytes = $_['Bytes']; Files = $_['Files']; SafetyClass = $_['SafetyClass']; Reclaimable = $_['Reclaimable']; ReportOnly = $_['ReportOnly']; NeedsAdmin = $_['NeedsAdmin']; HowToClean = $_['HowToClean']; Note = $_['Note'] } })
    Export-CsvInvariant -InputObject $candRows -Path ([IO.Path]::Combine($OutDir, 'cleanup-candidates.csv'))
    # user-profiles.csv
    $profRows = @($Data['Profiles'] | ForEach-Object { [ordered]@{ Name = $_['Name']; Path = $_['Path']; SID = $_['SID']; Loaded = $_['Loaded']; LastUseTime = $_['LastUseTime']; FolderLastWrite = $_['FolderLastWrite']; AgeDays = $_['AgeDays']; Bytes = $_['Bytes']; Files = $_['Files']; Readable = $_['Readable']; OldProfile = $_['OldProfile']; Source = $_['Source'] } })
    Export-CsvInvariant -InputObject $profRows -Path ([IO.Path]::Combine($OutDir, 'user-profiles.csv'))
    # disk-usage.json
    $scansJson = @($Data['Scans'] | ForEach-Object {
        $s = $_
        $o = [ordered]@{}
        foreach ($k in $s.Keys) { if ($k -ne 'TopFolders' -and $k -ne 'TopFiles') { $o[$k] = $s[$k] } }
        $o
    })
    $doc = [ordered]@{
        Meta            = (Get-ReportRunInfo -Mode 'Disk')
        DurationSeconds = [math]::Round($DurationSeconds, 1, [MidpointRounding]::AwayFromZero)
        WalkerMode      = $Data['WalkerMode']
        Findings        = (ConvertTo-WdDiskArray -Value (Get-Findings))
        Volumes         = @($Data['Volumes'])
        PhysicalDisks   = @($Data['PhysicalDisks'])
        Scans           = $scansJson
        TopFolders      = $folderRows.ToArray()
        TopFiles        = $fileRows.ToArray()
        Profiles        = @($Data['Profiles'])
        Cleanup         = [ordered]@{
            Savings           = @($Data['Savings'])
            Candidates        = $script:WdDiskCandidates.ToArray()
            PageFiles         = $Data['PageFiles']
            ShadowStorage     = $Data['ShadowStorage']
            ReservedStorage   = $Data['ReservedStorage']
            InstallerCache    = $Data['InstallerCache']
            KnownFolders      = @($Data['KnownFolders'])
            DownloadsTopFiles = @($Data['DownloadsTopFiles'])
            StorageSense      = $Data['StorageSense']
            CleanmgrHandlers  = @($Data['CleanmgrHandlers'])
        }
        InstalledApps   = @($Data['InstalledApps'])
        Appx            = @($Data['Appx'])
        AppxTotalBytes  = $Data['AppxTotalBytes']
        PackageData     = @($Data['PackageData'])
        Deep            = $Data['Deep']
        AdminSkips      = (ConvertTo-WdDiskArray -Value (Get-AdminSkips))
        CollectionErrors = (ConvertTo-WdDiskArray -Value $script:CollectionErrors)
    }
    Export-Json -Object $doc -Path ([IO.Path]::Combine($OutDir, 'disk-usage.json')) -Depth 8
    # summary.md
    Write-MarkdownFile -Path ([IO.Path]::Combine($OutDir, 'summary.md')) -Lines (Get-WdDiskSummaryLines -Data $Data -TopN $TopN -DurationSeconds $DurationSeconds)
}

# ---------------------------------------------------------------------------------------------
# Entry point of the module
# ---------------------------------------------------------------------------------------------
function Invoke-DiskScan {
    <#
    .SYNOPSIS
        Disk mode: per-volume usage, top folders/files, user profiles and a cleanup catalog with safety classes. Report only.
    .PARAMETER OutDir
        Report folder (created when missing). Receives summary.md, disk-usage.json and the CSV files.
    .PARAMETER Drives
        Drive letters to scan. Default: every fixed NTFS/ReFS volume with a letter.
    .PARAMETER TopN
        Number of top folders per depth, top files and top apps.
    .PARAMETER Deep
        Also deduplicate hard links under %windir% (opens every file for attributes; about half a minute).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutDir,
        [string[]]$Drives,
        [ValidateRange(1, 1000)][int]$TopN = 50,
        [switch]$Deep
    )
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $sw = [Diagnostics.Stopwatch]::StartNew()
    if (-not (Test-DirectoryExists -Path $OutDir)) { [void][IO.Directory]::CreateDirectory($OutDir) }
    if ([string]::IsNullOrEmpty($script:LogPath)) { $script:LogPath = [IO.Path]::Combine($OutDir, 'run.log') }
    if ([string]::IsNullOrEmpty($script:CurrentMode)) { $script:CurrentMode = 'Disk' }
    if ($null -eq $script:RunStart) { $script:RunStart = Get-Date }
    $script:WdDiskScans = New-Object 'System.Collections.Generic.List[object]'
    $script:WdDiskCandidates = New-Object 'System.Collections.Generic.List[object]'
    $script:WdDiskRemotePaths = New-Object 'System.Collections.Generic.List[string]'
    $script:WdDiskBrowserBytes = [int64]0
    $data = @{ Scans = @(); Volumes = @(); Profiles = @(); InstalledApps = @(); Appx = @(); PackageData = @(); Savings = @(); Deep = $null }

    Write-SectionHeader -Title 'Disk usage: volumes'
    $data['WalkerMode'] = Measure-Step -Name 'Disk.Walker' -ScriptBlock { Initialize-WdDiskWalker }
    $volumes = @(Measure-Step -Name 'Disk.Volumes' -ScriptBlock { Invoke-Safely -Name 'Disk.Volumes' -Default @() -ScriptBlock { Get-WdDiskVolumes -Drives $Drives } })
    $data['Volumes'] = $volumes
    $data['PhysicalDisks'] = @(Invoke-Safely -Name 'Disk.PhysicalDisks' -Default @() -ScriptBlock { Get-WdDiskPhysicalDisks })
    Invoke-Safely -Name 'Disk.VolumeFindings' -ScriptBlock { Add-WdDiskVolumeFindings -Volumes $volumes } | Out-Null
    foreach ($v in $volumes) {
        Write-Log -Level Info -Message ('{0}: {1} "{2}" {3}: {4} used, {5} free ({6} %) {7}' -f $(if ($v['HasLetter']) { $v['Letter'] + ':' } else { '(no letter)' }), $v['FileSystem'], $v['Label'], (Format-Bytes -Bytes $v['CapacityBytes']), (Format-Bytes -Bytes $v['UsedBytes']), (Format-Bytes -Bytes $v['FreeBytes']), (ConvertTo-InvariantString -Value $v['FreePercent'] -Decimals 1), $v['Status'])
    }

    Write-SectionHeader -Title 'Disk usage: scanning volumes'
    $scans = New-Object 'System.Collections.Generic.List[object]'
    $selected = @($volumes | Where-Object { $_['Selected'] })
    if ($selected.Count -eq 0) { Write-Log -Level Warn -Message 'No fixed NTFS/ReFS volume selected for scanning.' }
    foreach ($v in $selected) {
        $r = Measure-Step -Name ('Disk.Scan.' + $v['Letter']) -ScriptBlock { Invoke-Safely -Name ('Disk.Scan.' + $v['Letter']) -Default $null -ScriptBlock { Get-WdDiskVolumeScan -Volume $v -TopN $TopN } }
        if ($null -ne $r) { $scans.Add($r) }
    }
    $data['Scans'] = $scans.ToArray()
    Invoke-Safely -Name 'Disk.ScanFindings' -ScriptBlock { Add-WdDiskScanFindings -Scans $scans.ToArray() } | Out-Null

    Write-SectionHeader -Title 'Disk usage: user profiles'
    $profiles = @(Measure-Step -Name 'Disk.Profiles' -ScriptBlock { Invoke-Safely -Name 'Disk.Profiles' -Default @() -ScriptBlock { Get-WdDiskUserProfiles } })
    $data['Profiles'] = $profiles
    Write-Log -Level Info -Message ('{0} profile folder(s), {1} readable' -f $profiles.Count, @($profiles | Where-Object { $_['Readable'] }).Count)

    Write-SectionHeader -Title 'Disk usage: cleanup catalog'
    $sysExtra = Measure-Step -Name 'Disk.Cleanup.System' -ScriptBlock { Add-WdDiskSystemCandidates -Volumes $volumes -Profiles $profiles -TopN $TopN }
    Measure-Step -Name 'Disk.Cleanup.Browsers' -ScriptBlock { Add-WdDiskBrowserCandidates -Profiles $profiles } | Out-Null
    Measure-Step -Name 'Disk.Cleanup.AppCaches' -ScriptBlock { Add-WdDiskAppCacheCandidates -Profiles $profiles } | Out-Null
    Measure-Step -Name 'Disk.Cleanup.CloudGamesVm' -ScriptBlock { Add-WdDiskCloudAndGameCandidates -Profiles $profiles -Volumes $volumes } | Out-Null
    $devExtra = Measure-Step -Name 'Disk.Cleanup.DevPersonal' -ScriptBlock { Add-WdDiskDevAndPersonalCandidates -Profiles $profiles -TopN $TopN }
    foreach ($src in @($sysExtra, $devExtra)) { if ($null -ne $src) { foreach ($k in $src.Keys) { $data[$k] = $src[$k] } } }

    Write-SectionHeader -Title 'Disk usage: installed apps'
    $data['InstalledApps'] = @(Measure-Step -Name 'Disk.InstalledApps' -ScriptBlock { Invoke-Safely -Name 'Disk.InstalledApps' -Default @() -ScriptBlock { Get-WdDiskInstalledApps } })
    $appxExtra = Measure-Step -Name 'Disk.Appx' -ScriptBlock { Add-WdDiskAppxCandidates -Profiles $profiles -TopN $TopN }
    if ($null -ne $appxExtra) { foreach ($k in $appxExtra.Keys) { $data[$k] = $appxExtra[$k] } }
    $data['StorageSense'] = Invoke-Safely -Name 'Disk.StorageSense' -Default $null -ScriptBlock { Get-WdDiskStorageSense }
    $data['CleanmgrHandlers'] = @(Invoke-Safely -Name 'Disk.CleanmgrHandlers' -Default @() -ScriptBlock { Get-WdDiskCleanmgrHandlers })

    if ($Deep) {
        Write-SectionHeader -Title 'Disk usage: deep step (hard links in Windows)'
        $data['Deep'] = Measure-Step -Name 'Disk.Deep' -ScriptBlock {
            Invoke-Safely -Name 'Disk.Deep.HardLinks' -Default $null -ScriptBlock {
                if ($script:WdDiskWalkerMode -ne 'Native') { throw 'hard-link deduplication needs the native walker' }
                try { [WinDebug.FastWalker]::HookCancel() } catch { }
                try { $u = [WinDebug.FastWalker]::ScanUnique([string]$env:windir) } finally { try { [WinDebug.FastWalker]::UnhookCancel() } catch { } }
                if ($u.Cancelled) { throw 'deep step interrupted by Ctrl+C; partial totals discarded' }
                [ordered]@{ Root = [string]$u.Root; Files = [int64]$u.Files; Bytes = [int64]$u.Bytes; UniqueBytes = [int64]$u.UniqueBytes; LinkedFiles = [int64]$u.LinkedFiles; DuplicateLinks = [int64]$u.DuplicateLinks; OpenErrors = [int64]$u.OpenErrors; Denied = [int]$u.Denied; ElapsedSeconds = [math]::Round(([double]$u.ElapsedMs) / 1000.0, 1, [MidpointRounding]::AwayFromZero) }
            }
        }
        if ($null -ne $data['Deep']) { Write-Log -Level Info -Message ('{0}: {1} summed, {2} unique after hard-link deduplication' -f $data['Deep']['Root'], (Format-Bytes -Bytes $data['Deep']['Bytes']), (Format-Bytes -Bytes $data['Deep']['UniqueBytes'])) }
    }

    Write-SectionHeader -Title 'Disk usage: findings and report'
    $data['Savings'] = @(Invoke-Safely -Name 'Disk.Savings' -Default @() -ScriptBlock { Get-WdDiskSavings })
    Invoke-Safely -Name 'Disk.CatalogFindings' -ScriptBlock { Add-WdDiskCatalogFindings -Savings $data['Savings'] -Volumes $volumes -Profiles $profiles -StorageSense $data['StorageSense'] } | Out-Null
    $sw.Stop()
    $duration = $sw.Elapsed.TotalSeconds
    Measure-Step -Name 'Disk.Write' -ScriptBlock { Export-WdDiskOutputs -OutDir $OutDir -Data $data -TopN $TopN -DurationSeconds $duration } | Out-Null
    $safeRow = @($data['Savings'] | Where-Object { $_['SafetyClass'] -eq 'Safe' })
    $safeBytes = $(if ($safeRow.Count -gt 0) { [int64]$safeRow[0]['Reclaimable'] } else { [int64]0 })
    Write-Log -Level Info -Message ([string]::Format($inv, 'Disk scan finished in {0:F1} s: {1} volume(s), {2} cleanup candidates, about {3} reclaimable safely. Report: {4}', $duration, $scans.Count, @($script:WdDiskCandidates | Where-Object { $_['Exists'] }).Count, (Format-Bytes -Bytes $safeBytes), $OutDir))
    return [pscustomobject]@{
        OutDir          = $OutDir
        Volumes         = $scans.Count
        Candidates      = @($script:WdDiskCandidates | Where-Object { $_['Exists'] }).Count
        SafeReclaimable = $safeBytes
        WalkerMode      = $data['WalkerMode']
        DurationSeconds = [math]::Round($duration, 1, [MidpointRounding]::AwayFromZero)
    }
}
