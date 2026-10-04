# lib\Inventory.ps1 - Inventory mode of win-debug: hardware / OS / drivers / software / autostart /
# security / event-log inventory of a Windows 10/11 PC plus rule-based findings ("why is it slow").
# Dot-sourced by WinDebug.ps1 after lib\Common.ps1 (same script scope). Windows PowerShell 5.1 only.
# Read-only: the only files written are the report files in -OutDir (powercfg writes battery-report.xml there).
#
# Public API:
#   Invoke-InventoryScan -OutDir <string> [-Deep]
#     Writes summary.md, inventory.json, installed-programs.csv, autostart.csv, services.csv,
#     scheduled-tasks.csv, devices-problems.csv, drivers.csv, events.csv, processes-snapshot.csv
#     (and battery-report.xml on laptops: the raw powercfg report, which contains the computer name, battery serial
#     number and weeks of power-on/standby history - personal data, mentioned in the summary.md privacy line).
#     Returns the ordered data hashtable that was written to JSON.
#   -Deep adds: Authenticode signature of every autostart binary (not only flagged ones) and the full
#     Win32_PnPSignedDriver list in drivers.csv.
#
# Private helpers are prefixed Get-WdInv* / Test-WdInv* / Add-WdInv* / ConvertTo-WdInv* / Write-WdInv*.
# Rule ids and thresholds are documented in docs\inventory-rules.md.

Set-StrictMode -Off

# ---------------------------------------------------------------------------------------------
# Small private helpers
# ---------------------------------------------------------------------------------------------
function Get-WdInvNum {
    # Rounded double for report output ($null stays $null). AwayFromZero, never banker's rounding.
    [CmdletBinding()]
    param([AllowNull()][object]$Value, [int]$Decimals = 1)
    if ($null -eq $Value) { return $null }
    try {
        $d = [double]$Value
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return $null }
        return [math]::Round($d, $Decimals, [MidpointRounding]::AwayFromZero)
    } catch { return $null }
}

function Format-WdInvNum {
    # Culture-invariant text of a number for messages ("12.3"); $null -> "n/a".
    [CmdletBinding()]
    param([AllowNull()][object]$Value, [int]$Decimals = 1)
    if ($null -eq $Value) { return 'n/a' }
    $r = Get-WdInvNum -Value $Value -Decimals $Decimals
    if ($null -eq $r) { return 'n/a' }
    return (ConvertTo-InvariantString -Value $r -Decimals $Decimals)
}

function Get-WdInvAverage {
    # Average of the non-null numeric values in a list; $null when nothing usable.
    [CmdletBinding()]
    param([AllowNull()][object[]]$Values, [int]$Decimals = 1)
    if ($null -eq $Values) { return $null }
    $sum = 0.0
    $n = 0
    foreach ($v in $Values) {
        if ($null -eq $v) { continue }
        try { $sum += [double]$v; $n++ } catch { }
    }
    if ($n -eq 0) { return $null }
    return (Get-WdInvNum -Value ($sum / $n) -Decimals $Decimals)
}

function Get-WdInvMax {
    [CmdletBinding()]
    param([AllowNull()][object[]]$Values)
    if ($null -eq $Values) { return $null }
    $max = $null
    foreach ($v in $Values) {
        if ($null -eq $v) { continue }
        try { $d = [double]$v } catch { continue }
        if ($null -eq $max -or $d -gt $max) { $max = $d }
    }
    return $max
}

function Get-WdInvString {
    # Trimmed string of any value; $null -> ''.
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return '' }
    try { return ([string]$Value).Trim() } catch { return '' }
}

function Get-WdInvPropertyValue {
    # Property of a CIM/PS object by name; $null when missing (never throws).
    [CmdletBinding()]
    param([AllowNull()][object]$Object, [Parameter(Mandatory = $true)][string]$Name, [AllowNull()][object]$Default = $null)
    if ($null -eq $Object) { return $Default }
    try {
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($Name)) { return $Object[$Name] }
            return $Default
        }
        $p = $Object.PSObject.Properties[$Name]
        if ($null -eq $p) { return $Default }
        $v = $p.Value
        if ($null -eq $v) { return $Default }
        return $v
    } catch { return $Default }
}

function Get-WdInvDaysSince {
    # Whole days between a DateTime and now ($null when unknown).
    [CmdletBinding()]
    param([AllowNull()][object]$Date)
    if ($null -eq $Date) { return $null }
    try {
        $d = [DateTime]$Date
        if ($d.Year -lt 1990) { return $null }
        return [int][math]::Floor(((Get-Date) - $d).TotalDays)
    } catch { return $null }
}

function Get-WdInvRegistryValues {
    # All values of one registry key as an ordered hashtable (Get-Item + GetValueNames, names untouched,
    # environment variables NOT expanded). Empty hashtable when the key is missing or denied.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [switch]$Expand)
    $result = [ordered]@{}
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($null -eq $k) { return $result }
        $opt = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        if ($Expand) { $opt = [Microsoft.Win32.RegistryValueOptions]::None }
        foreach ($n in @($k.GetValueNames())) {
            try { $result[[string]$n] = $k.GetValue($n, $null, $opt) } catch { }
        }
    } catch { }
    return $result
}

function Get-WdInvRegistrySubKeyNames {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    $names = @()
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($null -ne $k) { $names = @($k.GetSubKeyNames()) }
    } catch { }
    return $names
}

function Test-WdInvRegistryKey {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)
    try { return [bool](Test-Path -LiteralPath $Path -ErrorAction Stop) } catch { return $false }
}

function ConvertTo-WdInvKeyValueRows {
    # [ordered] hashtable -> rows with Name/Value for ConvertTo-MarkdownTable.
    [CmdletBinding()]
    param([AllowNull()][System.Collections.IDictionary]$Pairs)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Pairs) { return $rows.ToArray() }
    foreach ($k in $Pairs.Keys) {
        $v = $Pairs[$k]
        if ($null -eq $v) { $v = '' }
        $rows.Add([pscustomobject]@{ Name = [string]$k; Value = (ConvertTo-InvariantString -Value $v) })
    }
    return $rows.ToArray()
}

function Add-WdInvAdminGap {
    # Records a data gap that needs administrator rights (footer of summary.md) and returns the placeholder text.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Item, [string]$Detail = '')
    Add-AdminSkip -Item $Item -Detail $Detail
    return '(requires administrator)'
}

function Get-WdInvCommandInfo {
    # Splits an autostart/service/task command line into executable path and arguments.
    # Expands %ENV% variables, strips quotes, resolves bare file names against System32/Windows/PATH.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Command, [AllowNull()][AllowEmptyString()][string]$Arguments = '')
    $r = [ordered]@{ Command = $Command; Path = ''; Arguments = ''; FileName = ''; Exists = $false; HasDirectory = $false }
    if ([string]::IsNullOrWhiteSpace($Command)) { return $r }
    $c = $Command.Trim()
    try { $c = [Environment]::ExpandEnvironmentVariables($c) } catch { }
    if ($c -match '^\\\?\?\\') { $c = $c.Substring(4) }
    if ($c -match '^\\SystemRoot\\') { $c = [string]$env:SystemRoot + $c.Substring(11) }
    elseif ($c -match '^(System32|SysWOW64)\\') { $c = [IO.Path]::Combine([string]$env:SystemRoot, $c) }
    $path = ''
    $argText = ''
    if ($c.StartsWith('"')) {
        $end = $c.IndexOf('"', 1)
        if ($end -gt 0) {
            $path = $c.Substring(1, $end - 1)
            if ($end + 1 -lt $c.Length) { $argText = $c.Substring($end + 1).Trim() }
        } else {
            $path = $c.Trim('"')
        }
    } else {
        # Unquoted: resolve the way CreateProcess does - try every whitespace boundary (shortest prefix first, also
        # with ".exe" appended) and take the first prefix that exists on disk. "C:\Program Files\Some.exe Tools\app.exe"
        # or "C:\Tools\NoExt Name\tool" would otherwise be cut at the first ".exe " / space.
        $found = $false
        if ($c -match '[\\/]') {
            $boundaries = New-Object 'System.Collections.Generic.List[int]'
            for ($i = 1; $i -lt $c.Length -and $boundaries.Count -lt 32; $i++) {
                if ([char]::IsWhiteSpace($c[$i]) -and -not [char]::IsWhiteSpace($c[$i - 1])) { $boundaries.Add($i) }
            }
            $boundaries.Add($c.Length)
            foreach ($b in $boundaries) {
                $prefix = $c.Substring(0, $b)
                $cand = ''
                if (Test-FileExists -Path $prefix) { $cand = $prefix }
                elseif ($prefix -notmatch '\.[a-z0-9]{2,4}$' -and (Test-FileExists -Path ($prefix + '.exe'))) { $cand = $prefix + '.exe' }
                if ($cand -ne '') {
                    $path = $cand
                    if ($b -lt $c.Length) { $argText = $c.Substring($b).Trim() }
                    $found = $true
                    break
                }
            }
        }
        if (-not $found) {
            $m = [regex]::Match($c, '^(.+?\.(exe|dll|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|scr|com|pif|msi|msc|lnk|py|cpl))(\s+(.*))?$', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($m.Success) {
                $path = $m.Groups[1].Value
                $argText = $m.Groups[4].Value
            } else {
                $sp = $c.IndexOf(' ')
                if ($sp -gt 0) { $path = $c.Substring(0, $sp); $argText = $c.Substring($sp + 1).Trim() } else { $path = $c }
            }
        }
    }
    if (-not [string]::IsNullOrWhiteSpace($Arguments)) {
        if ([string]::IsNullOrEmpty($argText)) { $argText = $Arguments.Trim() } else { $argText = $argText + ' ' + $Arguments.Trim() }
    }
    $path = $path.Trim().Trim('"')
    $r['HasDirectory'] = ($path -match '[\\/]')
    if (-not $r['HasDirectory'] -and -not [string]::IsNullOrEmpty($path)) {
        $candidateName = $path
        if ($candidateName -notmatch '\.[a-z0-9]{2,4}$') { $candidateName = $candidateName + '.exe' }
        $dirs = New-Object 'System.Collections.Generic.List[string]'
        $sysRoot = [string]$env:SystemRoot
        if (-not [string]::IsNullOrEmpty($sysRoot)) {
            $dirs.Add([IO.Path]::Combine($sysRoot, 'System32'))
            $dirs.Add($sysRoot)
            $dirs.Add([IO.Path]::Combine($sysRoot, 'SysWOW64'))
        }
        $pathVar = [string]$env:PATH
        if (-not [string]::IsNullOrEmpty($pathVar)) {
            foreach ($d in $pathVar.Split(';')) { if (-not [string]::IsNullOrWhiteSpace($d)) { $dirs.Add($d.Trim().Trim('"')) } }
        }
        foreach ($d in $dirs) {
            $cand = ''
            try { $cand = [IO.Path]::Combine($d, $candidateName) } catch { continue }
            if (Test-FileExists -Path $cand) { $path = $cand; break }
        }
    }
    $r['Path'] = $path
    $r['Arguments'] = [string]$argText
    try { $r['FileName'] = [IO.Path]::GetFileName($path) } catch { $r['FileName'] = $path }
    $r['Exists'] = Test-FileExists -Path $path
    return $r
}

function Get-WdInvSignatureInfo {
    # Cached Authenticode check. Returns [ordered] Status, Signer, Trusted (bool: Valid + trusted signer regex).
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Path)
    if ($null -eq $script:WdInvSigCache) { $script:WdInvSigCache = @{} }
    $r = [ordered]@{ Status = ''; Signer = ''; Trusted = $false }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $r }
    $key = $Path.ToLowerInvariant()
    if ($script:WdInvSigCache.ContainsKey($key)) { return $script:WdInvSigCache[$key] }
    if (-not (Test-FileExists -Path $Path)) { $r['Status'] = 'FileMissing'; $script:WdInvSigCache[$key] = $r; return $r }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $r['Status'] = [string]$sig.Status
        if ($null -ne $sig.SignerCertificate) { $r['Signer'] = [string]$sig.SignerCertificate.Subject }
        $trustedRegex = [string]$script:Rules['TrustedSignerRegex']
        if ($r['Status'] -eq 'Valid' -and -not [string]::IsNullOrEmpty($r['Signer']) -and $r['Signer'] -match $trustedRegex) { $r['Trusted'] = $true }
    } catch {
        $r['Status'] = 'Error'
    }
    $script:WdInvSigCache[$key] = $r
    return $r
}

function Test-WdInvSystemBinaryLocation {
    # True when a file that carries a Windows system binary name lives where that binary belongs.
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$BaseName, [Parameter(Mandatory = $true)][string]$Path)
    $locs = $script:Rules['SystemBinaryLocations']
    $allowed = @()
    if ($null -ne $locs) {
        if ($locs.Contains($BaseName)) { $allowed = @($locs[$BaseName]) } elseif ($locs.Contains('default')) { $allowed = @($locs['default']) }
    }
    $l = $Path.ToLowerInvariant()
    foreach ($a in $allowed) {
        $exp = ''
        try { $exp = ([Environment]::ExpandEnvironmentVariables([string]$a)).ToLowerInvariant() } catch { continue }
        if ($l.StartsWith($exp)) { return $true }
    }
    return $false
}

function Get-WdInvCommandFlags {
    # Classifies one command (already split by Get-WdInvCommandInfo). Returns [ordered] Flags (string[]),
    # LocationClass, Suspicious (bool), Signature (Status/Signer/Trusted or $null).
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Info,
        [switch]$CheckSignature,
        [switch]$ScriptFilesAreSuspicious
    )
    $flags = New-Object 'System.Collections.Generic.List[string]'
    $path = [string]$Info['Path']
    $argText = [string]$Info['Arguments']
    $fileName = [string]$Info['FileName']
    $full = ($path + ' ' + $argText).Trim()
    $loc = Get-ProcessLocationClass -Path $path
    $suspRegex   = [string]$script:Rules['SuspiciousPathRegex']
    $minerRegex  = [string]$script:Rules['MinerTokenRegex']
    $hostRegex   = [string]$script:Rules['ScriptHostRegex']
    # Shared rule data (lib\Common.ps1): WEAK script-host flags (-ExecutionPolicy Bypass, -NoProfile, -WindowStyle
    # Hidden, -NonInteractive) are how every legitimate scheduled PowerShell script is started and are recorded as
    # informational 'WeakRedFlagArgs' only; STRONG ones (encoded commands, downloads, IEX, base64, LOLBin tricks,
    # URLs) make a script-host entry suspicious on their own ('RedFlagArgs' + 'StrongRedFlagArgs').
    $weakArgRegex   = [string]$script:Rules['ScriptHostWeakArgRegex']
    $strongArgRegex = [string]$script:Rules['ScriptHostStrongArgRegex']
    if ([string]::IsNullOrEmpty($strongArgRegex)) { $strongArgRegex = [string]$script:Rules['ScriptHostArgRegex'] }
    $isScriptHost = ($fileName -ne '' -and $fileName -match $hostRegex)
    if ($path -ne '' -and $path -match $suspRegex) { $flags.Add('SuspiciousPath') }
    if ($argText -ne '' -and $argText -match $suspRegex) { $flags.Add('SuspiciousArgPath') }
    if ($isScriptHost) { $flags.Add('ScriptHost') }
    if ($argText -ne '' -and $weakArgRegex -ne '' -and $argText -match $weakArgRegex) { $flags.Add('WeakRedFlagArgs') }
    if ($argText -ne '' -and $strongArgRegex -ne '' -and $argText -match $strongArgRegex) { $flags.Add('RedFlagArgs'); $flags.Add('StrongRedFlagArgs') }
    if ($full -ne '' -and $full -match $minerRegex) { $flags.Add('MinerToken') }
    $ext = ''
    try { $ext = [IO.Path]::GetExtension($path).ToLowerInvariant() } catch { $ext = '' }
    if ($ext -in @('.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.bat', '.cmd', '.ps1', '.scr', '.pif', '.com')) { $flags.Add('ScriptFile') }
    $base = ''
    try { $base = [IO.Path]::GetFileNameWithoutExtension($path) } catch { $base = '' }
    if ($base -ne '' -and $Info['HasDirectory']) {
        foreach ($sysName in @($script:Rules['SystemBinaryNames'])) {
            if ([string]$sysName -ieq $base) {
                if (-not (Test-WdInvSystemBinaryLocation -BaseName ([string]$sysName) -Path $path)) { $flags.Add('SystemNameOutsideSystem32') }
                break
            }
        }
    }
    if ($loc -eq 'Network') { $flags.Add('NetworkPath') }
    if ($loc -eq 'Removable') { $flags.Add('RemovableDrive') }
    if ($Info['HasDirectory'] -and -not $Info['Exists'] -and $path -ne '' -and $path -notmatch '\*' -and $loc -ne 'Network') { $flags.Add('FileMissing') }
    $sig = $null
    $suspicious = ($flags.Contains('SuspiciousPath') -or $flags.Contains('SuspiciousArgPath') -or $flags.Contains('MinerToken') -or
                   $flags.Contains('SystemNameOutsideSystem32') -or ($flags.Contains('ScriptHost') -and $flags.Contains('StrongRedFlagArgs')) -or
                   $flags.Contains('NetworkPath'))
    if ($ScriptFilesAreSuspicious -and $flags.Contains('ScriptFile')) { $suspicious = $true }
    if ($CheckSignature -or ($suspicious -and $Info['Exists'])) {
        if ($Info['Exists'] -and $ext -in @('.exe', '.dll', '.sys', '.ocx', '.cpl', '.msi', '.scr')) {
            $sig = Get-WdInvSignatureInfo -Path $path
            if ($sig['Trusted']) { $flags.Add('SignedTrusted') }
            elseif ($sig['Status'] -eq 'Valid') { $flags.Add('Signed') }
            elseif ($sig['Status'] -ne '' -and $sig['Status'] -ne 'FileMissing' -and $sig['Status'] -ne 'Error') { $flags.Add('Unsigned') }
        }
    }
    # A validly signed binary from a trusted vendor in AppData/ProgramData is normal (updaters of Zoom, Teams, Discord...).
    # For a script host / LOLBin (rundll32, wscript, cmd, regsvr32 ...) the trusted signature belongs to the Windows
    # HOST, not to the payload in the arguments: "rundll32.exe %AppData%\evil.dll,Run" stays suspicious unless the
    # payload itself is validly signed by a trusted vendor.
    $payloadTrusted = $false
    if ($isScriptHost -and $flags.Contains('SuspiciousArgPath')) {
        $payload = Get-WdInvArgumentPayloadPath -Arguments $argText -PathRegex $suspRegex
        if ($payload -ne '') {
            if (-not (Test-FileExists -Path $payload)) { $flags.Add('PayloadMissing') }
            else {
                $pext = ''
                try { $pext = [IO.Path]::GetExtension($payload).ToLowerInvariant() } catch { $pext = '' }
                if ($pext -in @('.exe', '.dll', '.sys', '.ocx', '.cpl', '.msi', '.scr')) {
                    $psig = Get-WdInvSignatureInfo -Path $payload
                    if ($psig['Trusted']) { $payloadTrusted = $true; $flags.Add('PayloadSignedTrusted') }
                    elseif ($psig['Status'] -eq 'Valid') { $flags.Add('PayloadSigned') }
                    else { $flags.Add('PayloadUnsigned') }
                } else {
                    $flags.Add('PayloadScript')
                }
            }
        }
    }
    $hostOnlyTrust = ($isScriptHost -and $flags.Contains('SuspiciousArgPath') -and -not $payloadTrusted)
    if ($suspicious -and $null -ne $sig -and $sig['Trusted'] -and -not $hostOnlyTrust -and -not $flags.Contains('MinerToken') -and -not $flags.Contains('StrongRedFlagArgs') -and -not $flags.Contains('SystemNameOutsideSystem32')) {
        $suspicious = $false
    }
    return [ordered]@{ Flags = $flags.ToArray(); LocationClass = $loc; Suspicious = $suspicious; Signature = $sig }
}

function Get-WdInvArgumentPayloadPath {
    # First path-like token of an argument string (quoted or bare drive path) that matches -PathRegex; '' when none.
    # Environment variables are expanded; a trailing ",EntryPoint" (rundll32 syntax) is stripped.
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Arguments, [AllowNull()][AllowEmptyString()][string]$PathRegex = '')
    if ([string]::IsNullOrWhiteSpace($Arguments)) { return '' }
    $a = $Arguments
    try { $a = [Environment]::ExpandEnvironmentVariables($a) } catch { }
    foreach ($m in [regex]::Matches($a, '"([A-Za-z]:\\[^"]+)"|(?<![\w\\])([A-Za-z]:\\[^\s",;|<>]+)|"(\\\\[^"]+)"|(?<![\w\\])(\\\\[^\s",;|<>]+)')) {
        $p = ''
        foreach ($g in @(1, 2, 3, 4)) { if ($m.Groups[$g].Success) { $p = $m.Groups[$g].Value; break } }
        if ($p -eq '') { continue }
        if ($p -match '^(.+\.(dll|ocx|cpl))(,.*)?$') { $p = $Matches[1] }
        if ($PathRegex -ne '' -and $p -notmatch $PathRegex) { continue }
        return $p
    }
    return ''
}

function Get-WdInvEventGroups {
    # Groups events by Provider+Id: Count, Level, First, Last, one sample message (300 chars).
    [CmdletBinding()]
    param([AllowNull()][object[]]$Events, [string]$Log = '')
    $rows = New-Object 'System.Collections.Generic.List[object]'
    if ($null -eq $Events -or $Events.Count -eq 0) { return $rows.ToArray() }
    $groups = @{}
    $order = New-Object 'System.Collections.Generic.List[string]'
    foreach ($e in $Events) {
        if ($null -eq $e) { continue }
        $prov = [string]$e.ProviderName
        $id = [int]$e.Id
        $key = $prov + '/' + $id.ToString((Get-WdInv))
        if (-not $groups.ContainsKey($key)) {
            $msg = ''
            try { $msg = [string]$e.Message } catch { $msg = '' }
            if ($null -eq $msg) { $msg = '' }
            # Secret-masked (shared Hide-WdSecret) before it enters the data model: 7045 / Task Scheduler / PowerShell
            # messages carry command lines, so summary.md, inventory.json and events.csv all see the same masked text.
            $msg = Hide-WdSecret -Text (($msg -replace '\s+', ' ').Trim())
            if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) }
            $logName = $Log
            if ([string]::IsNullOrEmpty($logName)) { $logName = [string]$e.LogName }
            $groups[$key] = [ordered]@{
                Log = $logName; Provider = $prov; Id = $id; Level = [int]$e.Level; Count = 0
                First = $e.TimeCreated; Last = $e.TimeCreated; SampleMessage = $msg
            }
            $order.Add($key)
        }
        $g = $groups[$key]
        $g['Count'] = [int]$g['Count'] + 1
        if ($null -ne $e.TimeCreated) {
            if ($null -eq $g['First'] -or $e.TimeCreated -lt $g['First']) { $g['First'] = $e.TimeCreated }
            if ($null -eq $g['Last'] -or $e.TimeCreated -gt $g['Last']) { $g['Last'] = $e.TimeCreated }
        }
    }
    foreach ($k in $order) { $rows.Add([pscustomobject]$groups[$k]) }
    $sorted = @($rows.ToArray() | Sort-Object -Property @{ Expression = 'Count'; Descending = $true })
    return $sorted
}

function Get-WdInvEventProperty {
    [CmdletBinding()]
    param([AllowNull()][object]$EventRecord, [int]$Index)
    if ($null -eq $EventRecord) { return $null }
    try {
        $props = $EventRecord.Properties
        if ($null -eq $props -or $props.Count -le $Index) { return $null }
        return $props[$Index].Value
    } catch { return $null }
}

# ---------------------------------------------------------------------------------------------
# 0. Performance snapshot (runs FIRST, before the tool itself creates I/O)
# ---------------------------------------------------------------------------------------------
function Get-WdInvPerfSamples {
    # Several raw/formatted counter samples (CPU, thermal, memory, disk, system, GPU) and two process tables.
    [CmdletBinding()]
    param([int]$SampleCount = 5, [int]$IntervalMilliseconds = 1000)
    $inv = Get-WdInv
    $s = [ordered]@{
        Timestamps = New-Object 'System.Collections.Generic.List[object]'
        Cpu        = New-Object 'System.Collections.Generic.List[object]'
        Thermal    = New-Object 'System.Collections.Generic.List[object]'
        Memory     = New-Object 'System.Collections.Generic.List[object]'
        DiskRaw    = New-Object 'System.Collections.Generic.List[object]'
        System     = New-Object 'System.Collections.Generic.List[object]'
        Gpu        = New-Object 'System.Collections.Generic.List[object]'
        Process1   = @()
        Process2   = @()
        Process1Time = $null
        Process2Time = $null
        SampleCount = $SampleCount
    }
    $s['Process1Time'] = Get-Date
    $s['Process1'] = @(Invoke-Safely -Name 'Perf.ProcessTable1' -Default @() -ScriptBlock {
        Get-CimSafe -ClassName Win32_PerfFormattedData_PerfProc_Process -TimeoutSec 60
    })
    for ($i = 0; $i -lt $SampleCount; $i++) {
        $s['Timestamps'].Add((Get-Date))
        $cpu = @(Get-CimSafe -ClassName Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'")
        if ($cpu.Count -gt 0) { $s['Cpu'].Add($cpu[0]) } else { $s['Cpu'].Add($null) }
        $s['Thermal'].Add(@(Get-CimSafe -ClassName Win32_PerfFormattedData_Counters_ThermalZoneInformation))
        $mem = @(Get-CimSafe -ClassName Win32_PerfFormattedData_PerfOS_Memory)
        if ($mem.Count -gt 0) { $s['Memory'].Add($mem[0]) } else { $s['Memory'].Add($null) }
        $s['DiskRaw'].Add(@(Get-CimSafe -ClassName Win32_PerfRawData_PerfDisk_PhysicalDisk))
        $sys = @(Get-CimSafe -ClassName Win32_PerfFormattedData_PerfOS_System)
        if ($sys.Count -gt 0) { $s['System'].Add($sys[0]) } else { $s['System'].Add($null) }
        if ($i -eq 0 -or $i -eq [math]::Floor($SampleCount / 2) -or $i -eq ($SampleCount - 1)) {
            $gpu = @(Get-CimSafe -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine | Where-Object { $null -ne $_.UtilizationPercentage -and [int64]$_.UtilizationPercentage -gt 0 })
            $s['Gpu'].Add($gpu)
        }
        if ($i -lt ($SampleCount - 1)) { Start-Sleep -Milliseconds $IntervalMilliseconds }
    }
    $s['Process2Time'] = Get-Date
    $s['Process2'] = @(Invoke-Safely -Name 'Perf.ProcessTable2' -Default @() -ScriptBlock {
        Get-CimSafe -ClassName Win32_PerfFormattedData_PerfProc_Process -TimeoutSec 60
    })
    Write-Log -Level Info -Message ('Performance snapshot: {0} counter samples over {1} s, process table x2' -f $SampleCount, ([math]::Round(($s['Process2Time'] - $s['Process1Time']).TotalSeconds, 1, [MidpointRounding]::AwayFromZero)).ToString('F1', $inv))
    return $s
}

function Get-WdInvProcessOwners {
    # PID -> "DOMAIN\user" for every process whose logon session is visible (own sessions when not elevated).
    [CmdletBinding()]
    param()
    $owners = @{}
    $accounts = @{}
    foreach ($lu in @(Get-CimSafe -ClassName Win32_LoggedOnUser)) {
        if ($null -eq $lu) { continue }
        try {
            $lid = [string]$lu.Dependent.LogonId
            if ($lid -ne '' -and -not $accounts.ContainsKey($lid)) { $accounts[$lid] = ('{0}\{1}' -f [string]$lu.Antecedent.Domain, [string]$lu.Antecedent.Name) }
        } catch { }
    }
    if ($accounts.Count -eq 0) { return $owners }
    foreach ($sp in @(Get-CimSafe -ClassName Win32_SessionProcess)) {
        if ($null -eq $sp) { continue }
        try {
            $lid = [string]$sp.Antecedent.LogonId
            if ($accounts.ContainsKey($lid)) { $owners[[int]$sp.Dependent.Handle] = $accounts[$lid] }
        } catch { }
    }
    return $owners
}

function Get-WdInvProcessInventory {
    # Win32_Process for path/command line/parent; owner (GetOwner) is resolved later only for top processes.
    [CmdletBinding()]
    param()
    $map = @{}
    $rows = @(Get-CimSafe -ClassName Win32_Process -Property @('Name', 'ProcessId', 'ParentProcessId', 'ExecutablePath', 'CommandLine', 'CreationDate', 'SessionId'))
    foreach ($p in $rows) {
        if ($null -eq $p) { continue }
        $map[[int]$p.ProcessId] = $p
    }
    return $map
}

# ---------------------------------------------------------------------------------------------
# 1. System & OS
# ---------------------------------------------------------------------------------------------
function Get-WdInvSystem {
    [CmdletBinding()]
    param()
    $inv = Get-WdInv
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}

    $os = @(Get-CimSafe -ClassName Win32_OperatingSystem)
    $osRow = $null
    if ($os.Count -gt 0) { $osRow = $os[0] }
    $cv = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = 0
    try { $build = [int](Get-WdInvString -Value $cv['CurrentBuild']) } catch { $build = 0 }
    if ($build -eq 0 -and $null -ne $osRow) { try { $build = [int]$osRow.BuildNumber } catch { $build = 0 } }
    $ubr = $cv['UBR']
    $displayVersion = Get-WdInvString -Value $cv['DisplayVersion']
    if ($displayVersion -eq '') { $displayVersion = Get-WdInvString -Value $cv['ReleaseId'] }
    $productName = Get-WdInvString -Value $cv['ProductName']
    $isWin11 = ($build -ge 22000)
    $caption = ''
    if ($null -ne $osRow) { $caption = Get-WdInvString -Value $osRow.Caption }
    if ($isWin11 -and $productName -match 'Windows 10') { $productName = $productName -replace 'Windows 10', 'Windows 11' }
    $uptime = $null
    $lastBoot = $null
    if ($null -ne $osRow -and $null -ne $osRow.LastBootUpTime) {
        $lastBoot = [DateTime]$osRow.LastBootUpTime
        $uptime = (Get-Date) - $lastBoot
    }
    $installDate = $null
    if ($null -ne $osRow -and $null -ne $osRow.InstallDate) { $installDate = [DateTime]$osRow.InstallDate }
    $buildText = [string]$build
    if ($null -ne $ubr) { $buildText = '{0}.{1}' -f $build, ([int64]$ubr).ToString($inv) }
    $ctx['OsBuild'] = $build
    $ctx['IsWin11'] = $isWin11
    $sec['OS'] = [ordered]@{
        ProductName      = $productName
        Caption          = $caption
        DisplayVersion   = $displayVersion
        Build            = $buildText
        Version          = $(if ($null -ne $osRow) { [string]$osRow.Version } else { '' })
        EditionId        = Get-WdInvString -Value $cv['EditionID']
        InstallationType = Get-WdInvString -Value $cv['InstallationType']
        Architecture     = $(if ($null -ne $osRow) { [string]$osRow.OSArchitecture } else { '' })
        InstallDate      = $installDate
        LastBootUpTime   = $lastBoot
        UptimeDays       = $(if ($null -ne $uptime) { Get-WdInvNum -Value $uptime.TotalDays -Decimals 2 } else { $null })
        UptimeText       = $(if ($null -ne $uptime) { '{0}d {1}h {2}m' -f $uptime.Days, $uptime.Hours, $uptime.Minutes } else { '' })
        OSLanguage       = $(if ($null -ne $osRow) { $osRow.OSLanguage } else { $null })
        MUILanguages     = $(if ($null -ne $osRow -and $null -ne $osRow.MUILanguages) { @($osRow.MUILanguages) -join ';' } else { '' })
        RegisteredOwner  = Get-WdInvString -Value $cv['RegisteredOwner']
    }

    # Hardware model / chassis
    $cs = @(Get-CimSafe -ClassName Win32_ComputerSystem)
    $bios = @(Get-CimSafe -ClassName Win32_BIOS)
    $board = @(Get-CimSafe -ClassName Win32_BaseBoard)
    $enc = @(Get-CimSafe -ClassName Win32_SystemEnclosure)
    $csRow = $null
    if ($cs.Count -gt 0) { $csRow = $cs[0] }
    $chassis = @()
    if ($enc.Count -gt 0 -and $null -ne $enc[0].ChassisTypes) { $chassis = @($enc[0].ChassisTypes | ForEach-Object { [int]$_ }) }
    $laptopTypes = @(8, 9, 10, 11, 12, 14, 18, 21, 30, 31, 32)
    $desktopTypes = @(3, 4, 5, 6, 7, 13, 15, 16, 17, 24, 35)
    $isLaptop = $false
    foreach ($ct in $chassis) { if ($laptopTypes -contains $ct) { $isLaptop = $true } }
    if ($null -ne $csRow -and [int](Get-WdInvPropertyValue -Object $csRow -Name 'PCSystemType' -Default 0) -eq 2) { $isLaptop = $true }
    $formFactor = 'Unknown'
    if ($isLaptop) { $formFactor = 'Laptop' }
    else { foreach ($ct in $chassis) { if ($desktopTypes -contains $ct) { $formFactor = 'Desktop' } } }
    $ctx['IsLaptop'] = $isLaptop
    $ctx['FormFactor'] = $formFactor
    $ctx['IsDomainJoined'] = $false
    if ($null -ne $csRow) { $ctx['IsDomainJoined'] = [bool](Get-WdInvPropertyValue -Object $csRow -Name 'PartOfDomain' -Default $false) }
    $ctx['TotalRamBytes'] = $null
    if ($null -ne $csRow -and $null -ne $csRow.TotalPhysicalMemory) { $ctx['TotalRamBytes'] = [int64]$csRow.TotalPhysicalMemory }
    $ctx['HypervisorPresent'] = $false
    if ($null -ne $csRow) { $ctx['HypervisorPresent'] = ((Get-WdInvPropertyValue -Object $csRow -Name 'HypervisorPresent' -Default $false) -eq $true) }
    $biosDate = $null
    if ($bios.Count -gt 0 -and $null -ne $bios[0].ReleaseDate) { $biosDate = [DateTime]$bios[0].ReleaseDate }
    $sec['Hardware'] = [ordered]@{
        Manufacturer      = $(if ($null -ne $csRow) { Get-WdInvString -Value $csRow.Manufacturer } else { '' })
        Model             = $(if ($null -ne $csRow) { Get-WdInvString -Value $csRow.Model } else { '' })
        SystemFamily      = $(if ($null -ne $csRow) { Get-WdInvString -Value (Get-WdInvPropertyValue -Object $csRow -Name 'SystemFamily') } else { '' })
        SystemSKU         = $(if ($null -ne $csRow) { Get-WdInvString -Value (Get-WdInvPropertyValue -Object $csRow -Name 'SystemSKUNumber') } else { '' })
        PCSystemType      = $(if ($null -ne $csRow) { Get-WdInvPropertyValue -Object $csRow -Name 'PCSystemType' } else { $null })
        ChassisTypes      = ($chassis -join ';')
        FormFactor        = $formFactor
        TotalPhysicalMemory = $ctx['TotalRamBytes']
        TotalPhysicalMemoryText = Format-Bytes -Bytes $ctx['TotalRamBytes']
        HypervisorPresent = $(if ($null -ne $csRow) { Get-WdInvPropertyValue -Object $csRow -Name 'HypervisorPresent' } else { $null })
        PartOfDomain      = $ctx['IsDomainJoined']
        Domain            = $(if ($null -ne $csRow) { Get-WdInvString -Value $csRow.Domain } else { '' })
        BiosVersion       = $(if ($bios.Count -gt 0) { Get-WdInvString -Value $bios[0].SMBIOSBIOSVersion } else { '' })
        BiosReleaseDate   = $biosDate
        BiosManufacturer  = $(if ($bios.Count -gt 0) { Get-WdInvString -Value $bios[0].Manufacturer } else { '' })
        BaseBoard         = $(if ($board.Count -gt 0) { (Get-WdInvString -Value $board[0].Manufacturer) + ' ' + (Get-WdInvString -Value $board[0].Product) } else { '' })
        FirmwareType      = [string]$env:firmware_type
    }

    # Fast startup / hibernation
    $hiberboot = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power' -Name 'HiberbootEnabled'
    $hibernateEnabled = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power' -Name 'HibernateEnabled'
    $sec['Power'] = [ordered]@{
        FastStartupEnabled = $(if ($null -ne $hiberboot) { ([int]$hiberboot -eq 1) } else { $null })
        HibernateEnabled   = $(if ($null -ne $hibernateEnabled) { ([int]$hibernateEnabled -eq 1) } else { $null })
    }

    # Pending reboot
    $cbs = Test-WdInvRegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
    $wu = Test-WdInvRegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    $pfro = @(Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -Default @())
    $sec['PendingReboot'] = [ordered]@{
        ComponentBasedServicing = $cbs
        WindowsUpdate           = $wu
        PendingFileRenameOperations = $pfro.Count
    }
    if ($cbs -or $wu) {
        Add-Finding -Severity Warning -Category 'System' -RuleId 'SYS-REBOOT' -Title 'A reboot is pending (updates are not finished)' `
            -Detail ('CBS RebootPending={0}, WindowsUpdate RebootRequired={1}, pending file renames={2}' -f $cbs, $wu, $pfro.Count) `
            -Recommendation 'Restart the PC (Start > Power > Restart, not Shut down) so pending updates and file replacements complete.'
    }

    # Uptime / fast startup rules
    if ($null -ne $uptime) {
        $fast = ($null -ne $hiberboot -and [int]$hiberboot -eq 1)
        if ($uptime.TotalDays -gt 14 -or ($fast -and $uptime.TotalDays -gt 7)) {
            $extra = ''
            if ($fast) { $extra = ' Fast Startup is enabled, so "Shut down" does not really restart Windows.' }
            Add-Finding -Severity Info -Category 'System' -RuleId 'SYS-UPTIME' -Title ('Windows has not been restarted for {0} days' -f [int][math]::Floor($uptime.TotalDays)) `
                -Detail ('Last boot {0}.{1}' -f (Get-IsoTimestamp -Date $lastBoot), $extra) `
                -Recommendation 'Do a real Restart (Start > Power > Restart). Long uptimes accumulate leaked memory and pending updates.'
        }
    }

    # Build baseline / end of life
    if ($build -gt 0) {
        $eol = $false
        $why = ''
        if ($isWin11 -and $build -lt 22631) { $eol = $true; $why = 'Windows 11 build {0} is below the supported baseline (22631 = 23H2).' -f $build }
        elseif (-not $isWin11 -and $build -lt 19045) { $eol = $true; $why = 'Windows 10 build {0} is below the last supported version (19045 = 22H2).' -f $build }
        elseif (-not $isWin11 -and (Get-Date) -gt [DateTime]::new(2025, 10, 14)) { $eol = $true; $why = 'Windows 10 reached end of support on 2025-10-14.' }
        if ($eol) {
            Add-Finding -Severity Warning -Category 'System' -RuleId 'SYS-EOL' -Title 'Windows version is outdated / unsupported' -Detail $why `
                -Recommendation 'Install the latest feature update (Settings > Windows Update) or upgrade to Windows 11 if the hardware allows. Unsupported builds get no security fixes.'
        }
    }
    if ($null -ne $biosDate -and ((Get-Date) - $biosDate).TotalDays -gt 3 * 365) {
        Add-Finding -Severity Info -Category 'System' -RuleId 'SYS-BIOS-OLD' -Title ('BIOS/UEFI firmware is {0} years old' -f [int][math]::Floor(((Get-Date) - $biosDate).TotalDays / 365)) `
            -Detail ('BIOS {0} released {1}' -f $sec['Hardware']['BiosVersion'], $biosDate.ToString('yyyy-MM-dd', $inv)) `
            -Recommendation 'Check the vendor site for a firmware update (fixes CPU power management, USB and storage issues).'
    }

    # Activation
    $lic = @(Get-CimSafe -ClassName SoftwareLicensingProduct -Filter "ApplicationID='55c92734-d682-4d71-983e-d6ec3f16059f' AND PartialProductKey IS NOT NULL" -Property @('Name', 'LicenseStatus', 'Description', 'GracePeriodRemaining', 'PartialProductKey'))
    $licRows = New-Object 'System.Collections.Generic.List[object]'
    $statusNames = @{ 0 = 'Unlicensed'; 1 = 'Licensed'; 2 = 'OOBGrace'; 3 = 'OOTGrace'; 4 = 'NonGenuineGrace'; 5 = 'Notification'; 6 = 'ExtendedGrace' }
    foreach ($l in $lic) {
        $st = [int]$l.LicenseStatus
        $stName = [string]$st
        if ($statusNames.ContainsKey($st)) { $stName = $statusNames[$st] }
        $licRows.Add([ordered]@{ Name = [string]$l.Name; LicenseStatus = $stName; Channel = [string]$l.Description; GracePeriodRemainingMinutes = $l.GracePeriodRemaining })
        $isKms = ([string]$l.Description -match 'KMSCLIENT|KMS_CLIENT')
        if (-not $ctx['IsDomainJoined'] -and ($isKms -or $st -ne 1)) {
            Add-Finding -Severity Warning -Category 'System' -RuleId 'SYS-KMS' -Title 'Windows activation looks unusual for a home PC' `
                -Detail ('License status {0}, channel: {1}' -f $stName, [string]$l.Description) `
                -Recommendation 'A KMS/volume channel or unlicensed state on a home PC often means an "activator" tool was used; such tools frequently carry miners. Check Defender exclusions, scheduled tasks and services in this report.'
        }
    }
    $sec['Activation'] = $licRows.ToArray()

    # Windows Update state (COM, works non-admin)
    $wuInfo = Invoke-Safely -Name 'System.WindowsUpdate' -Default $null -ScriptBlock {
        $au = New-Object -ComObject 'Microsoft.Update.AutoUpdate' -ErrorAction Stop
        $r = [ordered]@{
            LastSearchSuccessDate       = $null
            LastInstallationSuccessDate = $null
            NotificationLevel           = $null
            ServiceEnabled              = $null
        }
        try { $r['LastSearchSuccessDate'] = [DateTime]$au.Results.LastSearchSuccessDate } catch { }
        try { $r['LastInstallationSuccessDate'] = [DateTime]$au.Results.LastInstallationSuccessDate } catch { }
        try { $r['NotificationLevel'] = [int]$au.Settings.NotificationLevel } catch { }
        try { $r['ServiceEnabled'] = [bool]$au.ServiceEnabled } catch { }
        $r
    }
    if ($null -eq $wuInfo) { $wuInfo = [ordered]@{ LastSearchSuccessDate = $null; LastInstallationSuccessDate = $null; NotificationLevel = $null; ServiceEnabled = $null } }
    $wuPol = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    $auPol = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    $ux = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\UX\Settings'
    $wuInfo['Policy_WUServer'] = Get-WdInvString -Value $wuPol['WUServer']
    $wuInfo['Policy_UseWUServer'] = $auPol['UseWUServer']
    $wuInfo['Policy_NoAutoUpdate'] = $auPol['NoAutoUpdate']
    $wuInfo['Policy_AUOptions'] = $auPol['AUOptions']
    $wuInfo['Policy_DoNotConnectToWindowsUpdateInternetLocations'] = $wuPol['DoNotConnectToWindowsUpdateInternetLocations']
    $pausedUntil = $null
    foreach ($n in @('PauseUpdatesExpiryTime', 'PauseFeatureUpdatesEndTime', 'PauseQualityUpdatesEndTime')) {
        $v = Get-WdInvString -Value $ux[$n]
        if ($v -ne '') { $d = [DateTime]::MinValue; if ([DateTime]::TryParse($v, $inv, [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$d)) { if ($null -eq $pausedUntil -or $d -gt $pausedUntil) { $pausedUntil = $d } } }
    }
    $wuInfo['PausedUntil'] = $pausedUntil
    $daysInstall = Get-WdInvDaysSince -Date $wuInfo['LastInstallationSuccessDate']
    if ($null -ne $daysInstall -and $daysInstall -gt 60) {
        $sev = 'Warning'
        if ($daysInstall -gt 180) { $sev = 'Critical' }
        Add-Finding -Severity $sev -Category 'System' -RuleId 'SYS-WU-OLD' -Title ('No Windows updates installed for {0} days' -f $daysInstall) `
            -Detail ('Last successful installation {0}; last successful search {1}' -f (ConvertTo-InvariantString -Value $wuInfo['LastInstallationSuccessDate']), (ConvertTo-InvariantString -Value $wuInfo['LastSearchSuccessDate'])) `
            -Recommendation 'Open Settings > Windows Update and check for errors; free disk space if needed; run the Windows Update troubleshooter. Long update gaps leave the PC unpatched and often indicate a broken servicing stack.'
    }
    $blocked = @()
    if ($null -ne $wuInfo['NotificationLevel'] -and [int]$wuInfo['NotificationLevel'] -eq 1) { $blocked += 'NotificationLevel=1 (automatic updates disabled)' }
    if ($null -ne $auPol['NoAutoUpdate'] -and [int]$auPol['NoAutoUpdate'] -eq 1) { $blocked += 'Policy NoAutoUpdate=1' }
    if ($wuInfo['Policy_WUServer'] -ne '' -and -not $ctx['IsDomainJoined']) { $blocked += ('WSUS server configured on a non-domain PC: ' + $wuInfo['Policy_WUServer']) }
    if ($null -ne $wuPol['DoNotConnectToWindowsUpdateInternetLocations'] -and [int]$wuPol['DoNotConnectToWindowsUpdateInternetLocations'] -eq 1 -and -not $ctx['IsDomainJoined']) { $blocked += 'DoNotConnectToWindowsUpdateInternetLocations=1' }
    if ($blocked.Count -gt 0) {
        Add-Finding -Severity Warning -Category 'System' -RuleId 'SYS-WU-BLOCK' -Title 'Windows Update is disabled or redirected' -Detail ($blocked -join '; ') `
            -Recommendation 'Update-blocker tools and some malware set these policies. Remove the policies (HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate) unless a company administrator configured them.'
    }
    if ($null -ne $pausedUntil -and $pausedUntil -gt (Get-Date).ToUniversalTime()) {
        Add-Finding -Severity Info -Category 'System' -RuleId 'SYS-WU-PAUSED' -Title ('Windows Update is paused until {0}' -f $pausedUntil.ToString('yyyy-MM-dd', $inv)) -Detail 'Settings > Windows Update > Pause updates is active.' -Recommendation 'Resume updates when convenient.'
    }
    $sec['WindowsUpdate'] = $wuInfo

    # Update history (COM) + hotfixes
    $history = @(Invoke-Safely -Name 'System.UpdateHistory' -Default @() -ScriptBlock {
        $session = New-Object -ComObject 'Microsoft.Update.Session' -ErrorAction Stop
        $searcher = $session.CreateUpdateSearcher()
        $n = [int]$searcher.GetTotalHistoryCount()
        $take = [math]::Min($n, 60)
        $out = New-Object 'System.Collections.Generic.List[object]'
        if ($take -gt 0) {
            $h = $searcher.QueryHistory(0, $take)
            foreach ($e in $h) {
                if ($null -eq $e) { continue }
                $out.Add([ordered]@{
                    Date       = $(try { [DateTime]$e.Date } catch { $null })
                    ResultCode = [int]$e.ResultCode
                    Operation  = [int]$e.Operation
                    Title      = [string]$e.Title
                })
            }
        }
        $out.ToArray()
    })
    $resultNames = @{ 0 = 'NotStarted'; 1 = 'InProgress'; 2 = 'Succeeded'; 3 = 'SucceededWithErrors'; 4 = 'Failed'; 5 = 'Aborted' }
    $histRows = New-Object 'System.Collections.Generic.List[object]'
    $failCounts = @{}
    foreach ($h in $history) {
        $rc = [int]$h['ResultCode']
        $rcName = [string]$rc
        if ($resultNames.ContainsKey($rc)) { $rcName = $resultNames[$rc] }
        $histRows.Add([ordered]@{ Date = $h['Date']; Result = $rcName; Operation = $(if ([int]$h['Operation'] -eq 1) { 'Install' } elseif ([int]$h['Operation'] -eq 2) { 'Uninstall' } else { [string]$h['Operation'] }); Title = $h['Title'] })
        if ($rc -eq 4) {
            $t = [string]$h['Title']
            if (-not $failCounts.ContainsKey($t)) { $failCounts[$t] = 0 }
            $failCounts[$t] = $failCounts[$t] + 1
        }
    }
    foreach ($t in $failCounts.Keys) {
        if ($failCounts[$t] -ge 3) {
            Add-Finding -Severity Warning -Category 'System' -RuleId 'SYS-WU-FAIL' -Title ('An update failed {0} times: {1}' -f $failCounts[$t], $t) `
                -Detail 'Windows Update history (last 60 entries).' -Recommendation 'Search the KB number for known issues; run "Windows Update troubleshooter"; check free disk space and the CBS log.'
        }
    }
    $sec['UpdateHistory'] = $histRows.ToArray()
    $hotfixes = @(Invoke-Safely -Name 'System.HotFix' -Default @() -ScriptBlock {
        @(Get-HotFix -ErrorAction Stop | ForEach-Object { [ordered]@{ HotFixID = [string]$_.HotFixID; Description = [string]$_.Description; InstalledOn = $_.InstalledOn } })
    })
    # Rows are [ordered] hashtables: a string property name does not sort them in PS 5.1, the key lookup does.
    $sec['HotFixes'] = @($hotfixes | Sort-Object -Property @{ Expression = { $_['InstalledOn'] }; Descending = $true })

    # Time synchronization
    $w32Params = Get-WdInvRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters'
    $lastGood = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Config' -Name 'LastKnownGoodTime'
    $lastGoodTime = $null
    if ($null -ne $lastGood) { try { $lastGoodTime = [DateTime]::FromFileTimeUtc([int64]$lastGood).ToLocalTime() } catch { } }
    $since14 = (Get-Date).AddDays(-14)
    $timeEvents = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Time-Service'; StartTime = $since14 } -MaxEvents 5000)
    $timeIds = @{}
    foreach ($e in $timeEvents) { $k = [int]$e.Id; if (-not $timeIds.ContainsKey($k)) { $timeIds[$k] = 0 }; $timeIds[$k] = $timeIds[$k] + 1 }
    $timeIdText = @($timeIds.Keys | Sort-Object | ForEach-Object { '{0}x{1}' -f $_, $timeIds[$_] }) -join ', '
    $syncType = Get-WdInvString -Value $w32Params['Type']
    $sec['TimeSync'] = [ordered]@{ Type = $syncType; NtpServer = (Get-WdInvString -Value $w32Params['NtpServer']); LastKnownGoodTime = $lastGoodTime; Events14d = $timeIdText }
    $okSync = ($timeIds.ContainsKey(35) -or $timeIds.ContainsKey(37))
    $failSync = ($timeIds.ContainsKey(129) -or $timeIds.ContainsKey(36) -or $timeIds.ContainsKey(131))
    if ($syncType -eq 'NoSync' -or ($failSync -and -not $okSync)) {
        Add-Finding -Severity Warning -Category 'System' -RuleId 'SYS-TIME' -Title 'The clock is not synchronizing' `
            -Detail ('W32Time type={0}, server={1}, events (14 d): {2}' -f $syncType, $sec['TimeSync']['NtpServer'], $timeIdText) `
            -Recommendation 'Settings > Time & language > Date & time > Sync now. A wrong clock breaks HTTPS, Windows Update and licensing.'
    }

    # Secure Boot / VBS
    $sb = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -Name 'UEFISecureBootEnabled'
    $dg = @(Get-CimSafe -Namespace 'root/Microsoft/Windows/DeviceGuard' -ClassName Win32_DeviceGuard)
    $vbsStatus = $null
    $servicesRunning = @()
    if ($dg.Count -gt 0) {
        $vbsStatus = $dg[0].VirtualizationBasedSecurityStatus
        if ($null -ne $dg[0].SecurityServicesRunning) { $servicesRunning = @($dg[0].SecurityServicesRunning | ForEach-Object { [int]$_ }) }
    }
    $sec['SecureBoot'] = [ordered]@{
        UEFISecureBootEnabled = $(if ($null -ne $sb) { ([int]$sb -eq 1) } else { $null })
        FirmwareType          = [string]$env:firmware_type
        VBSStatus             = $vbsStatus
        VBSStatusText         = $($vbsInt = -1; if ($null -ne $vbsStatus) { try { $vbsInt = [int]$vbsStatus } catch { } }; switch ($vbsInt) { 0 { 'Off' } 1 { 'Enabled, not running' } 2 { 'Running' } default { 'Unknown' } })
        HVCI                  = ($servicesRunning -contains 2)
        CredentialGuard       = ($servicesRunning -contains 1)
    }
    $ctx['HvciRunning'] = ($servicesRunning -contains 2)

    $sec['Locale'] = [ordered]@{
        Culture   = (Get-Culture).Name
        UICulture = (Get-UICulture).Name
        InstallLanguage = Get-WdInvString -Value (Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\Language' -Name 'InstallLanguage')
        TimeZone  = $(try { [TimeZoneInfo]::Local.Id } catch { '' })
    }
    return $sec
}

# ---------------------------------------------------------------------------------------------
# 2. CPU
# ---------------------------------------------------------------------------------------------
function Get-WdInvPowerPlan {
    [CmdletBinding()]
    param()
    $schemeNames = @{
        '381b4222-f694-41f0-9685-ff5bb260df2e' = 'Balanced'
        '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c' = 'High performance'
        'a1841308-3541-4fab-bc81-f71556f20b4a' = 'Power saver'
        'e9a42b02-d5df-448d-aa00-03f14749eb61' = 'Ultimate performance'
    }
    $overlayNames = @{
        'ded574b5-45a0-4f42-8737-46345c09c238' = 'Best performance'
        '3af9b8d9-7c97-431d-ad78-34a8bfea439f' = 'High performance (overlay)'
        '961cc777-2547-4f9d-8174-7d86181b8a7a' = 'Best power efficiency'
        '00000000-0000-0000-0000-000000000000' = 'Balanced (none)'
    }
    $ps = Get-WdInvRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes'
    $active = (Get-WdInvString -Value $ps['ActivePowerScheme']).ToLowerInvariant()
    $acOverlay = (Get-WdInvString -Value $ps['ActiveOverlayAcPowerScheme']).ToLowerInvariant()
    $dcOverlay = (Get-WdInvString -Value $ps['ActiveOverlayDcPowerScheme']).ToLowerInvariant()
    $activeName = 'Custom'
    if ($schemeNames.ContainsKey($active)) { $activeName = $schemeNames[$active] }
    elseif ($active -ne '') {
        $fn = Get-WdInvString -Value (Get-RegistryValueSafe -Path ('HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\' + $active) -Name 'FriendlyName')
        if ($fn -ne '' -and $fn -notmatch '^@') { $activeName = 'Custom: ' + $fn }
    }
    $acOverlayName = ''
    $dcOverlayName = ''
    if ($overlayNames.ContainsKey($acOverlay)) { $acOverlayName = $overlayNames[$acOverlay] } elseif ($acOverlay -ne '') { $acOverlayName = $acOverlay }
    if ($overlayNames.ContainsKey($dcOverlay)) { $dcOverlayName = $overlayNames[$dcOverlay] } elseif ($dcOverlay -ne '') { $dcOverlayName = $dcOverlay }
    $sub = '54533251-82be-4824-96c1-47b60b740d00'
    $settings = [ordered]@{
        'bc5038f7-23e0-4960-96da-33abaf5935ec' = 'ProcessorMaxState'
        '893dee8e-2bef-41e0-89c6-b55d0929964c' = 'ProcessorMinState'
        'be337238-0d82-4146-a960-4f3749d470c7' = 'ProcessorBoostMode'
    }
    $result = [ordered]@{
        ActiveScheme      = $active
        ActiveSchemeName  = $activeName
        AcOverlay         = $acOverlayName
        DcOverlay         = $dcOverlayName
    }
    foreach ($guid in $settings.Keys) {
        $name = $settings[$guid]
        $ac = $null
        $dc = $null
        if ($active -ne '') {
            $k = 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes\{0}\{1}\{2}' -f $active, $sub, $guid
            $vals = Get-WdInvRegistryValues -Path $k
            if ($vals.Contains('ACSettingIndex')) { $ac = $vals['ACSettingIndex'] }
            if ($vals.Contains('DCSettingIndex')) { $dc = $vals['DCSettingIndex'] }
            if ($null -eq $ac -or $null -eq $dc) {
                $def = Get-WdInvRegistryValues -Path ('HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerSettings\{0}\{1}\DefaultPowerSchemeValues\{2}' -f $sub, $guid, $active)
                if ($null -eq $ac -and $def.Contains('AcSettingIndex')) { $ac = $def['AcSettingIndex'] }
                if ($null -eq $dc -and $def.Contains('DcSettingIndex')) { $dc = $def['DcSettingIndex'] }
            }
        }
        $result[$name + 'AC'] = $ac
        $result[$name + 'DC'] = $dc
    }
    $pt = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling' -Name 'PowerThrottlingOff'
    $result['PowerThrottlingOff'] = $(if ($null -ne $pt) { ([int]$pt -eq 1) } else { $false })
    return $result
}

function Get-WdInvCpu {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Samples)
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}

    $procs = @(Get-CimSafe -ClassName Win32_Processor)
    $cpuRows = New-Object 'System.Collections.Generic.List[object]'
    $cpuName = ''
    $cores = 0
    $enabledCores = 0
    $logical = 0
    foreach ($p in $procs) {
        $name = Get-WdInvString -Value $p.Name
        if ($cpuName -eq '') { $cpuName = $name }
        $cores += [int](Get-WdInvPropertyValue -Object $p -Name 'NumberOfCores' -Default 0)
        $enabledCores += [int](Get-WdInvPropertyValue -Object $p -Name 'NumberOfEnabledCore' -Default 0)
        $logical += [int](Get-WdInvPropertyValue -Object $p -Name 'NumberOfLogicalProcessors' -Default 0)
        $cpuRows.Add([ordered]@{
            Name = $name
            Manufacturer = Get-WdInvString -Value $p.Manufacturer
            Cores = $p.NumberOfCores
            EnabledCores = Get-WdInvPropertyValue -Object $p -Name 'NumberOfEnabledCore'
            LogicalProcessors = $p.NumberOfLogicalProcessors
            MaxClockMHz = $p.MaxClockSpeed
            L2CacheKB = $p.L2CacheSize
            L3CacheKB = $p.L3CacheSize
            Socket = Get-WdInvString -Value $p.SocketDesignation
            VirtualizationFirmwareEnabled = Get-WdInvPropertyValue -Object $p -Name 'VirtualizationFirmwareEnabled'
            Status = Get-WdInvString -Value $p.Status
            CpuStatus = $p.CpuStatus
        })
    }
    if ($cpuName -eq '') {
        $cpuName = Get-WdInvString -Value (Get-RegistryValueSafe -Path 'HKLM:\HARDWARE\DESCRIPTION\System\CentralProcessor\0' -Name 'ProcessorNameString')
        $logical = $script:NCPU
    }
    $ctx['CpuName'] = $cpuName
    $sec['Processors'] = $cpuRows.ToArray()

    # Averages from the samples (the first formatted sample of a rate counter is unreliable -> skipped when >2 samples)
    $cpuSamples = @($Samples['Cpu'] | Where-Object { $null -ne $_ })
    $rateSamples = $cpuSamples
    if ($cpuSamples.Count -gt 2) { $rateSamples = @($cpuSamples | Select-Object -Skip 1) }
    $load = [ordered]@{
        Samples                     = $cpuSamples.Count
        PercentProcessorTime        = Get-WdInvAverage -Values @($rateSamples | ForEach-Object { $_.PercentProcessorTime })
        PercentProcessorUtility     = Get-WdInvAverage -Values @($rateSamples | ForEach-Object { $_.PercentProcessorUtility })
        PercentProcessorPerformance = Get-WdInvAverage -Values @($rateSamples | ForEach-Object { $_.PercentProcessorPerformance })
        PercentOfMaximumFrequency   = Get-WdInvAverage -Values @($rateSamples | ForEach-Object { $_.PercentofMaximumFrequency })
        PercentPerformanceLimit     = Get-WdInvAverage -Values @($cpuSamples | ForEach-Object { $_.PercentPerformanceLimit })
        PerformanceLimitFlagsMax    = Get-WdInvMax -Values @($cpuSamples | ForEach-Object { $_.PerformanceLimitFlags })
        PercentPrivilegedTime       = Get-WdInvAverage -Values @($rateSamples | ForEach-Object { $_.PercentPrivilegedTime })
        PercentInterruptTime        = Get-WdInvAverage -Values @($rateSamples | ForEach-Object { $_.PercentInterruptTime })
        PercentDPCTime              = Get-WdInvAverage -Values @($rateSamples | ForEach-Object { $_.PercentDPCTime })
        ActualFrequencyMHz          = Get-WdInvAverage -Values @($cpuSamples | ForEach-Object { $_.ActualFrequency }) -Decimals 0
        NominalFrequencyMHz         = Get-WdInvMax -Values @($cpuSamples | ForEach-Object { $_.ProcessorFrequency })
        ParkedCoresPercent          = Get-WdInvAverage -Values @($cpuSamples | ForEach-Object { $_.ParkingStatus })
        PerSample_PercentProcessorTime = @($cpuSamples | ForEach-Object { $_.PercentProcessorTime })
        PerSample_PercentProcessorPerformance = @($cpuSamples | ForEach-Object { $_.PercentProcessorPerformance })
    }
    $sysSamples = @($Samples['System'] | Where-Object { $null -ne $_ })
    $load['ProcessorQueueLength'] = Get-WdInvAverage -Values @($sysSamples | ForEach-Object { $_.ProcessorQueueLength })
    $load['ProcessorQueueLengthMax'] = Get-WdInvMax -Values @($sysSamples | ForEach-Object { $_.ProcessorQueueLength })
    $load['Processes'] = Get-WdInvMax -Values @($sysSamples | ForEach-Object { $_.Processes })
    $load['Threads'] = Get-WdInvMax -Values @($sysSamples | ForEach-Object { $_.Threads })
    $load['ContextSwitchesPersec'] = Get-WdInvAverage -Values @($sysSamples | Select-Object -Skip 1 | ForEach-Object { $_.ContextSwitchesPersec }) -Decimals 0
    $sec['Load'] = $load
    $ctx['CpuLoadPercent'] = $load['PercentProcessorTime']
    if ($cpuSamples.Count -eq 0 -or ($null -eq $load['PercentProcessorTime'] -and $null -eq $load['PercentProcessorUtility'])) {
        Add-Finding -Severity Info -Category 'CPU' -RuleId 'CPU-COUNTERS' -Title 'CPU performance counters are unavailable' `
            -Detail 'Win32_PerfFormattedData_Counters_ProcessorInformation returned nothing or empty values.' `
            -Recommendation 'Performance counters seem corrupted. Run "lodctr /R" in an elevated command prompt and reboot.'
    }

    # Thermal zones
    $thermalRows = New-Object 'System.Collections.Generic.List[object]'
    $zoneTemps = @{}
    $zonePassive = @{}
    $zoneThrottle = @{}
    foreach ($sample in $Samples['Thermal']) {
        foreach ($z in @($sample)) {
            if ($null -eq $z) { continue }
            $zn = [string]$z.Name
            $hp = $z.HighPrecisionTemperature
            $tC = $null
            if ($null -ne $hp -and [double]$hp -gt 0) { $tC = ([double]$hp / 10.0) - 273.15 }
            elseif ($null -ne $z.Temperature -and [double]$z.Temperature -gt 0) { $tC = [double]$z.Temperature - 273.15 }
            if (-not $zoneTemps.ContainsKey($zn)) { $zoneTemps[$zn] = New-Object 'System.Collections.Generic.List[object]'; $zonePassive[$zn] = New-Object 'System.Collections.Generic.List[object]'; $zoneThrottle[$zn] = New-Object 'System.Collections.Generic.List[object]' }
            $zoneTemps[$zn].Add($tC)
            $zonePassive[$zn].Add($z.PercentPassiveLimit)
            $zoneThrottle[$zn].Add($z.ThrottleReasons)
        }
    }
    $maxTemp = $null
    $passiveLimitMin = $null
    $throttleReasonsMax = $null
    foreach ($zn in $zoneTemps.Keys) {
        $avg = Get-WdInvAverage -Values $zoneTemps[$zn].ToArray()
        $mx = Get-WdInvMax -Values $zoneTemps[$zn].ToArray()
        $valid = ($null -ne $avg -and $avg -ge 20)
        $pl = Get-WdInvAverage -Values $zonePassive[$zn].ToArray() -Decimals 0
        $tr = Get-WdInvMax -Values $zoneThrottle[$zn].ToArray()
        $thermalRows.Add([ordered]@{ Zone = $zn; AvgTemperatureC = $avg; MaxTemperatureC = (Get-WdInvNum -Value $mx); PercentPassiveLimit = $pl; ThrottleReasons = $tr; Plausible = $valid })
        if ($valid -and ($null -eq $maxTemp -or $mx -gt $maxTemp)) { $maxTemp = $mx }
        if ($null -ne $pl -and ($null -eq $passiveLimitMin -or $pl -lt $passiveLimitMin)) { $passiveLimitMin = $pl }
        if ($null -ne $tr -and ($null -eq $throttleReasonsMax -or $tr -gt $throttleReasonsMax)) { $throttleReasonsMax = $tr }
    }
    $sec['ThermalZones'] = $thermalRows.ToArray()
    $sec['MaxTemperatureC'] = Get-WdInvNum -Value $maxTemp
    if ($thermalRows.Count -eq 0) {
        $sec['ThermalNote'] = 'No ACPI thermal zone exposed via performance counters (common on desktops).'
    }

    # Throttling rules
    $throttleReasons = @()
    $ppp = $load['PercentProcessorPerformance']
    $ppt = $load['PercentProcessorTime']
    if ($null -ne $ppp -and $null -ne $ppt -and $ppp -lt 60 -and $ppt -gt 50) { $throttleReasons += ('processor performance {0} % while load {1} %' -f (Format-WdInvNum $ppp 0), (Format-WdInvNum $ppt 0)) }
    if ($null -ne $load['PercentPerformanceLimit'] -and $load['PercentPerformanceLimit'] -lt 80) { $throttleReasons += ('performance limit {0} %' -f (Format-WdInvNum $load['PercentPerformanceLimit'] 0)) }
    if ($null -ne $load['PerformanceLimitFlagsMax'] -and $load['PerformanceLimitFlagsMax'] -ne 0) { $throttleReasons += ('PerformanceLimitFlags=0x{0:X}' -f [int64]$load['PerformanceLimitFlagsMax']) }
    if ($null -ne $passiveLimitMin -and $passiveLimitMin -lt 100) { $throttleReasons += ('thermal passive limit {0} %' -f (Format-WdInvNum $passiveLimitMin 0)) }
    if ($null -ne $throttleReasonsMax -and $throttleReasonsMax -ne 0) { $throttleReasons += ('ThrottleReasons=0x{0:X}' -f [int64]$throttleReasonsMax) }
    if ($throttleReasons.Count -gt 0) {
        Add-Finding -Severity Warning -Category 'CPU' -RuleId 'CPU-THROTTLE' -Title 'The CPU is being throttled (heat or power limit)' -Detail ($throttleReasons -join '; ') `
            -Recommendation 'Clean the fans and vents, replace thermal paste on an old machine, use the original power adapter (wattage), check that the laptop is not on a soft surface. A worn battery can also force throttling.'
    }
    if ($null -ne $maxTemp -and $maxTemp -gt 90) {
        Add-Finding -Severity Warning -Category 'CPU' -RuleId 'CPU-HOT' -Title ('Thermal zone reports {0} C' -f (Format-WdInvNum $maxTemp 0)) -Detail ('Highest plausible ACPI thermal zone temperature during the snapshot: {0} C' -f (Format-WdInvNum $maxTemp 1)) `
            -Recommendation 'Overheating causes throttling and instability: clean dust from fans and heatsinks, improve airflow, replace thermal paste.'
    }
    if ($null -ne $ppt -and $ppt -gt 40) {
        Add-Finding -Severity Warning -Category 'CPU' -RuleId 'CPU-BUSY-IDLE' -Title ('High CPU load during the scan: {0} % average' -f (Format-WdInvNum $ppt 0)) `
            -Detail ('Total CPU {0} % averaged over {1} samples (this tool itself uses a few percent). See the Performance snapshot section for the top processes.' -f (Format-WdInvNum $ppt 0), $rateSamples.Count) `
            -Recommendation 'If the PC was idle while the scan ran, something is burning CPU in the background: check the top processes (PROC-* findings), autostart entries and scheduled tasks.'
    }
    $intr = 0.0
    if ($null -ne $load['PercentInterruptTime']) { $intr += [double]$load['PercentInterruptTime'] }
    if ($null -ne $load['PercentDPCTime']) { $intr += [double]$load['PercentDPCTime'] }
    if ($intr -gt 10) {
        Add-Finding -Severity Warning -Category 'CPU' -RuleId 'CPU-INTR' -Title ('Interrupt + DPC time is {0} %' -f (Format-WdInvNum $intr 1)) -Detail 'High interrupt/DPC time points to a misbehaving driver (network, audio, USB, GPU) or failing hardware.' `
            -Recommendation 'Update chipset, network, audio and GPU drivers; unplug USB devices one by one to find the culprit.'
    }
    if ($cores -gt 0 -and $enabledCores -gt 0 -and $enabledCores -lt $cores) {
        Add-Finding -Severity Warning -Category 'CPU' -RuleId 'CPU-CORES' -Title ('Only {0} of {1} CPU cores are enabled' -f $enabledCores, $cores) -Detail 'NumberOfEnabledCore < NumberOfCores (Win32_Processor).' `
            -Recommendation 'Open msconfig > Boot > Advanced options and clear "Number of processors"; check the BIOS for disabled cores.'
    }
    # N-series: Celeron/Pentium N2000-N6000 (four digits) and the current Intel N50/N95/N97/N100/N200 and Core i3-N3xx parts.
    if ($cpuName -match 'Celeron|Pentium|Atom|Core\(TM\)2|Core 2|\bA4-|\bA6-|\bE1-|\bE2-|\bN(50|9[57]|[1-6]\d{2,3})\b|\bi3-N\d{3}\b' -or ($logical -gt 0 -and $logical -le 2)) {
        Add-Finding -Severity Info -Category 'CPU' -RuleId 'CPU-OLD' -Title 'Entry-level or old CPU' -Detail ('{0}, {1} logical processors' -f $cpuName, $logical) `
            -Recommendation 'This CPU is a bottleneck for modern browsers and Windows 11. Keep few browser tabs, disable autostart programs; a hardware upgrade is the real fix.'
    }
    if ($ctx['HvciRunning'] -and $cpuName -match 'i[3579]-[2-7]\d{3}|Ryzen [3579] 1\d{3}|i[3579] [2-7]\d{3}') {
        Add-Finding -Severity Info -Category 'CPU' -RuleId 'CPU-VBS' -Title 'Memory Integrity (HVCI) is running on an older CPU' -Detail ('CPU: {0}. Virtualization-based security with HVCI costs 5-15 % on CPUs without mode-based execution control.' -f $cpuName) `
            -Recommendation 'Windows Security > Device security > Core isolation > Memory integrity can be disabled if the user accepts the security trade-off.'
    }

    # Power plan
    $plan = Get-WdInvPowerPlan
    $sec['PowerPlan'] = $plan
    $ctx['PowerPlan'] = $plan
    if ($plan['ActiveSchemeName'] -eq 'Power saver') {
        Add-Finding -Severity Warning -Category 'CPU' -RuleId 'CPU-PLAN' -Title 'The "Power saver" power plan is active' -Detail 'Power saver caps CPU frequency and delays boosting.' `
            -Recommendation 'Switch to Balanced (Control Panel > Power Options or Settings > System > Power > Power mode).'
    }
    $maxAc = $plan['ProcessorMaxStateAC']
    if ($null -ne $maxAc -and [int]$maxAc -lt 100 -and [int]$maxAc -gt 0) {
        Add-Finding -Severity Warning -Category 'CPU' -RuleId 'CPU-MAXSTATE' -Title ('Maximum processor state is capped at {0} % (plugged in)' -f [int]$maxAc) `
            -Detail ('Power plan {0}: ProcessorMaxState AC={1}, DC={2}' -f $plan['ActiveSchemeName'], $maxAc, $plan['ProcessorMaxStateDC']) `
            -Recommendation 'A common "fix" for overheating that makes the PC slow. Restore 100 % in Power Options > Change advanced settings > Processor power management > Maximum processor state, and fix the cooling instead.'
    }

    # Kernel-Processor-Power 37 (firmware limits the speed)
    # Capped at 5000 events: a firmware that logs event 37 at every boot/resume for months fills the log with them.
    $ppEvents = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Processor-Power'; Id = 37; StartTime = (Get-Date).AddDays(-90) } -MaxEvents 5000)
    $sec['FirmwareLimitEvents90d'] = $ppEvents.Count
    $sec['FirmwareLimitEvents90dCapped'] = ($ppEvents.Count -ge 5000)
    if ($ppEvents.Count -gt 0) {
        $ppText = [string]$ppEvents.Count
        if ($ppEvents.Count -ge 5000) { $ppText = '>= ' + $ppText }
        Add-Finding -Severity Warning -Category 'CPU' -RuleId 'CPU-FW-LIMIT' -Title ('Firmware limited the CPU speed {0} times in 90 days (event 37)' -f $ppText) `
            -Detail ('Last: {0}' -f (Get-IsoTimestamp -Date $ppEvents[0].TimeCreated)) `
            -Recommendation 'The BIOS/firmware throttles the CPU: check power adapter wattage, battery health, BIOS update and cooling.'
    }
    return $sec
}

# ---------------------------------------------------------------------------------------------
# 3. Memory
# ---------------------------------------------------------------------------------------------
function Get-WdInvMemory {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Samples)
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}
    $memTypes = @{ 20 = 'DDR'; 21 = 'DDR2'; 24 = 'DDR3'; 26 = 'DDR4'; 27 = 'LPDDR'; 28 = 'LPDDR2'; 29 = 'LPDDR3'; 30 = 'LPDDR4'; 34 = 'DDR5'; 35 = 'LPDDR5' }
    $modules = @(Get-CimSafe -ClassName Win32_PhysicalMemory)
    $arrays = @(Get-CimSafe -ClassName Win32_PhysicalMemoryArray)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $totalBytes = [int64]0
    $oldType = $false
    $xmpOff = $false
    foreach ($m in $modules) {
        if ($null -eq $m) { continue }
        $cap = [int64](Get-WdInvPropertyValue -Object $m -Name 'Capacity' -Default 0)
        $totalBytes += $cap
        $t = [int](Get-WdInvPropertyValue -Object $m -Name 'SMBIOSMemoryType' -Default 0)
        $tName = [string]$t
        if ($memTypes.ContainsKey($t)) { $tName = $memTypes[$t] }
        if ($t -in @(20, 21, 24)) { $oldType = $true }
        $speed = Get-WdInvPropertyValue -Object $m -Name 'Speed'
        $cfg = Get-WdInvPropertyValue -Object $m -Name 'ConfiguredClockSpeed'
        if ($null -ne $speed -and $null -ne $cfg -and [int]$cfg -gt 0 -and [int]$cfg -lt [int]$speed) { $xmpOff = $true }
        $rows.Add([ordered]@{
            Bank = Get-WdInvString -Value $m.BankLabel
            Slot = Get-WdInvString -Value $m.DeviceLocator
            Capacity = $cap
            CapacityText = Format-Bytes -Bytes $cap -Decimals 0
            Type = $tName
            SpeedMHz = $speed
            ConfiguredMHz = $cfg
            Manufacturer = Get-WdInvString -Value $m.Manufacturer
            PartNumber = Get-WdInvString -Value $m.PartNumber
            FormFactor = $m.FormFactor
            DataWidth = $m.DataWidth
            TotalWidth = $m.TotalWidth
        })
    }
    if ($totalBytes -eq 0 -and $null -ne $ctx['TotalRamBytes']) { $totalBytes = [int64]$ctx['TotalRamBytes'] }
    if ($null -eq $ctx['TotalRamBytes'] -or [int64]$ctx['TotalRamBytes'] -eq 0) { $ctx['TotalRamBytes'] = $totalBytes }
    $slots = 0
    $maxCap = $null
    $ecc = $null
    if ($arrays.Count -gt 0) {
        foreach ($a in $arrays) { $slots += [int](Get-WdInvPropertyValue -Object $a -Name 'MemoryDevices' -Default 0) }
        $maxCap = Get-WdInvPropertyValue -Object $arrays[0] -Name 'MaxCapacityEx'
        if ($null -eq $maxCap) { $maxCap = Get-WdInvPropertyValue -Object $arrays[0] -Name 'MaxCapacity' }
        $ecc = Get-WdInvPropertyValue -Object $arrays[0] -Name 'MemoryErrorCorrection'
    }
    $sec['Modules'] = $rows.ToArray()
    $sec['Summary'] = [ordered]@{
        TotalInstalledBytes = $totalBytes
        TotalInstalledText  = Format-Bytes -Bytes $totalBytes -Decimals 1
        ModuleCount         = $rows.Count
        Slots               = $slots
        MaxCapacityKB       = $maxCap
        ErrorCorrection     = $ecc
    }
    $totalGB = [double]$totalBytes / 1GB
    if ($totalBytes -gt 0) {
        if ($totalGB -lt 3.5) {
            Add-Finding -Severity Critical -Category 'Memory' -RuleId 'MEM-LOW-CRIT' -Title ('Only {0} GB of RAM installed' -f (Format-WdInvNum $totalGB 1)) -Detail 'Windows 10/11 plus a browser needs more than 4 GB; the system swaps constantly.' `
                -Recommendation 'Upgrade the RAM (8 GB minimum, 16 GB comfortable). No software tweak compensates for this.'
        } elseif ($totalGB -lt 7.5) {
            Add-Finding -Severity Warning -Category 'Memory' -RuleId 'MEM-LOW' -Title ('{0} GB of RAM is the bare minimum' -f (Format-WdInvNum $totalGB 1)) -Detail 'With 4-8 GB the PC swaps as soon as a browser with several tabs and an antivirus run together.' `
                -Recommendation 'Consider upgrading to 16 GB; meanwhile keep autostart programs and browser tabs low.'
        }
    }
    if ($rows.Count -eq 1 -and $slots -ge 2 -and $ctx['FormFactor'] -eq 'Desktop') {
        Add-Finding -Severity Info -Category 'Memory' -RuleId 'MEM-SINGLE' -Title 'Single memory module in a system with free slots' -Detail ('1 module, {0} slots (single-channel mode).' -f $slots) `
            -Recommendation 'Adding a second identical module enables dual-channel mode (large gain for integrated graphics).'
    }
    if ($oldType) {
        Add-Finding -Severity Info -Category 'Memory' -RuleId 'MEM-OLDTYPE' -Title 'DDR3 or older memory: old platform' -Detail 'SMBIOSMemoryType indicates DDR/DDR2/DDR3.' -Recommendation 'Expectations management: the platform is 10+ years old; an SSD and enough RAM are the only worthwhile upgrades.'
    }
    if ($xmpOff) {
        Add-Finding -Severity Info -Category 'Memory' -RuleId 'MEM-XMP' -Title 'Memory runs below its rated speed (XMP/EXPO not enabled)' -Detail 'ConfiguredClockSpeed < Speed on at least one module.' -Recommendation 'Enable the XMP/EXPO/DOCP profile in the BIOS if stability allows.'
    }

    # Live usage from the samples
    $memSamples = @($Samples['Memory'] | Where-Object { $null -ne $_ })
    $rateSamples = $memSamples
    if ($memSamples.Count -gt 2) { $rateSamples = @($memSamples | Select-Object -Skip 1) }
    $usage = [ordered]@{
        Samples                    = $memSamples.Count
        AvailableMBytes            = Get-WdInvAverage -Values @($memSamples | ForEach-Object { $_.AvailableMBytes }) -Decimals 0
        AvailableMBytesMin         = $(try { $mins = @($memSamples | ForEach-Object { [double]$_.AvailableMBytes }); if ($mins.Count -gt 0) { ($mins | Measure-Object -Minimum).Minimum } else { $null } } catch { $null })
        CommittedBytes             = Get-WdInvMax -Values @($memSamples | ForEach-Object { $_.CommittedBytes })
        CommitLimit                = Get-WdInvMax -Values @($memSamples | ForEach-Object { $_.CommitLimit })
        PercentCommittedBytesInUse = Get-WdInvAverage -Values @($memSamples | ForEach-Object { $_.PercentCommittedBytesInUse }) -Decimals 0
        PagesPersec                = Get-WdInvAverage -Values @($rateSamples | ForEach-Object { $_.PagesPersec }) -Decimals 0
        PageFaultsPersec           = Get-WdInvAverage -Values @($rateSamples | ForEach-Object { $_.PageFaultsPersec }) -Decimals 0
        PoolNonpagedBytes          = Get-WdInvMax -Values @($memSamples | ForEach-Object { $_.PoolNonpagedBytes })
        PoolPagedBytes             = Get-WdInvMax -Values @($memSamples | ForEach-Object { $_.PoolPagedBytes })
        StandbyCacheNormalPriorityBytes = Get-WdInvMax -Values @($memSamples | ForEach-Object { $_.StandbyCacheNormalPriorityBytes })
        ModifiedPageListBytes      = Get-WdInvMax -Values @($memSamples | ForEach-Object { $_.ModifiedPageListBytes })
        FreeAndZeroPageListBytes   = Get-WdInvMax -Values @($memSamples | ForEach-Object { $_.FreeAndZeroPageListBytes })
    }
    if ($null -ne $usage['CommittedBytes']) { $usage['CommittedText'] = Format-Bytes -Bytes $usage['CommittedBytes'] }
    if ($null -ne $usage['CommitLimit']) { $usage['CommitLimitText'] = Format-Bytes -Bytes $usage['CommitLimit'] }
    if ($null -ne $usage['PoolNonpagedBytes']) { $usage['PoolNonpagedText'] = Format-Bytes -Bytes $usage['PoolNonpagedBytes'] }
    $sec['Usage'] = $usage
    $avail = $usage['AvailableMBytes']
    if ($totalBytes -gt 0 -and $null -ne $avail) {
        $availPct = ([double]$avail * 1MB) / [double]$totalBytes * 100
        $usage['AvailablePercent'] = Get-WdInvNum -Value $availPct -Decimals 1
        $commitPct = $usage['PercentCommittedBytesInUse']
        if ($availPct -lt 10 -or [double]$avail -lt 1024 -or ($null -ne $commitPct -and $commitPct -gt 90)) {
            Add-Finding -Severity Warning -Category 'Memory' -RuleId 'MEM-PRESSURE' -Title ('Memory pressure: {0} MB available ({1} %), commit {2} %' -f (Format-WdInvNum $avail 0), (Format-WdInvNum $availPct 0), (Format-WdInvNum $commitPct 0)) `
                -Detail ('Total RAM {0}; committed {1} of {2}' -f (Format-Bytes -Bytes $totalBytes), (Format-Bytes -Bytes $usage['CommittedBytes']), (Format-Bytes -Bytes $usage['CommitLimit'])) `
                -Recommendation 'RAM is exhausted: see the top memory processes in the Performance snapshot, close/uninstall memory hogs, reduce browser tabs, or add RAM.'
        }
    }
    $ctx['PagesPersec'] = $usage['PagesPersec']
    # With a hypervisor (Hyper-V, WSL2, Docker Desktop, Windows Sandbox) the vmmem/vmmemWSL memory is accounted as
    # non-paged pool: the threshold is raised to 2.5 GB and the finding is informational (D4).
    $vmmemRunning = $false
    foreach ($p in @($Samples['Process2'])) {
        if ($null -ne $p -and [string]$p.Name -match '^vmmem') { $vmmemRunning = $true; break }
    }
    $hypervisor = ($ctx['HypervisorPresent'] -eq $true) -or $vmmemRunning
    $poolLimit = 1.5GB
    $poolSev = 'Warning'
    $poolNote = 'A large non-paged pool is a kernel/driver memory leak.'
    if ($hypervisor) {
        $poolLimit = 2.5GB
        $poolSev = 'Info'
        $poolNote = 'A hypervisor is present (Hyper-V/WSL2/Docker/Sandbox): virtual machine memory (vmmem) is accounted as non-paged pool, so this is usually not a leak.'
    }
    $usage['HypervisorPresent'] = $hypervisor
    # Without a hypervisor: > 10 % of RAM or > 1.5 GB. With one, only the absolute 2.5 GB limit applies (vmmem on a
    # 16 GB PC easily exceeds 10 % of RAM).
    $poolHigh = ($null -ne $usage['PoolNonpagedBytes'] -and $totalBytes -gt 0 -and [double]$usage['PoolNonpagedBytes'] -gt $poolLimit)
    if (-not $hypervisor -and $null -ne $usage['PoolNonpagedBytes'] -and $totalBytes -gt 0 -and [double]$usage['PoolNonpagedBytes'] -gt 0.10 * $totalBytes) { $poolHigh = $true }
    if ($poolHigh) {
        Add-Finding -Severity $poolSev -Category 'Memory' -RuleId 'MEM-POOL' -Title ('Non-paged pool is {0}' -f (Format-Bytes -Bytes $usage['PoolNonpagedBytes'])) -Detail $poolNote `
            -Recommendation 'Update network, GPU, antivirus and storage drivers; reboot; use poolmon to find the tag if it recurs. With WSL2/Hyper-V, stop the virtual machines (wsl --shutdown) and compare.'
    }

    # Page file
    $pfUsage = @(Get-CimSafe -ClassName Win32_PageFileUsage)
    $pfSetting = @(Get-CimSafe -ClassName Win32_PageFileSetting)
    $mm = Get-WdInvRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
    $pfRows = New-Object 'System.Collections.Generic.List[object]'
    $peakMax = 0
    $allocTotal = 0
    foreach ($p in $pfUsage) {
        $pfRows.Add([ordered]@{ Name = [string]$p.Name; AllocatedMB = $p.AllocatedBaseSize; CurrentUsageMB = $p.CurrentUsage; PeakUsageMB = $p.PeakUsage; TempPageFile = $p.TempPageFile })
        if ($null -ne $p.PeakUsage -and [int64]$p.PeakUsage -gt $peakMax) { $peakMax = [int64]$p.PeakUsage }
        if ($null -ne $p.AllocatedBaseSize) { $allocTotal += [int64]$p.AllocatedBaseSize }
    }
    $pfSettings = @($pfSetting | ForEach-Object { [ordered]@{ Name = [string]$_.Name; InitialMB = $_.InitialSize; MaximumMB = $_.MaximumSize } })
    $pagingFiles = @($mm['PagingFiles'])
    $sysFiles = New-Object 'System.Collections.Generic.List[object]'
    $sysDrive = [string]$env:SystemDrive
    if ([string]::IsNullOrEmpty($sysDrive)) { $sysDrive = 'C:' }
    foreach ($fn in @('pagefile.sys', 'hiberfil.sys', 'swapfile.sys')) {
        $p = $sysDrive + '\' + $fn
        $sz = Get-FileSizeSafe -Path $p
        if ($null -ne $sz) { $sysFiles.Add([ordered]@{ File = $p; Bytes = $sz; Size = (Format-Bytes -Bytes $sz) }) }
    }
    $sec['PageFile'] = [ordered]@{
        Usage = $pfRows.ToArray()
        Settings = $pfSettings
        SystemManaged = ($pfSettings.Count -eq 0 -and $pfRows.Count -gt 0)
        PagingFilesRegistry = (@($pagingFiles | ForEach-Object { [string]$_ }) -join ';')
        ClearPageFileAtShutdown = $mm['ClearPageFileAtShutdown']
        SystemFiles = $sysFiles.ToArray()
    }
    $pagingEmpty = ($pagingFiles.Count -eq 0 -or ($pagingFiles.Count -eq 1 -and [string]::IsNullOrWhiteSpace([string]$pagingFiles[0])))
    if ($pfRows.Count -eq 0 -and $pagingEmpty) {
        Add-Finding -Severity Warning -Category 'Memory' -RuleId 'MEM-NOPF' -Title 'The page file is disabled' -Detail 'Win32_PageFileUsage is empty and PagingFiles is not set.' `
            -Recommendation 'Re-enable a system-managed page file (System > Advanced > Performance > Virtual memory). Without it applications crash under memory pressure.'
    }
    $totalMB = [double]$totalBytes / 1MB
    $heavyPaging = $false
    if ($null -ne $usage['PagesPersec']) {
        $limit = 1000
        if ($ctx['SystemMediaType'] -eq 'HDD') { $limit = 200 }
        if ([double]$usage['PagesPersec'] -gt $limit) { $heavyPaging = $true }
    }
    if ($totalMB -gt 0 -and $peakMax -gt 2 * $totalMB) { $heavyPaging = $true }
    if ($heavyPaging) {
        Add-Finding -Severity Warning -Category 'Memory' -RuleId 'MEM-PAGING' -Title 'Heavy paging / page file peak indicates RAM shortage' `
            -Detail ('Pages/sec {0}; page file peak {1} MB vs RAM {2} MB' -f (Format-WdInvNum $usage['PagesPersec'] 0), $peakMax, (Format-WdInvNum $totalMB 0)) `
            -Recommendation 'The PC swaps to disk: add RAM or reduce the memory load (see the top memory processes).'
    }

    # Memory diagnostics (newest first). Only a failed run of the last 90 days counts, and a later passing run (1201)
    # clears it - a years-old 1202 of a since-replaced module is not a current Critical.
    $md = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-MemoryDiagnostics-Results' } -MaxEvents 5)
    $sec['MemoryDiagnostics'] = @($md | ForEach-Object { [ordered]@{ Time = $_.TimeCreated; Id = $_.Id; Result = $(if ([int]$_.Id -eq 1201) { 'No errors' } elseif ([int]$_.Id -eq 1202) { 'ERRORS FOUND' } else { [string]$_.Id }) } })
    $since90 = (Get-Date).AddDays(-90)
    foreach ($e in $md) {
        if ([int]$e.Id -eq 1201) { break }
        if ([int]$e.Id -eq 1202 -and $null -ne $e.TimeCreated -and $e.TimeCreated -gt $since90) {
            Add-Finding -Severity Critical -Category 'Memory' -RuleId 'MEM-DIAG' -Title 'Windows Memory Diagnostic found RAM errors' -Detail ('Event 1202 at {0}' -f (Get-IsoTimestamp -Date $e.TimeCreated)) `
                -Recommendation 'Faulty RAM: remove overclock/XMP, test modules one by one (memtest86), replace the bad module.'
            break
        }
    }

    # SysMain / prefetch / memory compression
    $sysMain = Invoke-Safely -Name 'Memory.SysMain' -Default $null -ScriptBlock { Get-Service -Name 'SysMain' -ErrorAction Stop }
    $pf = Get-WdInvRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters'
    $compression = $null
    foreach ($p in @($Samples['Process2'])) {
        if ($null -ne $p -and [string]$p.Name -eq 'Memory Compression') { $compression = $p.WorkingSetPrivate; break }
    }
    $sec['SysMain'] = [ordered]@{
        Status = $(if ($null -ne $sysMain) { [string]$sysMain.Status } else { 'n/a' })
        StartType = $(if ($null -ne $sysMain) { [string]$sysMain.StartType } else { 'n/a' })
        EnablePrefetcher = $pf['EnablePrefetcher']
        EnableSuperfetch = $pf['EnableSuperfetch']
        MemoryCompressionWorkingSet = $compression
        MemoryCompressionText = Format-Bytes -Bytes $compression
    }
    $ctx['SysMainRunning'] = ($null -ne $sysMain -and [string]$sysMain.Status -eq 'Running')
    return $sec
}

# ---------------------------------------------------------------------------------------------
# 4. GPU
# ---------------------------------------------------------------------------------------------
function Get-WdInvGpu {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Samples, [Parameter(Mandatory = $true)][hashtable]$ProcessMap)
    $inv = Get-WdInv
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}
    $vcs = @(Get-CimSafe -ClassName Win32_VideoController)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $basicOnly = ($vcs.Count -gt 0)
    $hasDiscrete = $false
    foreach ($v in $vcs) {
        $name = Get-WdInvString -Value $v.Name
        if ($name -notmatch 'Microsoft Basic Display|Microsoft Basic Render|Remote Display|Virtual|VMware|Hyper-V|Parsec|DisplayLink|Meta Virtual') { $basicOnly = $false }
        $drvDate = $null
        if ($null -ne $v.DriverDate) { try { $drvDate = [DateTime]$v.DriverDate } catch { } }
        $err = [int](Get-WdInvPropertyValue -Object $v -Name 'ConfigManagerErrorCode' -Default 0)
        $res = ''
        if ($null -ne $v.CurrentHorizontalResolution -and $null -ne $v.CurrentVerticalResolution) { $res = '{0}x{1}' -f $v.CurrentHorizontalResolution, $v.CurrentVerticalResolution; if ($null -ne $v.CurrentRefreshRate) { $res += ' @ ' + [string]$v.CurrentRefreshRate + ' Hz' } }
        $vendor = Get-WdInvString -Value $v.AdapterCompatibility
        if ($name -match 'NVIDIA|GeForce|Radeon RX|Radeon Pro|Arc A|Arc B' -and $name -notmatch 'Graphics$|Vega|680M|780M|Radeon\(TM\) Graphics') { $hasDiscrete = $true }
        $rows.Add([ordered]@{
            Name = $name
            Vendor = $vendor
            DriverVersion = Get-WdInvString -Value $v.DriverVersion
            DriverDate = $drvDate
            DriverAgeYears = $(if ($null -ne $drvDate) { Get-WdInvNum -Value (((Get-Date) - $drvDate).TotalDays / 365.25) -Decimals 1 } else { $null })
            AdapterRAM_Reported = $v.AdapterRAM
            VideoProcessor = Get-WdInvString -Value $v.VideoProcessor
            Resolution = $res
            Status = Get-WdInvString -Value $v.Status
            ConfigManagerErrorCode = $err
            PNPDeviceID = Get-WdInvString -Value $v.PNPDeviceID
        })
        if ($err -ne 0) {
            Add-Finding -Severity Warning -Category 'GPU' -RuleId 'GPU-ERR' -Title ('Display adapter "{0}" reports device error code {1}' -f $name, $err) -Detail 'ConfigManagerErrorCode <> 0 on Win32_VideoController.' `
                -Recommendation 'Reinstall the GPU driver from the vendor site (code 43 = driver/hardware failure, 31/28 = no driver).'
        }
        if ($null -ne $drvDate -and $vendor -notmatch 'Microsoft' -and ((Get-Date) - $drvDate).TotalDays -gt 3 * 365) {
            Add-Finding -Severity Info -Category 'GPU' -RuleId 'GPU-OLDDRV' -Title ('GPU driver for "{0}" is from {1}' -f $name, $drvDate.ToString('yyyy-MM-dd', $inv)) -Detail ('Driver version {0}' -f (Get-WdInvString -Value $v.DriverVersion)) `
                -Recommendation 'Install a current GPU driver from the vendor (NVIDIA/AMD/Intel) site.'
        }
    }
    if ($basicOnly -and $vcs.Count -gt 0) {
        Add-Finding -Severity Critical -Category 'GPU' -RuleId 'GPU-NODRV' -Title 'No GPU driver installed (Microsoft Basic Display Adapter only)' -Detail (@($rows | ForEach-Object { $_['Name'] }) -join '; ') `
            -Recommendation 'Everything is software-rendered on the CPU. Install the graphics driver for the GPU (Device Manager > Display adapters shows the hardware id).'
    }
    $sec['Adapters'] = $rows.ToArray()

    # Real VRAM from the display class registry key
    $classKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}'
    $regRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($sub in @(Get-WdInvRegistrySubKeyNames -Path $classKey)) {
        if ($sub -notmatch '^\d{4}$') { continue }
        $vals = Get-WdInvRegistryValues -Path ($classKey + '\' + $sub)
        $desc = Get-WdInvString -Value $vals['DriverDesc']
        if ($desc -eq '') { continue }
        $vram = $null
        if ($vals.Contains('HardwareInformation.qwMemorySize')) { try { $vram = [int64]$vals['HardwareInformation.qwMemorySize'] } catch { } }
        if ($null -eq $vram -and $vals.Contains('HardwareInformation.MemorySize')) {
            $raw = $vals['HardwareInformation.MemorySize']
            try {
                if ($raw -is [byte[]]) { if ($raw.Length -ge 8) { $vram = [BitConverter]::ToInt64($raw, 0) } elseif ($raw.Length -ge 4) { $vram = [int64][BitConverter]::ToUInt32($raw, 0) } }
                else { $vram = [int64]$raw }
            } catch { }
        }
        $regRows.Add([ordered]@{
            Description = $desc
            DedicatedVideoMemory = $vram
            DedicatedVideoMemoryText = Format-Bytes -Bytes $vram -Decimals 0
            DriverVersion = Get-WdInvString -Value $vals['DriverVersion']
            DriverDate = Get-WdInvString -Value $vals['DriverDate']
            Provider = Get-WdInvString -Value $vals['ProviderName']
            MatchingDeviceId = Get-WdInvString -Value $vals['MatchingDeviceId']
        })
    }
    $sec['RegistryAdapters'] = $regRows.ToArray()
    $maxVram = Get-WdInvMax -Values @($regRows | ForEach-Object { $_['DedicatedVideoMemory'] })
    if (-not $hasDiscrete -and $null -ne $ctx['TotalRamBytes'] -and [int64]$ctx['TotalRamBytes'] -gt 0 -and ([double]$ctx['TotalRamBytes'] / 1GB) -lt 7.5 -and $vcs.Count -gt 0) {
        Add-Finding -Severity Warning -Category 'GPU' -RuleId 'GPU-IGPU-LOWRAM' -Title 'Integrated graphics shares the scarce RAM' -Detail ('RAM {0}; the iGPU reserves part of it as video memory.' -f (Format-Bytes -Bytes $ctx['TotalRamBytes'])) `
            -Recommendation 'Add RAM; with integrated graphics every GB counts twice.'
    }

    # GPU engine utilization per process (3 samples)
    $perPid = @{}
    $sampleCount = 0
    foreach ($sample in $Samples['Gpu']) {
        $sampleCount++
        $seen = @{}
        foreach ($e in @($sample)) {
            if ($null -eq $e) { continue }
            $m = [regex]::Match([string]$e.Name, '^pid_(\d+)_luid_(\S+?)_phys_(\d+)_eng_(\d+)_engtype_(.+)$')
            if (-not $m.Success) { continue }
            $procId = [int]$m.Groups[1].Value
            $eng = $m.Groups[5].Value
            $util = [double]$e.UtilizationPercentage
            if (-not $perPid.ContainsKey($procId)) { $perPid[$procId] = @{ Total = New-Object 'System.Collections.Generic.List[double]'; Heavy = New-Object 'System.Collections.Generic.List[double]'; Engines = @{} } }
            if (-not $seen.ContainsKey($procId)) { $seen[$procId] = @{ Total = 0.0; Heavy = 0.0 } }
            $seen[$procId]['Total'] += $util
            if ($eng -match '^(3D|Compute|Graphics)') { $seen[$procId]['Heavy'] += $util }
            if (-not $perPid[$procId]['Engines'].ContainsKey($eng)) { $perPid[$procId]['Engines'][$eng] = 0.0 }
            if ($util -gt $perPid[$procId]['Engines'][$eng]) { $perPid[$procId]['Engines'][$eng] = $util }
        }
        foreach ($procId in $perPid.Keys) {
            if ($seen.ContainsKey($procId)) { $perPid[$procId]['Total'].Add($seen[$procId]['Total']); $perPid[$procId]['Heavy'].Add($seen[$procId]['Heavy']) }
            else { $perPid[$procId]['Total'].Add(0.0); $perPid[$procId]['Heavy'].Add(0.0) }
        }
    }
    $gpuRows = New-Object 'System.Collections.Generic.List[object]'
    $heavyNames = @($script:Rules['KnownHeavyProcesses'] | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $total3d = 0.0
    foreach ($procId in $perPid.Keys) {
        $d = $perPid[$procId]
        $avgTotal = Get-WdInvAverage -Values $d['Total'].ToArray()
        $avgHeavy = Get-WdInvAverage -Values $d['Heavy'].ToArray()
        $minHeavy = $null
        try { $minHeavy = ($d['Heavy'].ToArray() | Measure-Object -Minimum).Minimum } catch { }
        $pName = ''
        $pPath = ''
        if ($ProcessMap.ContainsKey($procId)) { $pName = [string]$ProcessMap[$procId].Name; $pPath = [string]$ProcessMap[$procId].ExecutablePath }
        $engText = @($d['Engines'].Keys | Sort-Object | ForEach-Object { '{0}={1}' -f $_, (Format-WdInvNum $d['Engines'][$_] 0) }) -join ', '
        $gpuRows.Add([ordered]@{ Pid = $procId; Process = $pName; Path = $pPath; AvgUtilAllEngines = $avgTotal; AvgUtil3DCompute = $avgHeavy; MinUtil3DCompute = (Get-WdInvNum -Value $minHeavy); EnginesMax = $engText })
        if ($null -ne $avgHeavy) { $total3d += [double]$avgHeavy }
        $base = ''
        try { $base = [IO.Path]::GetFileNameWithoutExtension($pName).ToLowerInvariant() } catch { $base = $pName.ToLowerInvariant() }
        if ($null -ne $minHeavy -and [double]$minHeavy -gt 30 -and $d['Heavy'].Count -ge 2 -and -not ($heavyNames -contains $base) -and $base -ne 'dwm' -and $base -ne '') {
            $sev = 'Warning'
            $loc = Get-ProcessLocationClass -Path $pPath
            $susp = ($pPath -ne '' -and $pPath -match [string]$script:Rules['SuspiciousPathRegex'])
            if ($susp) { $sev = 'Critical' }
            # Trusted-signer damping: a binary validly signed by a vendor in TrustedSignerRegex (Windows components,
            # browsers, GPU vendor tools, Electron apps in AppData) is never a Critical miner suspicion by GPU load alone.
            $sigNote = ''
            if ($pPath -ne '') {
                $gsig = Get-WdInvSignatureInfo -Path $pPath
                if ($gsig['Trusted']) { $sev = 'Info'; $sigNote = ('; validly signed by {0} - not treated as a miner' -f $gsig['Signer']) }
            }
            Add-Finding -Severity $sev -Category 'GPU' -RuleId 'GPU-BUSY' -Title ('Process "{0}" keeps the GPU busy ({1} % 3D/Compute in every sample)' -f $pName, (Format-WdInvNum $avgHeavy 0)) `
                -Detail ('PID {0}, path {1} (location: {2}){3}' -f $procId, $(if ($pPath -ne '') { $pPath } else { 'n/a (other user or protected process)' }), $loc, $sigNote) `
                -Recommendation 'If this is not a game/video/3D application the user started, it may be a GPU miner: check its path, signature, autostart entries and network connections.'
        }
    }
    # Rows are [ordered] hashtables: a string property name does not sort them in PS 5.1, the key lookup does.
    $sec['ProcessUtilization'] = @($gpuRows.ToArray() | Sort-Object -Property @{ Expression = { [double]$(if ($null -ne $_['AvgUtilAllEngines']) { $_['AvgUtilAllEngines'] } else { -1 }) }; Descending = $true } | Select-Object -First 15)
    $sec['GpuSamples'] = $sampleCount
    $sec['Total3DComputePercent'] = Get-WdInvNum -Value $total3d -Decimals 0
    if ($total3d -gt 80 -and $sampleCount -ge 2) {
        Add-Finding -Severity Warning -Category 'GPU' -RuleId 'GPU-TOTAL-BUSY' -Title ('Total 3D/Compute GPU load is {0} % during the scan' -f (Format-WdInvNum $total3d 0)) -Detail 'Summed over processes and samples (per-engine percentages may exceed 100 in total).' `
            -Recommendation 'Something renders or computes heavily on the GPU right now; see the per-process GPU table.'
    }

    # GPU memory
    $am = @(Get-CimSafe -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUAdapterMemory)
    $sec['AdapterMemory'] = @($am | ForEach-Object { [ordered]@{ Name = [string]$_.Name; DedicatedUsage = $_.DedicatedUsage; DedicatedUsageText = (Format-Bytes -Bytes $_.DedicatedUsage); SharedUsage = $_.SharedUsage; SharedUsageText = (Format-Bytes -Bytes $_.SharedUsage); TotalCommitted = $_.TotalCommitted } })
    if ($null -ne $maxVram -and $maxVram -gt 0) {
        foreach ($a in $am) { if ($null -ne $a.DedicatedUsage -and [double]$a.DedicatedUsage -gt 0.9 * $maxVram) {
            Add-Finding -Severity Info -Category 'GPU' -RuleId 'GPU-VRAM-FULL' -Title 'Dedicated video memory is almost full' -Detail ('{0} used of {1}' -f (Format-Bytes -Bytes $a.DedicatedUsage), (Format-Bytes -Bytes $maxVram)) -Recommendation 'Close GPU-heavy applications or lower game/video settings.'
            break } }
    }

    # Monitors
    $mons = @(Get-CimSafe -Namespace 'root/wmi' -ClassName WmiMonitorID)
    $monRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($m in $mons) {
        $mf = ''
        $nm = ''
        $code = ''
        try { $mf = -join [char[]]@($m.ManufacturerName | Where-Object { $_ -ne 0 }) } catch { }
        try { $nm = -join [char[]]@($m.UserFriendlyName | Where-Object { $_ -ne 0 }) } catch { }
        try { $code = -join [char[]]@($m.ProductCodeID | Where-Object { $_ -ne 0 }) } catch { }
        $monRows.Add([ordered]@{ Manufacturer = $mf; Name = $nm; ProductCode = $code; Year = $m.YearOfManufacture; Week = $m.WeekOfManufacture; Instance = [string]$m.InstanceName })
    }
    $sec['Monitors'] = $monRows.ToArray()
    return $sec
}


# ---------------------------------------------------------------------------------------------
# 5. Storage
# ---------------------------------------------------------------------------------------------
function Get-WdInvDiskLatency {
    # Latency / idle / throughput per physical disk instance from the RAW samples (first vs last).
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Samples)
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $raw = @($Samples['DiskRaw'] | Where-Object { $null -ne $_ -and @($_).Count -gt 0 })
    if ($raw.Count -lt 2) { return $rows.ToArray() }
    $first = @($raw[0])
    $last = @($raw[$raw.Count - 1])
    $firstByName = @{}
    foreach ($r in $first) { if ($null -ne $r) { $firstByName[[string]$r.Name] = $r } }
    foreach ($r2 in $last) {
        if ($null -eq $r2) { continue }
        $name = [string]$r2.Name
        if (-not $firstByName.ContainsKey($name)) { continue }
        $r1 = $firstByName[$name]
        $freq = [double]$r2.Frequency_PerfTime
        if ($freq -le 0) { continue }
        $dPerf = [double]$r2.Timestamp_PerfTime - [double]$r1.Timestamp_PerfTime
        $d100 = [double]$r2.Timestamp_Sys100NS - [double]$r1.Timestamp_Sys100NS
        $secs = $dPerf / $freq
        if ($secs -le 0) { continue }
        $msTransfer = $null
        $msRead = $null
        $msWrite = $null
        $dB = [double]$r2.AvgDisksecPerTransfer_Base - [double]$r1.AvgDisksecPerTransfer_Base
        if ($dB -gt 0) { $msTransfer = ([double]$r2.AvgDisksecPerTransfer - [double]$r1.AvgDisksecPerTransfer) / $dB / $freq * 1000 }
        $dBr = [double]$r2.AvgDisksecPerRead_Base - [double]$r1.AvgDisksecPerRead_Base
        if ($dBr -gt 0) { $msRead = ([double]$r2.AvgDisksecPerRead - [double]$r1.AvgDisksecPerRead) / $dBr / $freq * 1000 }
        $dBw = [double]$r2.AvgDisksecPerWrite_Base - [double]$r1.AvgDisksecPerWrite_Base
        if ($dBw -gt 0) { $msWrite = ([double]$r2.AvgDisksecPerWrite - [double]$r1.AvgDisksecPerWrite) / $dBw / $freq * 1000 }
        $idle = $null
        if ($d100 -gt 0) { $idle = ([double]$r2.PercentIdleTime - [double]$r1.PercentIdleTime) / $d100 * 100; if ($idle -gt 100) { $idle = 100 }; if ($idle -lt 0) { $idle = 0 } }
        $queueVals = New-Object 'System.Collections.Generic.List[object]'
        foreach ($sample in $raw) { foreach ($x in @($sample)) { if ($null -ne $x -and [string]$x.Name -eq $name) { $queueVals.Add($x.CurrentDiskQueueLength) } } }
        $rows.Add([ordered]@{
            Disk = $name
            IntervalSeconds = Get-WdInvNum -Value $secs -Decimals 1
            AvgMsPerTransfer = Get-WdInvNum -Value $msTransfer -Decimals 2
            AvgMsPerRead = Get-WdInvNum -Value $msRead -Decimals 2
            AvgMsPerWrite = Get-WdInvNum -Value $msWrite -Decimals 2
            PercentIdle = Get-WdInvNum -Value $idle -Decimals 1
            ReadsPerSec = Get-WdInvNum -Value (([double]$r2.DiskReadsPersec - [double]$r1.DiskReadsPersec) / $secs) -Decimals 1
            WritesPerSec = Get-WdInvNum -Value (([double]$r2.DiskWritesPersec - [double]$r1.DiskWritesPersec) / $secs) -Decimals 1
            ReadBytesPerSec = [int64](([double]$r2.DiskReadBytesPersec - [double]$r1.DiskReadBytesPersec) / $secs)
            WriteBytesPerSec = [int64](([double]$r2.DiskWriteBytesPersec - [double]$r1.DiskWriteBytesPersec) / $secs)
            AvgQueueLength = Get-WdInvAverage -Values $queueVals.ToArray() -Decimals 2
            Transfers = [int64]$dB
        })
    }
    return $rows.ToArray()
}

function Get-WdInvStorage {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Samples)
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}
    $sysDrive = ([string]$env:SystemDrive).TrimEnd(':').ToUpperInvariant()
    if ([string]::IsNullOrEmpty($sysDrive)) { $sysDrive = 'C' }
    $ctx['SystemDrive'] = $sysDrive

    # Partitions -> system disk number
    $parts = @(Invoke-Safely -Name 'Storage.Partitions' -Default @() -ScriptBlock { @(Get-Partition -ErrorAction Stop) })
    $sysDiskNumber = $null
    $partRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in $parts) {
        if ($null -eq $p) { continue }
        $letter = ''
        if ($null -ne $p.DriveLetter -and [int][char]$p.DriveLetter -ne 0) { $letter = [string]$p.DriveLetter }
        if ($letter -eq $sysDrive) { $sysDiskNumber = [int]$p.DiskNumber }
        $partRows.Add([ordered]@{
            Disk = $p.DiskNumber; Partition = $p.PartitionNumber; Drive = $letter; Size = $p.Size; SizeText = (Format-Bytes -Bytes $p.Size)
            Type = [string]$p.Type; GptType = [string]$p.GptType; IsBoot = $p.IsBoot; IsSystem = $p.IsSystem; IsActive = $p.IsActive; Offset = $p.Offset
            Aligned4K = $(if ($null -ne $p.Offset) { (([int64]$p.Offset % 4096) -eq 0) } else { $null })
        })
    }
    $ctx['SystemDiskNumber'] = $sysDiskNumber

    # Physical disks
    $pds = @(Invoke-Safely -Name 'Storage.PhysicalDisk' -Default @() -ScriptBlock { @(Get-PhysicalDisk -ErrorAction Stop) })
    $diskDrives = @(Get-CimSafe -ClassName Win32_DiskDrive -Property @('Index', 'Model', 'InterfaceType', 'MediaType', 'Size', 'SerialNumber', 'FirmwareRevision', 'Status'))
    $modelByIndex = @{}
    foreach ($dd in $diskDrives) { if ($null -ne $dd -and $null -ne $dd.Index) { $modelByIndex[[int]$dd.Index] = $dd } }
    $pdRows = New-Object 'System.Collections.Generic.List[object]'
    $sysMedia = 'Unknown'
    $sysBus = ''
    foreach ($d in $pds) {
        if ($null -eq $d) { continue }
        $devId = -1
        try { $devId = [int]$d.DeviceId } catch { }
        $media = [string]$d.MediaType
        $spindle = $d.SpindleSpeed
        $model = Get-WdInvString -Value $d.FriendlyName
        $effective = $media
        if ($media -notin @('SSD', 'HDD')) {
            if ($null -ne $spindle -and [int64]$spindle -gt 0 -and [int64]$spindle -ne 4294967295) { $effective = 'HDD' }
            elseif ($model -match 'SSD|NVMe|Solid|M\.2' -or [string]$d.BusType -eq 'NVMe') { $effective = 'SSD' }
            elseif ($modelByIndex.ContainsKey($devId) -and [string]$modelByIndex[$devId].Model -match 'SSD|NVMe') { $effective = 'SSD' }
            else { $effective = 'Unknown' }
        }
        $isSystem = ($null -ne $sysDiskNumber -and $devId -eq $sysDiskNumber)
        if ($isSystem) { $sysMedia = $effective; $sysBus = [string]$d.BusType }
        $pdRows.Add([ordered]@{
            DeviceId = $devId
            Model = $model
            SerialNumber = Get-WdInvString -Value $d.SerialNumber
            MediaType = $media
            EffectiveMediaType = $effective
            BusType = [string]$d.BusType
            HealthStatus = [string]$d.HealthStatus
            OperationalStatus = (@($d.OperationalStatus | ForEach-Object { [string]$_ }) -join ';')
            Size = $d.Size
            SizeText = Format-Bytes -Bytes $d.Size
            SpindleSpeed = $spindle
            FirmwareVersion = Get-WdInvString -Value $d.FirmwareVersion
            PhysicalSectorSize = $d.PhysicalSectorSize
            LogicalSectorSize = $d.LogicalSectorSize
            IsSystemDisk = $isSystem
        })
        $health = [string]$d.HealthStatus
        if ($health -ne '' -and $health -ne 'Healthy') {
            Add-Finding -Severity Critical -Category 'Storage' -RuleId 'STO-HEALTH' -Title ('Disk "{0}" health status is {1}' -f $model, $health) -Detail ('Get-PhysicalDisk HealthStatus={0}, OperationalStatus={1}' -f $health, (@($d.OperationalStatus) -join ';')) `
                -Recommendation 'The disk is failing. Back up your data immediately and replace the disk.'
        }
        if ($isSystem -and [string]$d.BusType -eq 'USB') {
            Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-USB-SYS' -Title 'The system disk is connected over USB' -Detail $model -Recommendation 'Windows on a USB disk is slow; use an internal SATA/NVMe drive.'
        }
    }
    if ($pds.Count -eq 0 -and $diskDrives.Count -gt 0) {
        foreach ($dd in $diskDrives) {
            $effective = 'Unknown'
            if ([string]$dd.Model -match 'SSD|NVMe') { $effective = 'SSD' }
            $isSystem = ($null -ne $sysDiskNumber -and [int]$dd.Index -eq $sysDiskNumber)
            if ($isSystem) { $sysMedia = $effective; $sysBus = [string]$dd.InterfaceType }
            $pdRows.Add([ordered]@{ DeviceId = $dd.Index; Model = [string]$dd.Model; SerialNumber = (Get-WdInvString -Value $dd.SerialNumber); MediaType = [string]$dd.MediaType; EffectiveMediaType = $effective; BusType = [string]$dd.InterfaceType; HealthStatus = [string]$dd.Status; OperationalStatus = ''; Size = $dd.Size; SizeText = (Format-Bytes -Bytes $dd.Size); SpindleSpeed = $null; FirmwareVersion = [string]$dd.FirmwareRevision; PhysicalSectorSize = $null; LogicalSectorSize = $null; IsSystemDisk = $isSystem })
        }
    }
    $sec['PhysicalDisks'] = $pdRows.ToArray()
    $ctx['SystemMediaType'] = $sysMedia
    $sec['SystemDisk'] = [ordered]@{ Drive = $sysDrive; DiskNumber = $sysDiskNumber; MediaType = $sysMedia; BusType = $sysBus }
    if ($sysMedia -eq 'HDD') {
        Add-Finding -Severity Critical -Category 'Storage' -RuleId 'STO-HDD' -Title 'Windows runs on a mechanical hard disk (HDD)' -Detail ('System disk {0}: {1}' -f $sysDiskNumber, (@($pdRows | Where-Object { $_['IsSystemDisk'] } | ForEach-Object { $_['Model'] }) -join ', ')) `
            -Recommendation 'This is the #1 cause of "the PC is slow" on Windows 10/11. Clone the system to an SSD (even a cheap SATA SSD is 10x faster for Windows).'
    } elseif ($sysMedia -eq 'Unknown' -and $pdRows.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Storage' -RuleId 'STO-MEDIA-UNKNOWN' -Title 'Could not determine whether the system disk is an SSD or HDD' -Detail 'MediaType=Unspecified and no SSD/NVMe hint in the model name (USB bridge, RAID or virtual machine).' `
            -Recommendation 'Check the disk model manually; if it is a mechanical disk, replace it with an SSD.'
    }

    # SMART / reliability counters (admin)
    $smartRows = New-Object 'System.Collections.Generic.List[object]'
    if ($script:IsAdmin) {
        $src = @(Invoke-Safely -Name 'Storage.ReliabilityCounters' -Default @() -ScriptBlock { @(Get-PhysicalDisk -ErrorAction Stop | Get-StorageReliabilityCounter -ErrorAction Stop) })
        foreach ($r in $src) {
            if ($null -eq $r) { continue }
            $model = ''
            foreach ($pr in $pdRows) { if ([string]$pr['DeviceId'] -eq [string]$r.DeviceId) { $model = [string]$pr['Model'] } }
            $smartRows.Add([ordered]@{
                DeviceId = $r.DeviceId; Model = $model; TemperatureC = $r.Temperature; TemperatureMaxC = $r.TemperatureMax; WearPercent = $r.Wear
                ReadErrorsTotal = $r.ReadErrorsTotal; ReadErrorsCorrected = $r.ReadErrorsCorrected; ReadErrorsUncorrected = $r.ReadErrorsUncorrected
                WriteErrorsTotal = $r.WriteErrorsTotal; WriteErrorsUncorrected = $r.WriteErrorsUncorrected; PowerOnHours = $r.PowerOnHours
                StartStopCycleCount = $r.StartStopCycleCount; ReadLatencyMaxMs = $r.ReadLatencyMax; WriteLatencyMaxMs = $r.WriteLatencyMax; FlushLatencyMaxMs = $r.FlushLatencyMax
            })
            $wear = $r.Wear
            if ($null -ne $wear -and [int]$wear -gt 95) {
                Add-Finding -Severity Critical -Category 'Storage' -RuleId 'STO-HEALTH' -Title ('SSD "{0}" is worn out ({1} % used)' -f $model, $wear) -Detail 'SMART percentage used > 95.' -Recommendation 'Back up now and replace the SSD.'
            } elseif ($null -ne $wear -and [int]$wear -gt 80) {
                Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-WEAR' -Title ('SSD "{0}" is near its end of life ({1} % used)' -f $model, $wear) -Detail 'SMART percentage used 80-95.' -Recommendation 'Plan a replacement and keep backups current.'
            }
            if (([int64](Get-WdInvPropertyValue -Object $r -Name 'ReadErrorsUncorrected' -Default 0)) -gt 0 -or ([int64](Get-WdInvPropertyValue -Object $r -Name 'WriteErrorsUncorrected' -Default 0)) -gt 0) {
                Add-Finding -Severity Critical -Category 'Storage' -RuleId 'STO-HEALTH' -Title ('Disk "{0}" has uncorrectable read/write errors' -f $model) -Detail ('ReadErrorsUncorrected={0}, WriteErrorsUncorrected={1}' -f $r.ReadErrorsUncorrected, $r.WriteErrorsUncorrected) -Recommendation 'The disk is failing. Back up now and replace it.'
            }
            if ($null -ne $r.Temperature -and [int]$r.Temperature -gt 65) {
                Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-TEMP' -Title ('Disk "{0}" is at {1} C' -f $model, $r.Temperature) -Detail 'SMART temperature > 65 C.' -Recommendation 'Improve airflow / add an NVMe heatsink; hot SSDs throttle heavily.'
            }
            foreach ($latName in @('ReadLatencyMax', 'WriteLatencyMax', 'FlushLatencyMax')) {
                $lv = Get-WdInvPropertyValue -Object $r -Name $latName
                if ($null -ne $lv -and [int64]$lv -gt 1000) {
                    Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-LAT-MAX' -Title ('Disk "{0}" recorded a {1} of {2} ms' -f $model, $latName, $lv) -Detail 'Storage reliability counters.' -Recommendation 'Very high maximum latency: check cables, firmware and SMART; a dying disk stalls the whole system.'
                    break
                }
            }
        }
        $sec['Smart'] = $smartRows.ToArray()
    } else {
        $sec['Smart'] = Add-WdInvAdminGap -Item 'SMART / disk reliability counters (temperature, wear, errors, power-on hours)' -Detail 'Get-StorageReliabilityCounter'
    }

    # Disks (partition style) + partitions
    $disks = @(Invoke-Safely -Name 'Storage.Disk' -Default @() -ScriptBlock { @(Get-Disk -ErrorAction Stop) })
    $diskRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($d in $disks) {
        if ($null -eq $d) { continue }
        $diskRows.Add([ordered]@{ Number = $d.Number; FriendlyName = (Get-WdInvString -Value $d.FriendlyName); PartitionStyle = [string]$d.PartitionStyle; HealthStatus = [string]$d.HealthStatus; OperationalStatus = [string]$d.OperationalStatus; Size = $d.Size; SizeText = (Format-Bytes -Bytes $d.Size); BootFromDisk = $d.BootFromDisk; IsSystem = $d.IsSystem; IsBoot = $d.IsBoot; NumberOfPartitions = $d.NumberOfPartitions })
        if ($null -ne $sysDiskNumber -and [int]$d.Number -eq $sysDiskNumber -and [string]$d.PartitionStyle -eq 'MBR' -and [string]$env:firmware_type -eq 'UEFI') {
            Add-Finding -Severity Info -Category 'Storage' -RuleId 'STO-MBR-UEFI' -Title 'System disk uses MBR on a UEFI machine (legacy/CSM boot)' -Detail 'Get-Disk PartitionStyle=MBR, firmware_type=UEFI.' -Recommendation 'Not a slowness cause; converting with mbr2gpt enables Secure Boot and Windows 11 requirements.'
        }
    }
    $sec['Disks'] = $diskRows.ToArray()
    $sec['Partitions'] = $partRows.ToArray()
    foreach ($pr in $partRows) {
        if ($pr['Aligned4K'] -eq $false -and $pr['Drive'] -ne '') {
            $pdMedia = ''
            foreach ($x in $pdRows) { if ([string]$x['DeviceId'] -eq [string]$pr['Disk']) { $pdMedia = [string]$x['EffectiveMediaType'] } }
            if ($pdMedia -eq 'SSD') {
                Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-ALIGN' -Title ('Partition {0}: is not 4K aligned on an SSD' -f $pr['Drive']) -Detail ('Offset {0}' -f $pr['Offset']) -Recommendation 'Misaligned partitions halve SSD write performance; re-partition (clone with alignment) when convenient.'
            }
        }
    }

    # Volumes
    $vols = @(Invoke-Safely -Name 'Storage.Volume' -Default @() -ScriptBlock { @(Get-Volume -ErrorAction Stop) })
    $volRows = New-Object 'System.Collections.Generic.List[object]'
    $volByGuid = @{}
    foreach ($v in $vols) {
        if ($null -eq $v) { continue }
        $letter = ''
        if ($null -ne $v.DriveLetter -and [int][char]$v.DriveLetter -ne 0) { $letter = [string]$v.DriveLetter }
        $uid = [string]$v.UniqueId
        if ($uid -match '\{([0-9a-fA-F-]{36})\}') { $volByGuid[$Matches[1].ToLowerInvariant()] = $letter }
        if ([string]$v.DriveType -ne 'Fixed' -and $letter -eq '') { continue }
        $freePct = $null
        if ($null -ne $v.Size -and [int64]$v.Size -gt 0 -and $null -ne $v.SizeRemaining) { $freePct = Get-WdInvNum -Value ([double]$v.SizeRemaining / [double]$v.Size * 100) -Decimals 1 }
        $volRows.Add([ordered]@{
            Drive = $letter; Label = (Get-WdInvString -Value $v.FileSystemLabel); FileSystem = [string]$v.FileSystem; DriveType = [string]$v.DriveType; HealthStatus = [string]$v.HealthStatus
            Size = $v.Size; SizeText = (Format-Bytes -Bytes $v.Size); Free = $v.SizeRemaining; FreeText = (Format-Bytes -Bytes $v.SizeRemaining); FreePercent = $freePct
            AllocationUnitSize = $v.AllocationUnitSize; UniqueId = $uid
        })
        if ($letter -eq $sysDrive) {
            $ctx['SystemFreeBytes'] = $v.SizeRemaining
            $ctx['SystemFreePercent'] = $freePct
            $freeGB = 0.0
            if ($null -ne $v.SizeRemaining) { $freeGB = [double]$v.SizeRemaining / 1GB }
            if ($null -ne $freePct -and ($freePct -lt 5 -or $freeGB -lt 5)) {
                Add-Finding -Severity Critical -Category 'Storage' -RuleId 'STO-FREE-CRIT' -Title ('System drive {0}: has only {1} free ({2} %)' -f $letter, (Format-Bytes -Bytes $v.SizeRemaining), (Format-WdInvNum $freePct 1)) -Detail ('Size {0}' -f (Format-Bytes -Bytes $v.Size)) `
                    -Recommendation 'Windows needs free space for updates, the page file and SSD wear-leveling/TRIM; below 5 % everything slows down. Run the Disk mode of this tool to see what occupies the space, then clean up.'
            } elseif ($null -ne $freePct -and ($freePct -lt 10 -or $freeGB -lt 20)) {
                Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-FREE-WARN' -Title ('System drive {0}: is getting full ({1} free, {2} %)' -f $letter, (Format-Bytes -Bytes $v.SizeRemaining), (Format-WdInvNum $freePct 1)) -Detail ('Size {0}' -f (Format-Bytes -Bytes $v.Size)) `
                    -Recommendation 'Keep at least 10-15 % free: run the Disk mode of this tool, empty Downloads/Recycle Bin, enable Storage Sense.'
            }
            if ([string]$v.FileSystem -ne '' -and [string]$v.FileSystem -ne 'NTFS') {
                Add-Finding -Severity Info -Category 'Storage' -RuleId 'STO-FS' -Title ('System volume file system is {0}' -f $v.FileSystem) -Detail '' -Recommendation 'NTFS is expected for the Windows volume.'
            }
        }
        if ([string]$v.HealthStatus -ne '' -and [string]$v.HealthStatus -ne 'Healthy') {
            Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-VOL-HEALTH' -Title ('Volume {0}: health is {1}' -f $letter, $v.HealthStatus) -Detail '' -Recommendation 'Run chkdsk on the volume and check SMART.'
        }
    }
    if ($vols.Count -eq 0) {
        foreach ($ld in @(Get-CimSafe -ClassName Win32_LogicalDisk -Filter 'DriveType=3')) {
            $letter = ([string]$ld.DeviceID).TrimEnd(':')
            $freePct = $null
            if ($null -ne $ld.Size -and [int64]$ld.Size -gt 0) { $freePct = Get-WdInvNum -Value ([double]$ld.FreeSpace / [double]$ld.Size * 100) -Decimals 1 }
            $volRows.Add([ordered]@{ Drive = $letter; Label = [string]$ld.VolumeName; FileSystem = [string]$ld.FileSystem; DriveType = 'Fixed'; HealthStatus = ''; Size = $ld.Size; SizeText = (Format-Bytes -Bytes $ld.Size); Free = $ld.FreeSpace; FreeText = (Format-Bytes -Bytes $ld.FreeSpace); FreePercent = $freePct; AllocationUnitSize = $null; UniqueId = '' })
            if ($letter -eq $sysDrive) { $ctx['SystemFreeBytes'] = $ld.FreeSpace; $ctx['SystemFreePercent'] = $freePct }
        }
    }
    $sec['Volumes'] = $volRows.ToArray()
    $ctx['FixedVolumeLetters'] = @($volRows | Where-Object { $_['Drive'] -ne '' -and $_['DriveType'] -eq 'Fixed' } | ForEach-Object { $_['Drive'] })

    # TRIM (registry; absent = enabled)
    $ddn = Get-RegistryValueSafe -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'DisableDeleteNotify'
    $trimEnabled = $true
    if ($null -ne $ddn -and [int]$ddn -eq 1) { $trimEnabled = $false }
    $sec['Trim'] = [ordered]@{ DisableDeleteNotify = $ddn; TrimEnabled = $trimEnabled }
    if (-not $trimEnabled -and $sysMedia -eq 'SSD') {
        Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-TRIM' -Title 'TRIM is disabled on an SSD system' -Detail 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem DisableDeleteNotify=1' -Recommendation 'Run as administrator: fsutil behavior set DisableDeleteNotify 0'
    }

    # Dirty bit (admin)
    if ($script:IsAdmin) {
        $wv = @(Get-CimSafe -ClassName Win32_Volume -Filter ("DriveLetter='{0}:'" -f $sysDrive) -Property @('DriveLetter', 'DirtyBitSet'))
        $dirty = $null
        if ($wv.Count -gt 0) { $dirty = $wv[0].DirtyBitSet }
        $sec['SystemVolumeDirtyBit'] = $dirty
        if ($dirty -eq $true) {
            Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-DIRTY' -Title ('Volume {0}: is marked dirty (chkdsk needed)' -f $sysDrive) -Detail 'Win32_Volume.DirtyBitSet=True' -Recommendation ('Run "chkdsk {0}: /f" and let it check at the next reboot.' -f $sysDrive)
        }
    } else {
        $sec['SystemVolumeDirtyBit'] = Add-WdInvAdminGap -Item 'File-system dirty bit (chkdsk needed?)' -Detail 'Win32_Volume.DirtyBitSet is null for standard users'
    }

    # Live disk activity from the raw samples
    $lat = @(Get-WdInvDiskLatency -Samples $Samples)
    $sec['Activity'] = $lat
    foreach ($l in $lat) {
        if ([string]$l['Disk'] -ne '_Total') { continue }
        $limit = 5
        if ($sysMedia -eq 'HDD') { $limit = 25 }
        $reasons = @()
        if ($null -ne $l['AvgMsPerTransfer'] -and [double]$l['AvgMsPerTransfer'] -gt $limit -and [int64]$l['Transfers'] -gt 50) { $reasons += ('{0} ms per transfer (limit {1} ms for {2})' -f (Format-WdInvNum $l['AvgMsPerTransfer'] 1), $limit, $sysMedia) }
        if ($null -ne $l['PercentIdle'] -and [double]$l['PercentIdle'] -lt 20) { $reasons += ('disk idle only {0} %' -f (Format-WdInvNum $l['PercentIdle'] 0)) }
        if ($null -ne $l['AvgQueueLength'] -and [double]$l['AvgQueueLength'] -gt 2) { $reasons += ('average queue length {0}' -f (Format-WdInvNum $l['AvgQueueLength'] 1)) }
        if ($reasons.Count -gt 0) {
            Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-LAT' -Title 'The disk is busy or slow right now' -Detail (($reasons -join '; ') + ('; {0} reads/s, {1} writes/s over {2} s' -f (Format-WdInvNum $l['ReadsPerSec'] 0), (Format-WdInvNum $l['WritesPerSec'] 0), (Format-WdInvNum $l['IntervalSeconds'] 0))) `
                -Recommendation 'A saturated disk makes everything feel slow: check the top I/O processes (Performance snapshot: indexer, Defender scan, updates, sync clients), storage errors in the event log and SMART. On an HDD an SSD upgrade is the fix.'
        }
    }

    # Fragmentation statistics (Dfrg registry, SYSTEMTIME)
    $fragRows = New-Object 'System.Collections.Generic.List[object]'
    $dfrg = 'HKLM:\SOFTWARE\Microsoft\Dfrg\Statistics'
    foreach ($sub in @(Get-WdInvRegistrySubKeyNames -Path $dfrg)) {
        $vals = Get-WdInvRegistryValues -Path ($dfrg + '\' + $sub)
        $lastRun = $null
        $b = $vals['LastRunTime']
        if ($null -ne $b -and $b -is [byte[]] -and $b.Length -ge 16) {
            try {
                $y = [BitConverter]::ToUInt16($b, 0)
                if ($y -gt 1900) { $lastRun = New-Object DateTime ([int]$y, [int][BitConverter]::ToUInt16($b, 2), [int][BitConverter]::ToUInt16($b, 6), [int][BitConverter]::ToUInt16($b, 8), [int][BitConverter]::ToUInt16($b, 10), [int][BitConverter]::ToUInt16($b, 12), [DateTimeKind]::Utc) }
            } catch { $lastRun = $null }
        }
        $letter = ''
        if ($sub -match '\{([0-9a-fA-F-]{36})\}') { $g = $Matches[1].ToLowerInvariant(); if ($volByGuid.ContainsKey($g)) { $letter = $volByGuid[$g] } }
        $pct = $vals['LastRunPercentFragmentation']
        $fragRows.Add([ordered]@{ Volume = $sub; Drive = $letter; PercentFragmentation = $pct; LastRunUtc = $lastRun; MFTSize = $vals['MFTSize']; HardwareIssue = $vals['HardwareIssue'] })
        if ($letter -eq $sysDrive -and $sysMedia -eq 'HDD' -and $null -ne $pct) {
            if ([int]$pct -gt 30) { Add-Finding -Severity Critical -Category 'Storage' -RuleId 'STO-FRAG' -Title ('System drive is {0} % fragmented' -f $pct) -Detail ('Last analysis {0}' -f (ConvertTo-InvariantString -Value $lastRun)) -Recommendation 'Run Optimize Drives (dfrgui) and make sure the ScheduledDefrag task is enabled.' }
            elseif ([int]$pct -gt 10) { Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-FRAG' -Title ('System drive is {0} % fragmented' -f $pct) -Detail ('Last analysis {0}' -f (ConvertTo-InvariantString -Value $lastRun)) -Recommendation 'Run Optimize Drives (dfrgui) and make sure the ScheduledDefrag task is enabled.' }
        }
        if ($null -ne $vals['HardwareIssue'] -and [int]$vals['HardwareIssue'] -ne 0) {
            Add-Finding -Severity Warning -Category 'Storage' -RuleId 'STO-FRAG-HW' -Title ('Optimize Drives reported a hardware issue on {0}' -f $(if ($letter -ne '') { $letter + ':' } else { $sub })) -Detail ('Dfrg statistics HardwareIssue={0}' -f $vals['HardwareIssue']) -Recommendation 'Check SMART and cables of that disk.'
        }
    }
    $sec['Fragmentation'] = $fragRows.ToArray()
    $defragTask = Invoke-Safely -Name 'Storage.ScheduledDefrag' -Default $null -Quiet -ScriptBlock {
        $t = Get-ScheduledTask -TaskPath '\Microsoft\Windows\Defrag\' -TaskName 'ScheduledDefrag' -ErrorAction Stop
        $i = $t | Get-ScheduledTaskInfo -ErrorAction Stop
        [ordered]@{ State = [string]$t.State; LastRunTime = $i.LastRunTime; LastTaskResult = $i.LastTaskResult; NextRunTime = $i.NextRunTime }
    }
    $sec['ScheduledDefrag'] = $defragTask
    if ($null -ne $defragTask) {
        $days = Get-WdInvDaysSince -Date $defragTask['LastRunTime']
        if ([string]$defragTask['State'] -eq 'Disabled' -or ($null -ne $days -and $days -gt 60)) {
            Add-Finding -Severity Info -Category 'Storage' -RuleId 'STO-DEFRAG-TASK' -Title 'Optimize Drives has not run recently or is disabled' -Detail ('State {0}, last run {1}' -f $defragTask['State'], (ConvertTo-InvariantString -Value $defragTask['LastRunTime'])) -Recommendation 'Open Optimize Drives (dfrgui) and turn on scheduled optimization (weekly). SSDs need it for TRIM/retrim too.'
        }
    }

    # BitLocker via Shell property (works non-admin)
    $blRows = New-Object 'System.Collections.Generic.List[object]'
    $blNames = @{ 0 = 'Unencryptable/Off'; 1 = 'On (unlocked)'; 2 = 'Off'; 3 = 'Encrypting'; 4 = 'Decrypting'; 5 = 'Suspended'; 6 = 'On (locked)'; 7 = 'Unknown'; 8 = 'Waiting for activation' }
    $blList = @(Invoke-Safely -Name 'Storage.BitLocker' -Default @() -ScriptBlock {
        $sh = New-Object -ComObject 'Shell.Application' -ErrorAction Stop
        $out = New-Object 'System.Collections.Generic.List[object]'
        foreach ($vr in $volRows) {
            $letter = [string]$vr['Drive']
            if ($letter -eq '') { continue }
            $code = $null
            try { $ns = $sh.NameSpace(($letter + ':\')); if ($null -ne $ns) { $code = $ns.Self.ExtendedProperty('System.Volume.BitLockerProtection') } } catch { $code = $null }
            $out.Add([ordered]@{ Drive = $letter; Code = $code })
        }
        $out.ToArray()
    })
    foreach ($b in $blList) {
        $code = $b['Code']
        $txt = 'n/a'
        if ($null -ne $code -and $blNames.ContainsKey([int]$code)) { $txt = $blNames[[int]$code] }
        $blRows.Add([ordered]@{ Drive = $b['Drive']; Code = $code; Status = $txt })
        if ($null -ne $code -and [int]$code -eq 3) {
            Add-Finding -Severity Info -Category 'Storage' -RuleId 'STO-BLENC' -Title ('BitLocker is encrypting drive {0}: in the background' -f $b['Drive']) -Detail 'System.Volume.BitLockerProtection=3' -Recommendation 'Disk performance returns when encryption finishes; keep the PC on AC power.'
        }
    }
    $sec['BitLocker'] = $blRows.ToArray()

    # Hibernation file on a desktop with little space
    $hib = Get-FileSizeSafe -Path ($sysDrive + ':\hiberfil.sys')
    if ($null -ne $hib -and $ctx['FormFactor'] -eq 'Desktop' -and $null -ne $ctx['SystemFreePercent'] -and [double]$ctx['SystemFreePercent'] -lt 10) {
        Add-Finding -Severity Info -Category 'Storage' -RuleId 'STO-HIBERFIL' -Title ('hiberfil.sys occupies {0} on a desktop with little free space' -f (Format-Bytes -Bytes $hib)) -Detail 'Hibernation/Fast Startup file on the system drive.' -Recommendation 'If hibernation is not used: "powercfg /h off" (administrator) frees that space.'
    }
    return $sec
}

# ---------------------------------------------------------------------------------------------
# 6. Devices & drivers
# ---------------------------------------------------------------------------------------------
function Get-WdInvDevices {
    [CmdletBinding()]
    param([switch]$Deep)
    $inv = Get-WdInv
    $sec = [ordered]@{}
    $problemNames = @{ 1 = 'Not configured (no driver)'; 3 = 'Driver corrupted'; 9 = 'Bad hardware id'; 10 = 'Device cannot start'; 12 = 'Not enough resources'; 14 = 'Restart required'; 18 = 'Reinstall driver'; 19 = 'Registry corrupted'; 21 = 'Being removed'; 22 = 'Disabled'; 24 = 'Not present'; 28 = 'No driver installed'; 29 = 'Disabled by firmware'; 31 = 'Driver failed to load'; 33 = 'Translator error'; 34 = 'Manual configuration'; 35 = 'Firmware missing resources'; 37 = 'Driver init failed'; 38 = 'Driver instance already loaded'; 39 = 'Driver missing/corrupt'; 40 = 'Service key invalid'; 43 = 'Reported problems (hardware failure)'; 45 = 'Not connected'; 47 = 'Safe removal pending'; 48 = 'Blocked driver'; 52 = 'Unsigned driver'; 53 = 'Reserved by debugger'; 54 = 'Failed power state transition' }
    $pnp = @(Get-CimSafe -ClassName Win32_PnPEntity -Filter 'ConfigManagerErrorCode<>0' -Property @('Name', 'ConfigManagerErrorCode', 'PNPClass', 'DeviceID', 'Present', 'Status', 'Manufacturer', 'Service'))
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $keyClasses = @('Display', 'Net', 'System', 'HDC', 'SCSIAdapter', 'DiskDrive', 'Processor', 'USB', 'MEDIA', 'Bluetooth')
    foreach ($d in $pnp) {
        if ($null -eq $d) { continue }
        $present = Get-WdInvPropertyValue -Object $d -Name 'Present' -Default $true
        if ($present -eq $false) { continue }
        $code = [int]$d.ConfigManagerErrorCode
        $codeText = [string]$code
        if ($problemNames.ContainsKey($code)) { $codeText = $problemNames[$code] }
        $cls = Get-WdInvString -Value $d.PNPClass
        $name = Get-WdInvString -Value $d.Name
        $rows.Add([pscustomobject][ordered]@{ Status = [string]$d.Status; Class = $cls; FriendlyName = $name; InstanceId = [string]$d.DeviceID; ProblemCode = $code; Problem = $codeText; Manufacturer = (Get-WdInvString -Value $d.Manufacturer); Service = (Get-WdInvString -Value $d.Service) })
        if ($code -in @(1, 28, 31, 39) -and ($keyClasses -contains $cls -or $cls -eq '')) {
            Add-Finding -Severity Warning -Category 'Devices' -RuleId 'DEV-NODRV' -Title ('Missing driver: {0}' -f $(if ($name -ne '') { $name } else { [string]$d.DeviceID })) -Detail ('Class {0}, problem code {1} ({2}), id {3}' -f $cls, $code, $codeText, [string]$d.DeviceID) `
                -Recommendation 'Install the driver from the PC/motherboard vendor site (the hardware id in Device Manager identifies the device). Missing chipset/storage/network drivers cost performance and battery life.'
        } elseif ($code -in @(10, 43, 3, 37, 38)) {
            Add-Finding -Severity Warning -Category 'Devices' -RuleId 'DEV-FAIL' -Title ('Device fails to start: {0} (code {1})' -f $(if ($name -ne '') { $name } else { [string]$d.DeviceID }), $code) -Detail ('Class {0}: {1}; id {2}' -f $cls, $codeText, [string]$d.DeviceID) `
                -Recommendation 'Update or reinstall the driver; if it persists the hardware (or its USB cable/port) is faulty. A failing device can also cause interrupt storms.'
        } elseif ($code -eq 22) {
            Add-Finding -Severity Info -Category 'Devices' -RuleId 'DEV-DISABLED' -Title ('Device is disabled: {0}' -f $name) -Detail ('Class {0}, id {1}' -f $cls, [string]$d.DeviceID) -Recommendation 'Fine if intentional; otherwise enable it in Device Manager.'
        } elseif ($code -eq 52) {
            Add-Finding -Severity Warning -Category 'Devices' -RuleId 'DEV-UNSIGNED' -Title ('Unsigned driver blocked for: {0}' -f $name) -Detail ('Code 52, id {0}' -f [string]$d.DeviceID) -Recommendation 'Install a signed driver from the vendor.'
        }
    }
    $sec['ProblemDevices'] = $rows.ToArray()
    $sec['ProblemDeviceCount'] = $rows.Count

    # Signed drivers
    $drv = @(Get-CimSafe -ClassName Win32_PnPSignedDriver -TimeoutSec 60 -Property @('DeviceClass', 'DeviceName', 'DriverVersion', 'DriverDate', 'DriverProviderName', 'IsSigned', 'InfName', 'Manufacturer', 'DeviceID'))
    $ageClasses = @('DISPLAY', 'NET', 'SCSIADAPTER', 'HDC', 'SYSTEM', 'DISKDRIVE', 'MEDIA', 'BLUETOOTH', 'USB', 'PROCESSOR')
    $drvRows = New-Object 'System.Collections.Generic.List[object]'
    $oldDrivers = New-Object 'System.Collections.Generic.List[string]'
    $seenOld = @{}
    foreach ($r in $drv) {
        if ($null -eq $r) { continue }
        $cls = (Get-WdInvString -Value $r.DeviceClass).ToUpperInvariant()
        $prov = Get-WdInvString -Value $r.DriverProviderName
        $isMs = ($prov -match '^Microsoft')
        if (-not $Deep -and ($isMs -or -not ($ageClasses -contains $cls))) { continue }
        $date = $null
        if ($null -ne $r.DriverDate) { try { $date = [DateTime]$r.DriverDate } catch { } }
        $ageYears = $null
        if ($null -ne $date) { $ageYears = Get-WdInvNum -Value (((Get-Date) - $date).TotalDays / 365.25) -Decimals 1 }
        $name = Get-WdInvString -Value $r.DeviceName
        $drvRows.Add([pscustomobject][ordered]@{ DeviceClass = $cls; DeviceName = $name; DriverVersion = (Get-WdInvString -Value $r.DriverVersion); DriverDate = $date; AgeYears = $ageYears; Provider = $prov; IsSigned = $r.IsSigned; InfName = (Get-WdInvString -Value $r.InfName); Manufacturer = (Get-WdInvString -Value $r.Manufacturer); DeviceID = (Get-WdInvString -Value $r.DeviceID) })
        if ($r.IsSigned -eq $false -and $name -ne '') {
            Add-Finding -Severity Warning -Category 'Devices' -RuleId 'DEV-UNSIGNED' -Title ('Unsigned driver: {0}' -f $name) -Detail ('Class {0}, provider {1}, inf {2}' -f $cls, $prov, [string]$r.InfName) -Recommendation 'Unsigned drivers are a stability and security risk; replace with a signed vendor driver.'
        }
        if (-not $isMs -and $null -ne $ageYears -and $ageYears -gt 4 -and $cls -in @('DISPLAY', 'NET', 'SCSIADAPTER', 'HDC') -and $name -ne '') {
            $k = $cls + '|' + $name
            if (-not $seenOld.ContainsKey($k)) { $seenOld[$k] = $true; $oldDrivers.Add(('{0}: {1} ({2}, {3})' -f $cls, $name, (Get-WdInvString -Value $r.DriverVersion), $date.ToString('yyyy-MM-dd', $inv))) }
        }
    }
    $sec['Drivers'] = @($drvRows.ToArray() | Sort-Object -Property DeviceClass, DeviceName)
    $sec['DriverCountTotal'] = $drv.Count
    $sec['DriverListMode'] = $(if ($Deep) { 'all drivers (-Deep)' } else { 'non-Microsoft drivers of key device classes' })
    if ($oldDrivers.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Devices' -RuleId 'DEV-OLD' -Title ('{0} vendor driver(s) for GPU/network/storage are older than 4 years' -f $oldDrivers.Count) -Detail (@($oldDrivers | Select-Object -First 8) -join '; ') `
            -Recommendation 'Update chipset, storage, network and GPU drivers from the PC or component vendor (not from "driver updater" tools).'
    }

    # USB devices (present)
    $usb = @(Get-CimSafe -ClassName Win32_PnPEntity -Filter "DeviceID LIKE 'USB\\%'" -Property @('Name', 'PNPClass', 'DeviceID', 'Status', 'ConfigManagerErrorCode', 'Present'))
    $usbRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($u in $usb) {
        if ($null -eq $u) { continue }
        if ((Get-WdInvPropertyValue -Object $u -Name 'Present' -Default $true) -eq $false) { continue }
        $usbRows.Add([ordered]@{ Class = (Get-WdInvString -Value $u.PNPClass); Name = (Get-WdInvString -Value $u.Name); Status = [string]$u.Status; ErrorCode = $u.ConfigManagerErrorCode; DeviceID = [string]$u.DeviceID })
    }
    $sec['UsbDevices'] = $usbRows.ToArray()

    # Kernel-PnP 219 (driver failed to load) 14 days
    $pnpEvents = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-PnP'; Id = 219; StartTime = (Get-Date).AddDays(-14) } -MaxEvents 5000)
    $byDevice = @{}
    foreach ($e in $pnpEvents) {
        $dev = [string](Get-WdInvEventProperty -Event $e -Index 1)
        if ($dev -eq '') { $dev = '(unknown)' }
        if (-not $byDevice.ContainsKey($dev)) { $byDevice[$dev] = 0 }
        $byDevice[$dev] = $byDevice[$dev] + 1
    }
    $sec['DriverLoadFailures14d'] = @($byDevice.Keys | ForEach-Object { [ordered]@{ Device = $_; Count = $byDevice[$_] } } | Sort-Object -Property @{ Expression = { $_['Count'] }; Descending = $true })
    foreach ($dev in $byDevice.Keys) {
        if ($byDevice[$dev] -ge 5) {
            Add-Finding -Severity Warning -Category 'Devices' -RuleId 'DEV-FAIL' -Title ('A driver failed to load {0} times in 14 days (event 219)' -f $byDevice[$dev]) -Detail ('Device: {0}' -f $dev) -Recommendation 'The driver of this device fails at every boot: reinstall it or remove the orphaned device (Device Manager > View > Show hidden devices).'
        }
    }
    return $sec
}

# ---------------------------------------------------------------------------------------------
# 7. Network
# ---------------------------------------------------------------------------------------------
function Get-WdInvNetwork {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$ProcessMap)
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}
    $statusNames = @{ 0 = 'Disconnected'; 1 = 'Connecting'; 2 = 'Connected'; 3 = 'Disconnecting'; 4 = 'Hardware not present'; 5 = 'Hardware disabled'; 6 = 'Hardware malfunction'; 7 = 'Media disconnected'; 8 = 'Authenticating'; 9 = 'Authentication succeeded'; 10 = 'Authentication failed'; 11 = 'Invalid address'; 12 = 'Credentials required' }

    # Adapters: CIM fast path + Get-NetAdapter for media type / virtual flag
    $na = @(Get-CimSafe -ClassName Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE' -Property @('Name', 'NetConnectionID', 'NetConnectionStatus', 'Speed', 'MACAddress', 'PNPDeviceID', 'InterfaceIndex', 'AdapterType'))
    $netAdapters = @(Invoke-Safely -Name 'Network.NetAdapter' -Default @() -Quiet -ScriptBlock { @(Get-NetAdapter -IncludeHidden -ErrorAction Stop) })
    $naByIndex = @{}
    foreach ($x in $netAdapters) { if ($null -ne $x) { $naByIndex[[int]$x.InterfaceIndex] = $x } }
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $virtualCount = 0
    $vpnNames = New-Object 'System.Collections.Generic.List[string]'
    # Third-party virtual adapters only: the exclusion list is applied to the description AND the name, and adapters
    # with a blank description (Teredo, IP-HTTPS, 6to4 pseudo-interfaces in state "Not Present") are not counted.
    $excludeRx = 'Microsoft|Hyper-V|WAN Miniport|Bluetooth|Loopback|Wi-Fi Direct|Kernel Debug|Teredo|ISATAP|6to4|IP-HTTPS|Npcap|Pseudo-Interface'
    foreach ($x in $netAdapters) {
        if ($null -eq $x -or $x.Virtual -ne $true) { continue }
        $desc = [string]$x.InterfaceDescription
        $nm = [string]$x.Name
        if ([string]::IsNullOrWhiteSpace($desc)) { continue }
        if ($desc -match $excludeRx -or $nm -match $excludeRx) { continue }
        $virtualCount++
        if (-not $vpnNames.Contains($desc)) { $vpnNames.Add($desc) }
    }
    foreach ($a in $na) {
        if ($null -eq $a) { continue }
        $st = [int](Get-WdInvPropertyValue -Object $a -Name 'NetConnectionStatus' -Default -1)
        $stText = [string]$st
        if ($statusNames.ContainsKey($st)) { $stText = $statusNames[$st] }
        $idx = [int](Get-WdInvPropertyValue -Object $a -Name 'InterfaceIndex' -Default -1)
        $rich = $null
        if ($naByIndex.ContainsKey($idx)) { $rich = $naByIndex[$idx] }
        $media = ''
        $physMedia = ''
        $rx = $null
        $tx = $null
        $drvVer = ''
        $drvDate = ''
        $drvProv = ''
        if ($null -ne $rich) {
            $media = [string]$rich.MediaType; $physMedia = [string]$rich.PhysicalMediaType; $rx = $rich.ReceiveLinkSpeed; $tx = $rich.TransmitLinkSpeed
            $drvVer = [string]$rich.DriverVersion; $drvDate = [string]$rich.DriverDate; $drvProv = [string]$rich.DriverProvider
        }
        $isWifi = ($physMedia -match '802\.11' -or [string]$a.Name -match 'Wi-?Fi|Wireless|802\.11|WLAN')
        $speed = $a.Speed
        $speedMbps = $null
        if ($null -ne $speed -and [int64]$speed -gt 0 -and [int64]$speed -lt 9000000000000) { $speedMbps = Get-WdInvNum -Value ([double]$speed / 1e6) -Decimals 0 }
        $rows.Add([ordered]@{
            Name = (Get-WdInvString -Value $a.NetConnectionID); Description = (Get-WdInvString -Value $a.Name); Status = $stText; SpeedMbps = $speedMbps
            ReceiveLinkSpeedMbps = $(if ($null -ne $rx) { Get-WdInvNum -Value ([double]$rx / 1e6) -Decimals 0 } else { $null })
            TransmitLinkSpeedMbps = $(if ($null -ne $tx) { Get-WdInvNum -Value ([double]$tx / 1e6) -Decimals 0 } else { $null })
            IsWiFi = $isWifi; MediaType = $media; PhysicalMediaType = $physMedia; MACAddress = [string]$a.MACAddress
            DriverVersion = $drvVer; DriverDate = $drvDate; DriverProvider = $drvProv; PNPDeviceID = [string]$a.PNPDeviceID
        })
        if ($st -eq 2 -and -not $isWifi -and $null -ne $speedMbps -and $speedMbps -le 100 -and ([string]$a.Name -match 'Gigabit|GbE|GBE|I2\d\d|I21\d|RTL8168|RTL8111|RTL8125|2\.5G|Killer E|AX\d{3}|Ethernet Connection')) {
            Add-Finding -Severity Warning -Category 'Network' -RuleId 'NET-LINK' -Title ('Wired adapter "{0}" is linked at {1} Mbps although it supports gigabit' -f $a.NetConnectionID, $speedMbps) -Detail ([string]$a.Name) -Recommendation 'Replace the network cable (a damaged pair forces 100/10 Mbps) or try another switch/router port. This makes "the internet" slow, not the PC.'
        }
        if ($st -eq 2 -and $isWifi -and $null -ne $rx -and ([double]$rx / 1e6) -lt 50) {
            Add-Finding -Severity Info -Category 'Network' -RuleId 'NET-WIFI' -Title ('Wi-Fi link speed is only {0} Mbps' -f (Format-WdInvNum ([double]$rx / 1e6) 0)) -Detail ([string]$a.Name) -Recommendation 'Weak Wi-Fi (distance, 2.4 GHz band, interference) feels like a slow PC when browsing. Move closer to the router or use 5 GHz / a cable.'
        }
    }
    $sec['Adapters'] = $rows.ToArray()
    $sec['VirtualAdapterCount'] = $virtualCount
    $sec['ThirdPartyVirtualAdapters'] = $vpnNames.ToArray()
    if ($virtualCount -gt 3) {
        Add-Finding -Severity Info -Category 'Network' -RuleId 'NET-VPNS' -Title ('{0} third-party virtual network adapters (VPN/TAP) installed' -f $virtualCount) -Detail (@($vpnNames.ToArray() | Select-Object -First 8) -join '; ') -Recommendation 'Uninstall VPN clients that are no longer used; leftover filter drivers slow down networking.'
    }

    # IP configuration
    $cfgs = @(Get-CimSafe -ClassName Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=TRUE' -Property @('Description', 'IPAddress', 'DefaultIPGateway', 'DNSServerSearchOrder', 'DHCPEnabled', 'DHCPServer', 'MACAddress', 'DNSDomainSuffixSearchOrder', 'InterfaceIndex'))
    $cfgRows = New-Object 'System.Collections.Generic.List[object]'
    $gateways = New-Object 'System.Collections.Generic.List[string]'
    $dnsServers = New-Object 'System.Collections.Generic.List[string]'
    $dhcpServers = New-Object 'System.Collections.Generic.List[string]'
    foreach ($c in $cfgs) {
        if ($null -eq $c) { continue }
        $gw = @($c.DefaultIPGateway | ForEach-Object { [string]$_ })
        $dns = @($c.DNSServerSearchOrder | ForEach-Object { [string]$_ })
        # 0.0.0.0 / :: are placeholders reported by VPN and tunnel adapters, not gateways (same rule as the route loop below).
        foreach ($g in $gw) { if ($g -ne '' -and $g -ne '0.0.0.0' -and $g -ne '::' -and -not $gateways.Contains($g)) { $gateways.Add($g) } }
        foreach ($d in $dns) { if ($d -ne '' -and -not $dnsServers.Contains($d)) { $dnsServers.Add($d) } }
        if (-not [string]::IsNullOrEmpty([string]$c.DHCPServer)) { $dhcpServers.Add([string]$c.DHCPServer) }
        $cfgRows.Add([ordered]@{ Description = [string]$c.Description; IPAddresses = (@($c.IPAddress) -join ';'); Gateways = ($gw -join ';'); DnsServers = ($dns -join ';'); DHCPEnabled = $c.DHCPEnabled; DHCPServer = [string]$c.DHCPServer; MACAddress = [string]$c.MACAddress; DnsSuffixes = (@($c.DNSDomainSuffixSearchOrder) -join ';') })
    }
    $sec['IpConfiguration'] = $cfgRows.ToArray()
    $routes = @(Invoke-Safely -Name 'Network.DefaultRoutes' -Default @() -Quiet -ScriptBlock { @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop | ForEach-Object { [ordered]@{ Interface = [string]$_.InterfaceAlias; NextHop = [string]$_.NextHop; RouteMetric = $_.RouteMetric; InterfaceMetric = $_.InterfaceMetric } }) })
    $sec['DefaultRoutes'] = $routes
    foreach ($r in $routes) { $nh = [string]$r['NextHop']; if ($nh -ne '' -and $nh -ne '0.0.0.0' -and $nh -ne '::' -and -not $gateways.Contains($nh)) { $gateways.Add($nh) } }
    $profiles = @(Invoke-Safely -Name 'Network.ConnectionProfile' -Default @() -Quiet -ScriptBlock { @(Get-NetConnectionProfile -ErrorAction Stop | ForEach-Object { [ordered]@{ Name = [string]$_.Name; Interface = [string]$_.InterfaceAlias; Category = [string]$_.NetworkCategory; IPv4Connectivity = [string]$_.IPv4Connectivity; IPv6Connectivity = [string]$_.IPv6Connectivity } }) })
    $sec['ConnectionProfiles'] = $profiles
    if ($gateways.Count -eq 0 -and $cfgRows.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Network' -RuleId 'NET-NOGW' -Title 'No default gateway configured' -Detail 'No adapter has a default gateway; the PC is offline or on an isolated network.' -Recommendation 'Not a PC slowness cause; check the router/DHCP if internet is expected.'
    }

    # DNS trust check
    $trusted = @($script:Rules['TrustedDnsServers'] | ForEach-Object { [string]$_ })
    $privRegex = [string]$script:Rules['PrivateIpRegex']
    $untrusted = New-Object 'System.Collections.Generic.List[string]'
    foreach ($d in $dnsServers) {
        $ok = ($trusted -contains $d) -or ($gateways.Contains($d)) -or ($dhcpServers.Contains($d)) -or ($d -match $privRegex) -or ($d -match '^fe[89ab]|^f[cd]|^::1$|^127\.')
        if (-not $ok) { $untrusted.Add($d) }
    }
    $sec['Dns'] = [ordered]@{ Servers = $dnsServers.ToArray(); Gateways = $gateways.ToArray(); Untrusted = $untrusted.ToArray() }
    if ($untrusted.Count -gt 0) {
        $sev = 'Warning'
        if ($ctx['IsDomainJoined']) { $sev = 'Info' }
        Add-Finding -Severity $sev -Category 'Network' -RuleId 'NET-DNS' -Title ('DNS server not in the known-public/gateway list: {0}' -f ($untrusted.ToArray() -join ', ')) -Detail ('Gateways: {0}; DNS: {1}' -f ($gateways.ToArray() -join ', '), ($dnsServers.ToArray() -join ', ')) `
            -Recommendation 'Unknown DNS servers can mean a DNS hijack (adware/malware) or a leftover VPN/filter. Set DNS to automatic (DHCP) or to a known resolver (1.1.1.1, 8.8.8.8) unless this is the provider of a corporate network.'
    }

    # Proxy
    $is = Get-WdInvRegistryValues -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    $isPol = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings'
    $proxyEnable = $is['ProxyEnable']
    $proxyServer = Get-WdInvString -Value $is['ProxyServer']
    $pac = Get-WdInvString -Value $is['AutoConfigURL']
    $winHttp = $null
    $wh = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections' -Name 'WinHttpSettings'
    if ($null -ne $wh -and $wh -is [byte[]] -and $wh.Length -gt 12) {
        try { $txt = [Text.Encoding]::ASCII.GetString($wh); $m = [regex]::Match($txt, '[\w\.-]+:\d{2,5}'); if ($m.Success) { $winHttp = $m.Value } } catch { }
    }
    $sec['Proxy'] = [ordered]@{ ProxyEnable = $proxyEnable; ProxyServer = $proxyServer; ProxyOverride = (Get-WdInvString -Value $is['ProxyOverride']); AutoConfigURL = $pac; PolicyProxySettingsPerUser = $isPol['ProxySettingsPerUser']; WinHttpProxy = $winHttp }
    if (($null -ne $proxyEnable -and [int]$proxyEnable -eq 1 -and $proxyServer -ne '') -or $pac -ne '') {
        $sev = 'Warning'
        if ($ctx['IsDomainJoined']) { $sev = 'Info' }
        Add-Finding -Severity $sev -Category 'Network' -RuleId 'NET-PROXY' -Title 'A proxy server or PAC script is configured' -Detail ('ProxyEnable={0}, ProxyServer={1}, AutoConfigURL={2}' -f $proxyEnable, $proxyServer, $pac) `
            -Recommendation 'On a home PC this is usually adware, a leftover VPN/"internet accelerator" or a filtering tool, and makes browsing slow or impossible. Settings > Network > Proxy: turn it off unless intentional.'
    }

    # hosts file
    $hostsPath = [IO.Path]::Combine([string]$env:SystemRoot, 'System32\drivers\etc\hosts')
    $hostsActive = New-Object 'System.Collections.Generic.List[string]'
    $hostsHijack = New-Object 'System.Collections.Generic.List[string]'     # security/update infrastructure, or any vendor host redirected to a real IP
    $hostsVendorBlock = New-Object 'System.Collections.Generic.List[string]' # broad vendor/telemetry domains pointed at a block address (0.0.0.0, 127.0.0.1, ::1)
    if (Test-FileExists -Path $hostsPath) {
        $lines = @(Invoke-Safely -Name 'Network.HostsFile' -Default @() -ScriptBlock { @([IO.File]::ReadAllLines($hostsPath)) })
        # Two tiers: blocking antivirus / Windows Update / connectivity-test / banking hosts is what malware does (Critical);
        # blocking broad vendor domains (telemetry.microsoft.com, adservice.google.com ...) at 0.0.0.0 is what
        # StevenBlack/MVPS-style ad and telemetry block lists do (Warning, Info for a large list).
        $criticalRegex = 'windowsupdate|update\.microsoft|msftconnecttest|defender|kaspersky|eset\.|avast|avg\.com|bitdefender|malwarebytes|drweb|norton|mcafee|sophos|virustotal|sberbank|paypal|delivery\.mp\.microsoft|download\.windowsupdate|ctldl\.windowsupdate|wdcp\.microsoft|smartscreen'
        $vendorRegex = 'microsoft\.com|windows\.com|live\.com|google\.com|googleapis|yandex\.|bing\.com|mail\.ru|apple\.com|icloud|steampowered|nvidia\.com|amd\.com|intel\.com|adobe\.com'
        foreach ($l in $lines) {
            if ($null -eq $l) { continue }
            $t = $l.Trim()
            if ($t -eq '' -or $t.StartsWith('#')) { continue }
            $hostsActive.Add($t)
            $partsLine = @($t -split '\s+')
            if ($partsLine.Count -ge 2) {
                $ip = $partsLine[0]
                $isBlockIp = ($ip -match '^(0\.0\.0\.0|127\.0\.0\.1|::1|0:0:0:0:0:0:0:1|::)$')
                for ($i = 1; $i -lt $partsLine.Count; $i++) {
                    $h = $partsLine[$i]
                    if ($h.StartsWith('#')) { break }
                    if ($h -match $criticalRegex) { $hostsHijack.Add(('{0} -> {1}' -f $h, $ip)) }
                    elseif ($h -match $vendorRegex) {
                        if ($isBlockIp) { $hostsVendorBlock.Add(('{0} -> {1}' -f $h, $ip)) } else { $hostsHijack.Add(('{0} -> {1}' -f $h, $ip)) }
                    }
                }
            }
        }
    }
    $sec['Hosts'] = [ordered]@{ Path = $hostsPath; ActiveEntries = $hostsActive.Count; Entries = @($hostsActive.ToArray() | Select-Object -First 200); SuspiciousEntries = $hostsHijack.ToArray(); VendorBlockEntries = $hostsVendorBlock.ToArray() }
    if ($hostsHijack.Count -gt 0) {
        Add-Finding -Severity Critical -Category 'Network' -RuleId 'NET-HOSTS' -Title ('The hosts file redirects or blocks {0} security/update/bank domain(s)' -f $hostsHijack.Count) -Detail (@($hostsHijack.ToArray() | Select-Object -First 10) -join '; ') `
            -Recommendation 'Malware blocks antivirus/Windows Update sites this way, or redirects vendor sites to a fake server. Restore the default hosts file (C:\Windows\System32\drivers\etc\hosts) and run a full scan.'
    } elseif ($hostsVendorBlock.Count -gt 0) {
        $sev = 'Warning'
        if ($hostsActive.Count -gt 20) { $sev = 'Info' }
        Add-Finding -Severity $sev -Category 'Network' -RuleId 'NET-HOSTS' -Title ('The hosts file blocks {0} vendor/telemetry domain(s)' -f $hostsVendorBlock.Count) -Detail (@($hostsVendorBlock.ToArray() | Select-Object -First 10) -join '; ') `
            -Recommendation 'Entries pointing Microsoft/Google/Adobe/Apple hosts at 0.0.0.0 are usually an ad/telemetry block list (O&O ShutUp10, StevenBlack, MVPS) or an activation blocker. Verify it was intentional; such lists can also break Windows Update, Store and licensing.'
    }
    if ($hostsActive.Count -gt 20) {
        Add-Finding -Severity Info -Category 'Network' -RuleId 'NET-HOSTS-MANY' -Title ('The hosts file has {0} active entries' -f $hostsActive.Count) -Detail 'Large hosts files (ad-block lists) slow down name resolution slightly and can break sites.' -Recommendation 'Review the file; prefer a browser ad-blocker.'
    }

    # Adapter statistics / errors
    $stats = @(Invoke-Safely -Name 'Network.AdapterStatistics' -Default @() -Quiet -ScriptBlock { @(Get-NetAdapterStatistics -ErrorAction Stop) })
    $statRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($s in $stats) {
        if ($null -eq $s -or [int64](Get-WdInvPropertyValue -Object $s -Name 'ReceivedBytes' -Default 0) -le 0) { continue }
        $rxPk = [double](Get-WdInvPropertyValue -Object $s -Name 'ReceivedUnicastPackets' -Default 0) + [double](Get-WdInvPropertyValue -Object $s -Name 'ReceivedBroadcastPackets' -Default 0) + [double](Get-WdInvPropertyValue -Object $s -Name 'ReceivedMulticastPackets' -Default 0)
        $rxErr = [double](Get-WdInvPropertyValue -Object $s -Name 'ReceivedPacketErrors' -Default 0)
        $errPct = $null
        if ($rxPk -gt 0) { $errPct = Get-WdInvNum -Value ($rxErr / $rxPk * 100) -Decimals 3 }
        $statRows.Add([ordered]@{ Name = [string]$s.Name; ReceivedBytes = $s.ReceivedBytes; ReceivedText = (Format-Bytes -Bytes $s.ReceivedBytes); SentBytes = $s.SentBytes; SentText = (Format-Bytes -Bytes $s.SentBytes); ReceivedDiscarded = $s.ReceivedDiscardedPackets; ReceivedErrors = $s.ReceivedPacketErrors; OutboundDiscarded = $s.OutboundDiscardedPackets; OutboundErrors = $s.OutboundPacketErrors; ReceiveErrorPercent = $errPct })
        if ($null -ne $errPct -and $errPct -gt 0.1 -and $rxPk -gt 10000) {
            Add-Finding -Severity Warning -Category 'Network' -RuleId 'NET-ERR' -Title ('Adapter "{0}" has {1} % receive errors' -f $s.Name, (Format-WdInvNum $errPct 2)) -Detail ('{0} errors of {1} packets since boot' -f $rxErr, $rxPk) -Recommendation 'Bad cable, port or driver; replace the cable and update the network driver.'
        }
    }
    $sec['AdapterStatistics'] = $statRows.ToArray()

    # Established connections per process
    $conns = @(Invoke-Safely -Name 'Network.TcpConnections' -Default @() -Quiet -ScriptBlock { @(Get-NetTCPConnection -State Established -ErrorAction Stop) })
    $poolPorts = @($script:Rules['PoolPorts'] | ForEach-Object { [int]$_ })
    $byProc = @{}
    foreach ($cn in $conns) {
        if ($null -eq $cn) { continue }
        $remote = [string]$cn.RemoteAddress
        if ($remote -match $privRegex -or $remote -match '^(::1|fe80|::ffff:127\.|0\.0\.0\.0)') { continue }
        $procId = [int]$cn.OwningProcess
        if (-not $byProc.ContainsKey($procId)) { $byProc[$procId] = @{ Count = 0; Ports = New-Object 'System.Collections.Generic.List[int]'; Remotes = New-Object 'System.Collections.Generic.List[string]' } }
        $byProc[$procId]['Count'] = $byProc[$procId]['Count'] + 1
        $port = [int]$cn.RemotePort
        if (-not $byProc[$procId]['Ports'].Contains($port)) { $byProc[$procId]['Ports'].Add($port) }
        $rp = '{0}:{1}' -f $remote, $port
        if ($byProc[$procId]['Remotes'].Count -lt 8 -and -not $byProc[$procId]['Remotes'].Contains($rp)) { $byProc[$procId]['Remotes'].Add($rp) }
    }
    $connRows = New-Object 'System.Collections.Generic.List[object]'
    $suspRegex = [string]$script:Rules['SuspiciousPathRegex']
    foreach ($procId in $byProc.Keys) {
        $d = $byProc[$procId]
        $pName = ''
        $pPath = ''
        if ($ProcessMap.ContainsKey($procId)) { $pName = [string]$ProcessMap[$procId].Name; $pPath = [string]$ProcessMap[$procId].ExecutablePath }
        $pool = @($d['Ports'].ToArray() | Where-Object { $poolPorts -contains $_ })
        $loc = Get-ProcessLocationClass -Path $pPath
        $suspPath = ($pPath -ne '' -and $pPath -match $suspRegex)
        $flags = @()
        if ($pool.Count -gt 0) { $flags += 'PoolPort' }
        if ($suspPath) {
            $flags += 'SuspiciousPath'
            # Signed binaries of known vendors in AppData (Spotify, Telegram, Discord, Zoom...) are normal.
            $sig = Get-WdInvSignatureInfo -Path $pPath
            if ($sig['Trusted']) { $flags += 'SignedTrusted'; $suspPath = $false }
            elseif ($sig['Status'] -eq 'Valid') { $flags += 'Signed' }
        }
        $connRows.Add([pscustomobject][ordered]@{ Pid = $procId; Process = $pName; Path = $pPath; LocationClass = $loc; Connections = $d['Count']; Ports = (@($d['Ports'].ToArray() | Sort-Object) -join ','); Remotes = ($d['Remotes'].ToArray() -join ' '); Flags = ($flags -join ';') })
        if ($pool.Count -gt 0 -or $suspPath) {
            $sev = 'Warning'
            if ($pool.Count -gt 0 -and $suspPath) { $sev = 'Critical' }
            $why = @()
            if ($pool.Count -gt 0) { $why += ('remote port(s) {0} are typical mining-pool ports' -f ($pool -join ',')) }
            if ($suspPath) { $why += ('the executable runs from a suspicious location ({0})' -f $loc) }
            Add-Finding -Severity $sev -Category 'Network' -RuleId 'NET-POOL' -Title ('Suspicious outbound connection from "{0}" (PID {1})' -f $(if ($pName -ne '') { $pName } else { 'unknown process' }), $procId) `
                -Detail (($why -join '; ') + ('; remotes: {0}; path: {1}' -f ($d['Remotes'].ToArray() -join ' '), $(if ($pPath -ne '') { $pPath } else { 'n/a' }))) `
                -Recommendation 'Possible crypto-miner or backdoor traffic. Check the process in Task Manager, its signature and autostart entries; kill it, remove persistence and run a full scan.'
        } elseif ($d['Count'] -gt 20 -and $pName -eq '') {
            Add-Finding -Severity Info -Category 'Network' -RuleId 'NET-MANYCONN' -Title ('Unknown process PID {0} has {1} external connections' -f $procId, $d['Count']) -Detail ('Remotes: {0}' -f ($d['Remotes'].ToArray() -join ' ')) -Recommendation 'Re-run as administrator to see the process name and path.'
        }
    }
    $sec['ExternalConnections'] = @($connRows.ToArray() | Sort-Object -Property @{ Expression = 'Connections'; Descending = $true })
    $sec['ExternalConnectionTotal'] = $conns.Count
    return $sec
}

# ---------------------------------------------------------------------------------------------
# 8. Battery / laptop
# ---------------------------------------------------------------------------------------------
function Get-WdInvBattery {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$OutDir)
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}
    $bats = @(Get-CimSafe -ClassName Win32_Battery)
    $isLaptop = [bool]$ctx['IsLaptop']
    $sec['BatteryPresent'] = ($bats.Count -gt 0)
    if ($bats.Count -eq 0 -and -not $isLaptop) {
        $sec['Note'] = 'No battery and no laptop chassis: section skipped.'
        return $sec
    }
    $statusNames = @{ 1 = 'Discharging'; 2 = 'On AC'; 3 = 'Fully charged'; 4 = 'Low'; 5 = 'Critical'; 6 = 'Charging'; 7 = 'Charging (high)'; 8 = 'Charging (low)'; 9 = 'Charging (critical)'; 10 = 'Undefined'; 11 = 'Partially charged' }
    $batRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($b in $bats) {
        $st = [int](Get-WdInvPropertyValue -Object $b -Name 'BatteryStatus' -Default 0)
        $stText = [string]$st
        if ($statusNames.ContainsKey($st)) { $stText = $statusNames[$st] }
        $rt = $b.EstimatedRunTime
        if ($null -ne $rt -and [int64]$rt -ge 71582788) { $rt = $null }
        $batRows.Add([ordered]@{ Name = (Get-WdInvString -Value $b.Name); DeviceID = (Get-WdInvString -Value $b.DeviceID); Status = $stText; ChargePercent = $b.EstimatedChargeRemaining; EstimatedRunTimeMinutes = $rt; DesignVoltage = $b.DesignVoltage; Chemistry = $b.Chemistry })
    }
    $sec['Batteries'] = $batRows.ToArray()
    if ($bats.Count -eq 0 -and $isLaptop) {
        Add-Finding -Severity Info -Category 'Battery' -RuleId 'BAT-MISSING' -Title 'Laptop without a detected battery' -Detail 'Win32_Battery returned nothing on a mobile chassis.' -Recommendation 'Battery removed or dead; some laptops throttle the CPU when no battery can buffer peak current.'
    }
    $power = Invoke-Safely -Name 'Battery.PowerStatus' -Default $null -ScriptBlock {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $ps = [System.Windows.Forms.SystemInformation]::PowerStatus
        [ordered]@{ PowerLineStatus = [string]$ps.PowerLineStatus; BatteryChargeStatus = [string]$ps.BatteryChargeStatus; BatteryLifePercent = (Get-WdInvNum -Value ([double]$ps.BatteryLifePercent * 100) -Decimals 0) }
    }
    $sec['PowerStatus'] = $power
    $onBattery = ($null -ne $power -and [string]$power['PowerLineStatus'] -eq 'Offline')
    $ctx['OnBattery'] = $onBattery
    $full = @(Get-CimSafe -Namespace 'root/wmi' -ClassName BatteryFullChargedCapacity)
    $bstat = @(Get-CimSafe -Namespace 'root/wmi' -ClassName BatteryStatus)
    $cycles = @(Get-CimSafe -Namespace 'root/wmi' -ClassName BatteryCycleCount)
    $sec['Live'] = [ordered]@{
        FullChargedCapacity_mWh = $(if ($full.Count -gt 0) { $full[0].FullChargedCapacity } else { $null })
        RemainingCapacity_mWh = $(if ($bstat.Count -gt 0) { $bstat[0].RemainingCapacity } else { $null })
        ChargeRate_mW = $(if ($bstat.Count -gt 0) { $bstat[0].ChargeRate } else { $null })
        DischargeRate_mW = $(if ($bstat.Count -gt 0) { $bstat[0].DischargeRate } else { $null })
        Voltage_mV = $(if ($bstat.Count -gt 0) { $bstat[0].Voltage } else { $null })
        PowerOnline = $(if ($bstat.Count -gt 0) { $bstat[0].PowerOnline } else { $null })
        CycleCount = $(if ($cycles.Count -gt 0) { $cycles[0].CycleCount } else { $null })
    }
    # powercfg battery report as XML (locale independent). It writes only into the report folder.
    $reportPath = [IO.Path]::Combine($OutDir, 'battery-report.xml')
    $report = Invoke-Safely -Name 'Battery.PowercfgReport' -Default $null -ScriptBlock {
        # Invoke-Safely runs with $ErrorActionPreference = 'Stop': with stderr redirected, the first stderr line of a
        # native command would become a terminating NativeCommandError and abort the block, so reset it here.
        $ErrorActionPreference = 'Continue'
        $null = & powercfg.exe /batteryreport /output $reportPath /xml 2>&1
        $ErrorActionPreference = 'Stop'
        if (-not (Test-FileExists -Path $reportPath)) { throw 'powercfg did not write the XML report' }
        $x = New-Object System.Xml.XmlDocument
        $x.Load($reportPath)
        $ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
        $ns.AddNamespace('b', 'http://schemas.microsoft.com/battery/2012')
        $out = New-Object 'System.Collections.Generic.List[object]'
        foreach ($bat in @($x.SelectNodes('//b:Batteries/b:Battery', $ns))) {
            if ($null -eq $bat) { continue }
            $get = { param($n) $node = $bat.SelectSingleNode('b:' + $n, $ns); if ($null -ne $node) { $node.InnerText } else { $null } }
            $design = $null
            $fullCap = $null
            try { $design = [int64](& $get 'DesignCapacity') } catch { }
            try { $fullCap = [int64](& $get 'FullChargeCapacity') } catch { }
            $health = $null
            if ($null -ne $design -and $design -gt 0 -and $null -ne $fullCap) { $health = Get-WdInvNum -Value ([double]$fullCap / [double]$design * 100) -Decimals 1 }
            $out.Add([ordered]@{ Id = (& $get 'Id'); Manufacturer = (& $get 'Manufacturer'); SerialNumber = (& $get 'SerialNumber'); Chemistry = (& $get 'Chemistry'); DesignCapacity_mWh = $design; FullChargeCapacity_mWh = $fullCap; HealthPercent = $health; CycleCount = (& $get 'CycleCount') })
        }
        $out.ToArray()
    }
    $sec['Report'] = @($report)
    $sec['ReportFile'] = $(if (Test-FileExists -Path $reportPath) { 'battery-report.xml' } else { '' })
    foreach ($r in @($report)) {
        if ($null -eq $r) { continue }
        $h = $r['HealthPercent']
        if ($null -eq $h) { continue }
        if ([double]$h -lt 50) {
            Add-Finding -Severity Warning -Category 'Battery' -RuleId 'BAT-WORN' -Title ('Battery health is {0} % of design capacity' -f (Format-WdInvNum $h 0)) -Detail ('Design {0} mWh, full charge {1} mWh, cycles {2}' -f $r['DesignCapacity_mWh'], $r['FullChargeCapacity_mWh'], $r['CycleCount']) `
                -Recommendation 'Replace the battery. A worn battery cannot supply peak current, and many laptops throttle the CPU hard when that happens (even on AC).'
        } elseif ([double]$h -lt 80) {
            Add-Finding -Severity Info -Category 'Battery' -RuleId 'BAT-WORN-INFO' -Title ('Battery health is {0} %' -f (Format-WdInvNum $h 0)) -Detail ('Design {0} mWh, full charge {1} mWh, cycles {2}' -f $r['DesignCapacity_mWh'], $r['FullChargeCapacity_mWh'], $r['CycleCount']) -Recommendation 'Normal wear; plan a replacement below 50-60 %.'
        }
    }
    $plan = $ctx['PowerPlan']
    if ($onBattery) {
        $overlay = ''
        if ($null -ne $plan) { $overlay = [string]$plan['DcOverlay'] }
        Add-Finding -Severity Info -Category 'Battery' -RuleId 'BAT-DC' -Title 'The scan ran on battery power' -Detail ('Power mode on battery: {0}' -f $(if ($overlay -ne '') { $overlay } else { 'default' })) -Recommendation 'Windows limits CPU/GPU performance on battery (especially with "Best power efficiency"). Judge performance while plugged in.'
    }
    return $sec
}


# ---------------------------------------------------------------------------------------------
# 9. Software
# ---------------------------------------------------------------------------------------------
function Get-WdInvSoftware {
    [CmdletBinding()]
    param()
    $inv = Get-WdInv
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}
    $hives = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Hive = 'HKLM' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'; Hive = 'HKLM-x86' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'; Hive = 'HKCU' }
    )
    $programs = New-Object 'System.Collections.Generic.List[object]'
    $seen = @{}
    foreach ($h in $hives) {
        foreach ($sub in @(Get-WdInvRegistrySubKeyNames -Path $h.Path)) {
            $vals = Get-WdInvRegistryValues -Path ($h.Path + '\' + $sub)
            $name = Get-WdInvString -Value $vals['DisplayName']
            if ($name -eq '') { continue }
            if ($null -ne $vals['SystemComponent'] -and [int]$vals['SystemComponent'] -eq 1) { continue }
            if (-not [string]::IsNullOrEmpty([string]$vals['ParentKeyName'])) { continue }
            $ver = Get-WdInvString -Value $vals['DisplayVersion']
            $key = ($name + '|' + $ver).ToLowerInvariant()
            if ($seen.ContainsKey($key)) { continue }
            $seen[$key] = $true
            $instDate = $null
            $rawDate = Get-WdInvString -Value $vals['InstallDate']
            if ($rawDate -ne '') {
                $d = [DateTime]::MinValue
                if ([DateTime]::TryParseExact($rawDate, 'yyyyMMdd', $inv, [Globalization.DateTimeStyles]::None, [ref]$d)) { $instDate = $d }
            }
            $sizeKB = $null
            if ($null -ne $vals['EstimatedSize']) { try { $sizeKB = [int64]$vals['EstimatedSize'] } catch { } }
            $programs.Add([pscustomobject][ordered]@{
                DisplayName = $name; DisplayVersion = $ver; Publisher = (Get-WdInvString -Value $vals['Publisher']); InstallDate = $instDate
                EstimatedSizeMB = $(if ($null -ne $sizeKB) { Get-WdInvNum -Value ($sizeKB / 1024) -Decimals 1 } else { $null })
                InstallLocation = (Get-WdInvString -Value $vals['InstallLocation']); UninstallString = (Hide-WdSecret -Text (Get-WdInvString -Value $vals['UninstallString'])); Hive = $h.Hive; KeyName = $sub
            })
        }
    }
    $sorted = @($programs.ToArray() | Sort-Object -Property DisplayName)
    $sec['InstalledPrograms'] = $sorted
    $sec['InstalledProgramCount'] = $sorted.Count
    $pupRegex = [string]$script:Rules['PupNameRegex']
    $pupInfoRegex = [string]$script:Rules['PupInfoOnlyRegex']
    $recent = New-Object 'System.Collections.Generic.List[string]'
    $avNames = New-Object 'System.Collections.Generic.List[string]'
    foreach ($p in $sorted) {
        if ($p.DisplayName -match $pupRegex) {
            $sev = 'Warning'
            if ($p.DisplayName -match $pupInfoRegex) { $sev = 'Info' }
            Add-Finding -Severity $sev -Category 'Software' -RuleId 'SW-PUP' -Title ('Potentially unwanted program installed: {0}' -f $p.DisplayName) -Detail ('Version {0}, publisher {1}, installed {2}' -f $p.DisplayVersion, $p.Publisher, (ConvertTo-InvariantString -Value $p.InstallDate)) `
                -Recommendation '"Optimizers", "driver updaters", "cleaners" and toolbars slow the PC down, nag with pop-ups and bundle adware. Uninstall it (Settings > Apps) and run a Defender scan.'
        }
        if ($null -ne $p.InstallDate -and ((Get-Date) - $p.InstallDate).TotalDays -le 30) { $recent.Add(('{0} ({1})' -f $p.DisplayName, $p.InstallDate.ToString('yyyy-MM-dd', $inv))) }
        if ($p.DisplayName -match 'Kaspersky|ESET|Avast|AVG |AVG$|Bitdefender|Norton|McAfee|Malwarebytes|Dr\.Web|360 Total|Sophos|Panda|Avira|Comodo|Webroot|F-Secure|Trend Micro' -and $p.DisplayName -notmatch 'VPN|Password|Cleanup|Browser|Secure Connection|Driver Updater') { $avNames.Add($p.DisplayName) }
    }
    $sec['RecentInstalls30d'] = $recent.ToArray()
    $sec['AntivirusSuitesInstalled'] = $avNames.ToArray()
    $ctx['InstalledAvNames'] = $avNames.ToArray()
    if ($recent.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Software' -RuleId 'SW-RECENT' -Title ('{0} program(s) installed in the last 30 days' -f $recent.Count) -Detail (@($recent.ToArray() | Select-Object -First 15) -join '; ') -Recommendation 'Correlate with when the slowness began; uninstall what is not needed.'
    }

    # Store apps (current user)
    $appx = @(Invoke-Safely -Name 'Software.Appx' -Default @() -Quiet -ScriptBlock { @(Get-AppxPackage -ErrorAction Stop | Where-Object { -not $_.IsFramework }) })
    $sideloaded = New-Object 'System.Collections.Generic.List[string]'
    foreach ($a in $appx) {
        $kind = [string]$a.SignatureKind
        if ($kind -in @('None', 'Developer') -and [string]$a.Publisher -notmatch 'Microsoft Corporation|Microsoft Windows') { $sideloaded.Add(('{0} {1} ({2})' -f $a.Name, $a.Version, $kind)) }
    }
    $sec['StoreApps'] = [ordered]@{ Count = $appx.Count; Sideloaded = $sideloaded.ToArray(); Scope = $(if ($script:IsAdmin) { 'current user' } else { 'current user (all users requires administrator)' }) }
    if (-not $script:IsAdmin) { [void](Add-WdInvAdminGap -Item 'Store apps of other user accounts (Get-AppxPackage -AllUsers)') }
    if ($sideloaded.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Software' -RuleId 'SW-SIDELOAD' -Title ('{0} Store-format app(s) installed outside the Store (side-loaded)' -f $sideloaded.Count) -Detail (@($sideloaded.ToArray() | Select-Object -First 12) -join '; ') -Recommendation 'Normal for apps installed with their own MSIX installer (browsers, vendor tools) and for developers; check where unknown ones came from.'
    }
    if ($appx.Count -gt 300) {
        Add-Finding -Severity Info -Category 'Software' -RuleId 'SW-APPX-MANY' -Title ('{0} Store apps installed for this user' -f $appx.Count) -Detail '' -Recommendation 'Many Store apps run background tasks; uninstall unused ones.'
    }

    # .NET
    $rel = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name 'Release'
    $netFx = 'n/a'
    if ($null -ne $rel) {
        $r = [int]$rel
        $netFx = if ($r -ge 533320) { '4.8.1' } elseif ($r -ge 528040) { '4.8' } elseif ($r -ge 461808) { '4.7.2' } elseif ($r -ge 461308) { '4.7.1' } elseif ($r -ge 460798) { '4.7' } elseif ($r -ge 394802) { '4.6.2' } else { 'older than 4.6.2' }
    }
    $core = @()
    $coreDir = [IO.Path]::Combine([string]$env:ProgramFiles, 'dotnet\shared\Microsoft.NETCore.App')
    if (Test-DirectoryExists -Path $coreDir) { $core = @(Get-ChildItem -LiteralPath $coreDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }) }
    $sec['DotNet'] = [ordered]@{ FrameworkRelease = $rel; FrameworkVersion = $netFx; NetCoreRuntimes = ($core -join ';') }
    if ($null -ne $rel -and [int]$rel -lt 461808) {
        Add-Finding -Severity Info -Category 'Software' -RuleId 'SW-DOTNET-OLD' -Title ('.NET Framework {0} is outdated' -f $netFx) -Detail ('Release {0}' -f $rel) -Recommendation 'Install .NET Framework 4.8 via Windows Update.'
    }
    return $sec
}

# ---------------------------------------------------------------------------------------------
# 10. Autostart & persistence
# ---------------------------------------------------------------------------------------------
function Add-WdInvAutostartEntry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$List,
        [Parameter(Mandatory = $true)][string]$Source,
        [AllowNull()][AllowEmptyString()][string]$Name,
        [AllowNull()][AllowEmptyString()][string]$Command,
        [AllowNull()][AllowEmptyString()][string]$Arguments = '',
        [AllowNull()][AllowEmptyString()][string]$Publisher = '',
        [AllowNull()][object]$Enabled = $true,
        [string[]]$ExtraFlags = @(),
        [switch]$CheckSignature,
        [switch]$ScriptFilesAreSuspicious
    )
    $info = Get-WdInvCommandInfo -Command $Command -Arguments $Arguments
    $cls = Get-WdInvCommandFlags -Info $info -CheckSignature:$CheckSignature -ScriptFilesAreSuspicious:$ScriptFilesAreSuspicious
    $flags = New-Object 'System.Collections.Generic.List[string]'
    foreach ($f in @($cls['Flags'])) { $flags.Add([string]$f) }
    foreach ($f in $ExtraFlags) { if (-not [string]::IsNullOrEmpty($f)) { $flags.Add($f) } }
    if ($Enabled -eq $false) { $flags.Add('Disabled') }
    $sig = $cls['Signature']
    $signer = ''
    $sigStatus = ''
    if ($null -ne $sig) { $signer = [string]$sig['Signer']; $sigStatus = [string]$sig['Status'] }
    if ($Publisher -eq '' -and $signer -ne '') {
        $m = [regex]::Match($signer, '(?:^|,\s*)O=("[^"]+"|[^,]+)')
        if ($m.Success) { $Publisher = $m.Groups[1].Value.Trim('"') }
    }
    # Rules matched the ORIGINAL command above; only the secret-masked text is stored (summary.md, inventory.json, autostart.csv).
    $row = [pscustomobject][ordered]@{
        Source = $Source; Name = $Name; Command = (Hide-WdSecret -Text $Command)
        ResolvedPath = [string]$info['Path']; Arguments = (Hide-WdSecret -Text ([string]$info['Arguments']))
        LocationClass = [string]$cls['LocationClass']; Publisher = $Publisher
        Flags = ($flags.ToArray() -join ';'); Suspicious = [bool]$cls['Suspicious']; Enabled = $Enabled
        SignatureStatus = $sigStatus; Exists = [bool]$info['Exists']
    }
    $List.Add($row)
    return $row
}

function Get-WdInvStartupApproved {
    # Task Manager "Startup" enabled/disabled state: byte0 bit0 set = disabled, FILETIME at offset 4.
    [CmdletBinding()]
    param()
    $result = @{}
    $keys = @(
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\StartupFolder'
    )
    foreach ($k in $keys) {
        $vals = Get-WdInvRegistryValues -Path $k
        $scope = 'HKCU'
        if ($k.StartsWith('HKLM')) { $scope = 'HKLM' }
        $kind = 'Run'
        if ($k -match 'StartupFolder$') { $kind = 'Folder' }
        foreach ($n in $vals.Keys) {
            $b = $vals[$n]
            if ($null -eq $b -or -not ($b -is [byte[]]) -or $b.Length -lt 1) { continue }
            $enabled = (($b[0] -band 1) -eq 0)
            $disabledAt = $null
            if (-not $enabled -and $b.Length -ge 12) { try { $ft = [BitConverter]::ToInt64($b, 4); if ($ft -gt 0) { $disabledAt = [DateTime]::FromFileTime($ft) } } catch { } }
            $result[($scope + '|' + $kind + '|' + ([string]$n).ToLowerInvariant())] = @{ Enabled = $enabled; DisabledAt = $disabledAt }
        }
    }
    return $result
}

function Get-WdInvAutostart {
    [CmdletBinding()]
    param([switch]$Deep)
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}
    $entries = New-Object 'System.Collections.Generic.List[object]'
    $approved = Get-WdInvStartupApproved
    $checkAll = [bool]$Deep

    # Run / RunOnce / Policies / Winlogon Load-Run
    $runKeys = @(
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Source = 'HKLM Run'; Scope = 'HKLM' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Source = 'HKLM RunOnce'; Scope = 'HKLM' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'; Source = 'HKLM Run (32-bit)'; Scope = 'HKLM' },
        @{ Path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce'; Source = 'HKLM RunOnce (32-bit)'; Scope = 'HKLM' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'; Source = 'HKCU Run'; Scope = 'HKCU' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'; Source = 'HKCU RunOnce'; Scope = 'HKCU' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Source = 'HKLM Policies Run'; Scope = 'HKLM' },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'; Source = 'HKCU Policies Run'; Scope = 'HKCU' },
        @{ Path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Source = 'HKLM Winlogon Load/Run'; Scope = 'HKLM'; OnlyLoadRun = $true },
        @{ Path = 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; Source = 'HKCU Winlogon Load/Run'; Scope = 'HKCU'; OnlyLoadRun = $true }
    )
    foreach ($rk in $runKeys) {
        $vals = Get-WdInvRegistryValues -Path $rk.Path
        foreach ($n in $vals.Keys) {
            if ($rk.ContainsKey('OnlyLoadRun') -and $n -notin @('Load', 'Run')) { continue }
            $cmd = [string]$vals[$n]
            if ([string]::IsNullOrWhiteSpace($cmd)) { continue }
            $enabled = $true
            $ak = $rk.Scope + '|Run|' + ([string]$n).ToLowerInvariant()
            if ($approved.ContainsKey($ak)) { $enabled = [bool]$approved[$ak]['Enabled'] }
            $extra = @()
            if ($rk.ContainsKey('OnlyLoadRun')) { $extra += 'LegacyWinlogonRun' }
            [void](Add-WdInvAutostartEntry -List $entries -Source $rk.Source -Name ([string]$n) -Command $cmd -Enabled $enabled -ExtraFlags $extra -CheckSignature:$checkAll)
        }
    }
    if (-not $script:IsAdmin) { [void](Add-WdInvAdminGap -Item 'Autostart entries (Run keys, Startup folders) of other user accounts' -Detail 'HKEY_USERS hives of other users') }

    # Startup folders (.lnk resolved via WScript.Shell)
    $folders = @(
        @{ Path = [IO.Path]::Combine([string]$env:APPDATA, 'Microsoft\Windows\Start Menu\Programs\Startup'); Source = 'Startup folder (user)'; Scope = 'HKCU' },
        @{ Path = [IO.Path]::Combine([string]$env:ProgramData, 'Microsoft\Windows\Start Menu\Programs\Startup'); Source = 'Startup folder (all users)'; Scope = 'HKLM' }
    )
    $ws = $null
    try { $ws = New-Object -ComObject 'WScript.Shell' -ErrorAction Stop } catch { $ws = $null }
    foreach ($f in $folders) {
        if (-not (Test-DirectoryExists -Path $f.Path)) { continue }
        foreach ($item in @(Get-ChildItem -LiteralPath $f.Path -Force -File -ErrorAction SilentlyContinue)) {
            if ($item.Name -ieq 'desktop.ini') { continue }
            $cmd = $item.FullName
            $argText = ''
            if ($item.Extension -ieq '.lnk' -and $null -ne $ws) {
                try { $sc = $ws.CreateShortcut($item.FullName); if (-not [string]::IsNullOrEmpty([string]$sc.TargetPath)) { $cmd = [string]$sc.TargetPath; $argText = [string]$sc.Arguments } } catch { }
            }
            $enabled = $true
            $ak = $f.Scope + '|Folder|' + $item.Name.ToLowerInvariant()
            if ($approved.ContainsKey($ak)) { $enabled = [bool]$approved[$ak]['Enabled'] }
            [void](Add-WdInvAutostartEntry -List $entries -Source $f.Source -Name $item.Name -Command $cmd -Arguments $argText -Enabled $enabled -CheckSignature:$checkAll -ScriptFilesAreSuspicious)
        }
    }

    # Active Setup
    foreach ($asKey in @('HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components')) {
        foreach ($sub in @(Get-WdInvRegistrySubKeyNames -Path $asKey)) {
            $vals = Get-WdInvRegistryValues -Path ($asKey + '\' + $sub)
            $stub = Get-WdInvString -Value $vals['StubPath']
            if ($stub -eq '') { continue }
            $nm = Get-WdInvString -Value $vals['(default)']
            if ($nm -eq '') { $nm = Get-WdInvString -Value $vals[''] }
            if ($nm -eq '') { $nm = $sub }
            [void](Add-WdInvAutostartEntry -List $entries -Source 'Active Setup' -Name $nm -Command $stub -Enabled $true -CheckSignature:$checkAll)
        }
    }

    # Findings for Run/Startup/ActiveSetup entries
    $enabledCount = 0
    foreach ($e in $entries) {
        if ($e.Enabled -ne $false -and $e.Source -notmatch 'RunOnce|Active Setup') { $enabledCount++ }
        if ($e.Suspicious) {
            Add-Finding -Severity Warning -Category 'Autostart' -RuleId 'AUT-SUSP' -Title ('Suspicious autostart entry: {0} ({1})' -f $e.Name, $e.Source) -Detail ('Command: {0}; location: {1}; flags: {2}; signature: {3}' -f $e.Command, $e.LocationClass, $e.Flags, $(if ($e.SignatureStatus -ne '') { $e.SignatureStatus } else { 'not checked' })) `
                -Recommendation 'Programs starting from Temp/AppData/ProgramData/Public, script hosts with hidden/encoded arguments, or system binary names outside System32 are classic malware/miner persistence. Verify the publisher; remove the entry and the file if unknown (Task Manager > Startup, Autoruns).'
        }
    }
    $sec['Entries'] = $entries.ToArray()
    $sec['EnabledCount'] = $enabledCount
    if ($enabledCount -gt 15) {
        Add-Finding -Severity Info -Category 'Autostart' -RuleId 'AUT-MANY' -Title ('{0} programs start automatically with Windows' -f $enabledCount) -Detail (@($entries | Where-Object { $_.Enabled -ne $false -and $_.Source -notmatch 'RunOnce|Active Setup' } | ForEach-Object { $_.Name } | Select-Object -First 20) -join ', ') `
            -Recommendation 'Every autostart program costs logon time and RAM. Disable the unneeded ones in Task Manager > Startup apps.'
    }

    # Scheduled tasks
    $tasks = @(Invoke-Safely -Name 'Autostart.ScheduledTasks' -Default @() -ScriptBlock { @(Get-ScheduledTask -ErrorAction Stop) })
    $taskRows = New-Object 'System.Collections.Generic.List[object]'
    $known = @($script:Rules['KnownScheduledTasks'] | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $hiddenNonMs = 0
    $reported = 0
    foreach ($t in $tasks) {
        if ($null -eq $t) { continue }
        $path = [string]$t.TaskPath
        $name = [string]$t.TaskName
        $full = $path + $name
        $isMs = ($path -like '\Microsoft\*')
        $actions = New-Object 'System.Collections.Generic.List[string]'
        $execInfos = New-Object 'System.Collections.Generic.List[object]'
        foreach ($a in @($t.Actions)) {
            if ($null -eq $a) { continue }
            $exe = [string](Get-WdInvPropertyValue -Object $a -Name 'Execute')
            if ($exe -ne '') {
                $argsText = [string](Get-WdInvPropertyValue -Object $a -Name 'Arguments')
                # $execInfos keeps the original for rule matching; the stored/reported action text is secret-masked.
                $actions.Add((Hide-WdSecret -Text (($exe + ' ' + $argsText).Trim())))
                $execInfos.Add(@{ Exe = $exe; Args = $argsText })
            } else {
                $clsId = [string](Get-WdInvPropertyValue -Object $a -Name 'ClassId')
                if ($clsId -ne '') { $actions.Add('COM handler ' + $clsId) }
            }
        }
        $flags = New-Object 'System.Collections.Generic.List[string]'
        $suspicious = $false
        $critical = $false
        $hiddenVendor = $false
        $loc = ''
        $resolved = ''
        $userScript = ''
        $userScriptLoc = ''
        foreach ($ei in $execInfos) {
            $info = Get-WdInvCommandInfo -Command $ei.Exe -Arguments $ei.Args
            $cls = Get-WdInvCommandFlags -Info $info -CheckSignature:$checkAll
            $isFirstExec = ($resolved -eq '')
            if ($isFirstExec) { $resolved = [string]$info['Path']; $loc = [string]$cls['LocationClass'] }
            foreach ($f in @($cls['Flags'])) { if (-not $flags.Contains([string]$f)) { $flags.Add([string]$f) } }
            if ($cls['Suspicious']) { $suspicious = $true }
            $fileName = [string]$info['FileName']
            $argsText = [string]$info['Arguments']
            # mshta and PowerShell with STRONG red-flag arguments (shared ScriptHostStrongArgRegex: encoded command,
            # download, IEX, base64 ...) in a task are always critical; wscript/cscript are critical when the script
            # lives in a suspicious location, otherwise a warning (users do schedule their own .vbs/.js files).
            # WEAK flags (-ExecutionPolicy Bypass, -NoProfile, -WindowStyle Hidden) never escalate a task.
            $isWsh = ($fileName -match '^(wscript|cscript)(\.exe)?$')
            $isMshta = ($fileName -match '^mshta(\.exe)?$')
            $isStrongPs = ($fileName -match '^(powershell|pwsh)(\.exe)?$' -and @($cls['Flags']) -contains 'StrongRedFlagArgs')
            if ($isMshta -or $isStrongPs -or ($isWsh -and ($cls['Suspicious'] -or $argsText -match [string]$script:Rules['SuspiciousPathRegex']))) {
                $critical = $true
                if (-not $flags.Contains('ScriptHostAction')) { $flags.Add('ScriptHostAction') }
            } elseif ($isWsh) {
                $suspicious = $true
                if (-not $flags.Contains('ScriptHostAction')) { $flags.Add('ScriptHostAction') }
                if (-not $flags.Contains('UserScript')) { $flags.Add('UserScript') }
                # The script, not wscript.exe (System32), is what matters: report its path/location and check it
                # instead of the Microsoft-signed host when the task is hidden.
                $scriptPath = Get-WdInvArgumentPayloadPath -Arguments $argsText -PathRegex '\.(vbs|vbe|js|jse|wsf|wsh)$'
                if ($scriptPath -ne '' -and $userScript -eq '') {
                    $userScript = $scriptPath
                    $userScriptLoc = Get-ProcessLocationClass -Path $scriptPath
                    if ($isFirstExec) { $resolved = $scriptPath; $loc = $userScriptLoc }
                }
            }
        }
        $hidden = [bool](Get-WdInvPropertyValue -Object $t.Settings -Name 'Hidden' -Default $false)
        # "Microsoft" is decided by the action, not only by the task folder: anyone can create a hidden task under
        # \Microsoft\Windows\*, so a hidden task there is exempt only when it has no executable action (COM handler)
        # or its binary lives in the Windows folder / is Microsoft-signed.
        $execIsWindows = $true
        if ($hidden -and $isMs -and $execInfos.Count -gt 0) {
            $execIsWindows = $false
            if ($resolved -ne '') {
                $winDirPrefix = ([string]$env:SystemRoot).ToLowerInvariant().TrimEnd('\') + '\'
                if ($resolved.ToLowerInvariant().StartsWith($winDirPrefix)) { $execIsWindows = $true }
                else {
                    $msig = Get-WdInvSignatureInfo -Path $resolved
                    if ($msig['Trusted'] -and [string]$msig['Signer'] -match 'Microsoft') { $execIsWindows = $true }
                }
            }
        }
        if ($hidden -and (-not $isMs -or -not $execIsWindows)) {
            $flags.Add('Hidden')
            $hiddenNonMs++
            if ($isMs) { $flags.Add('HiddenInMicrosoftFolder') }
            # A hidden task whose binary is validly signed by a known vendor (AMD, Adobe... updaters) is reported, not escalated.
            $hsig = $null
            if ($resolved -ne '') { $hsig = Get-WdInvSignatureInfo -Path $resolved }
            if ($null -ne $hsig -and $hsig['Trusted']) { $hiddenVendor = $true; if (-not $flags.Contains('SignedTrusted')) { $flags.Add('SignedTrusted') } }
            else { $critical = $true }
        }
        $isKnown = ($known -contains $full.ToLowerInvariant())
        if ($isKnown) { $suspicious = $false; $critical = $false }
        if (-not $isMs -or $suspicious -or $critical) {
            $reported++
            $tinfo = Invoke-Safely -Name ('Autostart.TaskInfo ' + $full) -Default $null -Quiet -ScriptBlock { $t | Get-ScheduledTaskInfo -ErrorAction Stop }
            $triggers = @($t.Triggers | ForEach-Object { if ($null -ne $_) { ([string]$_.CimClass.CimClassName) -replace '^MSFT_Task', '' -replace 'Trigger$', '' } }) -join ','
            $author = [string]$t.Author
            if ($author -match '^\$\(@') { $author = '(resource string)' }
            $runLevel = ''
            $userId = ''
            if ($null -ne $t.Principal) { $runLevel = [string]$t.Principal.RunLevel; $userId = [string]$t.Principal.UserId }
            $taskRows.Add([pscustomobject][ordered]@{
                Path = $path; Name = $name; State = [string]$t.State; Author = $author; User = $userId; RunLevel = $runLevel; Hidden = $hidden
                Actions = ($actions.ToArray() -join ' | '); ResolvedPath = $resolved; LocationClass = $loc; Triggers = $triggers
                LastRunTime = $(if ($null -ne $tinfo) { $tinfo.LastRunTime } else { $null }); LastTaskResult = $(if ($null -ne $tinfo) { $tinfo.LastTaskResult } else { $null }); NextRunTime = $(if ($null -ne $tinfo) { $tinfo.NextRunTime } else { $null })
                Flags = ($flags.ToArray() -join ';'); Suspicious = ($suspicious -or $critical); IsMicrosoftPath = $isMs
            })
            if ($critical) {
                Add-Finding -Severity Critical -Category 'Autostart' -RuleId 'AUT-HIDDEN-TASK' -Title ('Hidden or script-host scheduled task: {0}' -f $full) -Detail ('State {0}; hidden={1}; actions: {2}; triggers: {3}; author: {4}' -f $t.State, $hidden, ($actions.ToArray() -join ' | '), $triggers, $author) `
                    -Recommendation 'A hidden task or one that runs mshta/wscript/encoded PowerShell is classic miner/malware persistence. Inspect the action, disable the task, remove the payload and run a full scan.'
            } elseif ($hiddenVendor) {
                Add-Finding -Severity Info -Category 'Autostart' -RuleId 'AUT-HIDDEN-TASK' -Title ('Hidden scheduled task from a signed vendor binary: {0}' -f $full) -Detail ('State {0}; actions: {1}; triggers: {2}' -f $t.State, ($actions.ToArray() -join ' | '), $triggers) `
                    -Recommendation 'Hidden tasks are unusual; this one runs a validly signed vendor program (updater/installer). Disable it if the software is not needed.'
            } elseif ($suspicious) {
                $flagText = ($flags.ToArray() -join ';')
                $onlyUserScript = ($flags.Contains('UserScript') -and -not ($flagText -match 'SuspiciousPath|SuspiciousArgPath|RedFlagArgs|MinerToken|SystemNameOutsideSystem32|NetworkPath|FileMissing'))
                if ($onlyUserScript) {
                    Add-Finding -Severity Warning -Category 'Autostart' -RuleId 'AUT-SUSP' -Title ('Scheduled task runs a user script: {0}' -f $full) -Detail ('State {0}; actions: {1}; script: {2}; script location: {3}; flags: {4}; triggers: {5}' -f $t.State, ($actions.ToArray() -join ' | '), $(if ($userScript -ne '') { $userScript } else { 'n/a' }), $(if ($userScriptLoc -ne '') { $userScriptLoc } else { 'n/a' }), $flagText, $triggers) `
                        -Recommendation 'The task runs a script via wscript/cscript. Open the .vbs/.js file and verify it is yours (a home-made backup or sync script is normal); disable/delete the task if unknown.'
                } else {
                    Add-Finding -Severity Warning -Category 'Autostart' -RuleId 'AUT-SUSP' -Title ('Suspicious scheduled task: {0}' -f $full) -Detail ('State {0}; actions: {1}; location: {2}; flags: {3}; triggers: {4}' -f $t.State, ($actions.ToArray() -join ' | '), $loc, $flagText, $triggers) `
                        -Recommendation 'The task starts a program from a suspicious location or with red-flag arguments. Verify the publisher; disable/delete the task if unknown.'
                }
            }
        }
    }
    $sec['ScheduledTasks'] = @($taskRows.ToArray() | Sort-Object -Property Path, Name)
    $sec['TaskCountVisible'] = $tasks.Count
    $sec['TaskCountReported'] = $reported
    # Total count via schtasks (rows start with "\ regardless of UI language) - detects tasks hidden from a standard user.
    $schCount = Invoke-Safely -Name 'Autostart.SchtasksCount' -Default $null -Quiet -ScriptBlock {
        # Invoke-Safely runs with $ErrorActionPreference = 'Stop': with stderr redirected, the first stderr line of
        # schtasks ("ERROR: The task image is corrupt or has been tampered with", common after in-place upgrades)
        # would become a terminating NativeCommandError and lose the whole count. Errors are kept and logged instead.
        $ErrorActionPreference = 'Continue'
        $out = @(& schtasks.exe /query /fo csv /nh 2>&1)
        $ErrorActionPreference = 'Stop'
        $n = 0
        foreach ($l in $out) {
            if ($l -is [System.Management.Automation.ErrorRecord]) {
                Write-Log -Level Debug -Message ('schtasks stderr: {0}' -f (([string]$l) -replace '\r?\n', ' ').Trim())
                continue
            }
            if ([string]$l -match '^"\\') { $n++ }
        }
        $n
    }
    $sec['TaskCountSchtasks'] = $schCount
    if ($null -ne $schCount -and [int]$schCount -gt $tasks.Count) {
        $diff = [int]$schCount - $tasks.Count
        $sec['TaskCountNotVisible'] = $diff
        if (-not $script:IsAdmin) {
            [void](Add-WdInvAdminGap -Item ('Scheduled tasks: {0} of {1} tasks are not visible to a standard user' -f $diff, $schCount) -Detail 'Get-ScheduledTask vs schtasks /query count')
            Add-Finding -Severity Info -Category 'Autostart' -RuleId 'AUT-TASKS-PARTIAL' -Title ('{0} scheduled task(s) could not be inspected without administrator rights' -f $diff) -Detail ('schtasks lists {0} tasks, Get-ScheduledTask returned {1}.' -f $schCount, $tasks.Count) -Recommendation 'Re-run win-debug as administrator to inspect every task (malware often hides in tasks readable only by SYSTEM).'
        }
    } elseif (-not $script:IsAdmin) {
        [void](Add-WdInvAdminGap -Item 'Scheduled tasks readable only by SYSTEM/administrators' -Detail 'task count could not be compared')
    }

    # Services
    $svcs = @(Get-CimSafe -ClassName Win32_Service -TimeoutSec 60 -Property @('Name', 'DisplayName', 'State', 'StartMode', 'DelayedAutoStart', 'ProcessId', 'StartName', 'PathName', 'Description', 'ServiceType'))
    $svcRows = New-Object 'System.Collections.Generic.List[object]'
    $winDir = ([string]$env:SystemRoot).ToLowerInvariant()
    $autoNotRunning = New-Object 'System.Collections.Generic.List[string]'
    $nonMsAuto = 0
    $svcState = @{}
    foreach ($s in $svcs) {
        if ($null -eq $s) { continue }
        $pathName = Get-WdInvString -Value $s.PathName
        # Rules below match the original PathName; only the secret-masked copy is stored and reported.
        $pathNameMasked = Hide-WdSecret -Text $pathName
        $info = Get-WdInvCommandInfo -Command $pathName
        $resolved = [string]$info['Path']
        $isMsPath = ($resolved -ne '' -and $resolved.ToLowerInvariant().StartsWith($winDir + '\'))
        $cls = Get-WdInvCommandFlags -Info $info -CheckSignature:($checkAll -and -not $isMsPath)
        $flags = New-Object 'System.Collections.Generic.List[string]'
        foreach ($f in @($cls['Flags'])) { $flags.Add([string]$f) }
        $unquoted = ($pathName -ne '' -and -not $pathName.StartsWith('"') -and $resolved -match '\s' -and $info['HasDirectory'])
        if ($unquoted) { $flags.Add('UnquotedPath') }
        $svcHostGroup = ''
        if ($pathName -match '-k\s+(\S+)') { $svcHostGroup = $Matches[1] }
        $state = [string]$s.State
        $startMode = [string]$s.StartMode
        $svcState[[string]$s.Name] = @{ State = $state; StartMode = $startMode }
        if ($startMode -eq 'Auto' -and $state -ne 'Running' -and $s.DelayedAutoStart -ne $true) { $autoNotRunning.Add([string]$s.Name) }
        if (-not $isMsPath -and $startMode -eq 'Auto') { $nonMsAuto++ }
        $svcRows.Add([pscustomobject][ordered]@{
            Name = [string]$s.Name; DisplayName = (Get-WdInvString -Value $s.DisplayName); State = $state; StartMode = $startMode; DelayedAutoStart = $s.DelayedAutoStart
            StartName = (Get-WdInvString -Value $s.StartName); ProcessId = $s.ProcessId; PathName = $pathNameMasked; ResolvedPath = $resolved; LocationClass = [string]$cls['LocationClass']
            IsMicrosoftPath = $isMsPath; SvcHostGroup = $svcHostGroup; Flags = ($flags.ToArray() -join ';'); Suspicious = [bool]$cls['Suspicious']
        })
        # No "-not $isMsPath" gate here: a Windows-folder HOST (cmd.exe /c ..., rundll32.exe ...) with a miner token,
        # strong red-flag arguments or an untrusted AppData/ProgramData payload must be reported like a task would be;
        # Get-WdInvCommandFlags already returns Suspicious=false for plain svchost/System32 images.
        if ($cls['Suspicious']) {
            Add-Finding -Severity Warning -Category 'Autostart' -RuleId 'AUT-SUSP' -Title ('Suspicious service: {0} ({1})' -f $s.Name, (Get-WdInvString -Value $s.DisplayName)) -Detail ('Path: {0}; start {1}, state {2}, account {3}; location {4}; flags {5}' -f $pathNameMasked, $startMode, $state, $s.StartName, $cls['LocationClass'], ($flags.ToArray() -join ';')) `
                -Recommendation 'A service running from Temp/AppData/ProgramData/Public, mimicking a Windows name, or a Windows script host (cmd/rundll32/powershell) starting a payload from such a folder is a common miner installation. Verify the binary signature; stop and delete the service (sc delete) after removing the file.'
        } elseif ($unquoted -and -not $isMsPath) {
            Add-Finding -Severity Info -Category 'Autostart' -RuleId 'SVC-UNQUOTED' -Title ('Service "{0}" has an unquoted path with spaces' -f $s.Name) -Detail $pathNameMasked -Recommendation 'A classic privilege-escalation weakness; the vendor should quote the path (sc config).'
        }
    }
    $sec['Services'] = @($svcRows.ToArray() | Sort-Object -Property Name)
    $sec['ServiceCount'] = $svcRows.Count
    $sec['NonMicrosoftAutoStartCount'] = $nonMsAuto
    $sec['AutoStartNotRunning'] = $autoNotRunning.ToArray()
    $ctx['ServiceState'] = $svcState
    foreach ($core in @(@{ Name = 'WinDefend'; Sev = 'Critical'; Text = 'Microsoft Defender Antivirus Service' }, @{ Name = 'MpsSvc'; Sev = 'Critical'; Text = 'Windows Defender Firewall' }, @{ Name = 'Schedule'; Sev = 'Critical'; Text = 'Task Scheduler' }, @{ Name = 'DPS'; Sev = 'Warning'; Text = 'Diagnostic Policy Service' }, @{ Name = 'wuauserv'; Sev = 'Info'; Text = 'Windows Update' }, @{ Name = 'EventLog'; Sev = 'Critical'; Text = 'Windows Event Log' })) {
        if (-not $svcState.ContainsKey($core.Name)) { continue }
        $st = $svcState[$core.Name]
        $thirdPartyAv = ($core.Name -eq 'WinDefend' -and $null -ne $ctx['InstalledAvNames'] -and @($ctx['InstalledAvNames']).Count -gt 0)
        if ([string]$st['StartMode'] -eq 'Disabled' -and -not $thirdPartyAv) {
            Add-Finding -Severity $core.Sev -Category 'Autostart' -RuleId 'SVC-DIS' -Title ('Core service "{0}" ({1}) is disabled' -f $core.Name, $core.Text) -Detail ('StartMode {0}, State {1}' -f $st['StartMode'], $st['State']) `
                -Recommendation 'Malware and "optimizer" tools disable core services. Re-enable it (services.msc > Startup type Automatic/Manual) and run a full scan.'
        } elseif ($core.Name -in @('WinDefend', 'MpsSvc', 'Schedule', 'EventLog') -and [string]$st['State'] -ne 'Running' -and -not $thirdPartyAv) {
            Add-Finding -Severity 'Warning' -Category 'Autostart' -RuleId 'SVC-DIS' -Title ('Core service "{0}" ({1}) is not running' -f $core.Name, $core.Text) -Detail ('StartMode {0}, State {1}' -f $st['StartMode'], $st['State']) -Recommendation 'Start the service and check the System log for its errors.'
        }
    }
    if ($ctx['SystemMediaType'] -eq 'HDD') {
        foreach ($n in @('SysMain', 'WSearch')) {
            if ($svcState.ContainsKey($n) -and ([string]$svcState[$n]['StartMode'] -eq 'Disabled' -or [string]$svcState[$n]['State'] -ne 'Running')) {
                Add-Finding -Severity Warning -Category 'Autostart' -RuleId 'SVC-SYSMAIN' -Title ('{0} is disabled on an HDD system' -f $n) -Detail ('StartMode {0}, State {1}' -f $svcState[$n]['StartMode'], $svcState[$n]['State']) -Recommendation 'SysMain (Superfetch) and Search indexing help HDD systems; re-enable them (a common "optimizer" tweak that backfires).'
            }
        }
    }

    # Winlogon / AppInit / IFEO / SilentProcessExit
    $wl = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $wlUser = Get-WdInvRegistryValues -Path 'HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
    $shell = Get-WdInvString -Value $wl['Shell']
    $userinit = Get-WdInvString -Value $wl['Userinit']
    $hijack = @()
    if ($shell -ne '' -and $shell -ine 'explorer.exe') { $hijack += ('Shell=' + $shell) }
    $uiParts = @($userinit.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
    if ($uiParts.Count -gt 1 -or ($uiParts.Count -eq 1 -and $uiParts[0] -notmatch '\\system32\\userinit\.exe$')) { $hijack += ('Userinit=' + $userinit) }
    if ((Get-WdInvString -Value $wlUser['Shell']) -ne '') { $hijack += ('HKCU Shell=' + $wlUser['Shell']) }
    if ((Get-WdInvString -Value $wlUser['Userinit']) -ne '') { $hijack += ('HKCU Userinit=' + $wlUser['Userinit']) }
    $appInit = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'
    $appInit32 = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows'
    foreach ($ai in @($appInit, $appInit32)) {
        $dlls = Get-WdInvString -Value $ai['AppInit_DLLs']
        $load = $ai['LoadAppInit_DLLs']
        if ($dlls -ne '' -and $null -ne $load -and [int]$load -eq 1) { $hijack += ('AppInit_DLLs=' + $dlls) }
    }
    # Winlogon values are command lines (a hijacked Shell/Userinit may carry arguments): stored secret-masked.
    $sec['Winlogon'] = [ordered]@{
        Shell = (Hide-WdSecret -Text $shell); Userinit = (Hide-WdSecret -Text $userinit); VMApplet = (Hide-WdSecret -Text (Get-WdInvString -Value $wl['VMApplet'])); AppSetup = (Hide-WdSecret -Text (Get-WdInvString -Value $wl['AppSetup'])); TaskMan = (Hide-WdSecret -Text (Get-WdInvString -Value $wl['TaskMan']))
        HKCU_Shell = (Hide-WdSecret -Text (Get-WdInvString -Value $wlUser['Shell'])); HKCU_Userinit = (Hide-WdSecret -Text (Get-WdInvString -Value $wlUser['Userinit']))
        AppInit_DLLs = (Get-WdInvString -Value $appInit['AppInit_DLLs']); LoadAppInit_DLLs = $appInit['LoadAppInit_DLLs']; RequireSignedAppInit_DLLs = $appInit['RequireSignedAppInit_DLLs']
        AppInit_DLLs_x86 = (Get-WdInvString -Value $appInit32['AppInit_DLLs']); LoadAppInit_DLLs_x86 = $appInit32['LoadAppInit_DLLs']
    }
    if ($hijack.Count -gt 0) {
        Add-Finding -Severity Critical -Category 'Autostart' -RuleId 'AUT-WINLOGON' -Title 'Logon sequence is hijacked (Winlogon/AppInit)' -Detail (Hide-WdSecret -Text ($hijack -join '; ')) -Recommendation 'Shell must be explorer.exe and Userinit must be only C:\Windows\system32\userinit.exe. Restore the values (regedit) after identifying and removing the injected program; run a full scan.'
    }
    $ifeoRows = New-Object 'System.Collections.Generic.List[object]'
    $knownDbg = @($script:Rules['KnownDebuggers'] | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $ifeoKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    $ifeoCount = 0
    foreach ($sub in @(Get-WdInvRegistrySubKeyNames -Path $ifeoKey)) {
        $ifeoCount++
        $dbg = Get-WdInvString -Value (Get-RegistryValueSafe -Path ($ifeoKey + '\' + $sub) -Name 'Debugger')
        if ($dbg -eq '') { continue }
        $info = Get-WdInvCommandInfo -Command $dbg
        $base = ''
        try { $base = [IO.Path]::GetFileNameWithoutExtension([string]$info['Path']).ToLowerInvariant() } catch { }
        $isKnown = ($knownDbg -contains $base)
        $dbgMasked = Hide-WdSecret -Text $dbg
        $ifeoRows.Add([ordered]@{ Executable = $sub; Debugger = $dbgMasked; KnownDebugger = $isKnown })
        if (-not $isKnown) {
            Add-Finding -Severity Critical -Category 'Autostart' -RuleId 'AUT-IFEO' -Title ('Image File Execution Options hijack: {0} -> {1}' -f $sub, $dbgMasked) -Detail 'A Debugger value silently replaces the program with another executable.' -Recommendation ('Delete the Debugger value under {0}\{1} after checking the target; this technique disables Task Manager/antivirus or launches malware.' -f $ifeoKey, $sub)
        }
    }
    $speRows = New-Object 'System.Collections.Generic.List[object]'
    $speKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    foreach ($sub in @(Get-WdInvRegistrySubKeyNames -Path $speKey)) {
        $mp = Get-WdInvString -Value (Get-RegistryValueSafe -Path ($speKey + '\' + $sub) -Name 'MonitorProcess')
        if ($mp -eq '') { continue }
        $mpMasked = Hide-WdSecret -Text $mp
        $speRows.Add([ordered]@{ Executable = $sub; MonitorProcess = $mpMasked })
        $info = Get-WdInvCommandInfo -Command $mp
        $cls = Get-WdInvCommandFlags -Info $info
        if ($cls['Suspicious'] -or [string]$info['FileName'] -match [string]$script:Rules['ScriptHostRegex']) {
            Add-Finding -Severity Critical -Category 'Autostart' -RuleId 'AUT-IFEO' -Title ('SilentProcessExit monitor for {0}: {1}' -f $sub, $mpMasked) -Detail 'MonitorProcess runs whenever the named program exits (persistence technique).' -Recommendation 'Remove the SilentProcessExit entry after identifying the target.'
        }
    }
    $sec['IFEO'] = [ordered]@{ SubKeysListed = $ifeoCount; Debuggers = $ifeoRows.ToArray(); SilentProcessExit = $speRows.ToArray() }

    # WMI event subscriptions
    $wmiRows = New-Object 'System.Collections.Generic.List[object]'
    $wmiSuspicious = @()
    foreach ($c in @('__EventFilter', '__FilterToConsumerBinding', 'CommandLineEventConsumer', 'ActiveScriptEventConsumer')) {
        foreach ($o in @(Get-CimSafe -Namespace 'root/subscription' -ClassName $c)) {
            if ($null -eq $o) { continue }
            $nm = [string](Get-WdInvPropertyValue -Object $o -Name 'Name')
            $detail = ''
            $label = ''
            switch ($c) {
                '__EventFilter' { $detail = [string](Get-WdInvPropertyValue -Object $o -Name 'Query'); if ($nm -ne 'SCM Event Log Filter') { $label = ('Filter "{0}": ' -f $nm) } }
                '__FilterToConsumerBinding' { $detail = ('{0} -> {1}' -f [string]$o.Filter, [string]$o.Consumer); if ([string]$o.Consumer -notmatch 'SCM Event Log Consumer') { $label = 'Binding: ' } }
                'CommandLineEventConsumer' { $detail = [string](Get-WdInvPropertyValue -Object $o -Name 'CommandLineTemplate'); $label = ('CommandLine consumer "{0}": ' -f $nm) }
                'ActiveScriptEventConsumer' { $detail = [string](Get-WdInvPropertyValue -Object $o -Name 'ScriptText'); if ($detail -eq '') { $detail = [string](Get-WdInvPropertyValue -Object $o -Name 'ScriptFilename') }; $label = ('Script consumer "{0}": ' -f $nm) }
            }
            # Consumer command lines / script text are secret-masked before they reach the row or the finding.
            $detail = Hide-WdSecret -Text $detail
            if ($detail.Length -gt 500) { $detail = $detail.Substring(0, 500) }
            if ($label -ne '') { $wmiSuspicious += ($label + $detail) }
            $wmiRows.Add([ordered]@{ Class = $c; Name = $nm; Detail = $detail })
        }
    }
    $sec['WmiSubscriptions'] = $wmiRows.ToArray()
    if ($wmiSuspicious.Count -gt 0) {
        Add-Finding -Severity Critical -Category 'Autostart' -RuleId 'AUT-WMI' -Title ('Non-default WMI event subscription(s): {0}' -f $wmiSuspicious.Count) -Detail (@($wmiSuspicious | Select-Object -First 5) -join ' || ') `
            -Recommendation 'WMI subscriptions run code without any file on disk (fileless miners/backdoors). Unless a known management tool created them, remove the consumer/filter/binding (Autoruns > WMI) and run a full scan.'
    }

    # PowerShell profiles
    $profRows = New-Object 'System.Collections.Generic.List[object]'
    $profPaths = [ordered]@{}
    try {
        foreach ($p in $PROFILE.PSObject.Properties) { if ($p.Name -match 'Host' -and -not [string]::IsNullOrEmpty([string]$p.Value)) { $profPaths[$p.Name] = [string]$p.Value } }
    } catch { }
    if ($profPaths.Count -eq 0) {
        $profPaths['AllUsersAllHosts'] = [IO.Path]::Combine([string]$env:SystemRoot, 'System32\WindowsPowerShell\v1.0\profile.ps1')
        $profPaths['CurrentUserAllHosts'] = [IO.Path]::Combine([Environment]::GetFolderPath('MyDocuments'), 'WindowsPowerShell\profile.ps1')
    }
    $pwsh7 = [IO.Path]::Combine([string]$env:ProgramFiles, 'PowerShell\7\profile.ps1')
    if (Test-FileExists -Path $pwsh7) { $profPaths['PowerShell7AllUsers'] = $pwsh7 }
    # STRONG script-host indicators only (encoded commands, downloads, IEX ...); weak launch options are meaningless in a profile.
    $argRegex = [string]$script:Rules['ScriptHostStrongArgRegex']
    if ([string]::IsNullOrEmpty($argRegex)) { $argRegex = [string]$script:Rules['ScriptHostArgRegex'] }
    $profileChecks = @(
        @{ Name = 'strong script-host argument'; Regex = $argRegex },
        @{ Name = 'miner token'; Regex = [string]$script:Rules['MinerTokenRegex'] },
        @{ Name = 'suspicious path'; Regex = [string]$script:Rules['SuspiciousPathRegex'] }
    )
    foreach ($scope in $profPaths.Keys) {
        $p = [string]$profPaths[$scope]
        $exists = Test-FileExists -Path $p
        $size = $null
        $susp = $false
        $evidence = New-Object 'System.Collections.Generic.List[string]'
        if ($exists) {
            $size = Get-FileSizeSafe -Path $p
            try {
                # Profile text is NOT copied into the report (profiles often set API keys/tokens as environment
                # variables); only the matched token of a rule that fired is recorded as evidence, secrets masked.
                $content = [IO.File]::ReadAllText($p)
                foreach ($chk in $profileChecks) {
                    if ([string]::IsNullOrEmpty($chk.Regex)) { continue }
                    $m = [regex]::Match($content, $chk.Regex, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
                    if ($m.Success) {
                        $susp = $true
                        $tok = $m.Value
                        # Shared masking helper (lib\Common.ps1) - the same rules as command lines and event messages.
                        $tok = Hide-WdSecret -Text $tok
                        if ($tok.Length -gt 60) { $tok = $tok.Substring(0, 60) + '...' }
                        $evidence.Add(('{0}: "{1}"' -f $chk.Name, $tok))
                    }
                }
            } catch { }
        }
        $profRows.Add([ordered]@{ Scope = $scope; Path = $p; Exists = $exists; Bytes = $size; Suspicious = $susp; Evidence = ($evidence.ToArray() -join '; ') })
        if ($susp) {
            Add-Finding -Severity Warning -Category 'Autostart' -RuleId 'AUT-PSPROFILE' -Title ('PowerShell profile contains suspicious code: {0}' -f $p) -Detail (('{0} bytes; matched ' -f (ConvertTo-InvariantString -Value $size)) + ($evidence.ToArray() -join '; ')) -Recommendation 'A profile runs every time PowerShell starts. Review and clean the file if you did not write it.'
        } elseif ($exists -and $scope -like 'AllUsers*' -and -not $ctx['IsDomainJoined']) {
            Add-Finding -Severity Info -Category 'Autostart' -RuleId 'AUT-PSPROFILE-ALLUSERS' -Title ('An all-users PowerShell profile exists: {0}' -f $p) -Detail ('{0} bytes' -f $size) -Recommendation 'Unusual on a home PC; check its content.'
        }
    }
    $sec['PowerShellProfiles'] = $profRows.ToArray()

    # Shell extensions / BHO / LSA packages (dump for the analyst)
    $bhoRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($bk in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects')) {
        foreach ($sub in @(Get-WdInvRegistrySubKeyNames -Path $bk)) { $bhoRows.Add([ordered]@{ Key = 'BHO'; Id = $sub }) }
    }
    foreach ($sk in @('ShellExecuteHooks', 'ShellServiceObjectDelayLoad')) {
        $vals = Get-WdInvRegistryValues -Path ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\' + $sk)
        foreach ($n in $vals.Keys) { $bhoRows.Add([ordered]@{ Key = $sk; Id = ([string]$n + ' = ' + [string]$vals[$n]) }) }
    }
    $lsa = Get-WdInvRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
    $lsaInfo = [ordered]@{
        SecurityPackages = (@($lsa['Security Packages']) -join ';')
        AuthenticationPackages = (@($lsa['Authentication Packages']) -join ';')
        NotificationPackages = (@($lsa['Notification Packages']) -join ';')
    }
    $defaultLsa = '^(msv1_0|kerberos|schannel|wdigest|tspkg|pku2u|cloudap|negoexts|livessp|scecli|rassfm|"")$'
    $oddLsa = @()
    foreach ($pkgList in @(@($lsa['Authentication Packages']), @($lsa['Notification Packages']), @($lsa['Security Packages']))) {
        foreach ($pkg in $pkgList) { $ps = Get-WdInvString -Value $pkg; if ($ps -ne '' -and $ps -notmatch $defaultLsa) { $oddLsa += $ps } }
    }
    $sec['ShellExtensions'] = $bhoRows.ToArray()
    $sec['Lsa'] = $lsaInfo
    if ($oddLsa.Count -gt 0) {
        Add-Finding -Severity Warning -Category 'Autostart' -RuleId 'AUT-LSA' -Title ('Non-default LSA package(s): {0}' -f ($oddLsa -join ', ')) -Detail 'HKLM\SYSTEM\CurrentControlSet\Control\Lsa Authentication/Notification/Security Packages' -Recommendation 'Some security products register LSA packages legitimately (password filters, smart cards). Unknown DLLs here are credential-stealing malware: verify the file and its signature.'
    }
    return $sec
}

# ---------------------------------------------------------------------------------------------
# 11. Security
# ---------------------------------------------------------------------------------------------
function Get-WdInvSecurity {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][hashtable]$ProcessMap)
    $inv = Get-WdInv
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}
    $defNs = 'root/Microsoft/Windows/Defender'

    # Third-party products (SecurityCenter2)
    $avRows = New-Object 'System.Collections.Generic.List[object]'
    $enabledAv = New-Object 'System.Collections.Generic.List[string]'
    $thirdPartyEnabled = $false
    foreach ($cls in @('AntiVirusProduct', 'AntiSpywareProduct', 'FirewallProduct')) {
        foreach ($p in @(Get-CimSafe -Namespace 'root/SecurityCenter2' -ClassName $cls)) {
            if ($null -eq $p) { continue }
            $state = [int](Get-WdInvPropertyValue -Object $p -Name 'productState' -Default 0)
            $hex = '{0:X6}' -f $state
            $enabled = ($hex.Substring(2, 2) -in @('10', '11'))
            $upToDate = ($hex.Substring(4, 2) -eq '00')
            $nm = [string]$p.displayName
            $avRows.Add([ordered]@{ Type = $cls; Name = $nm; ProductState = $state; Enabled = $enabled; UpToDate = $upToDate; Path = [string]$p.pathToSignedProductExe })
            if ($cls -eq 'AntiVirusProduct' -and $enabled) { $enabledAv.Add($nm); if ($nm -notmatch 'Defender|Windows') { $thirdPartyEnabled = $true } }
            if ($cls -eq 'AntiVirusProduct' -and $enabled -and -not $upToDate) {
                Add-Finding -Severity Warning -Category 'Security' -RuleId 'SEC-SIG' -Title ('Antivirus "{0}" reports outdated definitions' -f $nm) -Detail ('productState 0x{0}' -f $hex) -Recommendation 'Update the antivirus definitions or fix its update mechanism.'
            }
        }
    }
    $sec['SecurityCenterProducts'] = $avRows.ToArray()
    if ($enabledAv.Count -ge 2) {
        $names = @($enabledAv.ToArray() | Sort-Object -Unique)
        if ($names.Count -ge 2) {
            Add-Finding -Severity Warning -Category 'Security' -RuleId 'SEC-2AV' -Title ('Two or more antivirus products are active: {0}' -f ($names -join ', ')) -Detail 'Security Center reports several enabled real-time products.' -Recommendation 'Two real-time scanners fight over every file and slow the PC massively. Keep one (Defender is fine), uninstall the other with the vendor removal tool.'
        }
    }

    # Defender status (CIM MSFT_MpComputerStatus)
    $st = @(Get-CimSafe -Namespace $defNs -ClassName MSFT_MpComputerStatus)
    $def = [ordered]@{ Available = ($st.Count -gt 0) }
    $rtp = $null
    if ($st.Count -gt 0) {
        $s = $st[0]
        foreach ($n in @('AMRunningMode', 'AMServiceEnabled', 'AntivirusEnabled', 'AntispywareEnabled', 'RealTimeProtectionEnabled', 'BehaviorMonitorEnabled', 'IoavProtectionEnabled', 'OnAccessProtectionEnabled', 'NISEnabled', 'IsTamperProtected', 'AntivirusSignatureAge', 'AntivirusSignatureLastUpdated', 'AntivirusSignatureVersion', 'QuickScanAge', 'QuickScanEndTime', 'FullScanAge', 'DefenderSignaturesOutOfDate', 'RebootRequired', 'AMEngineVersion', 'AMProductVersion', 'IsVirtualMachine', 'DeviceControlState')) {
            $def[$n] = Get-WdInvPropertyValue -Object $s -Name $n
        }
        if ($null -ne $def['FullScanAge'] -and [int64]$def['FullScanAge'] -ge 4294967295) { $def['FullScanAge'] = 'never' }
        if ($null -ne $def['QuickScanAge'] -and [int64]$def['QuickScanAge'] -ge 4294967295) { $def['QuickScanAge'] = 'never' }
        $rtp = $def['RealTimeProtectionEnabled']
        $mode = [string]$def['AMRunningMode']
        if (($rtp -eq $false -or $mode -match 'Passive|Off|Disabled') -and -not $thirdPartyEnabled) {
            Add-Finding -Severity Critical -Category 'Security' -RuleId 'SEC-NOAV' -Title 'Real-time antivirus protection is OFF' -Detail ('Defender RealTimeProtectionEnabled={0}, running mode {1}, no other enabled antivirus registered.' -f $rtp, $mode) `
                -Recommendation 'Turn on Windows Security > Virus & threat protection > Real-time protection. If it turns itself off again, malware is disabling it: boot to Safe Mode and scan with Microsoft Defender Offline.'
        }
        $sigAge = $def['AntivirusSignatureAge']
        if ($null -ne $sigAge -and [int64]$sigAge -gt 7 -and $mode -notmatch 'Passive') {
            $sev = 'Warning'
            if ([int64]$sigAge -gt 30) { $sev = 'Critical' }
            Add-Finding -Severity $sev -Category 'Security' -RuleId 'SEC-SIG' -Title ('Defender definitions are {0} days old' -f $sigAge) -Detail ('Signature version {0}, last updated {1}' -f $def['AntivirusSignatureVersion'], (ConvertTo-InvariantString -Value $def['AntivirusSignatureLastUpdated'])) -Recommendation 'Windows Security > Virus & threat protection > Protection updates > Check for updates. Old definitions usually mean Windows Update is broken or blocked.'
        }
        if ($def['IsTamperProtected'] -eq $false -and -not $thirdPartyEnabled) {
            Add-Finding -Severity Warning -Category 'Security' -RuleId 'SEC-TAMPER' -Title 'Defender tamper protection is off' -Detail 'IsTamperProtected=False' -Recommendation 'Enable Windows Security > Virus & threat protection settings > Tamper Protection; malware disables it before switching protection off.'
        }
        if ($def['QuickScanAge'] -is [uint32] -and [int64]$def['QuickScanAge'] -gt 30 -and $mode -notmatch 'Passive') {
            Add-Finding -Severity Info -Category 'Security' -RuleId 'SEC-SCAN-OLD' -Title ('No Defender quick scan for {0} days' -f $def['QuickScanAge']) -Detail '' -Recommendation 'Run a quick scan (Windows Security) and then a full scan.'
        }
    } elseif (-not $thirdPartyEnabled) {
        Add-Finding -Severity Critical -Category 'Security' -RuleId 'SEC-NOAV' -Title 'No antivirus status could be read (Defender missing) and no other antivirus is enabled' -Detail 'MSFT_MpComputerStatus unavailable; SecurityCenter2 lists no enabled product.' -Recommendation 'Make sure an antivirus with real-time protection is installed and enabled.'
    }
    $sec['Defender'] = $def

    # Defender preferences and exclusions (exclusions need admin)
    $pref = @(Get-CimSafe -Namespace $defNs -ClassName MSFT_MpPreference)
    $prefInfo = [ordered]@{}
    if ($pref.Count -gt 0) {
        $p = $pref[0]
        foreach ($n in @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection', 'DisableScriptScanning', 'MAPSReporting', 'SubmitSamplesConsent', 'PUAProtection', 'ScanAvgCPULoadFactor', 'DisableTamperProtection', 'HideExclusionsFromLocalUsers', 'EnableControlledFolderAccess', 'EnableNetworkProtection')) {
            $prefInfo[$n] = Get-WdInvPropertyValue -Object $p -Name $n
        }
        if ($null -ne $prefInfo['PUAProtection'] -and [int]$prefInfo['PUAProtection'] -eq 0) {
            Add-Finding -Severity Info -Category 'Security' -RuleId 'SEC-PUA' -Title 'Defender PUA (potentially unwanted app) protection is off' -Detail 'PUAProtection=0' -Recommendation 'Windows Security > App & browser control > Reputation-based protection > Potentially unwanted app blocking: turn on. It catches optimizers, bundlers and miners.'
        }
        $excl = [ordered]@{}
        $exclReadable = $true
        foreach ($n in @('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension', 'ExclusionIpAddress')) {
            $v = Get-WdInvPropertyValue -Object $p -Name $n
            $list = @()
            if ($null -ne $v) { $list = @($v | ForEach-Object { [string]$_ }) }
            if ($list.Count -eq 1 -and $list[0] -match 'N/A|administrator') { $exclReadable = $false; $list = @() }
            $excl[$n] = $list
        }
        if (-not $exclReadable -or (-not $script:IsAdmin -and $prefInfo['HideExclusionsFromLocalUsers'] -ne $false)) {
            $prefInfo['Exclusions'] = Add-WdInvAdminGap -Item 'Defender exclusions (paths, processes, extensions)' -Detail 'Get-MpPreference hides exclusions from standard users'
            Add-Finding -Severity Info -Category 'Security' -RuleId 'SEC-EXCL-NA' -Title 'Defender exclusions could not be read without administrator rights' -Detail 'Miners typically add their folder to the exclusion list.' -Recommendation 'Re-run win-debug as administrator, or open Windows Security > Virus & threat protection settings > Exclusions and review the list.'
        } else {
            $prefInfo['Exclusions'] = $excl
            $all = @()
            foreach ($n in $excl.Keys) { foreach ($x in $excl[$n]) { $all += ('{0}: {1}' -f $n, $x) } }
            $broad = @()
            $broadRegex = '^[a-z]:\\?$|^[a-z]:\\windows\\?$|^[a-z]:\\users\\?$|\\temp\\?$|appdata\\?$|programdata\\?$|^\*?\.(exe|dll|ps1|bat|cmd|js|vbs)$|\\(powershell|pwsh|svchost|explorer|rundll32|wscript|cscript|mshta|cmd)\.exe$|^[a-z]:\\program files( \(x86\))?\\?$'
            $suspRegex = [string]$script:Rules['SuspiciousPathRegex']
            $runningSusp = @()
            foreach ($procId in $ProcessMap.Keys) { $ep = [string]$ProcessMap[$procId].ExecutablePath; if ($ep -ne '' -and $ep -match $suspRegex) { $runningSusp += $ep.ToLowerInvariant() } }
            foreach ($n in @('ExclusionPath', 'ExclusionProcess', 'ExclusionExtension')) {
                foreach ($x in $excl[$n]) {
                    $xl = ([string]$x).ToLowerInvariant().TrimEnd('\')
                    if ($xl -match $broadRegex -or $xl -match $suspRegex) { $broad += ('{0}: {1}' -f $n, $x); continue }
                    foreach ($rp in $runningSusp) { if ($rp.StartsWith($xl)) { $broad += ('{0}: {1} (covers running process {2})' -f $n, $x, $rp); break } }
                }
            }
            if ($broad.Count -gt 0) {
                Add-Finding -Severity Critical -Category 'Security' -RuleId 'SEC-EXCL' -Title ('Dangerous Defender exclusion(s): {0}' -f $broad.Count) -Detail ($broad -join '; ') -Recommendation 'Exclusions covering whole drives, Windows/Users folders, Temp/AppData, *.exe or system binaries are planted by miners/malware. Remove them (Windows Security > Exclusions) and run a full offline scan.'
            } elseif ($all.Count -gt 0) {
                Add-Finding -Severity Warning -Category 'Security' -RuleId 'SEC-EXCL-ANY' -Title ('{0} Defender exclusion(s) configured' -f $all.Count) -Detail ($all -join '; ') -Recommendation 'Review every exclusion; remove the ones you did not add yourself (developers often need a few, home users almost never).'
            }
        }
    } else {
        $prefInfo['Note'] = 'MSFT_MpPreference unavailable (Defender not present or disabled by another product).'
    }
    $polDef = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $polRtp = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'
    $prefInfo['Policy_DisableAntiSpyware'] = $polDef['DisableAntiSpyware']
    $prefInfo['Policy_DisableAntiVirus'] = $polDef['DisableAntiVirus']
    $prefInfo['Policy_DisableRealtimeMonitoring'] = $polRtp['DisableRealtimeMonitoring']
    if ((($null -ne $polDef['DisableAntiSpyware'] -and [int]$polDef['DisableAntiSpyware'] -eq 1) -or ($null -ne $polDef['DisableAntiVirus'] -and [int]$polDef['DisableAntiVirus'] -eq 1) -or ($null -ne $polRtp['DisableRealtimeMonitoring'] -and [int]$polRtp['DisableRealtimeMonitoring'] -eq 1)) -and -not $thirdPartyEnabled) {
        Add-Finding -Severity Critical -Category 'Security' -RuleId 'SEC-NOAV' -Title 'Defender is disabled by policy registry values' -Detail ('DisableAntiSpyware={0}, DisableAntiVirus={1}, DisableRealtimeMonitoring={2}' -f $polDef['DisableAntiSpyware'], $polDef['DisableAntiVirus'], $polRtp['DisableRealtimeMonitoring']) -Recommendation 'Delete these values under HKLM\SOFTWARE\Policies\Microsoft\Windows Defender (typical for "Defender disabler" tools and malware), then re-enable protection.'
    }
    $sec['DefenderPreferences'] = $prefInfo

    # Threat history
    $threats = @(Get-CimSafe -Namespace $defNs -ClassName MSFT_MpThreat)
    $dets = @(Get-CimSafe -Namespace $defNs -ClassName MSFT_MpThreatDetection)
    $threatNames = @{}
    foreach ($t in $threats) { if ($null -ne $t) { $threatNames[[string]$t.ThreatID] = [string]$t.ThreatName } }
    $detRows = New-Object 'System.Collections.Generic.List[object]'
    $since90 = (Get-Date).AddDays(-90)
    foreach ($d in @($dets | Sort-Object -Property InitialDetectionTime -Descending | Select-Object -First 50)) {
        if ($null -eq $d) { continue }
        $tid = [string]$d.ThreatID
        $tn = ''
        if ($threatNames.ContainsKey($tid)) { $tn = $threatNames[$tid] }
        $res = @($d.Resources | ForEach-Object { [string]$_ }) -join ';'
        if ($res.Length -gt 300) { $res = $res.Substring(0, 300) }
        $detRows.Add([ordered]@{ Time = $d.InitialDetectionTime; ThreatName = $tn; ThreatID = $tid; Process = [string]$d.ProcessName; Resources = $res; ActionSuccess = $d.ActionSuccess; ExecutionStatus = $d.CurrentThreatExecutionStatusID })
        if ($tn -match 'Miner|XMRig|CoinMiner|Crypto' -and $null -ne $d.InitialDetectionTime -and [DateTime]$d.InitialDetectionTime -gt $since90) {
            Add-Finding -Severity Critical -Category 'Security' -RuleId 'SEC-MINER-HIST' -Title ('Defender detected a crypto-miner on {0}: {1}' -f ([DateTime]$d.InitialDetectionTime).ToString('yyyy-MM-dd', $inv), $tn) -Detail ('Resources: {0}; process {1}; action success {2}' -f $res, $d.ProcessName, $d.ActionSuccess) `
                -Recommendation 'Verify the miner is really gone: check autostart, scheduled tasks, services, WMI subscriptions and Defender exclusions in this report; run a full offline scan.'
        }
    }
    $sec['ThreatDetections'] = $detRows.ToArray()
    $activeThreats = @($threats | Where-Object { $_.IsActive -eq $true })
    $sec['ThreatsKnown'] = $threats.Count
    $sec['ThreatsActive'] = @($activeThreats | ForEach-Object { [ordered]@{ ThreatName = [string]$_.ThreatName; Severity = $_.SeverityID; Category = $_.CategoryID } })
    if ($activeThreats.Count -gt 0) {
        Add-Finding -Severity Critical -Category 'Security' -RuleId 'SEC-THREAT-ACTIVE' -Title ('{0} active threat(s) reported by Defender' -f $activeThreats.Count) -Detail (@($activeThreats | ForEach-Object { [string]$_.ThreatName }) -join ', ') -Recommendation 'Open Windows Security > Protection history and remove the threats; then run a full scan.'
    }
    $puaDet = @($detRows | Where-Object { [string]$_['ThreatName'] -match '^PUA' })
    if ($puaDet.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Security' -RuleId 'SEC-PUA-HIST' -Title ('{0} potentially unwanted application detection(s) in Defender history' -f $puaDet.Count) -Detail (@($puaDet | ForEach-Object { [string]$_['ThreatName'] } | Select-Object -Unique | Select-Object -First 8) -join ', ') -Recommendation 'Bundled adware/optimizers were seen; check the installed programs list.'
    }

    # Defender operational events (30 d)
    $since30 = (Get-Date).AddDays(-30)
    $defEvents = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = @(1006, 1007, 1008, 1015, 1116, 1117, 1118, 1119, 5000, 5001, 5004, 5007, 5010, 5012, 5013); StartTime = $since30 } -MaxEvents 10000)
    $defGroups = @(Get-WdInvEventGroups -Events $defEvents -Log 'Microsoft-Windows-Windows Defender/Operational')
    $sec['DefenderEvents30d'] = $defGroups
    $rtpOff = @($defEvents | Where-Object { [int]$_.Id -eq 5001 } | Sort-Object -Property TimeCreated -Descending)
    $rtpOn = @($defEvents | Where-Object { [int]$_.Id -eq 5000 } | Sort-Object -Property TimeCreated -Descending)
    if ($rtpOff.Count -gt 0) {
        $lastOff = $rtpOff[0].TimeCreated
        $reEnabled = ($rtpOn.Count -gt 0 -and $rtpOn[0].TimeCreated -gt $lastOff) -or ($rtp -eq $true)
        if (-not $reEnabled -and -not $thirdPartyEnabled) {
            Add-Finding -Severity Critical -Category 'Security' -RuleId 'SEC-RTP-EVT' -Title ('Real-time protection was turned off on {0} and not re-enabled' -f (Get-IsoTimestamp -Date $lastOff)) -Detail ('Defender event 5001 x{0} in 30 days' -f $rtpOff.Count) -Recommendation 'Re-enable real-time protection; if a program keeps disabling it, that program is the malware.'
        } elseif ($rtpOff.Count -ge 3) {
            Add-Finding -Severity Warning -Category 'Security' -RuleId 'SEC-RTP-TOGGLE' -Title ('Real-time protection was switched off {0} times in 30 days' -f $rtpOff.Count) -Detail ('Last: {0}' -f (Get-IsoTimestamp -Date $lastOff)) -Recommendation 'Frequent toggling is suspicious (crack tools, "optimizers"); check what runs at those times.'
        }
    }
    $exclChanges = @($defEvents | Where-Object { [int]$_.Id -eq 5007 -and (@($_.Properties | ForEach-Object { [string]$_.Value }) -join ' ') -match '\\Exclusions\\|DisableRealtimeMonitoring|DisableAntiSpyware' })
    if ($exclChanges.Count -gt 0) {
        $when = @($exclChanges | Sort-Object -Property TimeCreated -Descending | Select-Object -First 5 | ForEach-Object { Get-IsoTimestamp -Date $_.TimeCreated }) -join ', '
        Add-Finding -Severity Warning -Category 'Security' -RuleId 'SEC-EXCL-CHANGED' -Title ('Defender exclusions or protection settings were changed {0} time(s) in 30 days' -f $exclChanges.Count) -Detail ('Event 5007 at: {0}' -f $when) -Recommendation 'If you did not change exclusions yourself, a program did: review the exclusion list (administrator) and what was installed at those times.'
    }

    # Firewall (registry, fast)
    $fw = [ordered]@{}
    $fwDisabled = @()
    $thirdPartyFw = @($avRows | Where-Object { $_['Type'] -eq 'FirewallProduct' -and $_['Enabled'] -and $_['Name'] -notmatch 'Defender|Windows' })
    foreach ($prof in @('Domain', 'Standard', 'Public')) {
        $pol = Get-RegistryValueSafe -Path ('HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\{0}Profile' -f $prof) -Name 'EnableFirewall'
        $val = Get-RegistryValueSafe -Path ('HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{0}Profile' -f $prof) -Name 'EnableFirewall'
        $eff = $val
        if ($null -ne $pol) { $eff = $pol }
        $label = $prof
        if ($prof -eq 'Standard') { $label = 'Private' }
        $enabled = $null
        if ($null -ne $eff) { $enabled = ([int]$eff -eq 1) }
        $fw[$label] = $enabled
        if ($enabled -eq $false -and $thirdPartyFw.Count -eq 0) { $fwDisabled += $label }
    }
    $mps = 'n/a'
    if ($null -ne $ctx['ServiceState'] -and $ctx['ServiceState'].ContainsKey('MpsSvc')) { $mps = [string]$ctx['ServiceState']['MpsSvc']['State'] }
    $fw['MpsSvcState'] = $mps
    $sec['Firewall'] = $fw
    if ($fwDisabled.Count -gt 0) {
        $sev = 'Warning'
        if ($ctx['IsDomainJoined'] -and $fwDisabled.Count -eq 1 -and $fwDisabled[0] -eq 'Domain') { $sev = 'Info' }
        Add-Finding -Severity $sev -Category 'Security' -RuleId 'SEC-FW' -Title ('Windows Firewall is disabled for profile(s): {0}' -f ($fwDisabled -join ', ')) -Detail 'EnableFirewall=0 and no third-party firewall registered.' -Recommendation 'Turn the firewall back on (Windows Security > Firewall & network protection) unless a company policy manages it.'
    }

    # UAC
    $uac = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    $sec['UAC'] = [ordered]@{ EnableLUA = $uac['EnableLUA']; ConsentPromptBehaviorAdmin = $uac['ConsentPromptBehaviorAdmin']; ConsentPromptBehaviorUser = $uac['ConsentPromptBehaviorUser']; PromptOnSecureDesktop = $uac['PromptOnSecureDesktop']; EnableVirtualization = $uac['EnableVirtualization'] }
    if ($null -ne $uac['EnableLUA'] -and [int]$uac['EnableLUA'] -eq 0) {
        Add-Finding -Severity Critical -Category 'Security' -RuleId 'SEC-UAC' -Title 'User Account Control (UAC) is disabled' -Detail 'EnableLUA=0' -Recommendation 'Every program runs with full administrator rights silently. Re-enable UAC (Control Panel > User Accounts > Change UAC settings) and reboot.'
    } elseif (($null -ne $uac['ConsentPromptBehaviorAdmin'] -and [int]$uac['ConsentPromptBehaviorAdmin'] -eq 0) -or ($null -ne $uac['PromptOnSecureDesktop'] -and [int]$uac['PromptOnSecureDesktop'] -eq 0)) {
        Add-Finding -Severity Warning -Category 'Security' -RuleId 'SEC-UAC-WEAK' -Title 'UAC is set to "never notify" or without secure desktop' -Detail ('ConsentPromptBehaviorAdmin={0}, PromptOnSecureDesktop={1}' -f $uac['ConsentPromptBehaviorAdmin'], $uac['PromptOnSecureDesktop']) -Recommendation 'Restore the default UAC level (notify when apps try to make changes).'
    }

    # SmartScreen
    $ss = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled'
    $ssPol = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -Name 'EnableSmartScreen'
    $ssApps = Get-RegistryValueSafe -Path 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' -Name 'EnableWebContentEvaluation'
    $sec['SmartScreen'] = [ordered]@{ ExplorerSmartScreenEnabled = $(if ($null -ne $ss) { [string]$ss } else { '(default: on)' }); PolicyEnableSmartScreen = $ssPol; StoreAppsWebContentEvaluation = $ssApps }
    if (([string]$ss -eq 'Off') -or ($null -ne $ssPol -and [int]$ssPol -eq 0)) {
        Add-Finding -Severity Warning -Category 'Security' -RuleId 'SEC-SS' -Title 'SmartScreen is turned off' -Detail ('SmartScreenEnabled={0}, policy EnableSmartScreen={1}' -f $ss, $ssPol) -Recommendation 'Windows Security > App & browser control > Check apps and files: Warn/Block. SmartScreen stops most downloaded malware.'
    }

    # Local accounts (SID-based, names are localized)
    $users = @(Invoke-Safely -Name 'Security.LocalUsers' -Default @() -Quiet -ScriptBlock { @(Get-LocalUser -ErrorAction Stop) })
    # Get-LocalGroupMember resolves every member SID; with domain members and an unreachable domain controller
    # that took 33 s on the test machine, so on domain-joined PCs the membership list is skipped.
    $admins = @()
    $adminsNote = ''
    if ($ctx['IsDomainJoined']) { $adminsNote = 'skipped on a domain-joined PC (domain SID lookups can take 30+ s)' }
    else { $admins = @(Invoke-Safely -Name 'Security.LocalAdmins' -Default @() -Quiet -ScriptBlock { @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop) }) }
    $userRows = New-Object 'System.Collections.Generic.List[object]'
    $adminNames = @($admins | ForEach-Object { [string]$_.Name })
    foreach ($u in $users) {
        if ($null -eq $u) { continue }
        $sid = [string]$u.SID
        $rid = -1
        if ($sid -match '-(\d+)$') { $rid = [int]$Matches[1] }
        $isAdmin = $false
        foreach ($an in $adminNames) { if ($an -match ('\\' + [regex]::Escape([string]$u.Name) + '$') -or $an -ieq [string]$u.Name) { $isAdmin = $true } }
        $userRows.Add([ordered]@{ Name = [string]$u.Name; Enabled = $u.Enabled; IsAdministrator = $isAdmin; RID = $rid; PasswordRequired = $u.PasswordRequired; PasswordLastSet = $u.PasswordLastSet; LastLogon = $u.LastLogon; Description = [string]$u.Description })
        if ($u.Enabled -eq $true -and $u.PasswordRequired -eq $false -and $rid -ne 501) {
            Add-Finding -Severity Warning -Category 'Security' -RuleId 'SEC-ACCT' -Title ('Enabled local account "{0}" requires no password' -f $u.Name) -Detail ('SID {0}' -f $sid) -Recommendation 'Set a password or disable the account.'
        }
        if ($u.Enabled -eq $true -and $rid -eq 500) {
            Add-Finding -Severity Info -Category 'Security' -RuleId 'SEC-ACCT-ADMIN500' -Title 'The built-in Administrator account is enabled' -Detail ([string]$u.Name) -Recommendation 'Usually disabled on home PCs; disable it unless needed.'
        }
    }
    $sec['LocalUsers'] = $userRows.ToArray()
    if ($adminsNote -ne '') { $sec['LocalAdministrators'] = $adminsNote }
    else { $sec['LocalAdministrators'] = @($admins | ForEach-Object { [ordered]@{ Name = [string]$_.Name; ObjectClass = [string]$_.ObjectClass; Source = [string]$_.PrincipalSource } }) }
    $localAdminsEnabled = @($userRows | Where-Object { $_['IsAdministrator'] -and $_['Enabled'] -eq $true -and $_['RID'] -ne 500 })
    if ($localAdminsEnabled.Count -gt 2 -and -not $ctx['IsDomainJoined']) {
        Add-Finding -Severity Warning -Category 'Security' -RuleId 'SEC-ACCT' -Title ('{0} enabled local administrator accounts' -f $localAdminsEnabled.Count) -Detail (@($localAdminsEnabled | ForEach-Object { $_['Name'] }) -join ', ') -Recommendation 'Review local administrators; remove or demote unknown accounts (malware sometimes creates its own).'
    }

    # User profiles
    $profs = @(Get-CimSafe -ClassName Win32_UserProfile -Property @('LocalPath', 'LastUseTime', 'Loaded', 'SID', 'Special'))
    $profRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($p in $profs) {
        if ($null -eq $p -or $p.Special -eq $true) { continue }
        $profRows.Add([ordered]@{ LocalPath = [string]$p.LocalPath; Loaded = $p.Loaded; LastUseTime = $p.LastUseTime; SID = [string]$p.SID })
    }
    $sec['UserProfiles'] = $profRows.ToArray()
    $sec['UserProfileCount'] = $profRows.Count
    return $sec
}


# ---------------------------------------------------------------------------------------------
# 12. Event logs
# ---------------------------------------------------------------------------------------------
function Get-WdInvEvents {
    [CmdletBinding()]
    param()
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}
    $since14 = (Get-Date).AddDays(-14)
    $since30 = (Get-Date).AddDays(-30)
    $since90 = (Get-Date).AddDays(-90)
    $allGroups = New-Object 'System.Collections.Generic.List[object]'
    $noisy = @($script:Rules['NoisyEventProviders'] | ForEach-Object { [string]$_ })
    # Every Get-WinEvent query is capped: an event flood (one error per second from a driver, a WHEA-17 storm on an
    # enlarged log) is exactly what the rules look for, and without a cap it would cost ~1 ms and ~2 KB per record.
    # Count-based rules report ">= N" when a cap was hit; the JSON section records Capped = $true.
    $capLarge = 20000
    $capMedium = 10000
    $capSmall = 2000
    # Each numbered sub-step runs in its own Invoke-Safely so that one failing query or a malformed event can never
    # discard the whole Events section (and events.csv); the failure is logged and listed under Collection errors.

    # 12.1 errors/criticals by provider (14 d)
    $null = Invoke-Safely -Name 'Events.ErrorsByProvider' -Default $null -ScriptBlock {
        foreach ($log in @('System', 'Application')) {
            $ev = @(Get-WinEventSafe -FilterHashtable @{ LogName = $log; Level = @(1, 2); StartTime = $since14 } -MaxEvents $capLarge)
            $capped = ($ev.Count -ge $capLarge)
            $groups = @(Get-WdInvEventGroups -Events $ev -Log $log)
            foreach ($g in $groups) { $allGroups.Add($g) }
            $byProvider = @{}
            foreach ($g in $groups) { $pn = [string]$g.Provider; if (-not $byProvider.ContainsKey($pn)) { $byProvider[$pn] = 0 }; $byProvider[$pn] = $byProvider[$pn] + [int]$g.Count }
            $provRows = @($byProvider.Keys | ForEach-Object { [pscustomobject]@{ Provider = $_; Count = $byProvider[$_]; Noisy = ($noisy -contains $_) } } | Sort-Object -Property @{ Expression = 'Count'; Descending = $true })
            $sec[$log + 'ErrorsByProvider14d'] = $provRows
            $sec[$log + 'ErrorCount14d'] = $ev.Count
            $sec[$log + 'ErrorCount14dCapped'] = $capped
            $sec[$log + 'TopErrors14d'] = @($groups | Select-Object -First 15)
            if ($capped) { Write-Log -Level Info -Message ('{0} log: more than {1} errors/criticals in 14 days; only the newest {1} were analysed.' -f $log, $capLarge) }
            foreach ($pr in $provRows) {
                if ($pr.Count -gt 50 -and -not $pr.Noisy) {
                    $cntText = [string]$pr.Count
                    if ($capped) { $cntText = '>= ' + $cntText }
                    Add-Finding -Severity Info -Category 'Events' -RuleId 'EVT-NOISY' -Title ('{0} errors from "{1}" in the {2} log (14 days)' -f $cntText, $pr.Provider, $log) -Detail (@($groups | Where-Object { $_.Provider -eq $pr.Provider } | Select-Object -First 3 | ForEach-Object { 'id {0} x{1}: {2}' -f $_.Id, $_.Count, $_.SampleMessage }) -join ' | ') -Recommendation 'A component fails repeatedly; check the sample message and the component (driver/service/app).'
                }
            }
        }
    }

    # 12.2 unexpected shutdowns / BSOD
    $null = Invoke-Safely -Name 'Events.Crashes' -Default $null -ScriptBlock {
        $kp41 = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41; StartTime = $since90 } -MaxEvents $capSmall)
        $bug = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001; StartTime = $since90 } -MaxEvents $capSmall)
        $e6008 = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'EventLog'; Id = 6008; StartTime = $since90 } -MaxEvents $capSmall)
        $bsod = New-Object 'System.Collections.Generic.List[object]'
        $powerLoss = 0
        foreach ($e in $kp41) {
            $code = Get-WdInvEventProperty -Event $e -Index 0
            $codeInt = 0
            try { $codeInt = [int64]$code } catch { }
            if ($codeInt -ne 0) { $bsod.Add([ordered]@{ Time = $e.TimeCreated; Source = 'Kernel-Power 41'; BugcheckCode = ('0x{0:X}' -f $codeInt) }) } else { $powerLoss++ }
        }
        foreach ($e in $bug) { $bsod.Add([ordered]@{ Time = $e.TimeCreated; Source = 'BugCheck 1001'; BugcheckCode = [string](Get-WdInvEventProperty -Event $e -Index 0); Dump = [string](Get-WdInvEventProperty -Event $e -Index 1) }) }
        $sec['Crashes90d'] = [ordered]@{ KernelPower41 = $kp41.Count; KernelPower41_PowerLoss = $powerLoss; BugCheck1001 = $bug.Count; UnexpectedShutdown6008 = $e6008.Count; Bsod = $bsod.ToArray() }
        if ($bsod.Count -gt 0) {
            $sev = 'Warning'
            if ($bsod.Count -ge 3) { $sev = 'Critical' }
            $codes = @($bsod | ForEach-Object { $_['BugcheckCode'] } | Select-Object -Unique) -join ', '
            Add-Finding -Severity $sev -Category 'Events' -RuleId 'PWR-41' -Title ('{0} blue screen(s) (BSOD) in 90 days' -f $bsod.Count) -Detail ('Bugcheck codes: {0}; last: {1}' -f $codes, (ConvertTo-InvariantString -Value $bsod[0]['Time'])) `
                -Recommendation 'Analyse the minidumps (WinDbg / BlueScreenView): most BSODs come from drivers, RAM, overheating or a failing disk. Update drivers, run memtest, check SMART.'
        }
        if ($powerLoss -ge 3) {
            Add-Finding -Severity Warning -Category 'Events' -RuleId 'PWR-41-0' -Title ('{0} hard power-offs in 90 days (Kernel-Power 41, no bugcheck)' -f $powerLoss) -Detail ('Unexpected shutdown events (6008): {0}' -f $e6008.Count) `
                -Recommendation 'The PC lost power or was switched off by holding the power button: failing PSU/adapter, overheating shutdowns, or the user forcing a reboot because the PC hangs.'
        }
    }

    # 12.3 WHEA
    $null = Invoke-Safely -Name 'Events.Whea' -Default $null -ScriptBlock {
        $whea = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; StartTime = $since90 } -MaxEvents $capLarge)
        $wheaCapped = ($whea.Count -ge $capLarge)
        $wheaIds = @{}
        foreach ($e in $whea) { $k = [int]$e.Id; if (-not $wheaIds.ContainsKey($k)) { $wheaIds[$k] = 0 }; $wheaIds[$k] = $wheaIds[$k] + 1 }
        $sec['Whea90d'] = @($wheaIds.Keys | Sort-Object | ForEach-Object { [ordered]@{ Id = $_; Count = $wheaIds[$_] } })
        $sec['Whea90dCapped'] = $wheaCapped
        $fatal = 0
        foreach ($k in @(1, 18, 19, 20, 46, 47)) { if ($wheaIds.ContainsKey($k)) { $fatal += $wheaIds[$k] } }
        if ($fatal -gt 0) {
            Add-Finding -Severity Critical -Category 'Events' -RuleId 'MEM-DIAG' -Title ('{0} WHEA hardware error(s) (CPU/memory/cache) in 90 days' -f $fatal) -Detail (@($wheaIds.Keys | Sort-Object | ForEach-Object { 'id {0} x{1}' -f $_, $wheaIds[$_] }) -join ', ') `
                -Recommendation 'Machine-check errors: remove overclock/undervolt/XMP, run memtest86, check CPU temperatures and the power supply.'
        } elseif ($wheaIds.ContainsKey(17) -and $wheaIds[17] -gt 100) {
            $cntText = [string]$wheaIds[17]
            if ($wheaCapped) { $cntText = '>= ' + $cntText }
            Add-Finding -Severity Info -Category 'Events' -RuleId 'WHEA-17' -Title ('{0} corrected PCIe errors (WHEA 17) in 90 days' -f $cntText) -Detail 'Corrected errors are usually benign but a flood points to a flaky PCIe/NVMe link or driver.' -Recommendation 'Update chipset/GPU/NVMe drivers and firmware; reseat the card.'
        }
    }

    # 12.4 boot type
    $null = Invoke-Safely -Name 'Events.BootTypes' -Default $null -ScriptBlock {
        $boots = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Boot'; Id = 27; StartTime = $since14 } -MaxEvents $capSmall)
        $bootTypes = @($boots | ForEach-Object { [int](Get-WdInvEventProperty -Event $_ -Index 0) })
        $sec['BootTypes14d'] = [ordered]@{ Count = $boots.Count; FullBoot = @($bootTypes | Where-Object { $_ -eq 0 }).Count; ResumeHibernate = @($bootTypes | Where-Object { $_ -eq 1 }).Count; FastStartup = @($bootTypes | Where-Object { $_ -eq 2 }).Count }
        if ($boots.Count -ge 3 -and @($bootTypes | Where-Object { $_ -eq 0 }).Count -eq 0) {
            Add-Finding -Severity Info -Category 'Events' -RuleId 'SYS-UPTIME' -Title 'No full restart in the last 14 days (every boot was Fast Startup/hibernate resume)' -Detail ('{0} boots, all type 1/2 (Kernel-Boot 27).' -f $boots.Count) -Recommendation 'Do a real Restart (Start > Power > Restart). "Shut down" with Fast Startup keeps the kernel session alive.'
        }
    }

    # 12.5 boot performance (admin)
    if ($script:IsAdmin) {
        $null = Invoke-Safely -Name 'Events.BootPerformance' -Default $null -ScriptBlock {
            $bp = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = 100; StartTime = $since30 } -MaxEvents $capSmall)
            $bootRows = New-Object 'System.Collections.Generic.List[object]'
            foreach ($e in $bp) {
                # Event 100 template: [1] BootStartTime (FILETIME -> DateTime), [5] BootTime, [6] MainPathBootTime,
                # [19] BootPostBootTime (UInt32 milliseconds). Values are coerced to [int64] or $null so a stray type
                # can never abort the rule.
                $bt = ConvertTo-WdInvInt64 -Value (Get-WdInvEventProperty -Event $e -Index 5)
                $mp = ConvertTo-WdInvInt64 -Value (Get-WdInvEventProperty -Event $e -Index 6)
                $pb = ConvertTo-WdInvInt64 -Value (Get-WdInvEventProperty -Event $e -Index 19)
                $bootRows.Add([ordered]@{ Time = $e.TimeCreated; BootTimeMs = $bt; MainPathBootTimeMs = $mp; PostBootTimeMs = $pb })
            }
            $sec['BootPerformance30d'] = $bootRows.ToArray()
            $slowLimit = 120000
            if ($ctx['SystemMediaType'] -eq 'HDD') { $slowLimit = 300000 }
            $slow = @($bootRows | Where-Object { $null -ne $_['BootTimeMs'] -and [int64]$_['BootTimeMs'] -gt $slowLimit })
            if ($slow.Count -gt 0 -and $bootRows.Count -gt 0 -and $slow.Count -ge [math]::Ceiling($bootRows.Count / 2)) {
                Add-Finding -Severity Warning -Category 'Events' -RuleId 'BOOT-SLOW' -Title ('Slow boot: {0} of {1} boots took more than {2} s' -f $slow.Count, $bootRows.Count, ($slowLimit / 1000)) -Detail (@($bootRows | Select-Object -First 5 | ForEach-Object { '{0}: {1} ms' -f (ConvertTo-InvariantString -Value $_['Time']), (ConvertTo-InvariantString -Value $_['BootTimeMs']) }) -join '; ') -Recommendation 'Reduce autostart programs and services; on an HDD move to an SSD.'
            }
            $deg = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'Microsoft-Windows-Diagnostics-Performance/Operational'; Id = @(101, 102, 103, 106, 108, 109, 110); StartTime = $since30 } -MaxEvents $capMedium)
            $degByFile = @{}
            foreach ($e in $deg) { $f = [string](Get-WdInvEventProperty -Event $e -Index 2); if ($f -eq '') { $f = '(unknown)' }; if (-not $degByFile.ContainsKey($f)) { $degByFile[$f] = 0 }; $degByFile[$f] = $degByFile[$f] + 1 }
            $sec['BootDegradation30d'] = @($degByFile.Keys | ForEach-Object { [pscustomobject]@{ Component = $_; Count = $degByFile[$_] } } | Sort-Object -Property @{ Expression = 'Count'; Descending = $true } | Select-Object -First 15)
        }
    } else {
        $sec['BootPerformance30d'] = Add-WdInvAdminGap -Item 'Boot performance events (Diagnostics-Performance 100-110: boot time, degrading drivers/apps)' -Detail 'log is readable only by administrators'
    }

    # 12.6 storage errors
    $null = Invoke-Safely -Name 'Events.Storage' -Default $null -ScriptBlock {
        $stoProviders = @('disk', 'storahci', 'stornvme', 'iaStorA', 'iaStorAC', 'iaStorAVC', 'iaStorV', 'amdsata', 'amd_sata', 'amdsbs', 'Ntfs', 'Microsoft-Windows-Ntfs', 'volmgr', 'partmgr', 'nvme', 'storport', 'Microsoft-Windows-StorPort', 'volsnap', 'usbstor', 'UASPStor')
        # Ntfs 98 ("volume is healthy") is informational and is deliberately not queried.
        $stoEv = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; Id = @(7, 11, 51, 55, 129, 130, 140, 153, 157); StartTime = $since90 } -MaxEvents $capMedium | Where-Object { $stoProviders -contains [string]$_.ProviderName -and [int]$_.Level -le 3 })
        $stoGroups = @(Get-WdInvEventGroups -Events $stoEv -Log 'System')
        foreach ($g in $stoGroups) { $allGroups.Add($g) }
        $sec['StorageErrors90d'] = $stoGroups
        # Storport/Operational is readable only by administrators; the FilterHashtable form of Get-WinEvent then
        # reports "No events were found" instead of access denied, so the gap must be marked explicitly.
        $storport = @()
        if ($script:IsAdmin) {
            $storport = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'Microsoft-Windows-Storage-Storport/Operational'; Level = @(1, 2, 3); StartTime = $since30 } -MaxEvents $capMedium)
            $storportGroups = @(Get-WdInvEventGroups -Events $storport -Log 'Microsoft-Windows-Storage-Storport/Operational')
            $sec['StorportWarnings30d'] = @($storportGroups | Select-Object -First 10)
        } else {
            $sec['StorportWarnings30d'] = Add-WdInvAdminGap -Item 'Storport high-latency/warning events (Storport/Operational 500/505)' -Detail 'log is readable only by administrators'
        }
        $critIds = @($stoEv | Where-Object { [int]$_.Id -in @(7, 51, 55) })
        $resetIds = @($stoEv | Where-Object { [int]$_.Id -in @(11, 129, 153, 157) })
        $flushIds = @($stoEv | Where-Object { [int]$_.Id -in @(130, 140) })
        if ($critIds.Count -gt 0) {
            Add-Finding -Severity Critical -Category 'Events' -RuleId 'STO-EVT' -Title ('{0} disk I/O / file-system error event(s) in 90 days' -f $critIds.Count) -Detail (@($stoGroups | Where-Object { $_.Id -in @(7, 51, 55) } | ForEach-Object { '{0} id {1} x{2} (last {3})' -f $_.Provider, $_.Id, $_.Count, (ConvertTo-InvariantString -Value $_.Last) }) -join '; ') `
                -Recommendation 'Bad blocks (disk 7), paging errors (51) or NTFS corruption (55): back up, run chkdsk /f, check SMART and the SATA cable; replace the disk if errors continue.'
        }
        if ($flushIds.Count -ge 3) {
            Add-Finding -Severity Warning -Category 'Events' -RuleId 'STO-FLUSH' -Title ('{0} NTFS flush/transaction-log failure event(s) in 90 days (Ntfs 130/140)' -f $flushIds.Count) -Detail (@($stoGroups | Where-Object { $_.Id -in @(130, 140) } | ForEach-Object { '{0} id {1} x{2} (last {3})' -f $_.Provider, $_.Id, $_.Count, (ConvertTo-InvariantString -Value $_.Last) }) -join '; ') `
                -Recommendation 'The disk stopped answering writes for a moment (USB disks unplugged, sleeping drives, failing SSD or cable). If the volume is the system drive, check SMART and cables.'
        }
        if ($resetIds.Count -ge 3) {
            Add-Finding -Severity Warning -Category 'Events' -RuleId 'STO-RESET' -Title ('{0} storage controller reset/retry event(s) in 90 days' -f $resetIds.Count) -Detail (@($stoGroups | Where-Object { $_.Id -in @(11, 129, 153, 157) } | ForEach-Object { '{0} id {1} x{2}' -f $_.Provider, $_.Id, $_.Count }) -join '; ') `
                -Recommendation 'Each reset freezes the PC for seconds: update the storage driver/SSD firmware, replace the SATA cable/power connector, disable aggressive link power management (LPM).'
        }
        $latencyEvents = @($storport | Where-Object { [int]$_.Id -in @(500, 505) })
        if ($latencyEvents.Count -ge 10) {
            Add-Finding -Severity Warning -Category 'Events' -RuleId 'STO-LAT' -Title ('{0} Storport high-latency events in 30 days' -f $latencyEvents.Count) -Detail 'Microsoft-Windows-Storage-Storport/Operational id 500/505.' -Recommendation 'The disk regularly takes seconds to answer: check SMART, cables, firmware; on an HDD consider an SSD.'
        }
    }

    # 12.7 application crashes / hangs
    $null = Invoke-Safely -Name 'Events.AppCrashes' -Default $null -ScriptBlock {
        $crash = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Error'; Id = 1000; StartTime = $since14 } -MaxEvents $capMedium)
        $hang = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'Application'; ProviderName = 'Application Hang'; Id = 1002; StartTime = $since14 } -MaxEvents $capMedium)
        $crashByApp = @{}
        $moduleByApp = @{}
        foreach ($e in $crash) {
            $app = [string](Get-WdInvEventProperty -Event $e -Index 0)
            if ($app -eq '') { $app = '(unknown)' }
            if (-not $crashByApp.ContainsKey($app)) { $crashByApp[$app] = 0; $moduleByApp[$app] = [string](Get-WdInvEventProperty -Event $e -Index 3) }
            $crashByApp[$app] = $crashByApp[$app] + 1
        }
        $hangByApp = @{}
        foreach ($e in $hang) { $app = [string](Get-WdInvEventProperty -Event $e -Index 0); if ($app -eq '') { $app = '(unknown)' }; if (-not $hangByApp.ContainsKey($app)) { $hangByApp[$app] = 0 }; $hangByApp[$app] = $hangByApp[$app] + 1 }
        $sec['AppCrashes14d'] = @($crashByApp.Keys | ForEach-Object { [pscustomobject]@{ Application = $_; Count = $crashByApp[$_]; FaultingModule = $moduleByApp[$_] } } | Sort-Object -Property @{ Expression = 'Count'; Descending = $true })
        $sec['AppHangs14d'] = @($hangByApp.Keys | ForEach-Object { [pscustomobject]@{ Application = $_; Count = $hangByApp[$_] } } | Sort-Object -Property @{ Expression = 'Count'; Descending = $true })
        $sec['AppCrashes14dCapped'] = ($crash.Count -ge $capMedium -or $hang.Count -ge $capMedium)
        foreach ($app in $crashByApp.Keys) {
            $n = $crashByApp[$app]
            if ($n -ge 5 -or ($app -match '^(explorer|dwm|svchost|lsass|services|winlogon|csrss)\.exe$' -and $n -ge 2)) {
                Add-Finding -Severity Warning -Category 'Events' -RuleId 'APP-CRASH' -Title ('{0} crashed {1} times in 14 days' -f $app, $n) -Detail ('Faulting module: {0}' -f $moduleByApp[$app]) -Recommendation 'Repeated crashes of one program: update/reinstall it; if the faulting module is a system DLL or driver, suspect RAM, disk or a shell extension/antivirus hook.'
            }
        }
        if ($hang.Count -ge 5) {
            Add-Finding -Severity Warning -Category 'Events' -RuleId 'APP-HANG' -Title ('{0} application hangs in 14 days' -f $hang.Count) -Detail (@($sec['AppHangs14d'] | Select-Object -First 5 | ForEach-Object { '{0} x{1}' -f $_.Application, $_.Count }) -join ', ') -Recommendation 'Frequent "Not responding": typical of a saturated disk, RAM shortage or a bad driver. See the Storage/Memory findings.'
        }
    }

    # 12.8 service failures / timeouts, 7045 new services
    $null = Invoke-Safely -Name 'Events.Services' -Default $null -ScriptBlock {
        $scm = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = @(7000, 7009, 7011, 7022, 7023, 7024, 7031, 7034, 7043); StartTime = $since14 } -MaxEvents $capMedium)
        $scmGroups = @(Get-WdInvEventGroups -Events $scm -Log 'System')
        foreach ($g in $scmGroups) { $allGroups.Add($g) }
        $sec['ServiceEvents14d'] = $scmGroups
        $timeouts = @($scm | Where-Object { [int]$_.Id -in @(7009, 7011, 7022) })
        if ($timeouts.Count -ge 3) {
            # 7009/7011: property 0 is the timeout in ms, property 1 the service name; 7022: property 0 is the service.
            $svcNames = @($timeouts | ForEach-Object { $idx = 1; if ([int]$_.Id -eq 7022) { $idx = 0 }; [string](Get-WdInvEventProperty -Event $_ -Index $idx) } | Where-Object { $_ -ne '' -and $_ -notmatch '^\d+$' } | Select-Object -Unique | Select-Object -First 8) -join ', '
            Add-Finding -Severity Warning -Category 'Events' -RuleId 'SVC-TIMEOUT' -Title ('{0} service start/stop timeouts in 14 days' -f $timeouts.Count) -Detail ('Services: {0}' -f $svcNames) -Recommendation 'Services waiting 30 s at boot make logon slow; disable/repair the named services or their dependencies.'
        }
        $crashSvc = @{}
        foreach ($e in @($scm | Where-Object { [int]$_.Id -in @(7031, 7034) })) { $sn = [string](Get-WdInvEventProperty -Event $e -Index 0); if (-not $crashSvc.ContainsKey($sn)) { $crashSvc[$sn] = 0 }; $crashSvc[$sn] = $crashSvc[$sn] + 1 }
        foreach ($sn in $crashSvc.Keys) {
            if ($crashSvc[$sn] -ge 3) { Add-Finding -Severity Warning -Category 'Events' -RuleId 'SVC-CRASH' -Title ('Service "{0}" crashed {1} times in 14 days' -f $sn, $crashSvc[$sn]) -Detail 'Service Control Manager 7031/7034.' -Recommendation 'Reinstall/update the program owning the service, or disable it if unneeded.' }
        }
        $newSvc = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Service Control Manager'; Id = 7045; StartTime = $since90 } -MaxEvents $capSmall)
        $newRows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($e in $newSvc) {
            $sn = [string](Get-WdInvEventProperty -Event $e -Index 0)
            $img = [string](Get-WdInvEventProperty -Event $e -Index 1)
            $acct = [string](Get-WdInvEventProperty -Event $e -Index 4)
            $info = Get-WdInvCommandInfo -Command $img
            $cls = Get-WdInvCommandFlags -Info $info
            $susp = ($cls['Suspicious'] -or [string]$info['FileName'] -match '^(powershell|pwsh|cmd|mshta|wscript|cscript)(\.exe)?$')
            # Matched on the original image path; stored and reported secret-masked (a VPN service installed with its key on the command line).
            $imgMasked = Hide-WdSecret -Text $img
            $newRows.Add([pscustomobject][ordered]@{ Time = $e.TimeCreated; Service = $sn; ImagePath = $imgMasked; Account = $acct; LocationClass = [string]$cls['LocationClass']; Flags = (@($cls['Flags']) -join ';'); Suspicious = $susp })
            if ($susp) {
                Add-Finding -Severity Critical -Category 'Events' -RuleId 'SVC-NEW' -Title ('Suspicious service installed on {0}: {1}' -f (ConvertTo-InvariantString -Value $e.TimeCreated), $sn) -Detail ('Image path: {0}; account {1}; flags {2}' -f $imgMasked, $acct, (@($cls['Flags']) -join ';')) -Recommendation 'A service running a script host or a binary from a suspicious folder is typical for miners/backdoors. Check whether it still exists (services.csv), remove it and its file, full scan.'
            }
        }
        $sec['ServicesInstalled90d'] = $newRows.ToArray()
    }

    # 12.9 resource exhaustion
    $null = Invoke-Safely -Name 'Events.ResourceExhaustion' -Default $null -ScriptBlock {
        $oom = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Resource-Exhaustion-Detector'; Id = 2004; StartTime = $since30 } -MaxEvents $capSmall)
        $oomRows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($e in $oom) {
            $consumers = @()
            try { $consumers = @($e.Properties | ForEach-Object { [string]$_.Value } | Where-Object { $_ -match '\.exe$' } | Select-Object -First 3) } catch { }
            $oomRows.Add([ordered]@{ Time = $e.TimeCreated; TopConsumers = ($consumers -join ', ') })
        }
        $sec['OutOfMemory30d'] = $oomRows.ToArray()
        if ($oom.Count -gt 0) {
            $sev = 'Warning'
            if ($oom.Count -ge 5) { $sev = 'Critical' }
            Add-Finding -Severity $sev -Category 'Events' -RuleId 'MEM-OOM' -Title ('Windows ran out of memory {0} time(s) in 30 days' -f $oom.Count) -Detail (@($oomRows | Select-Object -First 5 | ForEach-Object { '{0}: {1}' -f (ConvertTo-InvariantString -Value $_['Time']), $_['TopConsumers'] }) -join '; ') -Recommendation 'Resource-Exhaustion-Detector 2004: the listed programs consumed the virtual memory. Add RAM, keep the page file system-managed, close/uninstall the consumers.'
        }
    }

    # 12.10 crash dumps
    $null = Invoke-Safely -Name 'Events.CrashDumps' -Default $null -ScriptBlock {
        $dumpRows = New-Object 'System.Collections.Generic.List[object]'
        $sysRoot = [string]$env:SystemRoot
        $dumpPaths = @(
            @{ Path = [IO.Path]::Combine($sysRoot, 'Minidump'); Kind = 'Minidump' },
            @{ Path = [IO.Path]::Combine($sysRoot, 'LiveKernelReports'); Kind = 'LiveKernelReports' },
            @{ Path = [IO.Path]::Combine([string]$env:LOCALAPPDATA, 'CrashDumps'); Kind = 'UserCrashDumps' },
            @{ Path = [IO.Path]::Combine([string]$env:ProgramData, 'Microsoft\Windows\WER\ReportQueue'); Kind = 'WER ReportQueue' }
        )
        $minidumps90 = 0
        $watchdog = 0
        foreach ($dp in $dumpPaths) {
            if (-not (Test-DirectoryExists -Path $dp.Path)) { continue }
            $items = $null
            try { $items = @(Get-ChildItem -LiteralPath $dp.Path -Force -Recurse -ErrorAction Stop | Where-Object { -not $_.PSIsContainer }) } catch { $items = $null }
            if ($null -eq $items) {
                $dumpRows.Add([ordered]@{ Kind = $dp.Kind; Path = $dp.Path; Files = $null; Bytes = $null; Newest = $null; Note = (Add-WdInvAdminGap -Item ('Crash dump folder ' + $dp.Path) -Detail 'access denied') })
                continue
            }
            $bytes = [int64]0
            $newest = $null
            foreach ($it in $items) { $bytes += [int64]$it.Length; if ($null -eq $newest -or $it.LastWriteTime -gt $newest) { $newest = $it.LastWriteTime } }
            $dumpRows.Add([ordered]@{ Kind = $dp.Kind; Path = $dp.Path; Files = $items.Count; Bytes = $bytes; Size = (Format-Bytes -Bytes $bytes); Newest = $newest; Note = '' })
            if ($dp.Kind -eq 'Minidump') { $minidumps90 = @($items | Where-Object { $_.LastWriteTime -gt $since90 }).Count }
            if ($dp.Kind -eq 'LiveKernelReports') { $watchdog = @($items | Where-Object { $_.FullName -match 'WATCHDOG' -and $_.LastWriteTime -gt $since90 }).Count }
        }
        $memDmp = Get-FileSizeSafe -Path ([IO.Path]::Combine($sysRoot, 'MEMORY.DMP'))
        if ($null -ne $memDmp) { $dumpRows.Add([ordered]@{ Kind = 'MEMORY.DMP'; Path = [IO.Path]::Combine($sysRoot, 'MEMORY.DMP'); Files = 1; Bytes = $memDmp; Size = (Format-Bytes -Bytes $memDmp); Newest = $(try { (New-Object IO.FileInfo([IO.Path]::Combine($sysRoot, 'MEMORY.DMP'))).LastWriteTime } catch { $null }); Note = '' }) }
        $cc = Get-WdInvRegistryValues -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
        $sec['CrashDumps'] = [ordered]@{ Folders = $dumpRows.ToArray(); CrashDumpEnabled = $cc['CrashDumpEnabled']; DumpFile = (Get-WdInvString -Value $cc['DumpFile']); MinidumpDir = (Get-WdInvString -Value $cc['MinidumpDir']); AutoReboot = $cc['AutoReboot'] }
        if ($minidumps90 -gt 0 -or $watchdog -gt 0) {
            Add-Finding -Severity Warning -Category 'Events' -RuleId 'DMP-PRESENT' -Title ('{0} kernel minidump(s) and {1} watchdog live dump(s) written in 90 days' -f $minidumps90, $watchdog) -Detail (@($dumpRows | Where-Object { $_['Kind'] -in @('Minidump', 'LiveKernelReports') } | ForEach-Object { '{0}: {1} files, newest {2}' -f $_['Kind'], $_['Files'], (ConvertTo-InvariantString -Value $_['Newest']) }) -join '; ') `
                -Recommendation 'Kernel crashes/GPU watchdog resets were recorded; analyse the dumps (WinDbg) or at least note the dates against driver installations.'
        }
        if ($null -ne $cc['CrashDumpEnabled'] -and [int]$cc['CrashDumpEnabled'] -eq 0) {
            Add-Finding -Severity Info -Category 'Events' -RuleId 'DMP-DISABLED' -Title 'Crash dumps are disabled' -Detail 'CrashControl CrashDumpEnabled=0' -Recommendation 'Enable "Automatic memory dump" (System > Advanced > Startup and Recovery) so BSODs can be analysed.'
        }
    }
    if (-not $sec.Contains('CrashDumps')) { $sec['CrashDumps'] = [ordered]@{ Folders = @(); CrashDumpEnabled = $null; DumpFile = ''; MinidumpDir = ''; AutoReboot = $null } }

    # 12.11 reliability monitor
    $null = Invoke-Safely -Name 'Events.Reliability' -Default $null -ScriptBlock {
        $rel = @(Get-CimSafe -ClassName Win32_ReliabilityRecords -TimeoutSec 60 -Property @('TimeGenerated', 'SourceName', 'EventIdentifier', 'ProductName', 'Message'))
        $relRows = New-Object 'System.Collections.Generic.List[object]'
        foreach ($r in @($rel | Where-Object { $null -ne $_.TimeGenerated -and [DateTime]$_.TimeGenerated -gt $since90 } | Sort-Object -Property TimeGenerated -Descending | Select-Object -First 60)) {
            $msg = [string]$r.Message
            if ($null -eq $msg) { $msg = '' }
            $msg = Hide-WdSecret -Text (($msg -replace '\s+', ' ').Trim())
            if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
            $relRows.Add([ordered]@{ Time = $r.TimeGenerated; Source = [string]$r.SourceName; EventId = $r.EventIdentifier; Product = [string]$r.ProductName; Message = $msg })
        }
        $sec['ReliabilityRecords90d'] = $relRows.ToArray()
        $metrics = @(Get-CimSafe -ClassName Win32_ReliabilityStabilityMetrics -Property @('TimeGenerated', 'SystemStabilityIndex'))
        $latest = $null
        foreach ($m in $metrics) { if ($null -ne $m -and ($null -eq $latest -or $m.TimeGenerated -gt $latest.TimeGenerated)) { $latest = $m } }
        $idx = $null
        if ($null -ne $latest) { $idx = Get-WdInvNum -Value $latest.SystemStabilityIndex -Decimals 2 }
        $sec['StabilityIndex'] = [ordered]@{ Value = $idx; Time = $(if ($null -ne $latest) { $latest.TimeGenerated } else { $null }) }
        if ($null -ne $idx) {
            if ($idx -lt 3) { Add-Finding -Severity Critical -Category 'Events' -RuleId 'REL-LOW' -Title ('Reliability index is {0} / 10' -f (Format-WdInvNum $idx 1)) -Detail 'Win32_ReliabilityStabilityMetrics (Reliability Monitor).' -Recommendation 'Frequent crashes and failures; open Reliability Monitor (perfmon /rel) for the timeline.' }
            elseif ($idx -lt 5) { Add-Finding -Severity Warning -Category 'Events' -RuleId 'REL-LOW' -Title ('Reliability index is {0} / 10' -f (Format-WdInvNum $idx 1)) -Detail 'Win32_ReliabilityStabilityMetrics (Reliability Monitor).' -Recommendation 'Several failures recently; open Reliability Monitor (perfmon /rel) for the timeline.' }
        }
    }

    # 12.13 Security log (admin only; Get-WinEventSafe records the skip otherwise)
    $null = Invoke-Safely -Name 'Events.SecurityLog' -Default $null -ScriptBlock {
        $secEv = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'Security'; Id = @(4720, 4732, 4728, 4756); StartTime = $since90 } -MaxEvents $capSmall)
        if ($script:IsAdmin) {
            $sec['SecurityAccountChanges90d'] = @(Get-WdInvEventGroups -Events $secEv -Log 'Security')
            if ($secEv.Count -gt 0) {
                Add-Finding -Severity Warning -Category 'Events' -RuleId 'SEC-ACCT-EVT' -Title ('{0} account creation / admin-group change event(s) in 90 days' -f $secEv.Count) -Detail (@($secEv | Select-Object -First 5 | ForEach-Object { '{0} id {1}' -f (ConvertTo-InvariantString -Value $_.TimeCreated), $_.Id }) -join '; ') -Recommendation 'Verify that you created these accounts / group changes yourself.'
            }
        } else {
            $sec['SecurityAccountChanges90d'] = '(requires administrator)'
        }
    }

    $sec['EventGroupsForCsv'] = $allGroups.ToArray()
    return $sec
}

function ConvertTo-WdInvInt64 {
    # [int64] of an event property value, or $null when it is missing or not numeric (DateTime, string, GUID...).
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [DateTime] -or $Value -is [Guid] -or $Value -is [byte[]]) { return $null }
    try {
        if ($Value -is [string]) {
            $v = [int64]0
            if ([int64]::TryParse($Value, [Globalization.NumberStyles]::Integer, (Get-WdInv), [ref]$v)) { return $v }
            return $null
        }
        return [int64]$Value
    } catch { return $null }
}

# ---------------------------------------------------------------------------------------------
# 13. Performance snapshot (process analysis + key background services)
# ---------------------------------------------------------------------------------------------
function Get-WdInvPerformance {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][System.Collections.IDictionary]$Samples, [Parameter(Mandatory = $true)][hashtable]$ProcessMap)
    $ctx = $script:WdInvCtx
    $sec = [ordered]@{}
    $ncpu = [double]$script:NCPU
    if ($ncpu -le 0) { $ncpu = 1 }
    $ownPid = $PID
    $p1 = @{}
    foreach ($p in @($Samples['Process1'])) { if ($null -ne $p -and [string]$p.Name -notin @('_Total', 'Idle')) { $p1[[int]$p.IDProcess] = $p } }
    $rows = New-Object 'System.Collections.Generic.List[object]'
    $totalRam = [double]0
    if ($null -ne $ctx['TotalRamBytes']) { $totalRam = [double]$ctx['TotalRamBytes'] }
    $heavy = @($script:Rules['KnownHeavyProcesses'] | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $suspRegex = [string]$script:Rules['SuspiciousPathRegex']
    $minerRegex = [string]$script:Rules['MinerTokenRegex']
    $sysNames = @($script:Rules['SystemBinaryNames'] | ForEach-Object { ([string]$_).ToLowerInvariant() })
    $seen = @{}
    foreach ($p in @($Samples['Process2'])) {
        if ($null -eq $p -or [string]$p.Name -in @('_Total', 'Idle')) { continue }
        $procId = [int]$p.IDProcess
        $seen[$procId] = $true
        $cpu2 = $null
        if ($null -ne $p.PercentProcessorTime) { $cpu2 = [double]$p.PercentProcessorTime / $ncpu }
        $cpu1 = $null
        if ($p1.ContainsKey($procId) -and $null -ne $p1[$procId].PercentProcessorTime) { $cpu1 = [double]$p1[$procId].PercentProcessorTime / $ncpu }
        $cpuAvg = Get-WdInvAverage -Values @($cpu1, $cpu2)
        $cpuMin = $null
        if ($null -ne $cpu1 -and $null -ne $cpu2) { $cpuMin = [math]::Min($cpu1, $cpu2) } elseif ($null -ne $cpu2) { $cpuMin = $cpu2 }
        $name = [string]$p.Name -replace '#\d+$', ''
        $path = ''
        $cmd = ''
        $parent = $null
        $created = $null
        $exeName = ''
        if ($ProcessMap.ContainsKey($procId)) {
            $wp = $ProcessMap[$procId]
            $path = [string]$wp.ExecutablePath
            $cmd = [string]$wp.CommandLine
            $parent = $wp.ParentProcessId
            $created = $wp.CreationDate
            $exeName = [string]$wp.Name
        }
        if ($exeName -eq '') { $exeName = $name + '.exe' }
        $loc = Get-ProcessLocationClass -Path $path
        $flags = New-Object 'System.Collections.Generic.List[string]'
        $base = $name.ToLowerInvariant()
        if ($path -ne '' -and $path -match $suspRegex) { $flags.Add('SuspiciousPath') }
        if (($path + ' ' + $cmd) -match $minerRegex) { $flags.Add('MinerToken') }
        if (($sysNames -contains $base) -and $path -ne '' -and -not (Test-WdInvSystemBinaryLocation -BaseName $base -Path $path)) { $flags.Add('SystemNameOutsideSystem32') }
        if ($procId -eq $ownPid) { $flags.Add('ThisTool') }
        $parentName = ''
        if ($null -ne $parent -and $ProcessMap.ContainsKey([int]$parent)) { $parentName = [string]$ProcessMap[[int]$parent].Name }
        if ($base -eq 'svchost' -and $parentName -ne '' -and $parentName -ine 'services.exe') { $flags.Add('UnexpectedParent:' + $parentName) }
        $ws = $p.WorkingSetPrivate
        # The miner-token rule above matched the ORIGINAL command line; the row (summary.md, inventory.json,
        # processes-snapshot.csv, PROC-* findings) carries only the secret-masked text (shared Hide-WdSecret).
        $rows.Add([pscustomobject][ordered]@{
            Name = $name; Pid = $procId; ParentPid = $parent; ParentName = $parentName
            CpuPct1 = (Get-WdInvNum -Value $cpu1); CpuPct2 = (Get-WdInvNum -Value $cpu2); CpuPctAvg = $cpuAvg
            WorkingSetPrivateMB = $(if ($null -ne $ws) { Get-WdInvNum -Value ([double]$ws / 1MB) -Decimals 1 } else { $null })
            PrivateBytesMB = $(if ($null -ne $p.PrivateBytes) { Get-WdInvNum -Value ([double]$p.PrivateBytes / 1MB) -Decimals 1 } else { $null })
            IOBytesPerSec = $(if ($null -ne $p.IODataBytesPersec) { [int64]$p.IODataBytesPersec } else { $null })
            HandleCount = $p.HandleCount; ThreadCount = $p.ThreadCount; ElapsedSeconds = $p.ElapsedTime
            Path = $path; CommandLine = (Hide-WdSecret -Text $cmd); LocationClass = $loc; Owner = ''; Created = $created; Flags = ($flags.ToArray() -join ';')
            CpuPctMin = (Get-WdInvNum -Value $cpuMin)
        })
    }
    # Processes only in the first sample (exited meanwhile) are ignored.
    $all = $rows.ToArray()
    $top = @($all | Sort-Object -Property @{ Expression = 'CpuPctAvg'; Descending = $true } | Select-Object -First 25)
    $topMem = @($all | Sort-Object -Property @{ Expression = 'WorkingSetPrivateMB'; Descending = $true } | Select-Object -First 25)
    $topIo = @($all | Sort-Object -Property @{ Expression = 'IOBytesPerSec'; Descending = $true } | Select-Object -First 10)
    # Owners in bulk via the LogonSession associations (two CIM queries, < 1 s for 1000 processes).
    # Invoke-CimMethod GetOwner costs ~0.4 s per process on the test machine and is therefore not used.
    $ownerMap = Invoke-Safely -Name 'Perf.ProcessOwners' -Default @{} -Quiet -ScriptBlock { Get-WdInvProcessOwners }
    if ($null -eq $ownerMap) { $ownerMap = @{} }
    foreach ($r in $all) { if ($ownerMap.ContainsKey([int]$r.Pid)) { $r.Owner = $ownerMap[[int]$r.Pid] } }
    $sec['TopCpu'] = @($top | Select-Object -First 15)
    $sec['TopMemory'] = @($topMem | Select-Object -First 15)
    $sec['TopIO'] = $topIo
    $sec['ProcessCount'] = $all.Count
    $sec['LogicalProcessors'] = [int]$ncpu
    $sec['SampleIntervalSeconds'] = $(if ($null -ne $Samples['Process1Time'] -and $null -ne $Samples['Process2Time']) { Get-WdInvNum -Value (($Samples['Process2Time'] - $Samples['Process1Time']).TotalSeconds) } else { $null })
    $ctx['ProcessRows'] = $all
    $nullPaths = @($all | Where-Object { $_.Path -eq '' }).Count
    if (-not $script:IsAdmin -and $nullPaths -gt 0) { [void](Add-WdInvAdminGap -Item ('Executable path and command line of {0} processes of other users / protected processes' -f $nullPaths) -Detail 'Win32_Process.ExecutablePath is null for them without administrator rights') }

    if ($all.Count -gt 400) {
        Add-Finding -Severity Info -Category 'Performance' -RuleId 'PROC-COUNT' -Title ('{0} processes are running' -f $all.Count) -Detail 'More than 400 processes.' -Recommendation 'Many processes = many autostart programs, browser tabs and background services; review autostart and installed software.'
    }
    foreach ($r in $all) {
        if ($r.Pid -eq $ownPid) { continue }
        $base = $r.Name.ToLowerInvariant()
        $isHeavy = ($heavy -contains $base)
        $susp = ($r.Flags -match 'SuspiciousPath|MinerToken|SystemNameOutsideSystem32')
        if ($null -ne $r.CpuPctMin -and [double]$r.CpuPctMin -ge 25) {
            # Damping (same idea as Analyze): CPU plus a suspicious LOCATION alone is not a miner when the binary is
            # validly signed by a vendor in TrustedSignerRegex (Discord/Spotify/Teams updaters live in AppData) or the
            # process is in KnownHeavyProcesses. Only a miner TOKEN is never damped. The signature is checked here for
            # the few hot processes only (Get-AuthenticodeSignature for ~1000 processes would cost minutes).
            $dampNote = ''
            if ($susp -and $r.Flags -notmatch 'MinerToken') {
                if ($isHeavy) { $dampNote = 'known heavy background process' }
                elseif ($r.Path -ne '') {
                    $psig = Get-WdInvSignatureInfo -Path $r.Path
                    if ($psig['Trusted']) {
                        $dampNote = ('validly signed by ' + $psig['Signer'])
                        if ($r.Flags -notmatch 'SignedTrusted') { $r.Flags = (@(@($r.Flags -split ';' | Where-Object { $_ -ne '' }) + 'SignedTrusted') -join ';') }
                    }
                }
            }
            if ($susp -and $dampNote -eq '') {
                Add-Finding -Severity Critical -Category 'Performance' -RuleId 'PROC-MINER' -Title ('Probable crypto-miner: {0} (PID {1}) at {2} % CPU' -f $r.Name, $r.Pid, (Format-WdInvNum $r.CpuPctAvg 0)) -Detail ('Path: {0}; command line: {1}; owner {2}; flags {3}' -f $(if ($r.Path -ne '') { $r.Path } else { 'n/a' }), $r.CommandLine, $r.Owner, $r.Flags) `
                    -Recommendation 'High sustained CPU from a suspicious location or with miner arguments. End the process, remove its autostart/task/service entries (see Autostart section) and Defender exclusions, then run a full offline scan.'
            } elseif ($susp) {
                Add-Finding -Severity Info -Category 'Performance' -RuleId 'PROC-MINER' -Title ('Sustained CPU from an unusual location, damped: {0} (PID {1}) at {2} % CPU' -f $r.Name, $r.Pid, (Format-WdInvNum $r.CpuPctAvg 0)) -Detail ('Not treated as a miner: {0}. Path: {1}; owner {2}; flags {3}' -f $dampNote, $(if ($r.Path -ne '') { $r.Path } else { 'n/a' }), $r.Owner, $r.Flags) `
                    -Recommendation 'A trusted-signed or known heavy program running from AppData/ProgramData; normal for updaters, browsers and Electron apps. Use Monitor mode if it stays this busy while the PC is idle.'
            } elseif ($base -eq 'msmpeng') {
                Add-Finding -Severity Info -Category 'Performance' -RuleId 'PROC-DEFENDER' -Title ('Microsoft Defender is scanning right now ({0} % CPU)' -f (Format-WdInvNum $r.CpuPctAvg 0)) -Detail 'MsMpEng.exe in both samples.' -Recommendation 'Temporary; if it is permanent, check for a stuck scan or a folder with millions of files.'
            } elseif ($base -in @('tiworker', 'trustedinstaller', 'mousocoreworker', 'usoclient', 'wuauclt')) {
                Add-Finding -Severity Info -Category 'Performance' -RuleId 'PROC-SERVICING' -Title ('Windows Update servicing is running ({0} at {1} % CPU)' -f $r.Name, (Format-WdInvNum $r.CpuPctAvg 0)) -Detail '' -Recommendation 'Let it finish and reboot; if it runs for hours daily, the servicing stack is broken (DISM /RestoreHealth).'
            } elseif ($base -in @('searchindexer', 'searchprotocolhost', 'searchfilterhost')) {
                Add-Finding -Severity Info -Category 'Performance' -RuleId 'IDX-BUSY' -Title ('Windows Search is indexing ({0} at {1} % CPU)' -f $r.Name, (Format-WdInvNum $r.CpuPctAvg 0)) -Detail '' -Recommendation 'Normal after big file changes; if permanent, rebuild the index (Indexing Options) or exclude huge folders.'
            } elseif (-not $isHeavy) {
                Add-Finding -Severity Warning -Category 'Performance' -RuleId 'PROC-CPU' -Title ('High CPU: {0} (PID {1}) at {2} % in both samples' -f $r.Name, $r.Pid, (Format-WdInvNum $r.CpuPctAvg 0)) -Detail ('Path: {0}; owner {1}; parent {2}' -f $(if ($r.Path -ne '') { $r.Path } else { 'n/a (requires administrator)' }), $r.Owner, $r.ParentName) `
                    -Recommendation 'If the user was not actively using this program, it is a background CPU hog: check what it is (path, publisher), update or uninstall it, or run the Monitor mode to see how often this happens.'
            }
        }
        if ($totalRam -gt 0 -and $null -ne $r.WorkingSetPrivateMB -and ([double]$r.WorkingSetPrivateMB * 1MB) -gt 0.25 * $totalRam) {
            Add-Finding -Severity Warning -Category 'Performance' -RuleId 'PROC-MEM' -Title ('{0} (PID {1}) uses {2} of RAM' -f $r.Name, $r.Pid, (Format-Bytes -Bytes ([double]$r.WorkingSetPrivateMB * 1MB))) -Detail ('{0} % of {1}' -f (Format-WdInvNum (([double]$r.WorkingSetPrivateMB * 1MB) / $totalRam * 100) 0), (Format-Bytes -Bytes $totalRam)) -Recommendation 'One process holds a quarter of the memory; restart it or check for a memory leak (browser tabs, Electron apps, VMs).'
        }
        if (($null -ne $r.HandleCount -and [int64]$r.HandleCount -gt 50000) -or ($null -ne $r.ThreadCount -and [int64]$r.ThreadCount -gt 2000)) {
            Add-Finding -Severity Warning -Category 'Performance' -RuleId 'PROC-LEAK' -Title ('Handle/thread leak suspected in {0} (PID {1})' -f $r.Name, $r.Pid) -Detail ('Handles {0}, threads {1}' -f $r.HandleCount, $r.ThreadCount) -Recommendation 'Restart the process/service; if it grows again, update or replace the program (driver/AV hooks are common culprits).'
        }
        if ($r.Flags -match 'UnexpectedParent') {
            Add-Finding -Severity Warning -Category 'Performance' -RuleId 'PROC-PARENT' -Title ('svchost.exe (PID {0}) has an unexpected parent: {1}' -f $r.Pid, $r.ParentName) -Detail ('Path {0}; command line {1}' -f $r.Path, $r.CommandLine) -Recommendation 'Legitimate svchost is always started by services.exe. Check this process (signature, path); a fake svchost is a classic miner disguise.'
        } elseif ($r.Flags -match 'SystemNameOutsideSystem32' -and $null -eq $r.CpuPctMin) {
            Add-Finding -Severity Warning -Category 'Performance' -RuleId 'PROC-FAKE-SYS' -Title ('Process named like a Windows binary runs from an unusual location: {0}' -f $r.Name) -Detail ('Path {0}' -f $r.Path) -Recommendation 'Verify the signature; system binaries live in C:\Windows\System32.'
        } elseif ($r.Flags -match 'SystemNameOutsideSystem32') {
            Add-Finding -Severity Warning -Category 'Performance' -RuleId 'PROC-FAKE-SYS' -Title ('Process named like a Windows binary runs from an unusual location: {0}' -f $r.Name) -Detail ('Path {0}' -f $r.Path) -Recommendation 'Verify the signature; system binaries live in C:\Windows\System32.'
        }
    }

    # Key background services and processes
    $keyServices = @('WSearch', 'SysMain', 'DiagTrack', 'wuauserv', 'UsoSvc', 'BITS', 'WinDefend', 'MpsSvc', 'WdNisSvc', 'DPS', 'WerSvc', 'Schedule', 'Spooler', 'DoSvc', 'EventLog', 'Themes', 'OneSyncSvc')
    $svcRows = New-Object 'System.Collections.Generic.List[object]'
    $state = $ctx['ServiceState']
    foreach ($n in $keyServices) {
        if ($null -ne $state -and $state.ContainsKey($n)) { $svcRows.Add([ordered]@{ Service = $n; State = $state[$n]['State']; StartMode = $state[$n]['StartMode'] }) }
    }
    $sec['KeyServices'] = $svcRows.ToArray()
    $keyProcs = @('OneDrive', 'SearchIndexer', 'SearchHost', 'MsMpEng', 'MoUsoCoreWorker', 'TiWorker', 'CompatTelRunner', 'wsappx', 'SgrmBroker', 'YourPhone', 'PhoneExperienceHost', 'WidgetService', 'Widgets', 'msedgewebview2', 'GameBar', 'Cortana', 'Teams', 'ms-teams', 'Copilot')
    $kpRows = New-Object 'System.Collections.Generic.List[object]'
    foreach ($r in $all) { if ($keyProcs -contains $r.Name) { $kpRows.Add([ordered]@{ Name = $r.Name; Pid = $r.Pid; CpuPctAvg = $r.CpuPctAvg; WorkingSetPrivateMB = $r.WorkingSetPrivateMB; IOBytesPerSec = $r.IOBytesPerSec }) } }
    $sec['KeyBackgroundProcesses'] = $kpRows.ToArray()
    foreach ($k in $kpRows) {
        if ([string]$k['Name'] -eq 'OneDrive' -and $null -ne $k['CpuPctAvg'] -and [double]$k['CpuPctAvg'] -gt 25) {
            Add-Finding -Severity Info -Category 'Performance' -RuleId 'SYNC-BUSY' -Title ('OneDrive is syncing heavily ({0} % CPU)' -f (Format-WdInvNum $k['CpuPctAvg'] 0)) -Detail '' -Recommendation 'Normal after large changes; if permanent, check for sync conflicts (OneDrive icon) or exclude huge folders.'
        }
    }

    # Windows Search index
    $ws = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows Search'
    $dataDir = Get-WdInvString -Value $ws['DataDirectory']
    try { $dataDir = [Environment]::ExpandEnvironmentVariables($dataDir) } catch { }
    $edbSize = $null
    $edbNote = ''
    if ($dataDir -ne '') {
        foreach ($fn in @('Windows.edb', 'Windows.db')) {
            $p = [IO.Path]::Combine($dataDir, 'Applications\Windows\' + $fn)
            $s = Get-FileSizeSafe -Path $p
            if ($null -ne $s) { $edbSize = $s; break }
        }
        if ($null -eq $edbSize) {
            if ($script:IsAdmin) { $edbNote = 'index file not found' } else { $edbNote = Add-WdInvAdminGap -Item 'Windows Search index size (Windows.edb)' -Detail 'ProgramData\Microsoft\Search is not readable by standard users' }
        }
    }
    $indexing = @(Get-CimSafe -ClassName Win32_Volume -Filter 'DriveType=3' -Property @('DriveLetter', 'IndexingEnabled') | Where-Object { -not [string]::IsNullOrEmpty([string]$_.DriveLetter) } | ForEach-Object { [ordered]@{ Drive = [string]$_.DriveLetter; IndexingEnabled = $_.IndexingEnabled } })
    $sec['WindowsSearch'] = [ordered]@{ SetupCompletedSuccessfully = $ws['SetupCompletedSuccessfully']; DataDirectory = $dataDir; IndexFileBytes = $edbSize; IndexFileSize = $(if ($null -ne $edbSize) { Format-Bytes -Bytes $edbSize } else { $edbNote }); VolumeIndexing = $indexing }
    if ($null -ne $edbSize -and $edbSize -gt 5GB) {
        Add-Finding -Severity Info -Category 'Performance' -RuleId 'IDX-LARGE' -Title ('Windows Search index is {0}' -f (Format-Bytes -Bytes $edbSize)) -Detail $dataDir -Recommendation 'Indexing Options > Advanced > Rebuild, and exclude folders with millions of files.'
    }

    # OneDrive accounts
    $od = New-Object 'System.Collections.Generic.List[object]'
    foreach ($sub in @(Get-WdInvRegistrySubKeyNames -Path 'HKCU:\Software\Microsoft\OneDrive\Accounts')) {
        $vals = Get-WdInvRegistryValues -Path ('HKCU:\Software\Microsoft\OneDrive\Accounts\' + $sub)
        $od.Add([ordered]@{ Account = $sub; UserFolder = (Get-WdInvString -Value $vals['UserFolder']); Business = ($sub -like 'Business*') })
    }
    $sec['OneDriveAccounts'] = $od.ToArray()

    # Storage Sense
    $ssp = Get-WdInvRegistryValues -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy'
    $sec['StorageSense'] = [ordered]@{ Enabled = $ssp['01']; CleanTempFiles = $ssp['04']; RecycleBin = $ssp['08']; RecycleBinDays = $ssp['256']; DownloadsDays = $ssp['512']; Cadence = $ssp['2048'] }
    if (($null -eq $ssp['01'] -or [int]$ssp['01'] -eq 0) -and $null -ne $ctx['SystemFreePercent'] -and [double]$ctx['SystemFreePercent'] -lt 10) {
        Add-Finding -Severity Info -Category 'Performance' -RuleId 'STO-SENSE' -Title 'Storage Sense is off while the system drive is nearly full' -Detail 'StoragePolicy 01=0/absent.' -Recommendation 'Settings > System > Storage > Storage Sense: turn on (cleans temp files and the recycle bin automatically).'
    }

    # Visual effects / responsiveness tweaks
    $vfx = Get-RegistryValueSafe -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects' -Name 'VisualFXSetting'
    $mm = Get-WdInvRegistryValues -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile'
    $sec['Tweaks'] = [ordered]@{ VisualFXSetting = $vfx; SystemResponsiveness = $mm['SystemResponsiveness']; NetworkThrottlingIndex = $mm['NetworkThrottlingIndex'] }
    $odd = @()
    if ($null -ne $mm['SystemResponsiveness'] -and [int64]$mm['SystemResponsiveness'] -ne 20) { $odd += ('SystemResponsiveness=' + $mm['SystemResponsiveness']) }
    if ($null -ne $mm['NetworkThrottlingIndex'] -and [int64]$mm['NetworkThrottlingIndex'] -ne 10) { $odd += ('NetworkThrottlingIndex=' + $mm['NetworkThrottlingIndex']) }
    if ($odd.Count -gt 0) {
        Add-Finding -Severity Info -Category 'Performance' -RuleId 'SYS-TWEAKS' -Title 'Non-default "gaming/optimizer" registry tweaks detected' -Detail ($odd -join '; ') -Recommendation 'Traces of tweak tools. Usually harmless, but such tools often also disabled services or planted software; restore defaults (20 / 10) if in doubt.'
    }
    return $sec
}

# ---------------------------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------------------------
function Add-WdInvLines {
    # Note: the $Lines parameters of the writer helpers are deliberately NOT mandatory - mandatory
    # collection parameters reject lists that contain empty strings (blank markdown lines).
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][AllowEmptyString()][System.Collections.Generic.List[string]]$Lines, [AllowNull()][AllowEmptyCollection()][string[]]$Add)
    if ($null -eq $Add) { return }
    foreach ($l in $Add) { $Lines.Add([string]$l) }
}

function Add-WdInvTable {
    [CmdletBinding()]
    param(
        [AllowNull()][AllowEmptyCollection()][AllowEmptyString()][System.Collections.Generic.List[string]]$Lines,
        [AllowNull()][object]$Rows,
        [Parameter(Mandatory = $true)][string[]]$Columns,
        [string[]]$Headers,
        [string]$Title = '',
        [int]$Max = 0
    )
    if ($Title -ne '') { $Lines.Add(('### ' + $Title)); $Lines.Add('') }
    $arr = @()
    if ($null -ne $Rows) {
        if ($Rows -is [string]) { $Lines.Add($Rows); $Lines.Add(''); return }
        $arr = @($Rows)
    }
    $total = $arr.Count
    if ($Max -gt 0 -and $total -gt $Max) { $arr = @($arr | Select-Object -First $Max) }
    $p = @{ InputObject = $arr; Columns = $Columns }
    if ($null -ne $Headers) { $p['Headers'] = $Headers }
    Add-WdInvLines -Lines $Lines -Add @(ConvertTo-MarkdownTable @p)
    if ($Max -gt 0 -and $total -gt $Max) { $Lines.Add(('_{0} of {1} rows shown; the full list is in the CSV/JSON files._' -f $Max, $total)) }
    $Lines.Add('')
}

function Add-WdInvKeyValues {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyCollection()][AllowEmptyString()][System.Collections.Generic.List[string]]$Lines, [AllowNull()][object]$Pairs, [string]$Title = '', [string[]]$Skip = @())
    if ($Title -ne '') { $Lines.Add(('### ' + $Title)); $Lines.Add('') }
    if ($null -eq $Pairs) { $Lines.Add('_none_'); $Lines.Add(''); return }
    if ($Pairs -is [string]) { $Lines.Add($Pairs); $Lines.Add(''); return }
    $filtered = [ordered]@{}
    foreach ($k in $Pairs.Keys) {
        if ($Skip -contains [string]$k) { continue }
        $v = $Pairs[$k]
        if ($null -ne $v -and -not ($v -is [string]) -and ($v -is [System.Collections.IDictionary] -or ($v -is [System.Collections.IEnumerable] -and @($v).Count -gt 6))) { continue }
        $filtered[$k] = $v
    }
    Add-WdInvLines -Lines $Lines -Add @(ConvertTo-MarkdownTable -InputObject @(ConvertTo-WdInvKeyValueRows -Pairs $filtered) -Columns @('Name', 'Value') -Headers @('Item', 'Value'))
    $Lines.Add('')
}

function Write-WdInvSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Data, [double]$DurationSeconds)
    $L = New-Object 'System.Collections.Generic.List[string]'
    $L.Add(('# win-debug inventory: {0}' -f [string]$env:COMPUTERNAME))
    $L.Add('')
    $L.Add('Read-only diagnostic report. It contains personal data (computer/user names, serial numbers, installed programs, process command lines, and on laptops battery-report.xml with weeks of power-on/standby history): review before sharing.')
    $L.Add('')
    Add-WdInvLines -Lines $L -Add @(Get-RunInfoSectionLines -DurationSeconds $DurationSeconds -Mode 'Inventory')

    # Findings
    $L.Add('## Findings')
    $L.Add('')
    $findings = @(Get-Findings)
    if ($findings.Count -eq 0) { $L.Add('_No findings: nothing in the collected data matched a rule._'); $L.Add('') }
    foreach ($sev in @('Critical', 'Warning', 'Info')) {
        $items = @($findings | Where-Object { [string]$_['Severity'] -eq $sev })
        $L.Add(('### {0} ({1})' -f $sev, $items.Count))
        $L.Add('')
        if ($items.Count -eq 0) { $L.Add('_none_'); $L.Add(''); continue }
        foreach ($f in $items) {
            $rid = [string]$f['RuleId']
            $title = ConvertTo-WdInvMdText -Text ([string]$f['Title'])
            $detail = ConvertTo-WdInvMdText -Text ([string]$f['Detail'])
            $rec = ConvertTo-WdInvMdText -Text ([string]$f['Recommendation'])
            $L.Add(('- **[{0}] {1}** ({2})' -f $rid, $title, [string]$f['Category']))
            if ($detail -ne '') { $L.Add(('  - Detail: {0}' -f $detail)) }
            if ($rec -ne '') { $L.Add(('  - Recommendation: {0}' -f $rec)) }
        }
        $L.Add('')
    }

    # System
    $s = $Data['System']
    $L.Add('## System & OS'); $L.Add('')
    Add-WdInvKeyValues -Lines $L -Pairs $s['OS'] -Title 'Operating system'
    Add-WdInvKeyValues -Lines $L -Pairs $s['Hardware'] -Title 'Hardware'
    Add-WdInvKeyValues -Lines $L -Pairs $s['Power'] -Title 'Fast Startup / hibernation'
    Add-WdInvKeyValues -Lines $L -Pairs $s['PendingReboot'] -Title 'Pending reboot'
    Add-WdInvTable -Lines $L -Rows $s['Activation'] -Columns @('Name', 'LicenseStatus', 'Channel') -Title 'Activation'
    Add-WdInvKeyValues -Lines $L -Pairs $s['WindowsUpdate'] -Title 'Windows Update'
    Add-WdInvTable -Lines $L -Rows $s['UpdateHistory'] -Columns @('Date', 'Result', 'Operation', 'Title') -Title 'Update history (last 60)' -Max 25
    Add-WdInvTable -Lines $L -Rows $s['HotFixes'] -Columns @('HotFixID', 'Description', 'InstalledOn') -Title 'Hotfixes (Get-HotFix)'
    Add-WdInvKeyValues -Lines $L -Pairs $s['TimeSync'] -Title 'Time synchronization'
    Add-WdInvKeyValues -Lines $L -Pairs $s['SecureBoot'] -Title 'Secure Boot / virtualization-based security'
    Add-WdInvKeyValues -Lines $L -Pairs $s['Locale'] -Title 'Locale'

    # CPU
    $c = $Data['CPU']
    $L.Add('## CPU'); $L.Add('')
    Add-WdInvTable -Lines $L -Rows $c['Processors'] -Columns @('Name', 'Cores', 'EnabledCores', 'LogicalProcessors', 'MaxClockMHz', 'L2CacheKB', 'L3CacheKB', 'VirtualizationFirmwareEnabled') -Title 'Processor'
    Add-WdInvKeyValues -Lines $L -Pairs $c['Load'] -Title ('Load during the snapshot (average of the samples)') -Skip @('PerSample_PercentProcessorTime', 'PerSample_PercentProcessorPerformance')
    Add-WdInvTable -Lines $L -Rows $c['ThermalZones'] -Columns @('Zone', 'AvgTemperatureC', 'MaxTemperatureC', 'PercentPassiveLimit', 'ThrottleReasons', 'Plausible') -Title 'ACPI thermal zones'
    if ($null -ne $c['ThermalNote']) { $L.Add($c['ThermalNote']); $L.Add('') }
    Add-WdInvKeyValues -Lines $L -Pairs $c['PowerPlan'] -Title 'Power plan'

    # Memory
    $m = $Data['Memory']
    $L.Add('## Memory'); $L.Add('')
    Add-WdInvKeyValues -Lines $L -Pairs $m['Summary'] -Title 'Installed'
    Add-WdInvTable -Lines $L -Rows $m['Modules'] -Columns @('Bank', 'Slot', 'CapacityText', 'Type', 'SpeedMHz', 'ConfiguredMHz', 'Manufacturer', 'PartNumber') -Title 'Modules'
    Add-WdInvKeyValues -Lines $L -Pairs $m['Usage'] -Title 'Usage during the snapshot'
    Add-WdInvTable -Lines $L -Rows $m['PageFile']['Usage'] -Columns @('Name', 'AllocatedMB', 'CurrentUsageMB', 'PeakUsageMB') -Title 'Page file'
    Add-WdInvKeyValues -Lines $L -Pairs $m['PageFile'] -Skip @('Usage', 'Settings', 'SystemFiles')
    Add-WdInvTable -Lines $L -Rows $m['PageFile']['SystemFiles'] -Columns @('File', 'Size') -Title 'System files on the system drive'
    Add-WdInvTable -Lines $L -Rows $m['MemoryDiagnostics'] -Columns @('Time', 'Id', 'Result') -Title 'Windows Memory Diagnostic results'
    Add-WdInvKeyValues -Lines $L -Pairs $m['SysMain'] -Title 'SysMain / prefetch / memory compression'

    # GPU
    $g = $Data['GPU']
    $L.Add('## GPU'); $L.Add('')
    Add-WdInvTable -Lines $L -Rows $g['Adapters'] -Columns @('Name', 'Vendor', 'DriverVersion', 'DriverDate', 'DriverAgeYears', 'Resolution', 'Status', 'ConfigManagerErrorCode') -Title 'Display adapters'
    Add-WdInvTable -Lines $L -Rows $g['RegistryAdapters'] -Columns @('Description', 'DedicatedVideoMemoryText', 'DriverVersion', 'DriverDate', 'Provider') -Title 'Video memory (registry)'
    Add-WdInvTable -Lines $L -Rows $g['ProcessUtilization'] -Columns @('Pid', 'Process', 'AvgUtilAllEngines', 'AvgUtil3DCompute', 'MinUtil3DCompute', 'EnginesMax', 'Path') -Title ('GPU utilization per process ({0} samples)' -f $g['GpuSamples'])
    Add-WdInvTable -Lines $L -Rows $g['AdapterMemory'] -Columns @('Name', 'DedicatedUsageText', 'SharedUsageText') -Title 'GPU memory usage'
    Add-WdInvTable -Lines $L -Rows $g['Monitors'] -Columns @('Manufacturer', 'Name', 'ProductCode', 'Year', 'Week') -Title 'Monitors'

    # Storage
    $st = $Data['Storage']
    $L.Add('## Storage'); $L.Add('')
    Add-WdInvKeyValues -Lines $L -Pairs $st['SystemDisk'] -Title 'System disk'
    Add-WdInvTable -Lines $L -Rows $st['PhysicalDisks'] -Columns @('DeviceId', 'Model', 'MediaType', 'EffectiveMediaType', 'BusType', 'HealthStatus', 'SizeText', 'FirmwareVersion', 'IsSystemDisk') -Title 'Physical disks'
    Add-WdInvTable -Lines $L -Rows $st['Smart'] -Columns @('DeviceId', 'Model', 'TemperatureC', 'WearPercent', 'ReadErrorsUncorrected', 'WriteErrorsUncorrected', 'PowerOnHours', 'ReadLatencyMaxMs', 'WriteLatencyMaxMs') -Title 'SMART / reliability counters'
    Add-WdInvTable -Lines $L -Rows $st['Disks'] -Columns @('Number', 'FriendlyName', 'PartitionStyle', 'HealthStatus', 'SizeText', 'IsBoot', 'NumberOfPartitions') -Title 'Disks'
    Add-WdInvTable -Lines $L -Rows $st['Volumes'] -Columns @('Drive', 'Label', 'FileSystem', 'HealthStatus', 'SizeText', 'FreeText', 'FreePercent') -Title 'Volumes'
    Add-WdInvTable -Lines $L -Rows $st['Activity'] -Columns @('Disk', 'IntervalSeconds', 'AvgMsPerTransfer', 'AvgMsPerRead', 'AvgMsPerWrite', 'PercentIdle', 'ReadsPerSec', 'WritesPerSec', 'AvgQueueLength') -Title 'Disk activity during the snapshot (raw counters)'
    Add-WdInvKeyValues -Lines $L -Pairs $st['Trim'] -Title 'TRIM'
    $L.Add(('- System volume dirty bit: {0}' -f (ConvertTo-InvariantString -Value $st['SystemVolumeDirtyBit']))); $L.Add('')
    Add-WdInvTable -Lines $L -Rows $st['Fragmentation'] -Columns @('Drive', 'Volume', 'PercentFragmentation', 'LastRunUtc', 'HardwareIssue') -Title 'Fragmentation statistics (last Optimize Drives run)'
    Add-WdInvKeyValues -Lines $L -Pairs $st['ScheduledDefrag'] -Title 'ScheduledDefrag task'
    Add-WdInvTable -Lines $L -Rows $st['BitLocker'] -Columns @('Drive', 'Code', 'Status') -Title 'BitLocker'

    # Devices
    $d = $Data['Devices']
    $L.Add('## Devices & drivers'); $L.Add('')
    Add-WdInvTable -Lines $L -Rows $d['ProblemDevices'] -Columns @('Class', 'FriendlyName', 'ProblemCode', 'Problem', 'InstanceId') -Title ('Devices with problems ({0})' -f $d['ProblemDeviceCount'])
    Add-WdInvTable -Lines $L -Rows $d['Drivers'] -Columns @('DeviceClass', 'DeviceName', 'DriverVersion', 'DriverDate', 'AgeYears', 'Provider', 'IsSigned') -Title ('Drivers: {0} (of {1} signed drivers)' -f $d['DriverListMode'], $d['DriverCountTotal']) -Max 40
    Add-WdInvTable -Lines $L -Rows $d['UsbDevices'] -Columns @('Class', 'Name', 'Status', 'ErrorCode') -Title 'USB devices (present)' -Max 30
    Add-WdInvTable -Lines $L -Rows $d['DriverLoadFailures14d'] -Columns @('Device', 'Count') -Title 'Driver load failures (Kernel-PnP 219, 14 days)'

    # Network
    $n = $Data['Network']
    $L.Add('## Network'); $L.Add('')
    Add-WdInvTable -Lines $L -Rows $n['Adapters'] -Columns @('Name', 'Description', 'Status', 'SpeedMbps', 'ReceiveLinkSpeedMbps', 'IsWiFi', 'MACAddress', 'DriverVersion', 'DriverDate') -Title 'Physical adapters'
    Add-WdInvTable -Lines $L -Rows $n['IpConfiguration'] -Columns @('Description', 'IPAddresses', 'Gateways', 'DnsServers', 'DHCPEnabled', 'DHCPServer') -Title 'IP configuration'
    Add-WdInvTable -Lines $L -Rows $n['DefaultRoutes'] -Columns @('Interface', 'NextHop', 'RouteMetric', 'InterfaceMetric') -Title 'Default routes'
    Add-WdInvTable -Lines $L -Rows $n['ConnectionProfiles'] -Columns @('Name', 'Interface', 'Category', 'IPv4Connectivity') -Title 'Connection profiles'
    Add-WdInvKeyValues -Lines $L -Pairs ([ordered]@{ DnsServers = ($n['Dns']['Servers'] -join ', '); Gateways = ($n['Dns']['Gateways'] -join ', '); UntrustedDns = ($n['Dns']['Untrusted'] -join ', ') }) -Title 'DNS check'
    Add-WdInvKeyValues -Lines $L -Pairs $n['Proxy'] -Title 'Proxy'
    Add-WdInvKeyValues -Lines $L -Pairs ([ordered]@{ Path = $n['Hosts']['Path']; ActiveEntries = $n['Hosts']['ActiveEntries']; SuspiciousEntries = ($n['Hosts']['SuspiciousEntries'] -join '; ') }) -Title 'hosts file'
    if (@($n['Hosts']['Entries']).Count -gt 0) { $L.Add('Active hosts entries:'); $L.Add(''); foreach ($he in @($n['Hosts']['Entries'] | Select-Object -First 40)) { $L.Add(('    ' + $he)) }; $L.Add('') }
    Add-WdInvTable -Lines $L -Rows $n['AdapterStatistics'] -Columns @('Name', 'ReceivedText', 'SentText', 'ReceivedErrors', 'ReceivedDiscarded', 'ReceiveErrorPercent') -Title 'Adapter statistics since boot'
    Add-WdInvTable -Lines $L -Rows $n['ExternalConnections'] -Columns @('Pid', 'Process', 'Connections', 'Ports', 'Remotes', 'LocationClass', 'Flags') -Title ('Established external TCP connections per process ({0} connections total)' -f $n['ExternalConnectionTotal']) -Max 25

    # Battery
    $b = $Data['Battery']
    $L.Add('## Battery'); $L.Add('')
    if ($null -ne $b['Note']) { $L.Add([string]$b['Note']); $L.Add('') }
    else {
        Add-WdInvTable -Lines $L -Rows $b['Batteries'] -Columns @('Name', 'Status', 'ChargePercent', 'EstimatedRunTimeMinutes', 'Chemistry') -Title 'Batteries (Win32_Battery)'
        Add-WdInvKeyValues -Lines $L -Pairs $b['PowerStatus'] -Title 'Power status'
        Add-WdInvKeyValues -Lines $L -Pairs $b['Live'] -Title 'Live values (root\wmi)'
        Add-WdInvTable -Lines $L -Rows $b['Report'] -Columns @('Manufacturer', 'Chemistry', 'DesignCapacity_mWh', 'FullChargeCapacity_mWh', 'HealthPercent', 'CycleCount') -Title 'powercfg battery report (battery-report.xml)'
    }

    # Software
    $sw = $Data['Software']
    $L.Add('## Software'); $L.Add('')
    $L.Add(('- Installed programs (registry): {0}; see installed-programs.csv' -f $sw['InstalledProgramCount']))
    $L.Add(('- Store apps ({0}): {1}; side-loaded: {2}' -f $sw['StoreApps']['Scope'], $sw['StoreApps']['Count'], @($sw['StoreApps']['Sideloaded']).Count))
    $L.Add(('- .NET Framework: {0}; .NET runtimes: {1}' -f $sw['DotNet']['FrameworkVersion'], $sw['DotNet']['NetCoreRuntimes']))
    $L.Add(('- Antivirus suites found in the program list: {0}' -f $(if (@($sw['AntivirusSuitesInstalled']).Count -gt 0) { @($sw['AntivirusSuitesInstalled']) -join ', ' } else { 'none' })))
    $L.Add('')
    Add-WdInvTable -Lines $L -Rows @($sw['RecentInstalls30d'] | ForEach-Object { [pscustomobject]@{ Program = $_ } }) -Columns @('Program') -Title 'Installed in the last 30 days'
    Add-WdInvTable -Lines $L -Rows $sw['InstalledPrograms'] -Columns @('DisplayName', 'DisplayVersion', 'Publisher', 'InstallDate', 'EstimatedSizeMB', 'Hive') -Title 'Installed programs' -Max 60

    # Autostart
    $a = $Data['Autostart']
    $L.Add('## Autostart & persistence'); $L.Add('')
    Add-WdInvTable -Lines $L -Rows $a['Entries'] -Columns @('Source', 'Name', 'Command', 'LocationClass', 'Publisher', 'Enabled', 'Flags') -Title ('Run keys, Startup folders, Active Setup ({0} enabled)' -f $a['EnabledCount'])
    $L.Add(('### Scheduled tasks: {0} visible, {1} listed by schtasks, {2} non-Microsoft or flagged shown below' -f $a['TaskCountVisible'], (ConvertTo-InvariantString -Value $a['TaskCountSchtasks']), $a['TaskCountReported']))
    $L.Add('')
    if ($null -ne $a['TaskCountNotVisible']) { $L.Add(('{0} task(s) are not visible to a standard user (requires administrator).' -f $a['TaskCountNotVisible'])); $L.Add('') }
    Add-WdInvTable -Lines $L -Rows $a['ScheduledTasks'] -Columns @('Path', 'Name', 'State', 'Actions', 'Triggers', 'RunLevel', 'Hidden', 'LastRunTime', 'LastTaskResult', 'Flags') -Max 60
    $nonMs = @($a['Services'] | Where-Object { -not $_.IsMicrosoftPath })
    Add-WdInvTable -Lines $L -Rows $nonMs -Columns @('Name', 'DisplayName', 'State', 'StartMode', 'StartName', 'PathName', 'LocationClass', 'Flags') -Title ('Services outside the Windows folder ({0} of {1} services; {2} of them auto-start)' -f $nonMs.Count, $a['ServiceCount'], $a['NonMicrosoftAutoStartCount']) -Max 60
    $L.Add(('- Automatic services not running: {0}' -f $(if (@($a['AutoStartNotRunning']).Count -gt 0) { @($a['AutoStartNotRunning']) -join ', ' } else { 'none' }))); $L.Add('')
    Add-WdInvKeyValues -Lines $L -Pairs $a['Winlogon'] -Title 'Winlogon / AppInit'
    Add-WdInvTable -Lines $L -Rows $a['IFEO']['Debuggers'] -Columns @('Executable', 'Debugger', 'KnownDebugger') -Title ('Image File Execution Options debuggers ({0} subkeys listed)' -f $a['IFEO']['SubKeysListed'])
    Add-WdInvTable -Lines $L -Rows $a['IFEO']['SilentProcessExit'] -Columns @('Executable', 'MonitorProcess') -Title 'SilentProcessExit monitors'
    Add-WdInvTable -Lines $L -Rows $a['WmiSubscriptions'] -Columns @('Class', 'Name', 'Detail') -Title 'WMI event subscriptions (root\subscription)'
    Add-WdInvTable -Lines $L -Rows $a['PowerShellProfiles'] -Columns @('Scope', 'Path', 'Exists', 'Bytes', 'Suspicious') -Title 'PowerShell profiles'
    Add-WdInvTable -Lines $L -Rows $a['ShellExtensions'] -Columns @('Key', 'Id') -Title 'Browser helper objects / shell hooks'
    Add-WdInvKeyValues -Lines $L -Pairs $a['Lsa'] -Title 'LSA packages'

    # Security
    $se = $Data['Security']
    $L.Add('## Security'); $L.Add('')
    Add-WdInvTable -Lines $L -Rows $se['SecurityCenterProducts'] -Columns @('Type', 'Name', 'Enabled', 'UpToDate', 'Path') -Title 'Security Center products'
    Add-WdInvKeyValues -Lines $L -Pairs $se['Defender'] -Title 'Microsoft Defender status'
    Add-WdInvKeyValues -Lines $L -Pairs $se['DefenderPreferences'] -Title 'Defender preferences' -Skip @('Exclusions')
    $ex = $se['DefenderPreferences']['Exclusions']
    if ($ex -is [string]) { $L.Add(('- Exclusions: {0}' -f $ex)); $L.Add('') }
    elseif ($null -ne $ex) { foreach ($k in $ex.Keys) { $L.Add(('- {0}: {1}' -f $k, $(if (@($ex[$k]).Count -gt 0) { @($ex[$k]) -join '; ' } else { 'none' }))) }; $L.Add('') }
    Add-WdInvTable -Lines $L -Rows $se['ThreatDetections'] -Columns @('Time', 'ThreatName', 'Process', 'Resources', 'ActionSuccess') -Title ('Defender threat detections ({0} threats known, {1} active)' -f $se['ThreatsKnown'], @($se['ThreatsActive']).Count) -Max 20
    Add-WdInvTable -Lines $L -Rows $se['DefenderEvents30d'] -Columns @('Id', 'Count', 'First', 'Last', 'SampleMessage') -Title 'Defender operational events (30 days)' -Max 15
    Add-WdInvKeyValues -Lines $L -Pairs $se['Firewall'] -Title 'Firewall profiles (registry)'
    Add-WdInvKeyValues -Lines $L -Pairs $se['UAC'] -Title 'UAC'
    Add-WdInvKeyValues -Lines $L -Pairs $se['SmartScreen'] -Title 'SmartScreen'
    Add-WdInvTable -Lines $L -Rows $se['LocalUsers'] -Columns @('Name', 'Enabled', 'IsAdministrator', 'PasswordRequired', 'PasswordLastSet', 'LastLogon') -Title 'Local accounts'
    Add-WdInvTable -Lines $L -Rows $se['LocalAdministrators'] -Columns @('Name', 'ObjectClass', 'Source') -Title 'Members of the local Administrators group'
    Add-WdInvTable -Lines $L -Rows $se['UserProfiles'] -Columns @('LocalPath', 'Loaded', 'LastUseTime') -Title 'User profiles'

    # Events
    $e = $Data['Events']
    $L.Add('## Event logs'); $L.Add('')
    Add-WdInvTable -Lines $L -Rows $e['SystemErrorsByProvider14d'] -Columns @('Provider', 'Count', 'Noisy') -Title ('System log: {0} errors/criticals in 14 days, by provider' -f $e['SystemErrorCount14d']) -Max 15
    Add-WdInvTable -Lines $L -Rows $e['SystemTopErrors14d'] -Columns @('Provider', 'Id', 'Count', 'Last', 'SampleMessage') -Title 'System log: top error groups' -Max 15
    Add-WdInvTable -Lines $L -Rows $e['ApplicationErrorsByProvider14d'] -Columns @('Provider', 'Count', 'Noisy') -Title ('Application log: {0} errors/criticals in 14 days, by provider' -f $e['ApplicationErrorCount14d']) -Max 15
    Add-WdInvTable -Lines $L -Rows $e['ApplicationTopErrors14d'] -Columns @('Provider', 'Id', 'Count', 'Last', 'SampleMessage') -Title 'Application log: top error groups' -Max 15
    Add-WdInvKeyValues -Lines $L -Pairs $e['Crashes90d'] -Title 'Crashes and unexpected shutdowns (90 days)' -Skip @('Bsod')
    Add-WdInvTable -Lines $L -Rows $e['Crashes90d']['Bsod'] -Columns @('Time', 'Source', 'BugcheckCode', 'Dump') -Title 'Blue screens'
    Add-WdInvTable -Lines $L -Rows $e['Whea90d'] -Columns @('Id', 'Count') -Title 'WHEA hardware errors (90 days)'
    Add-WdInvKeyValues -Lines $L -Pairs $e['BootTypes14d'] -Title 'Boot types (Kernel-Boot 27, 14 days)'
    Add-WdInvTable -Lines $L -Rows $e['BootPerformance30d'] -Columns @('Time', 'BootTimeMs', 'MainPathBootTimeMs', 'PostBootTimeMs') -Title 'Boot performance (30 days)' -Max 10
    if ($null -ne $e['BootDegradation30d']) { Add-WdInvTable -Lines $L -Rows $e['BootDegradation30d'] -Columns @('Component', 'Count') -Title 'Boot degradation by component (30 days)' }
    Add-WdInvTable -Lines $L -Rows $e['StorageErrors90d'] -Columns @('Provider', 'Id', 'Count', 'First', 'Last', 'SampleMessage') -Title 'Storage error events (90 days)'
    Add-WdInvTable -Lines $L -Rows $e['StorportWarnings30d'] -Columns @('Id', 'Level', 'Count', 'Last', 'SampleMessage') -Title 'Storport warnings (30 days)'
    Add-WdInvTable -Lines $L -Rows $e['AppCrashes14d'] -Columns @('Application', 'Count', 'FaultingModule') -Title 'Application crashes (14 days)' -Max 15
    Add-WdInvTable -Lines $L -Rows $e['AppHangs14d'] -Columns @('Application', 'Count') -Title 'Application hangs (14 days)' -Max 10
    Add-WdInvTable -Lines $L -Rows $e['ServiceEvents14d'] -Columns @('Id', 'Count', 'Last', 'SampleMessage') -Title 'Service Control Manager failures/timeouts (14 days)' -Max 10
    Add-WdInvTable -Lines $L -Rows $e['ServicesInstalled90d'] -Columns @('Time', 'Service', 'ImagePath', 'Account', 'LocationClass', 'Suspicious') -Title 'Services installed (7045, 90 days)' -Max 20
    Add-WdInvTable -Lines $L -Rows $e['OutOfMemory30d'] -Columns @('Time', 'TopConsumers') -Title 'Out-of-memory events (30 days)'
    Add-WdInvTable -Lines $L -Rows $e['CrashDumps']['Folders'] -Columns @('Kind', 'Path', 'Files', 'Size', 'Newest', 'Note') -Title 'Crash dump folders'
    Add-WdInvKeyValues -Lines $L -Pairs $e['CrashDumps'] -Skip @('Folders')
    Add-WdInvKeyValues -Lines $L -Pairs $e['StabilityIndex'] -Title 'Reliability monitor stability index (0-10)'
    Add-WdInvTable -Lines $L -Rows $e['ReliabilityRecords90d'] -Columns @('Time', 'Source', 'Product', 'Message') -Title 'Reliability records (90 days)' -Max 20
    $L.Add(('- Security log account/admin-group changes (90 days): {0}' -f $(if ($e['SecurityAccountChanges90d'] -is [string]) { $e['SecurityAccountChanges90d'] } else { [string]@($e['SecurityAccountChanges90d']).Count + ' event group(s)' }))); $L.Add('')

    # Performance
    $p = $Data['Performance']
    $L.Add('## Performance snapshot'); $L.Add('')
    $L.Add(('{0} processes; two process samples {1} s apart; CPU percentages are normalized to {2} logical processors. Full table: processes-snapshot.csv.' -f $p['ProcessCount'], (ConvertTo-InvariantString -Value $p['SampleIntervalSeconds']), $p['LogicalProcessors']))
    $L.Add('')
    Add-WdInvTable -Lines $L -Rows $p['TopCpu'] -Columns @('Name', 'Pid', 'CpuPct1', 'CpuPct2', 'WorkingSetPrivateMB', 'Owner', 'LocationClass', 'Path', 'Flags') -Title 'Top processes by CPU'
    Add-WdInvTable -Lines $L -Rows $p['TopMemory'] -Columns @('Name', 'Pid', 'WorkingSetPrivateMB', 'PrivateBytesMB', 'CpuPctAvg', 'Owner', 'Path') -Title 'Top processes by private working set'
    Add-WdInvTable -Lines $L -Rows $p['TopIO'] -Columns @('Name', 'Pid', 'IOBytesPerSec', 'CpuPctAvg', 'Path') -Title 'Top processes by I/O bytes per second'
    Add-WdInvTable -Lines $L -Rows $p['KeyServices'] -Columns @('Service', 'State', 'StartMode') -Title 'Key background services'
    Add-WdInvTable -Lines $L -Rows $p['KeyBackgroundProcesses'] -Columns @('Name', 'Pid', 'CpuPctAvg', 'WorkingSetPrivateMB', 'IOBytesPerSec') -Title 'Key background processes'
    Add-WdInvKeyValues -Lines $L -Pairs $p['WindowsSearch'] -Title 'Windows Search'
    Add-WdInvTable -Lines $L -Rows $p['OneDriveAccounts'] -Columns @('Account', 'UserFolder', 'Business') -Title 'OneDrive accounts'
    Add-WdInvKeyValues -Lines $L -Pairs $p['StorageSense'] -Title 'Storage Sense (current user)'
    Add-WdInvKeyValues -Lines $L -Pairs $p['Tweaks'] -Title 'Visual effects / responsiveness registry values'

    Add-WdInvLines -Lines $L -Add @(Get-SummaryFooterLines)
    Write-MarkdownFile -Path $Path -Lines $L.ToArray()
}

function ConvertTo-WdInvMdText {
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $t = $Text -replace '\r\n|\r|\n', ' '
    $t = $t.Replace('|', '\|')
    return $t
}

function Export-WdInvCsvFiles {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$OutDir, [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Data)
    $exportErrorStart = $script:CollectionErrors.Count
    Invoke-Safely -Name 'Export.installed-programs.csv' -ScriptBlock {
        Export-CsvInvariant -InputObject @($Data['Software']['InstalledPrograms'] | ForEach-Object { [pscustomobject][ordered]@{ DisplayName = $_.DisplayName; DisplayVersion = $_.DisplayVersion; Publisher = $_.Publisher; InstallDate = $_.InstallDate; EstimatedSizeMB = $_.EstimatedSizeMB; InstallLocation = $_.InstallLocation; UninstallString = $_.UninstallString; Hive = $_.Hive; KeyName = $_.KeyName } }) -Path ([IO.Path]::Combine($OutDir, 'installed-programs.csv'))
    } | Out-Null
    Invoke-Safely -Name 'Export.autostart.csv' -ScriptBlock {
        Export-CsvInvariant -InputObject @($Data['Autostart']['Entries'] | ForEach-Object { [pscustomobject][ordered]@{ Source = $_.Source; Name = $_.Name; Command = $_.Command; ResolvedPath = $_.ResolvedPath; LocationClass = $_.LocationClass; Publisher = $_.Publisher; Flags = $_.Flags; Enabled = $_.Enabled; Exists = $_.Exists; SignatureStatus = $_.SignatureStatus } }) -Path ([IO.Path]::Combine($OutDir, 'autostart.csv'))
    } | Out-Null
    Invoke-Safely -Name 'Export.services.csv' -ScriptBlock {
        Export-CsvInvariant -InputObject @($Data['Autostart']['Services']) -Path ([IO.Path]::Combine($OutDir, 'services.csv'))
    } | Out-Null
    # CSVs that are legitimately empty on a healthy PC (no problem devices, nothing flagged, no errors, no -Deep) get
    # their documented header row through -Columns so that Import-Csv / Excel always see the same schema.
    Invoke-Safely -Name 'Export.scheduled-tasks.csv' -ScriptBlock {
        Export-CsvInvariant -InputObject @($Data['Autostart']['ScheduledTasks']) -Path ([IO.Path]::Combine($OutDir, 'scheduled-tasks.csv')) `
            -Columns @('Path', 'Name', 'State', 'Author', 'User', 'RunLevel', 'Hidden', 'Actions', 'ResolvedPath', 'LocationClass', 'Triggers', 'LastRunTime', 'LastTaskResult', 'NextRunTime', 'Flags', 'Suspicious', 'IsMicrosoftPath')
    } | Out-Null
    Invoke-Safely -Name 'Export.devices-problems.csv' -ScriptBlock {
        Export-CsvInvariant -InputObject @($Data['Devices']['ProblemDevices']) -Path ([IO.Path]::Combine($OutDir, 'devices-problems.csv')) `
            -Columns @('Status', 'Class', 'FriendlyName', 'InstanceId', 'ProblemCode', 'Problem', 'Manufacturer', 'Service')
    } | Out-Null
    Invoke-Safely -Name 'Export.drivers.csv' -ScriptBlock {
        Export-CsvInvariant -InputObject @($Data['Devices']['Drivers']) -Path ([IO.Path]::Combine($OutDir, 'drivers.csv')) `
            -Columns @('DeviceClass', 'DeviceName', 'DriverVersion', 'DriverDate', 'AgeYears', 'Provider', 'IsSigned', 'InfName', 'Manufacturer', 'DeviceID')
    } | Out-Null
    Invoke-Safely -Name 'Export.events.csv' -ScriptBlock {
        Export-CsvInvariant -InputObject @($Data['Events']['EventGroupsForCsv'] | ForEach-Object { [pscustomobject][ordered]@{ Log = $_.Log; Provider = $_.Provider; Id = $_.Id; Level = $_.Level; Count = $_.Count; First = $_.First; Last = $_.Last; SampleMessage = $_.SampleMessage } }) -Path ([IO.Path]::Combine($OutDir, 'events.csv')) `
            -Columns @('Log', 'Provider', 'Id', 'Level', 'Count', 'First', 'Last', 'SampleMessage')
    } | Out-Null
    Invoke-Safely -Name 'Export.processes-snapshot.csv' -ScriptBlock {
        $rows = @($script:WdInvCtx['ProcessRows'] | Sort-Object -Property @{ Expression = 'CpuPctAvg'; Descending = $true } | ForEach-Object { [pscustomobject][ordered]@{ Name = $_.Name; Pid = $_.Pid; ParentPid = $_.ParentPid; ParentName = $_.ParentName; CpuPct1 = $_.CpuPct1; CpuPct2 = $_.CpuPct2; CpuPctAvg = $_.CpuPctAvg; WorkingSetPrivateMB = $_.WorkingSetPrivateMB; PrivateBytesMB = $_.PrivateBytesMB; IOBytesPerSec = $_.IOBytesPerSec; HandleCount = $_.HandleCount; ThreadCount = $_.ThreadCount; ElapsedSeconds = $_.ElapsedSeconds; Owner = $_.Owner; LocationClass = $_.LocationClass; Path = $_.Path; CommandLine = $_.CommandLine; Created = $_.Created; Flags = $_.Flags } })
        Export-CsvInvariant -InputObject $rows -Path ([IO.Path]::Combine($OutDir, 'processes-snapshot.csv'))
    } | Out-Null
    Confirm-WdReportExport -ErrorStart $exportErrorStart
}

# ---------------------------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------------------------
function Invoke-InventoryScan {
    <#
    .SYNOPSIS
        Collects the inventory of this PC and writes summary.md, inventory.json and CSV files into -OutDir.
    .PARAMETER OutDir
        Existing or creatable report folder (normally created by New-ReportDirectory).
    .PARAMETER Deep
        Also check the Authenticode signature of every autostart binary and export the full driver list.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutDir,
        [switch]$Deep
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    if ($null -eq $script:Rules) { Initialize-Common }
    if (-not (Test-DirectoryExists -Path $OutDir)) { [void][IO.Directory]::CreateDirectory($OutDir) }
    if ([string]::IsNullOrEmpty($script:LogPath)) { $script:LogPath = [IO.Path]::Combine($OutDir, 'run.log') }
    if ([string]::IsNullOrEmpty($script:ReportDir)) { $script:ReportDir = $OutDir }
    if ([string]::IsNullOrEmpty($script:CurrentMode)) { $script:CurrentMode = 'Inventory' }
    $script:WdInvCtx = @{ SystemMediaType = 'Unknown'; IsLaptop = $false; FormFactor = 'Unknown'; IsDomainJoined = $false; TotalRamBytes = $null; ProcessRows = @() }
    $script:WdInvSigCache = @{}
    Write-Log -Level Info -Message ('Inventory scan started (administrator: {0}, deep: {1})' -f $script:IsAdmin, [bool]$Deep)
    if (-not $script:IsAdmin) { Write-Log -Level Info -Message 'Collected with standard user rights: SMART, Defender exclusions, hidden scheduled tasks, Security log and boot-performance events need administrator rights and are marked "(requires administrator)".' }

    $data = [ordered]@{}
    $samples = $null
    $processMap = @{}
    Write-SectionHeader -Title 'Performance snapshot (sampling counters and two process tables)'
    $samples = Measure-Step -Name 'PerformanceSampling' -ScriptBlock { Invoke-Safely -Name 'Perf.Samples' -Default $null -ScriptBlock { Get-WdInvPerfSamples -SampleCount 5 -IntervalMilliseconds 750 } }
    $processMap = Measure-Step -Name 'ProcessInventory' -ScriptBlock { Invoke-Safely -Name 'Perf.Win32_Process' -Default @{} -ScriptBlock { Get-WdInvProcessInventory } }
    if ($null -eq $processMap -or -not ($processMap -is [hashtable])) { $processMap = @{} }
    if ($null -eq $samples) {
        $samples = [ordered]@{ Cpu = @(); Thermal = @(); Memory = @(); DiskRaw = @(); System = @(); Gpu = @(); Process1 = @(); Process2 = @(); Process1Time = $null; Process2Time = $null; Timestamps = @(); SampleCount = 0 }
    }

    $sections = @(
        # Storage runs before Memory: MEM-PAGING needs the system disk media type ($ctx['SystemMediaType']) that only
        # Get-WdInvStorage sets; Storage itself reads only System values (FormFactor) and its own.
        @{ Key = 'System';      Title = 'System & OS';           Block = { Get-WdInvSystem } },
        @{ Key = 'CPU';         Title = 'CPU';                   Block = { Get-WdInvCpu -Samples $samples } },
        @{ Key = 'Storage';     Title = 'Storage';               Block = { Get-WdInvStorage -Samples $samples } },
        @{ Key = 'Memory';      Title = 'Memory';                Block = { Get-WdInvMemory -Samples $samples } },
        @{ Key = 'GPU';         Title = 'GPU';                   Block = { Get-WdInvGpu -Samples $samples -ProcessMap $processMap } },
        @{ Key = 'Devices';     Title = 'Devices & drivers';     Block = { Get-WdInvDevices -Deep:$Deep } },
        @{ Key = 'Network';     Title = 'Network';               Block = { Get-WdInvNetwork -ProcessMap $processMap } },
        @{ Key = 'Battery';     Title = 'Battery';               Block = { Get-WdInvBattery -OutDir $OutDir } },
        @{ Key = 'Software';    Title = 'Software';              Block = { Get-WdInvSoftware } },
        @{ Key = 'Autostart';   Title = 'Autostart & persistence'; Block = { Get-WdInvAutostart -Deep:$Deep } },
        @{ Key = 'Security';    Title = 'Security';              Block = { Get-WdInvSecurity -ProcessMap $processMap } },
        @{ Key = 'Events';      Title = 'Event logs';            Block = { Get-WdInvEvents } },
        @{ Key = 'Performance'; Title = 'Performance snapshot';  Block = { Get-WdInvPerformance -Samples $samples -ProcessMap $processMap } }
    )
    foreach ($s in $sections) {
        Write-SectionHeader -Title $s.Title
        $block = $s.Block
        $result = Measure-Step -Name $s.Key -ScriptBlock {
            Invoke-Safely -Name ('Section.' + $s.Key) -Default $null -ScriptBlock { & $block }
        }
        if ($null -eq $result) { $result = [ordered]@{ Error = ('section failed; see Collection errors') } }
        $data[$s.Key] = $result
    }

    Write-SectionHeader -Title 'Writing report files'
    $exportErrorStart = $script:CollectionErrors.Count
    $sw.Stop()
    $duration = [math]::Round($sw.Elapsed.TotalSeconds, 1, [MidpointRounding]::AwayFromZero)
    Measure-Step -Name 'WriteReports' -ScriptBlock {
        Export-WdInvCsvFiles -OutDir $OutDir -Data $data
        $meta = Get-ReportRunInfo -Mode 'Inventory'
        $meta['DurationSeconds'] = $duration
        $meta['Deep'] = [bool]$Deep
        $meta['Files'] = @('summary.md', 'inventory.json', 'installed-programs.csv', 'autostart.csv', 'services.csv', 'scheduled-tasks.csv', 'devices-problems.csv', 'drivers.csv', 'events.csv', 'processes-snapshot.csv')
        $json = [ordered]@{ Meta = $meta; Findings = @(Get-Findings); AdminSkips = @(Get-AdminSkips) }
        foreach ($k in $data.Keys) {
            $sectionCopy = $data[$k]
            if ($k -eq 'Events' -and $sectionCopy -is [System.Collections.IDictionary] -and $sectionCopy.Contains('EventGroupsForCsv')) {
                $sectionCopy = [ordered]@{}
                foreach ($kk in $data[$k].Keys) { if ($kk -ne 'EventGroupsForCsv') { $sectionCopy[$kk] = $data[$k][$kk] } }
            }
            $json[$k] = $sectionCopy
        }
        $json['CollectionErrors'] = @($script:CollectionErrors.ToArray())
        Invoke-Safely -Name 'Export.inventory.json' -ScriptBlock { Export-Json -Object $json -Path ([IO.Path]::Combine($OutDir, 'inventory.json')) -Depth 8 } | Out-Null
        Invoke-Safely -Name 'Export.summary.md' -ScriptBlock { Write-WdInvSummary -Path ([IO.Path]::Combine($OutDir, 'summary.md')) -Data $data -DurationSeconds $duration } | Out-Null
    }
    $counts = @{ Critical = 0; Warning = 0; Info = 0 }
    Confirm-WdReportExport -ErrorStart $exportErrorStart
    foreach ($f in @(Get-Findings)) { $sv = [string]$f['Severity']; if ($counts.ContainsKey($sv)) { $counts[$sv] = $counts[$sv] + 1 } }
    Write-Log -Level Info -Message ('Inventory finished in {0} s: {1} critical, {2} warning, {3} info findings; {4} collection error(s).' -f (ConvertTo-InvariantString -Value $duration -Decimals 1), $counts['Critical'], $counts['Warning'], $counts['Info'], $script:CollectionErrors.Count)
    return $data
}
