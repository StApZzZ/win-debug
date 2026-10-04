# lib\Common.ps1 - shared helpers and rule data for win-debug.
# Dot-sourced by WinDebug.ps1 BEFORE the module files, all into the same script scope.
# Windows PowerShell 5.1 only. No aliases, no external modules, read-only on the machine.
#
# API index (see docs/ARCHITECTURE.md, section "lib\Common.ps1 API", for the full contract):
#   Initialize-Common [-ToolVersion]              culture/console setup, script state, $script:Rules; idempotent
#   Test-IsAdmin                                  [bool] SID based (S-1-5-32-544); cached in $script:IsAdmin
#   New-ReportDirectory -OutputRoot -Mode         creates <root>\<PC>_<yyyyMMdd-HHmmss>_<mode>[-N], sets $script:ReportDir/LogPath
#   Write-Log -Level -Message [-NoConsole]        console + run.log; never throws
#   Write-SectionHeader -Title                    console "=== Title ===" + log line
#   Invoke-Safely -Name -ScriptBlock [-Default] [-Quiet]   catch-all wrapper for one collection item
#   Measure-Step -Name -ScriptBlock               timing wrapper for a whole section (does not catch)
#   Get-CimSafe -ClassName [-Namespace] [-Filter] [-Property] [-TimeoutSec]   always an array
#   Get-WinEventSafe -FilterHashtable [-MaxEvents]                            always an array
#   Get-RegistryValueSafe -Path -Name [-Default] [-Expand]
#   Export-Json -Object -Path [-Depth] [-Compress]          ISO dates, no \/Date(, UTF-8 no BOM
#   Export-CsvInvariant -InputObject -Path [-Columns] [-Append]   pipeline or array; dot decimals, ISO dates, UTF-8 BOM;
#                                                           -Columns fixes the column order, adds missing columns as empty
#                                                           cells and writes the quoted header line for an empty result
#   ConvertTo-InvariantString -Value [-Decimals]            culture-invariant text for any value
#   ConvertTo-Double -Text                                  safe parse ("1.5" or "1,5"), $null on failure
#   Format-Bytes -Bytes [-Decimals]                         "12.3 GB"; $null/negative -> "n/a"
#   Get-IsoTimestamp [-Date] [-Utc] [-ForFileName]          yyyy-MM-ddTHH:mm:ss.fffK / yyyyMMdd-HHmmss
#   Add-Finding -Severity -Category -Title -Detail -Recommendation [-RuleId] [-Data]
#   Get-Findings [-Severity]                                Critical -> Warning -> Info, then Category
#   Add-AdminSkip -Item [-Detail]  /  Get-AdminSkips        items skipped because they need administrator
#   ConvertTo-MarkdownTable -InputObject -Columns [-Headers]   markdown lines; "_none_" when empty
#   Get-RunInfoSectionLines [-DurationSeconds]              "## Run info" markdown lines (first section of a summary)
#   Get-SummaryFooterLines                                  "## Skipped (requires administrator)" + "## Collection errors"
#   Get-ProcessLocationClass -Path                          System32|Windows|ProgramFiles|...|Other|Unknown
#   Add-NativeType -TypeName -SourcePath                    guarded Add-Type from lib\native\*.cs; [bool]
#   Get-WinDebugRule -Name                                  rule data item from $script:Rules (throws on unknown)
#   Test-DirectoryExists -Path / Test-FileExists -Path / Get-FileSizeSafe -Path
#   Get-CurrentDirectory / Resolve-PathSafe -Path        file-system cwd without provider prefix; relative -> absolute
#   ConvertTo-CommandLineArgument -Text                     one quoted Win32 argument ("D:\" -> "D:\\", embedded quotes as \")
#   Protect-WdCsvText -Text                                 CSV cell guard: leading = + @ - TAB CR get a leading space (Excel formulas);
#                                                           only a cell that is entirely a number ("-5", "-1.50") keeps its leading "-"
#   Hide-WdSecret -Text                                     best-effort masking of passwords/keys/tokens in command lines and messages (value -> ***)
#   Write-TextFile -Path -Content / Write-MarkdownFile -Path -Lines    UTF-8 no BOM
#   Get-ReportRunInfo [-Mode]                               [ordered] Tool, Version, Mode, Computer, User, IsAdmin, ...
#
#
# Return convention: helpers that return lists (Get-CimSafe, Get-WinEventSafe, Get-Findings, Get-AdminSkips,
#   ConvertTo-MarkdownTable, Get-*Lines, Get-WinDebugRule) enumerate their items like every PowerShell command.
#   Callers MUST wrap them in @(...) - for example @(Get-CimSafe -ClassName Win32_Process).Count - because in
#   PowerShell 5.1 a single result is not an array and Write-Output -NoEnumerate would nest under @(...).
# Script state (set by Initialize-Common): $script:Inv, $script:Utf8NoBom, $script:Utf8Bom, $script:ToolVersion,
#   $script:IsAdmin, $script:Findings, $script:CollectionErrors, $script:AdminSkips, $script:ReportDir,
#   $script:LogPath, $script:VerboseLog, $script:Rules, $script:NCPU, $script:RepoRoot, $script:LibRoot,
#   $script:DownloadsDir, $script:CurrentMode, $script:RunStart.

Set-StrictMode -Off

$script:LibRoot = $PSScriptRoot
if ([string]::IsNullOrEmpty($script:LibRoot)) { try { $script:LibRoot = (Get-Location).ProviderPath } catch { $script:LibRoot = [Environment]::CurrentDirectory } }

# ---------------------------------------------------------------------------------------------
# Rule data (docs/ARCHITECTURE.md, section "Shared rule data"). Data, not code. Regexes are strings, case-insensitive with -match.
# ---------------------------------------------------------------------------------------------
function Get-WdRuleTable {
    [CmdletBinding()]
    param()

    # Cyrillic words are built from code points so the source stays ASCII-only.
    $cyrAgent   = -join @([char]0x0410, [char]0x0433, [char]0x0435, [char]0x043D, [char]0x0442)            # "Agent"
    $cyrSputnik = -join @([char]0x0421, [char]0x043F, [char]0x0443, [char]0x0442, [char]0x043D, [char]0x0438, [char]0x043A)   # "Sputnik"

    $expectedParents = [ordered]@{
        'svchost'       = @('services')
        'RuntimeBroker' = @('svchost')
        'taskhostw'     = @('svchost')
        'dllhost'       = @('svchost')
        'sihost'        = @('svchost')
        'ctfmon'        = @('svchost')
        'csrss'         = @('smss', '<none>')
        'wininit'       = @('smss', '<none>')
        'winlogon'      = @('smss', '<none>')
        'lsass'         = @('wininit')
        'services'      = @('wininit')
        'explorer'      = @('userinit', 'winlogon', 'explorer')
        'conhost'       = @('any')
        'spoolsv'       = @('services')
    }

    # Script-host argument flags come in two strengths (Inventory/Monitor/Analyze use STRONG for red flags,
    # WEAK is informational only): WEAK = launch options that legitimate installers and tasks also use;
    # STRONG = payload delivery (encoded commands, downloads, URLs, base64, COM scriptlets, LOLBin decoding).
    $scriptHostWeak   = '-ex(ecutionpolicy)?\s+bypass|-ep\s+bypass|\bbypass\b|-nop\b|-noprofile\b|-w(in|indowstyle)?\s+h(idden)?\b|-noni\b|-noninteractive\b'
    $scriptHostStrong = '-enc\b|-encodedcommand\b|-ec\b|-e\s+[A-Za-z0-9+/=]{16,}|downloadstring|downloadfile|\biex\b|invoke-expression|frombase64string|scrobj\.dll|urlcache|certutil(\.exe)?\s[^|&]*-decode|\bbitsadmin\b|\bcurl\b|\bwget\b|https?://|javascript:|vbscript:|/i:http'

    $rules = [ordered]@{
        # Folder names carry their separator so that Templates\, Tempo\, PerfLogsX\ ... do not match.
        # The last group lists the user-writable folders inside %windir% (Tasks, spool\drivers\color, com\dmp, tracing,
        # Registration\CRMLog): a standard user can drop a binary there and the location still "looks like Windows".
        SuspiciousPathRegex = '\\(Temp|Tmp)\\|\\AppData\\Local\\Temp\\|\\AppData\\Roaming\\|\\AppData\\Local(?!\\Microsoft\\WindowsApps|\\Programs)\\|ProgramData(?!\\Microsoft\\Windows Defender\\Platform|\\Microsoft\\Windows\\|\\Package Cache)\\|Users\\Public\\|\\\$Recycle|\\Windows\\Temp\\|\\PerfLogs\\|\\Fonts\\|\\Windows\\Tasks\\|\\System32\\Tasks\\|\\spool\\drivers\\color\\|\\System32\\com\\dmp\\|\\SysWOW64\\com\\dmp\\|\\Windows\\tracing\\|\\Windows\\Registration\\CRMLog\\'
        # "--url=" alone matched Electron/Chromium "--url=https://..." command lines; only stratum URLs count.
        MinerTokenRegex     = 'stratum\+(tcp|ssl)|\bxmr\b|monero|\bpool\b|--donate-level|--algo\b|--randomx|cryptonight|kawpow|ethash|etchash|--cpu-priority|--cpu-max-threads-hint|nicehash|minergate|xmrig|ethminer|\bt-rex\b|lolminer|nbminer|phoenixminer|gminer|teamredminer|srbminer|kryptex|unmineable|-o\s+\S+:\d{4,5}|-o\s+stratum|--url=stratum|-u\s+[48][0-9A-Za-z]{90,}'
        ScriptHostRegex     = '^(powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|msbuild|installutil|certutil|bitsadmin|cmd)(\.exe)?$'
        ScriptHostWeakArgRegex   = $scriptHostWeak
        ScriptHostStrongArgRegex = $scriptHostStrong
        ScriptHostArgRegex  = $scriptHostStrong   # backward-compatible alias of the STRONG regex
        SystemBinaryNames   = @('svchost', 'csrss', 'lsass', 'smss', 'wininit', 'winlogon', 'services', 'explorer', 'RuntimeBroker',
                                'dllhost', 'conhost', 'taskhostw', 'spoolsv', 'dwm', 'fontdrvhost', 'sihost', 'SearchIndexer', 'MsMpEng',
                                'WmiPrvSE', 'System', 'Registry', 'ctfmon', 'sppsvc', 'lsaiso', 'taskmgr')
        SystemBinaryLocations = [ordered]@{
            'default'  = @('%windir%\System32', '%windir%\SysWOW64')
            'explorer' = @('%windir%')
            'MsMpEng'  = @('%ProgramData%\Microsoft\Windows Defender\Platform', '%ProgramFiles%\Windows Defender')
        }
        ExpectedParents     = $expectedParents
        PoolPorts           = @(3333, 3334, 3335, 3357, 4444, 5555, 6666, 7777, 8888, 9999, 14433, 14444, 45560, 45700, 20535, 1314, 17777, 18081)
        TrustedDnsServers   = @('1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220',
                                '77.88.8.8', '77.88.8.1', '94.140.14.14', '94.140.15.15', '76.76.2.0', '76.76.10.0',
                                '2606:4700:4700::1111', '2001:4860:4860::8888')
        PrivateIpRegex      = '^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|::1$|fe80:|fc|fd|224\.|239\.|255\.)'
        PupNameRegex        = ('Advanced SystemCare|Driver Booster|Driver Updater|DriverPack|Reimage|Restoro|PC Accelerate|PC Optimizer|Web Companion|MyCleanPC|Auslogics|WinZip (Driver|System)|Segurazo|McAfee WebAdvisor|Weather(bug| Nation)|SpeedUpMyPC|OneSafe|Smart PC Care|Wise Care|Glary Utilities|IObit|Ask Toolbar|Bing Bar|Search Protect|Conduit|MyWebSearch|Baidu|Amigo|Mail\.Ru ({0}|{1})|{1}|Yandex Punto|Kometa|OpenCandy|RelevantKnowledge|PC HelpSoft|TotalAV|ByteFence|Avast Cleanup|CCleaner' -f $cyrAgent, $cyrSputnik)
        PupInfoOnlyRegex    = 'CCleaner'
        KnownHeavyProcesses = @('MsMpEng', 'MpDefenderCoreService', 'NisSrv', 'SearchIndexer', 'SearchProtocolHost', 'SearchFilterHost', 'TiWorker',
                                'TrustedInstaller', 'MoUsoCoreWorker', 'UsoClient', 'wuauclt', 'CompatTelRunner', 'OneDrive', 'OneDrive.Sync.Service',
                                'Microsoft.Photos', 'PhotosApp', 'backgroundTaskHost', 'RuntimeBroker', 'WmiPrvSE', 'dwm', 'vmmemWSL', 'vmmem', 'vmwp',
                                'NVIDIA Container', 'NVDisplay.Container', 'nvcontainer', 'cpumetricsserver', 'RadeonSoftware', 'atieclxx',
                                'AdobeUpdateService', 'AGSService', 'AGMService', 'CCXProcess', 'AdobeCollabSync', 'GoogleUpdater', 'updater',
                                'edgeupdate', 'MicrosoftEdgeUpdate', 'steamwebhelper', 'EpicWebHelper', 'ollama', 'LM Studio', 'python', 'ffmpeg',
                                'HandBrake', 'obs64', 'Code', 'chrome', 'msedge', 'firefox', 'browser', 'opera', 'brave', 'Discord', 'Telegram',
                                'Spotify', 'Teams', 'ms-teams', 'Zoom', 'GeForceNOW', 'javaw', 'java', 'MemCompression', 'Memory Compression',
                                'Registry', 'System', 'Idle')
        # Applied to the X.500 subject of a VALID Authenticode signature. Anchored on the organisation attribute:
        # the O= value must START with one of the vendor names (word boundary after it), so "CN=Dellwood Games",
        # "O=Placer Software" or "L=Dell" never match. Values containing a comma are quoted in the subject string.
        TrustedSignerRegex  = '(^|,\s*)O="?(Microsoft Corporation|Microsoft Windows|Google LLC|Mozilla Corporation|Valve|NVIDIA Corporation|Advanced Micro Devices|Intel Corporation|Adobe Inc|Apple Inc|Discord Inc|Dropbox|Spotify AB|Yandex|Telegram FZ|Zoom (Video )?Communications|Logitech|Realtek|Oracle America|Python Software Foundation|OpenJS Foundation|JetBrains|Docker Inc|Canonical|1Password|AgileBits|Bitwarden|Kaspersky|AO Kaspersky Lab|ESET|Avast|AVG|Bitdefender|Malwarebytes|Dr\.Web|Doctor Web|Epic Games|Ubisoft|Electronic Arts|Riot Games|Blizzard|Xiaomi|Beijing Xiaomi|Huawei|Samsung|ASUSTeK|Acer|Lenovo|HP Inc|Dell)\b[^,"]*"?(,|$)'
        KnownDebuggers      = @('vsjitdebugger', 'procexp', 'procexp64', 'windbg', 'windbgx', 'cdb', 'devenv', 'DebugView')
        NoisyEventProviders = @('Microsoft-Windows-GroupPolicy', 'NETLOGON', 'Microsoft-Windows-Security-SPP', 'DistributedCOM',
                                'Microsoft-Windows-DistributedCOM', 'Microsoft-Windows-Perflib')
        KnownScheduledTasks = @('\WinDebug Monitor')
        MonitorTaskName     = 'WinDebug Monitor'
    }
    return $rules
}

# ---------------------------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------------------------
function Test-IsAdmin {
    [CmdletBinding()]
    param()
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p  = New-Object Security.Principal.WindowsPrincipal($id)
        $result = [bool]$p.IsInRole([Security.Principal.SecurityIdentifier]'S-1-5-32-544')   # BUILTIN\Administrators
    } catch {
        $result = $false
    }
    $script:IsAdmin = $result
    return $result
}

function Initialize-Common {
    [CmdletBinding()]
    param([string]$ToolVersion = '1.0.0')

    # Remember the user's culture before switching the thread to invariant (ConvertTo-Double falls back to it).
    if ($null -eq $script:OriginalCulture) {
        try { $script:OriginalCulture = [Globalization.CultureInfo]::CurrentCulture } catch { $script:OriginalCulture = $null }
        if ($null -eq $script:OriginalCulture -or $script:OriginalCulture.Name -eq '') {
            try { $script:OriginalCulture = [Globalization.CultureInfo]::InstalledUICulture } catch { $script:OriginalCulture = $null }
        }
    }
    try { [Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::InvariantCulture } catch { }
    try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
    try { $global:OutputEncoding = [Text.Encoding]::UTF8 } catch { }

    $script:Inv         = [Globalization.CultureInfo]::InvariantCulture
    $script:Utf8NoBom   = New-Object System.Text.UTF8Encoding($false)
    $script:Utf8Bom     = New-Object System.Text.UTF8Encoding($true)
    $script:ToolVersion = $ToolVersion
    $script:ToolName    = 'win-debug'
    $script:IsAdmin     = Test-IsAdmin
    if ($null -eq $script:Findings)         { $script:Findings         = New-Object 'System.Collections.Generic.List[object]' }
    if ($null -eq $script:CollectionErrors) { $script:CollectionErrors = New-Object 'System.Collections.Generic.List[object]' }
    if ($null -eq $script:AdminSkips)       { $script:AdminSkips       = New-Object 'System.Collections.Generic.List[object]' }
    if ($null -eq $script:ReportDir)   { $script:ReportDir = $null }
    if ($null -eq $script:LogPath)     { $script:LogPath = $null }
    if ($null -eq $script:VerboseLog)  { $script:VerboseLog = $false }
    if ($null -eq $script:CurrentMode) { $script:CurrentMode = '' }
    if ($null -eq $script:RunStart)    { $script:RunStart = Get-Date }
    $script:Rules    = Get-WdRuleTable
    $script:NCPU     = [Environment]::ProcessorCount
    $script:RepoRoot = Split-Path -Parent $script:LibRoot

    # Relocated Downloads folder (lowercase, expanded), used by Get-ProcessLocationClass.
    $script:DownloadsDir = $null
    try {
        $dl = Get-RegistryValueSafe -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders' -Name '{374DE290-123F-4565-9164-39C4925E467B}' -Expand
        if (-not [string]::IsNullOrWhiteSpace([string]$dl)) {
            $script:DownloadsDir = ([Environment]::ExpandEnvironmentVariables([string]$dl)).ToLowerInvariant()
        }
    } catch { $script:DownloadsDir = $null }
}

# ---------------------------------------------------------------------------------------------
# Time, numbers, text
# ---------------------------------------------------------------------------------------------
function Get-WdInv {
    [CmdletBinding()]
    param()
    if ($null -eq $script:Inv) { return [Globalization.CultureInfo]::InvariantCulture }
    return $script:Inv
}

function Get-CurrentDirectory {
    # File-system path of the current location without a provider prefix (never throws).
    [CmdletBinding()]
    param()
    try {
        $loc = Get-Location
        if ($loc.Provider.Name -eq 'FileSystem' -and -not [string]::IsNullOrEmpty($loc.ProviderPath)) { return [string]$loc.ProviderPath }
    } catch { }
    try { return [Environment]::CurrentDirectory } catch { return $script:RepoRoot }
}

function Resolve-PathSafe {
    # Makes a relative path absolute against the current directory; returns the input when that fails.
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    try {
        if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
        return [IO.Path]::GetFullPath([IO.Path]::Combine((Get-CurrentDirectory), $Path))
    } catch { return $Path }
}

function ConvertTo-CommandLineArgument {
    # Quotes one value for a Win32 command line the way powershell.exe / the C runtime split it:
    # backslashes that precede a quote or the closing quote are doubled, embedded quotes become \".
    # A naive "{0}" would turn -OutputRoot "D:\" into D:" plus everything that follows. Never throws.
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { $Text = '' }
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append([char]'"')
    $i = 0
    $n = $Text.Length
    while ($i -lt $n) {
        $backslashes = 0
        while ($i -lt $n -and $Text[$i] -eq [char]'\') { $backslashes++; $i++ }
        if ($i -ge $n) {
            # Trailing backslashes precede the closing quote: double them so the quote stays a delimiter.
            [void]$sb.Append([char]'\', $backslashes * 2)
            break
        }
        if ($Text[$i] -eq [char]'"') {
            [void]$sb.Append([char]'\', $backslashes * 2 + 1)
            [void]$sb.Append([char]'"')
        } else {
            [void]$sb.Append([char]'\', $backslashes)
            [void]$sb.Append($Text[$i])
        }
        $i++
    }
    [void]$sb.Append([char]'"')
    return $sb.ToString()
}

function Get-IsoTimestamp {
    [CmdletBinding()]
    param(
        [Nullable[DateTime]]$Date,
        [switch]$Utc,
        [switch]$ForFileName
    )
    $inv = Get-WdInv
    if ($null -eq $Date) { $d = Get-Date } else { $d = [DateTime]$Date }
    if ($Utc) {
        if ($d.Kind -eq [DateTimeKind]::Unspecified) { $d = [DateTime]::SpecifyKind($d, [DateTimeKind]::Local) }
        return $d.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $inv)
    }
    if ($d.Kind -eq [DateTimeKind]::Utc) { $d = $d.ToLocalTime() }
    elseif ($d.Kind -eq [DateTimeKind]::Unspecified) { $d = [DateTime]::SpecifyKind($d, [DateTimeKind]::Local) }
    if ($ForFileName) { return $d.ToString('yyyyMMdd-HHmmss', $inv) }
    return $d.ToString('yyyy-MM-ddTHH:mm:ss.fffK', $inv)
}

function Test-WdIsIntegerType {
    [CmdletBinding()]
    param([object]$Value)
    return ($Value -is [int] -or $Value -is [long] -or $Value -is [uint32] -or $Value -is [uint64] -or
            $Value -is [int16] -or $Value -is [uint16] -or $Value -is [byte] -or $Value -is [sbyte] -or
            $Value -is [bigint])
}

function ConvertTo-InvariantString {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][AllowNull()][object]$Value,
        [int]$Decimals = 2
    )
    $inv = Get-WdInv
    if ($null -eq $Value) { return '' }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool] -or $Value -is [System.Management.Automation.SwitchParameter]) {
        if ([bool]$Value) { return 'True' } else { return 'False' }
    }
    if ($Value -is [DateTime]) { return (Get-IsoTimestamp -Date $Value) }
    if ($Value -is [DateTimeOffset]) { return $Value.ToString('yyyy-MM-ddTHH:mm:ss.fffzzz', $inv) }
    if (Test-WdIsIntegerType -Value $Value) { return $Value.ToString($inv) }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        $d = [double]$Value
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return '' }
        return ([math]::Round($d, $Decimals, [MidpointRounding]::AwayFromZero)).ToString('F' + $Decimals.ToString($inv), $inv)
    }
    if ($Value -is [enum]) { return $Value.ToString() }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = New-Object 'System.Collections.Generic.List[string]'
        foreach ($k in $Value.Keys) { $parts.Add(('{0}={1}' -f [string]$k, (ConvertTo-InvariantString -Value $Value[$k] -Decimals $Decimals))) }
        return ($parts -join ';')
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = New-Object 'System.Collections.Generic.List[string]'
        foreach ($item in $Value) { $parts.Add((ConvertTo-InvariantString -Value $item -Decimals $Decimals)) }
        return ($parts -join ';')
    }
    try { return [string]$Value.ToString() } catch { return '' }
}

function ConvertTo-Double {
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $inv = Get-WdInv
    $d = 0.0
    $t = $Text.Trim()
    if ([double]::TryParse($t, [Globalization.NumberStyles]::Float, $inv, [ref]$d)) { return $d }
    $fallback = $script:OriginalCulture
    if ($null -eq $fallback) { $fallback = [Globalization.CultureInfo]::CurrentCulture }
    if ([double]::TryParse($t, [Globalization.NumberStyles]::Float, $fallback, [ref]$d)) { return $d }
    # Last resort: a plain decimal comma ("1,5") regardless of culture.
    if ($t -match '^[+-]?\d+,\d+$' -and [double]::TryParse($t.Replace(',', '.'), [Globalization.NumberStyles]::Float, $inv, [ref]$d)) { return $d }
    return $null
}

function Format-Bytes {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][AllowNull()][object]$Bytes,
        [int]$Decimals = 1
    )
    $inv = Get-WdInv
    if ($null -eq $Bytes) { return 'n/a' }
    $b = 0.0
    try { $b = [double]$Bytes } catch { return 'n/a' }
    if ([double]::IsNaN($b) -or $b -lt 0) { return 'n/a' }
    $units = @('B', 'KB', 'MB', 'GB', 'TB', 'PB')
    $i = 0
    while ($b -ge 1024 -and $i -lt ($units.Count - 1)) { $b = $b / 1024; $i++ }
    if ($i -eq 0) { return ('{0} {1}' -f ([math]::Round($b, 0, [MidpointRounding]::AwayFromZero)).ToString('F0', $inv), $units[$i]) }
    $s = ([math]::Round($b, $Decimals, [MidpointRounding]::AwayFromZero)).ToString('F' + $Decimals.ToString($inv), $inv)
    return ('{0} {1}' -f $s, $units[$i])
}

# ---------------------------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------------------------
function Write-Log {
    # Levels: Info, Warn, Error, Debug. No [ValidateSet]: a binding failure would be a terminating error outside
    # the try/catch, and this function must never throw. Unknown or abbreviated levels are normalized here
    # (tests\Invoke-Checks.ps1 still rejects literal typos at self-check time).
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][AllowNull()][AllowEmptyString()][object]$Level = 'Info',
        [Parameter(Position = 1)][AllowNull()][object]$Message,
        [switch]$NoConsole
    )
    try {
        if ($null -eq $Message) { $Message = '' }
        $Message = [string]$Message
        $Level = [string]$Level
        switch -Regex ($Level) {
            '^warn'          { $Level = 'Warn' }
            '^err'           { $Level = 'Error' }
            '^(dbg|debug|verbose)' { $Level = 'Debug' }
            default          { $Level = 'Info' }
        }
        $tag = $Level.ToUpperInvariant().PadRight(5)
        if (-not $NoConsole) {
            switch ($Level) {
                'Warn'  { Write-Host ('WARN: ' + $Message) -ForegroundColor Yellow }
                'Error' { Write-Host ('ERROR: ' + $Message) -ForegroundColor Red }
                'Debug' { if ($script:VerboseLog) { Write-Host ('DEBUG: ' + $Message) -ForegroundColor DarkGray } }
                default { Write-Host $Message }
            }
        }
        if (-not [string]::IsNullOrEmpty($script:LogPath)) {
            $enc = $script:Utf8NoBom
            if ($null -eq $enc) { $enc = New-Object System.Text.UTF8Encoding($false) }
            $line = '{0} [{1}] {2}{3}' -f (Get-IsoTimestamp), $tag, $Message, "`r`n"
            [IO.File]::AppendAllText($script:LogPath, $line, $enc)
        }
    } catch { }
}

function Write-SectionHeader {
    [CmdletBinding()]
    param([Parameter(Position = 0)][string]$Title)
    try {
        Write-Host ''
        Write-Host ('=== {0} ===' -f $Title) -ForegroundColor Cyan
    } catch { }
    Write-Log -Level Info -NoConsole -Message ('--- {0} ---' -f $Title)
}

function Invoke-Safely {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Name,
        [Parameter(Position = 1, Mandatory = $true)][scriptblock]$ScriptBlock,
        [AllowNull()][object]$Default = $null,
        [switch]$Quiet
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $ErrorActionPreference = 'Stop'
    try {
        $result = & $ScriptBlock
        $sw.Stop()
        Write-Log -Level Debug -Message ('{0} ok in {1} ms' -f $Name, $sw.ElapsedMilliseconds.ToString((Get-WdInv)))
        return $result
    } catch {
        $sw.Stop()
        $msg = $_.Exception.Message
        if ([string]::IsNullOrEmpty($msg)) { $msg = [string]$_ }
        $msg = ($msg -replace '\r?\n', ' ').Trim()
        # A .NET stack dump or a 50 KB WMI error must not flood run.log and the summary table.
        if ($msg.Length -gt 1000) { $msg = $msg.Substring(0, 1000) + (' ... [truncated, {0} chars]' -f $msg.Length.ToString((Get-WdInv))) }
        $adminSkip = Test-WdAdminSkipMessage -Name $Name -Message $msg
        if ($Quiet -or $adminSkip) {
            Write-Log -Level Debug -Message ('{0} failed: {1}' -f $Name, $msg)
        } else {
            Write-Log -Level Warn -Message ('{0} failed: {1}' -f $Name, $msg)
        }
        # Add-WdCollectionError drops an item that failed only for lack of administrator rights (it is listed under
        # "Skipped (requires administrator)" instead).
        Add-WdCollectionError -Name $Name -Message $msg
        return $Default
    }
}

function Measure-Step {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Name,
        [Parameter(Position = 1, Mandatory = $true)][scriptblock]$ScriptBlock
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $ScriptBlock
    } finally {
        $sw.Stop()
        Write-Log -Level Info -Message ([string]::Format((Get-WdInv), 'Step {0} took {1:F1} s', $Name, $sw.Elapsed.TotalSeconds))
    }
}

# ---------------------------------------------------------------------------------------------
# Data sources
# ---------------------------------------------------------------------------------------------
function Test-WdAdminSkipMessage {
    # $true when a failure message ends with the "(requires administrator)" marker: the item is an admin skip, not a
    # collection error. Whoever produced the message normally registered the skip already (Get-WinEventSafe does);
    # when nobody did, the skip is registered here under the item name so that summary.md still lists it once, under
    # "Skipped (requires administrator)". Items are matched ignoring case and whitespace ("EventLog Security" vs
    # "Event log Security").
    [CmdletBinding()]
    param([AllowNull()][AllowEmptyString()][string]$Name, [AllowNull()][AllowEmptyString()][string]$Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    if (-not $Message.TrimEnd().EndsWith('(requires administrator)', [StringComparison]::OrdinalIgnoreCase)) { return $false }
    $key = ([string]$Name -replace '\s', '').ToLowerInvariant()
    $registered = $false
    if ($null -ne $script:AdminSkips) {
        foreach ($s in $script:AdminSkips) {
            $item = ([string]$s['Item'] -replace '\s', '').ToLowerInvariant()
            if ([string]::IsNullOrEmpty($item)) { continue }
            if ($item -eq $key -or ($key.Length -gt 0 -and ($key.Contains($item) -or $item.Contains($key)))) { $registered = $true; break }
        }
    }
    if (-not $registered -and -not [string]::IsNullOrWhiteSpace($Name)) {
        $detail = $Message.TrimEnd()
        $detail = $detail.Substring(0, $detail.Length - '(requires administrator)'.Length).TrimEnd()
        Add-AdminSkip -Item $Name -Detail $detail
    }
    return $true
}

function Add-WdCollectionError {
    # Records one collection failure for the "Collection errors" section. A message that ends with
    # "(requires administrator)" is not recorded: it belongs to "Skipped (requires administrator)" only.
    [CmdletBinding()]
    param([string]$Name, [string]$Message)
    if ($null -eq $script:CollectionErrors) { $script:CollectionErrors = New-Object 'System.Collections.Generic.List[object]' }
    if (Test-WdAdminSkipMessage -Name $Name -Message $Message) { return }
    $script:CollectionErrors.Add([ordered]@{ Name = $Name; Error = $Message; Time = (Get-IsoTimestamp) })
}

function Confirm-WdReportExport {
    # Collection gaps are recoverable, but failed report writes must not end with a success message.
    [CmdletBinding()]
    param([int]$ErrorStart = 0)
    if ($script:CollectionErrors.Count -le $ErrorStart) { return }
    $names = @()
    for ($index = $ErrorStart; $index -lt $script:CollectionErrors.Count; $index++) {
        $names += [string]$script:CollectionErrors[$index]['Name']
    }
    throw ('Report export failed ({0}). Partial files were preserved; see the log for details.' -f ($names -join ', '))
}

function Get-CimSafe {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$ClassName,
        [string]$Namespace = 'root/cimv2',
        [string]$Filter,
        [string[]]$Property,
        [int]$TimeoutSec = 30
    )
    # Verbose:$false keeps "Perform operation 'Enumerate CimInstances'" chatter out of -Verbose runs.
    $p = @{ ClassName = $ClassName; Namespace = $Namespace; OperationTimeoutSec = $TimeoutSec; ErrorAction = 'Stop'; Verbose = $false }
    if (-not [string]::IsNullOrEmpty($Filter)) { $p['Filter'] = $Filter }
    if ($null -ne $Property -and $Property.Count -gt 0) { $p['Property'] = $Property }
    try {
        $r = @(Get-CimInstance @p)
        return $r
    } catch {
        $msg = ($_.Exception.Message -replace '\r?\n', ' ').Trim()
        Write-Log -Level Debug -Message ('CIM {0} failed: {1}' -f $ClassName, $msg)
        Add-WdCollectionError -Name ('CIM ' + $ClassName) -Message ('{0}: {1}' -f $ClassName, $msg)
        return @()
    }
}

function Get-WinEventSafe {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)][hashtable]$FilterHashtable,
        [int]$MaxEvents = 0
    )
    $logName = ''
    if ($FilterHashtable.ContainsKey('LogName')) { $logName = [string]$FilterHashtable['LogName'] }
    elseif ($FilterHashtable.ContainsKey('ProviderName')) { $logName = 'provider ' + [string]$FilterHashtable['ProviderName'] }
    # These logs answer a standard user with "No events were found" (or access denied) instead of data.
    $adminOnlyLogs = @('Security', 'Microsoft-Windows-Diagnostics-Performance/Operational', 'Microsoft-Windows-Storage-Storport/Operational')
    if (-not $script:IsAdmin -and ($adminOnlyLogs -contains $logName)) {
        Add-AdminSkip -Item ('Event log ' + $logName) -Detail 'log is readable only by administrators'
        Write-Log -Level Debug -Message ('Event log {0} skipped (requires administrator)' -f $logName)
        return @()
    }
    # Verbose:$false keeps Get-WinEvent's "Constructed structured query" / "Found matching provider" chatter out of -Verbose runs.
    $p = @{ FilterHashtable = $FilterHashtable; ErrorAction = 'Stop'; Verbose = $false }
    if ($MaxEvents -gt 0) { $p['MaxEvents'] = $MaxEvents }
    try {
        $r = @(Get-WinEvent @p)
        return $r
    } catch {
        $msg = ($_.Exception.Message -replace '\r?\n', ' ').Trim()
        # Classify by culture-neutral data first: the message text is localized on a Russian-UI Windows
        # (PowerShell ships ru-RU resources), the FullyQualifiedErrorId and the exception type are not.
        $fqid = ''
        try { $fqid = [string]$_.FullyQualifiedErrorId } catch { $fqid = '' }
        $ex = $_.Exception
        $hresult = 0
        try { $hresult = [int]$ex.HResult } catch { $hresult = 0 }
        if ($fqid -like 'NoMatchingEventsFound*' -or $msg -match 'No events were found') {
            return @()
        }
        if ($fqid -like 'NoMatchingLogsFound*') {
            # The log does not exist on this Windows edition (for example Storport/Operational): not an error.
            Write-Log -Level Debug -Message ('Event log {0}: log not present on this system' -f $logName)
            return @()
        }
        $denied = ($ex -is [System.UnauthorizedAccessException]) -or ($hresult -eq -2147024891) -or
                  ($fqid -match 'UnauthorizedAccess|AccessDenied') -or ($msg -match 'unauthorized|access is denied|Attempted to perform')
        if ($denied) {
            # An admin skip, not a collection error (Add-WdCollectionError would drop the marker message anyway).
            Add-AdminSkip -Item ('Event log ' + $logName) -Detail $msg
            Write-Log -Level Debug -Message ('Event log {0}: {1} (requires administrator)' -f $logName, $msg)
        } else {
            Add-WdCollectionError -Name ('EventLog ' + $logName) -Message ('{0}: {1}' -f $logName, $msg)
            Write-Log -Level Debug -Message ('Event log {0} failed: {1}' -f $logName, $msg)
        }
        return @()
    }
}

function Get-RegistryValueSafe {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Path,
        [Parameter(Position = 1, Mandatory = $true)][AllowEmptyString()][string]$Name,
        [AllowNull()][object]$Default = $null,
        [switch]$Expand
    )
    try {
        $k = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($null -eq $k) { return $Default }
        $opt = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames
        if ($Expand) { $opt = [Microsoft.Win32.RegistryValueOptions]::None }
        $v = $k.GetValue($Name, $null, $opt)
        if ($null -eq $v) { return $Default }
        return $v
    } catch {
        return $Default
    }
}

function Test-DirectoryExists {
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { return [IO.Directory]::Exists($Path) } catch { return $false }
}

function Test-FileExists {
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    try { return [IO.File]::Exists($Path) } catch { return $false }
}

function Get-FileSizeSafe {
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try {
        $fi = New-Object System.IO.FileInfo($Path)
        if (-not $fi.Exists) { return $null }
        return [int64]$fi.Length
    } catch { return $null }
}

# ---------------------------------------------------------------------------------------------
# Output files
# ---------------------------------------------------------------------------------------------
function Get-WdUtf8NoBom {
    [CmdletBinding()]
    param()
    if ($null -eq $script:Utf8NoBom) { return (New-Object System.Text.UTF8Encoding($false)) }
    return $script:Utf8NoBom
}

function Write-TextFile {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Path,
        [Parameter(Position = 1)][AllowNull()][AllowEmptyString()][string]$Content
    )
    if ($null -eq $Content) { $Content = '' }
    $dir = [IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrEmpty($dir) -and -not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
    [IO.File]::WriteAllText($Path, $Content, (Get-WdUtf8NoBom))
}

function Write-MarkdownFile {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Path,
        [Parameter(Position = 1)][AllowNull()][AllowEmptyCollection()][string[]]$Lines
    )
    if ($null -eq $Lines) { $Lines = @() }
    $text = ($Lines -join "`r`n") + "`r`n"
    Write-TextFile -Path $Path -Content $text
}

function ConvertTo-JsonReady {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][AllowNull()][object]$Value,
        [int]$Depth = 8,
        [int]$Level = 0
    )
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return $Value }
    if ($Value -is [bool]) { return [bool]$Value }
    if ($Value -is [System.Management.Automation.SwitchParameter]) { return [bool]$Value }
    if ($Value -is [DateTime]) { return (Get-IsoTimestamp -Date $Value) }
    if ($Value -is [DateTimeOffset]) { return $Value.ToString('yyyy-MM-ddTHH:mm:ss.fffzzz', (Get-WdInv)) }
    if ($Value -is [TimeSpan]) { return [math]::Round($Value.TotalSeconds, 3, [MidpointRounding]::AwayFromZero) }
    if ($Value -is [enum]) { return $Value.ToString() }
    if ($Value -is [double] -or $Value -is [single]) {
        $d = [double]$Value
        if ([double]::IsNaN($d) -or [double]::IsInfinity($d)) { return $null }
        return $d
    }
    if ($Value -is [bigint]) {
        # ConvertTo-Json (PS 5.1) serializes BigInteger as a property bag (IsZero, Sign...): use a number when it fits.
        if ($Value -ge [long]::MinValue -and $Value -le [long]::MaxValue) { return [long]$Value }
        return $Value.ToString((Get-WdInv))
    }
    if ($Value -is [decimal] -or (Test-WdIsIntegerType -Value $Value)) { return $Value }
    if ($Value -is [char] -or $Value -is [guid] -or $Value -is [version] -or $Value -is [uri] -or $Value -is [System.Net.IPAddress] -or $Value -is [scriptblock] -or $Value -is [type]) {
        return $Value.ToString()
    }
    if ($Level -ge $Depth) {
        try { return [string]$Value.ToString() } catch { return $null }
    }
    if ($Value -is [Microsoft.Management.Infrastructure.CimInstance]) {
        $o = [ordered]@{}
        foreach ($prop in $Value.CimInstanceProperties) {
            $pv = $null
            try { $pv = $prop.Value } catch { $pv = $null }
            $o[[string]$prop.Name] = ConvertTo-JsonReady -Value $pv -Depth $Depth -Level ($Level + 1)
        }
        return $o
    }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Value.Keys) {
            $o[[string]$k] = ConvertTo-JsonReady -Value $Value[$k] -Depth $Depth -Level ($Level + 1)
        }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = New-Object 'System.Collections.Generic.List[object]'
        foreach ($item in $Value) { $list.Add((ConvertTo-JsonReady -Value $item -Depth $Depth -Level ($Level + 1))) }
        return ,$list.ToArray()
    }
    if ($Value -is [System.Management.Automation.PSObject] -or $Value -is [System.Management.Automation.PSCustomObject]) {
        $o = [ordered]@{}
        foreach ($prop in $Value.PSObject.Properties) {
            $pv = $null
            try { $pv = $prop.Value } catch { $pv = $null }
            $o[[string]$prop.Name] = ConvertTo-JsonReady -Value $pv -Depth $Depth -Level ($Level + 1)
        }
        return $o
    }
    $t = $Value.GetType()
    if ($t.IsPrimitive) { return $Value }
    if ($t.IsValueType) { return $Value.ToString() }
    # Arbitrary .NET object: project its public properties.
    $o = [ordered]@{}
    foreach ($prop in $Value.PSObject.Properties) {
        if ($prop.MemberType -ne 'Property' -and $prop.MemberType -ne 'NoteProperty' -and $prop.MemberType -ne 'ScriptProperty') { continue }
        $pv = $null
        try { $pv = $prop.Value } catch { $pv = $null }
        $o[[string]$prop.Name] = ConvertTo-JsonReady -Value $pv -Depth $Depth -Level ($Level + 1)
    }
    return $o
}

function Export-Json {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][AllowNull()][object]$Object,
        [Parameter(Position = 1, Mandatory = $true)][string]$Path,
        [int]$Depth = 8,
        [switch]$Compress
    )
    $ready = ConvertTo-JsonReady -Value $Object -Depth $Depth
    if ($null -eq $ready) { $json = 'null' }
    else {
        $jp = @{ InputObject = $ready; Depth = $Depth }
        if ($Compress) { $jp['Compress'] = $true }
        $json = ConvertTo-Json @jp
    }
    Write-TextFile -Path $Path -Content $json
}

function Protect-WdCsvText {
    # CSV cells are opened in Excel, which evaluates a cell starting with = + @ - TAB or CR as a formula even
    # when it is quoted (CSV injection via an autostart command or a planted DisplayName). A leading space
    # neutralizes that without the visible apostrophe. Only a cell that is entirely a number ("-5", "-1.50", "-1,5")
    # keeps its leading "-": "-2+3" or "-1+cmd|x" would still be evaluated by Excel and are guarded like any other text.
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $c = $Text[0]
    if ($c -eq [char]'=' -or $c -eq [char]'+' -or $c -eq [char]'@' -or $c -eq [char]9 -or $c -eq [char]13) { return ' ' + $Text }
    if ($c -eq [char]'-' -and $Text -notmatch '^-\d+([.,]\d+)?$') { return ' ' + $Text }
    return $Text
}

function Hide-WdSecret {
    # Best-effort masking of secrets that can appear in command lines, service paths, task arguments, script text and
    # event messages before they are written to reports (a VPN private key or a password passed on a command line
    # must not travel with a shared summary). The key name is kept, the value becomes ***. Over-masking is the
    # preferred failure mode; miner wallets/pool hosts are deliberately NOT masked because they are evidence.
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $t = $Text
    # Mask complete quoted values first: stopping at whitespace would leave most of a passphrase visible.
    $secretName = '(?:(?:password|passwd|passphrase|pwd|secret|token|client[-_]?secret|authorization|auth[-_]?token|bearer|credentials?|session[-_]?id|signature)[\w-]{0,16}|[\w-]*key)'
    $quotedValue = '(?<quote>["''])(?:\\.|(?!\k<quote>)[\s\S])*?\k<quote>'
    $t = [regex]::Replace($t, ('(?i)\b(?<prefix>' + $secretName + '\s*["'']?\s*[=:]\s*)' + $quotedValue), '${prefix}${quote}***${quote}')
    $switchName = '(?:password|passwd|passphrase|pwd|pass|token|secret|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret|credentials?)'
    $t = [regex]::Replace($t, ('(?i)(?<prefix>(?:^|\s)[-/]{1,2}' + $switchName + '(?:\s+|[=:]))' + $quotedValue), '${prefix}${quote}***${quote}')
    # key = value / key: value / "key": "value"   (PrivateKey = <base64>, password=..., "token": "...")
    $t = [regex]::Replace($t, '(?i)\b((?:(?:password|passwd|passphrase|pwd|secret|token|client[-_]?secret|authorization|auth[-_]?token|bearer|credentials?|session[-_]?id|signature)[\w-]{0,16}|[\w-]*key)\s*["'']?\s*[=:]\s*["'']?)([^\s"''&;,]+)', '$1***')
    # switches: --password xxx, /password:xxx, --token=xxx, -secret xxx (single -p is left alone: usually a port)
    $t = [regex]::Replace($t, '(?i)((?:^|\s)[-/]{1,2}(?:password|passwd|passphrase|pwd|pass|token|secret|api[-_]?key|access[-_]?key|private[-_]?key|client[-_]?secret|credentials?)(?:\s+|[=:]))(["'']?)([^\s"'']+)', '$1$2***')
    # URL user info: scheme://user:secret@host
    $t = [regex]::Replace($t, '(?i)(://[^/\s:@]+:)([^@\s/]+)(@)', '$1***$3')
    # URL query parameters
    $t = [regex]::Replace($t, '(?i)([?&](?:token|key|secret|password|pwd|sig|signature|access_token|auth|apikey|api_key)=)([^&\s"'']+)', '$1***')
    return $t
}
function ConvertTo-WdCsvCell {
    # Text values get the formula guard; numbers, dates and bools are formatted culture-invariantly (never prefixed,
    # so "-1.50" stays machine-readable).
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    if ($Value -is [string]) { return (Protect-WdCsvText -Text $Value) }
    return (ConvertTo-InvariantString -Value $Value)
}

function ConvertTo-WdFlatRow {
    [CmdletBinding()]
    param([AllowNull()][object]$InputObject)
    $row = [ordered]@{}
    if ($null -eq $InputObject) { return [pscustomobject]$row }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($k in $InputObject.Keys) { $row[[string]$k] = ConvertTo-WdCsvCell -Value $InputObject[$k] }
        return [pscustomobject]$row
    }
    foreach ($prop in $InputObject.PSObject.Properties) {
        $pv = $null
        try { $pv = $prop.Value } catch { $pv = $null }
        $row[[string]$prop.Name] = ConvertTo-WdCsvCell -Value $pv
    }
    return [pscustomobject]$row
}

function Export-CsvInvariant {
    # -Columns: the schema of the file. With rows it fixes the column order (columns missing from a row become empty
    # cells; properties not listed are appended after them so no data is lost); without rows the quoted header line
    # is written instead of a BOM-only file, so an empty devices-problems.csv still tells the reader what it would hold.
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)][AllowNull()][AllowEmptyCollection()][object[]]$InputObject,
        [Parameter(Mandatory = $true)][string]$Path,
        [AllowNull()][AllowEmptyCollection()][string[]]$Columns,
        [switch]$Append
    )
    begin {
        $rows = New-Object 'System.Collections.Generic.List[object]'
        $schema = New-Object 'System.Collections.Generic.List[string]'
        if ($null -ne $Columns) {
            foreach ($c in $Columns) { if (-not [string]::IsNullOrEmpty($c) -and -not $schema.Contains($c)) { $schema.Add([string]$c) } }
        }
    }
    process {
        if ($null -eq $InputObject) { return }
        foreach ($item in $InputObject) {
            if ($null -eq $item) { continue }
            $rows.Add((ConvertTo-WdFlatRow -InputObject $item))
        }
    }
    end {
        $dir = [IO.Path]::GetDirectoryName($Path)
        if (-not [string]::IsNullOrEmpty($dir) -and -not [IO.Directory]::Exists($dir)) { [void][IO.Directory]::CreateDirectory($dir) }
        if ($rows.Count -eq 0) {
            if (-not $Append -and -not [IO.File]::Exists($Path)) {
                if ($schema.Count -gt 0) {
                    # Empty result with a known schema: header line only (same quoting as Export-Csv), UTF-8 BOM.
                    $hdr = New-Object 'System.Collections.Generic.List[string]'
                    foreach ($c in $schema) { $hdr.Add('"' + $c.Replace('"', '""') + '"') }
                    [IO.File]::WriteAllText($Path, (($hdr -join ',') + "`r`n"), (New-Object System.Text.UTF8Encoding($true)))
                } else {
                    # Empty result without a schema: create an empty UTF-8 BOM file so the artifact exists.
                    [IO.File]::WriteAllText($Path, '', (New-Object System.Text.UTF8Encoding($true)))
                }
            }
            return
        }
        $out = $rows
        if ($schema.Count -gt 0) {
            # Export-Csv takes the header from the first object: normalize every row to schema + extras (first seen order).
            $allColumns = New-Object 'System.Collections.Generic.List[string]'
            foreach ($c in $schema) { $allColumns.Add($c) }
            foreach ($r in $rows) {
                foreach ($prop in $r.PSObject.Properties) { if (-not $allColumns.Contains([string]$prop.Name)) { $allColumns.Add([string]$prop.Name) } }
            }
            $out = New-Object 'System.Collections.Generic.List[object]'
            foreach ($r in $rows) {
                $o = [ordered]@{}
                foreach ($c in $allColumns) {
                    $prop = $r.PSObject.Properties[$c]
                    if ($null -eq $prop) { $o[$c] = '' } else { $o[$c] = $prop.Value }
                }
                $out.Add([pscustomobject]$o)
            }
        }
        $p = @{ NoTypeInformation = $true; Encoding = 'UTF8'; Delimiter = ','; LiteralPath = $Path }
        if ($Append) { $p['Append'] = $true }
        $out.ToArray() | Export-Csv @p
    }
}

# ---------------------------------------------------------------------------------------------
# Findings and admin skips
# ---------------------------------------------------------------------------------------------
function Add-Finding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateSet('Critical', 'Warning', 'Info')][string]$Severity,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$Title,
        [AllowNull()][AllowEmptyString()][string]$Detail = '',
        [AllowNull()][AllowEmptyString()][string]$Recommendation = '',
        [AllowNull()][AllowEmptyString()][string]$RuleId = '',
        [AllowNull()][object]$Data = $null
    )
    if ($null -eq $script:Findings) { $script:Findings = New-Object 'System.Collections.Generic.List[object]' }
    foreach ($f in $script:Findings) {
        if ([string]$f['RuleId'] -eq $RuleId -and [string]$f['Title'] -eq $Title) { return }
    }
    $item = [ordered]@{
        RuleId         = $RuleId
        Severity       = $Severity
        Category       = $Category
        Title          = $Title
        Detail         = $Detail
        Recommendation = $Recommendation
        Time           = (Get-IsoTimestamp)
    }
    if ($null -ne $Data) { $item['Data'] = $Data }
    $script:Findings.Add($item)
    $color = 'Gray'
    switch ($Severity) {
        'Critical' { $color = 'Red' }
        'Warning'  { $color = 'Yellow' }
    }
    try { Write-Host ('[{0}] {1}' -f $Severity.ToUpperInvariant(), $Title) -ForegroundColor $color } catch { }
    Write-Log -Level Info -NoConsole -Message ('[{0}] {1}{2}' -f $Severity.ToUpperInvariant(), $Title, $(if ($RuleId) { ' (' + $RuleId + ')' } else { '' }))
}

function Get-Findings {
    [CmdletBinding()]
    param([string[]]$Severity)
    if ($null -eq $script:Findings -or $script:Findings.Count -eq 0) { return @() }
    $rank = @{ 'Critical' = 0; 'Warning' = 1; 'Info' = 2 }
    $indexed = New-Object 'System.Collections.Generic.List[object]'
    $i = 0
    foreach ($f in $script:Findings) {
        $i++
        if ($null -ne $Severity -and $Severity.Count -gt 0 -and -not ($Severity -contains [string]$f['Severity'])) { continue }
        $r = 9
        if ($rank.ContainsKey([string]$f['Severity'])) { $r = $rank[[string]$f['Severity']] }
        $indexed.Add([pscustomobject]@{ Rank = $r; Category = [string]$f['Category']; Index = $i; Item = $f })
    }
    $sorted = @($indexed.ToArray() | Sort-Object -Property @{ Expression = 'Rank' }, @{ Expression = 'Category' }, @{ Expression = 'Index' } | ForEach-Object { $_.Item })
    return $sorted
}

function Add-AdminSkip {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$Item,
        [AllowNull()][AllowEmptyString()][string]$Detail = ''
    )
    if ($null -eq $script:AdminSkips) { $script:AdminSkips = New-Object 'System.Collections.Generic.List[object]' }
    foreach ($s in $script:AdminSkips) { if ([string]$s['Item'] -eq $Item) { return } }
    $script:AdminSkips.Add([ordered]@{ Item = $Item; Detail = $Detail; Time = (Get-IsoTimestamp) })
    Write-Log -Level Info -Message ('Skipped (requires administrator): {0}' -f $Item)
}

function Get-AdminSkips {
    [CmdletBinding()]
    param()
    if ($null -eq $script:AdminSkips) { return @() }
    return @($script:AdminSkips.ToArray())
}

# ---------------------------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------------------------
function ConvertTo-WdMarkdownCell {
    [CmdletBinding()]
    param([AllowNull()][object]$Value)
    $s = ConvertTo-InvariantString -Value $Value
    if ($null -eq $s) { $s = '' }
    $s = $s -replace '\r\n|\r|\n', ' '
    $s = $s.Replace('|', '\|')
    if ($s.Length -gt 200) { $s = $s.Substring(0, 199) + [string][char]0x2026 }
    return $s
}

function Get-WdRowValue {
    [CmdletBinding()]
    param([AllowNull()][object]$Row, [string]$Column)
    if ($null -eq $Row) { return $null }
    if ($Row -is [System.Collections.IDictionary]) {
        if ($Row.Contains($Column)) { return $Row[$Column] }
        return $null
    }
    $prop = $Row.PSObject.Properties[$Column]
    if ($null -eq $prop) { return $null }
    try { return $prop.Value } catch { return $null }
}

function ConvertTo-MarkdownTable {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)][AllowNull()][AllowEmptyCollection()][object[]]$InputObject,
        [Parameter(Position = 1, Mandatory = $true)][string[]]$Columns,
        [string[]]$Headers
    )
    $lines = New-Object 'System.Collections.Generic.List[string]'
    if ($null -eq $InputObject -or $InputObject.Count -eq 0) {
        $lines.Add('_none_')
        return $lines.ToArray()
    }
    $titles = @($Columns)
    if ($null -ne $Headers -and $Headers.Count -gt 0) {
        $titles = @()
        for ($i = 0; $i -lt $Columns.Count; $i++) {
            if ($i -lt $Headers.Count -and -not [string]::IsNullOrEmpty($Headers[$i])) { $titles += $Headers[$i] } else { $titles += $Columns[$i] }
        }
    }
    $hdr = @()
    foreach ($t in $titles) { $hdr += (ConvertTo-WdMarkdownCell -Value $t) }
    $lines.Add('| ' + ($hdr -join ' | ') + ' |')
    $sep = @()
    foreach ($t in $titles) { $sep += '---' }
    $lines.Add('|' + ($sep -join '|') + '|')
    foreach ($row in $InputObject) {
        if ($null -eq $row) { continue }
        $cells = @()
        foreach ($c in $Columns) { $cells += (ConvertTo-WdMarkdownCell -Value (Get-WdRowValue -Row $row -Column $c)) }
        $lines.Add('| ' + ($cells -join ' | ') + ' |')
    }
    return $lines.ToArray()
}

function Get-RunInfoSectionLines {
    [CmdletBinding()]
    param(
        [Nullable[double]]$DurationSeconds,
        [string]$Mode
    )
    $inv = Get-WdInv
    $info = Get-ReportRunInfo -Mode $Mode
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('## Run info')
    $lines.Add('')
    $lines.Add(('- Computer: {0}' -f $info['Computer']))
    $lines.Add(('- User: {0}' -f $info['User']))
    $lines.Add(('- Time: {0}' -f $info['StartTime']))
    $lines.Add(('- Tool: {0} {1}, mode {2}' -f $info['Tool'], $info['Version'], $info['Mode']))
    $lines.Add(('- Elevated (administrator): {0}' -f $(if ($info['IsAdmin']) { 'yes' } else { 'no (some data is missing; see "Skipped (requires administrator)")' })))
    $lines.Add(('- Windows build: {0}; PowerShell {1}; culture {2} / UI {3}' -f $info['OSBuild'], $info['PSVersion'], $info['Culture'], $info['UICulture']))
    if ($null -ne $DurationSeconds) {
        $lines.Add(('- Duration: {0} s' -f ([math]::Round([double]$DurationSeconds, 1, [MidpointRounding]::AwayFromZero)).ToString('F1', $inv)))
    }
    # Every summary / report carries the privacy notice (the CSV/JSON files next to it hold the same data).
    $lines.Add('- Privacy: this report and its CSV/JSON files contain personal data (computer and user names, paths, command lines, network addresses). Secrets on command lines are masked best-effort. Review before sharing.')
    $lines.Add('')
    return $lines.ToArray()
}

function Get-SummaryFooterLines {
    [CmdletBinding()]
    param()
    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add('## Skipped (requires administrator)')
    $lines.Add('')
    $skips = @(Get-AdminSkips)
    if ($skips.Count -eq 0) {
        if ($script:IsAdmin) { $lines.Add('_none_ (the run was elevated)') } else { $lines.Add('_none_') }
    } else {
        foreach ($s in $skips) {
            $d = [string]$s['Detail']
            if ([string]::IsNullOrWhiteSpace($d)) { $lines.Add(('- {0} (requires administrator)' -f (ConvertTo-WdMarkdownCell -Value $s['Item']))) }
            else { $lines.Add(('- {0} (requires administrator): {1}' -f (ConvertTo-WdMarkdownCell -Value $s['Item']), (ConvertTo-WdMarkdownCell -Value $d))) }
        }
    }
    $lines.Add('')
    $lines.Add('## Collection errors')
    $lines.Add('')
    $errs = @()
    if ($null -ne $script:CollectionErrors) { $errs = @($script:CollectionErrors.ToArray()) }
    if ($errs.Count -eq 0) {
        $lines.Add('_none_')
    } else {
        foreach ($l in (ConvertTo-MarkdownTable -InputObject $errs -Columns @('Name', 'Error', 'Time') -Headers @('Item', 'Error', 'Time'))) { $lines.Add($l) }
    }
    $lines.Add('')
    return $lines.ToArray()
}

# ---------------------------------------------------------------------------------------------
# Report directory and run info
# ---------------------------------------------------------------------------------------------
function Get-WdOsBuild {
    [CmdletBinding()]
    param()
    $build = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild' -Default ''
    $ubr   = Get-RegistryValueSafe -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'UBR' -Default $null
    if ([string]::IsNullOrEmpty([string]$build)) { return [string][Environment]::OSVersion.Version }
    if ($null -eq $ubr) { return [string]$build }
    return ('{0}.{1}' -f [string]$build, ([int64]$ubr).ToString((Get-WdInv)))
}

function Get-ReportRunInfo {
    [CmdletBinding()]
    param([string]$Mode)
    if ([string]::IsNullOrEmpty($Mode)) { $Mode = [string]$script:CurrentMode }
    $start = $script:RunStart
    if ($null -eq $start) { $start = Get-Date }
    $user = $env:USERNAME
    if (-not [string]::IsNullOrEmpty($env:USERDOMAIN)) { $user = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME }
    $psv = ''
    try { $psv = $PSVersionTable.PSVersion.ToString() } catch { $psv = '' }
    $culture = ''
    $uiCulture = ''
    try { $culture = (Get-Culture).Name } catch { }
    try { $uiCulture = (Get-UICulture).Name } catch { }
    return [ordered]@{
        Tool      = $(if ($script:ToolName) { $script:ToolName } else { 'win-debug' })
        Version   = [string]$script:ToolVersion
        Mode      = $Mode
        Computer  = [string]$env:COMPUTERNAME
        User      = $user
        IsAdmin   = [bool]$script:IsAdmin
        StartTime = (Get-IsoTimestamp -Date $start)
        PSVersion = $psv
        OSBuild   = (Get-WdOsBuild)
        Culture   = $culture
        UICulture = $uiCulture
    }
}

function New-ReportDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$OutputRoot,
        [Parameter(Mandatory = $true)][string]$Mode
    )
    $inv = Get-WdInv
    [void][IO.Directory]::CreateDirectory($OutputRoot)
    $pc = [string]$env:COMPUTERNAME
    if ([string]::IsNullOrWhiteSpace($pc)) { $pc = 'PC' }
    foreach ($bad in [IO.Path]::GetInvalidFileNameChars()) { $pc = $pc.Replace([string]$bad, '_') }
    $now = Get-Date
    $base = '{0}_{1}_{2}' -f $pc, (Get-IsoTimestamp -Date $now -ForFileName), $Mode.ToLowerInvariant()
    $dir = [IO.Path]::Combine($OutputRoot, $base)
    $n = 1
    while ([IO.Directory]::Exists($dir) -or [IO.File]::Exists($dir)) {
        $n++
        $dir = [IO.Path]::Combine($OutputRoot, ('{0}-{1}' -f $base, $n.ToString($inv)))
    }
    [void][IO.Directory]::CreateDirectory($dir)
    $script:ReportDir   = $dir
    $script:LogPath     = [IO.Path]::Combine($dir, 'run.log')
    $script:CurrentMode = $Mode
    $script:RunStart    = $now
    $info = Get-ReportRunInfo -Mode $Mode
    $header = 'win-debug {0} | mode={1} | user={2} | admin={3} | ps={4} | os={5} | culture={6}/{7}' -f `
        $info['Version'], $Mode.ToLowerInvariant(), $info['User'], $info['IsAdmin'], $info['PSVersion'], $info['OSBuild'], $info['Culture'], $info['UICulture']
    Write-Log -Level Info -NoConsole -Message $header
    return $dir
}

# ---------------------------------------------------------------------------------------------
# Classification and native helpers
# ---------------------------------------------------------------------------------------------
function Get-WdFolderPrefix {
    # Lower-cased folder path with exactly one trailing backslash ('' for empty input), for StartsWith checks.
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    $v = $Value.Trim().Trim('"').TrimEnd('\').ToLowerInvariant()
    if ([string]::IsNullOrEmpty($v)) { return '' }
    return $v + '\'
}

function Get-ProcessLocationClass {
    [CmdletBinding()]
    param([Parameter(Position = 0)][AllowNull()][AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return 'Unknown' }
    $l = $Path.Trim('"').ToLowerInvariant()
    # Every folder prefix carries a trailing separator, otherwise "C:\Program FilesFake\" or "C:\ProgramDataX\"
    # would be classified as the trusted sibling.
    $win = Get-WdFolderPrefix -Value ([string]$env:windir)
    if ([string]::IsNullOrEmpty($win)) { $win = 'c:\windows\' }
    $temp = Get-WdFolderPrefix -Value ([string]$env:TEMP)
    if ($l -match '^[a-z]:\\\$recycle\.bin\\') { return 'RecycleBin' }
    if ((-not [string]::IsNullOrEmpty($temp) -and $l.StartsWith($temp)) -or $l -match '\\temp\\|\\tmp\\') { return 'Temp' }
    if ($l.StartsWith($win + 'system32\') -or $l.StartsWith($win + 'syswow64\')) { return 'System32' }
    if ($l.StartsWith($win)) { return 'Windows' }
    $pf = Get-WdFolderPrefix -Value ([string]$env:ProgramFiles)
    $pf86 = Get-WdFolderPrefix -Value ([string]${env:ProgramFiles(x86)})
    if ((-not [string]::IsNullOrEmpty($pf) -and $l.StartsWith($pf)) -or (-not [string]::IsNullOrEmpty($pf86) -and $l.StartsWith($pf86))) { return 'ProgramFiles' }
    $pd = Get-WdFolderPrefix -Value ([string]$env:ProgramData)
    if (-not [string]::IsNullOrEmpty($pd) -and $l.StartsWith($pd)) { return 'ProgramData' }
    $pub = Get-WdFolderPrefix -Value ([string]$env:PUBLIC)
    if (-not [string]::IsNullOrEmpty($pub) -and $l.StartsWith($pub)) { return 'Public' }
    $dl = Get-WdFolderPrefix -Value ([string]$script:DownloadsDir)
    if ($l -match '\\downloads\\' -or (-not [string]::IsNullOrEmpty($dl) -and $l.StartsWith($dl))) { return 'Downloads' }
    if ($l -match '^[a-z]:\\users\\[^\\]+\\appdata\\') { return 'AppData' }
    if ($l -match '^[a-z]:\\users\\') { return 'UserProfile' }
    if ($l -match '^\\\\') { return 'Network' }
    if ($l.Length -ge 3) {
        $drv = $l.Substring(0, 3)
        try {
            $di = [IO.DriveInfo]::GetDrives() | Where-Object { $_.Name.ToLowerInvariant() -eq $drv }
            if ($di -and $di.DriveType -eq 'Removable') { return 'Removable' }
        } catch { }
    }
    return 'Other'
}

function Add-NativeType {
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true)][string]$TypeName,
        [Parameter(Position = 1, Mandatory = $true)][string]$SourcePath
    )
    if ($TypeName -as [type]) { return $true }
    $candidates = New-Object 'System.Collections.Generic.List[string]'
    if ([IO.Path]::IsPathRooted($SourcePath)) {
        $candidates.Add($SourcePath)
    } else {
        $candidates.Add([IO.Path]::Combine($script:LibRoot, $SourcePath))
        $candidates.Add([IO.Path]::Combine([IO.Path]::Combine($script:LibRoot, 'native'), $SourcePath))
        $cwdCandidate = Resolve-PathSafe -Path $SourcePath
        if (-not [string]::IsNullOrEmpty($cwdCandidate)) { $candidates.Add($cwdCandidate) }
    }
    $resolved = $null
    foreach ($c in $candidates) { if ([IO.File]::Exists($c)) { $resolved = $c; break } }
    if ($null -eq $resolved) {
        Write-Log -Level Warn -Message ('Native helper {0} unavailable: source file not found ({1})' -f $TypeName, $SourcePath)
        return $false
    }
    try {
        $src = Get-Content -LiteralPath $resolved -Raw -Encoding UTF8 -ErrorAction Stop
        Add-Type -TypeDefinition $src -ErrorAction Stop
        if ($TypeName -as [type]) { return $true }
        Write-Log -Level Warn -Message ('Native helper {0} unavailable: compiled but type not found' -f $TypeName)
        return $false
    } catch {
        $msg = ($_.Exception.Message -replace '\r?\n', ' ').Trim()
        Write-Log -Level Warn -Message ('Native helper {0} unavailable: {1}' -f $TypeName, $msg)
        return $false
    }
}

function Get-WinDebugRule {
    [CmdletBinding()]
    param([Parameter(Position = 0, Mandatory = $true)][string]$Name)
    if ($null -eq $script:Rules) { $script:Rules = Get-WdRuleTable }
    if (-not $script:Rules.Contains($Name)) { throw ('Unknown win-debug rule "{0}" (programming error)' -f $Name) }
    $v = $script:Rules[$Name]
    return $v
}
