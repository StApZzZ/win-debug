#Requires -Version 5.1

# Functional regressions on synthetic data and a temporary directory; no reports leave %TEMP%.
[CmdletBinding()]
param([switch]$IncludeMonitor)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
foreach ($module in @('Common', 'Inventory', 'DiskUsage', 'Monitor', 'Analyze')) {
    . ([IO.Path]::Combine($repoRoot, 'lib', ($module + '.ps1')))
}
Initialize-Common -ToolVersion 'functional-check'
$scratchRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('wd-functional-' + [guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($scratchRoot)
$script:checkCount = 0
$monitorProcess = $null

function Assert-FunctionalCheck {
    [CmdletBinding()]
    param([bool]$Condition, [string]$Detail)
    $script:checkCount++
    if (-not $Condition) { throw $Detail }
}

function Reset-CheckState {
    [CmdletBinding()]
    param()
    $script:Findings.Clear()
    $script:CollectionErrors.Clear()
    $script:AdminSkips.Clear()
    $script:LogPath = $null
}

function New-AnalysisFixture {
    [CmdletBinding()]
    param([string]$Name, [string]$CommandLine, [switch]$Empty, [switch]$Broken)
    $folder = [IO.Path]::Combine($scratchRoot, $Name)
    [void][IO.Directory]::CreateDirectory($folder)
    $timestamp = '2026-01-01T12:00:00.000+00:00'
    $key = '4242|134117424000000000'
    $sampleRows = @()
    $procRows = @()
    if (-not $Empty) {
        $sampleRows = @([ordered]@{ Timestamp = $timestamp; SampleNo = 1; IntervalSec = 10; CpuPct = 1; IsIdle = $false; MemTotalMB = 8192; MemUsedMB = 2048 })
        $procRows = @([ordered]@{ Timestamp = $timestamp; Key = $key; Pid = 4242; Name = 'fixture'; CpuPct = 1; CpuCores = 0.01; WorkingSet = 16MB; IsIdle = $false; Flags = '' })
    }
    Export-CsvInvariant -InputObject $sampleRows -Path ([IO.Path]::Combine($folder, 'samples_20260101.csv')) -Columns @('Timestamp', 'SampleNo', 'IntervalSec', 'CpuPct', 'IsIdle', 'MemTotalMB', 'MemUsedMB')
    Export-CsvInvariant -InputObject $procRows -Path ([IO.Path]::Combine($folder, 'procs_20260101.csv')) -Columns @('Timestamp', 'Key', 'Pid', 'Name', 'CpuPct', 'CpuCores', 'WorkingSet', 'IsIdle', 'Flags')
    if (-not $Empty) {
        Export-CsvInvariant -InputObject @([ordered]@{ Key = $key; Pid = 4242; Name = 'fixture'; ImageName = 'fixture.exe'; Path = 'C:\Program Files\Fixture\fixture.exe'; CommandLine = $CommandLine; LocationClass = 'ProgramFiles'; SigStatus = 'Valid'; Signer = 'Microsoft Corporation'; FirstSeen = $timestamp; Started = $timestamp; Flags = '' }) -Path ([IO.Path]::Combine($folder, 'procmeta.csv'))
    }
    if ($Broken) { [IO.File]::WriteAllText([IO.Path]::Combine($folder, 'procsum.json'), '{broken JSON', [Text.Encoding]::UTF8) }
    return $folder
}

try {
    # Both walkers must count hidden/empty folders and files, preserve [brackets], and avoid a junction loop.
    $tree = [IO.Path]::Combine($scratchRoot, 'tree')
    $child = [IO.Path]::Combine($tree, 'child [check]')
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($child, 'empty'))
    [IO.File]::WriteAllBytes([IO.Path]::Combine($tree, 'first.bin'), (New-Object byte[] 1024))
    [IO.File]::WriteAllBytes([IO.Path]::Combine($child, 'second.bin'), (New-Object byte[] 2048))
    $loop = [IO.Path]::Combine($tree, 'loop')
    New-Item -ItemType Junction -Path $loop -Target $tree -ErrorAction Stop | Out-Null
    Assert-FunctionalCheck -Condition (Add-NativeType -TypeName 'WinDebug.FastWalker' -SourcePath 'FastWalker.cs') -Detail 'FastWalker did not compile'
    $native = [WinDebug.FastWalker]::Scan($tree, 3, 0, 0)
    $fallback = Get-WdDiskFallbackScan -Path $tree -MaxDepth 3 -LargeFileThreshold 0 -OldDays 0
    foreach ($scan in @($native, $fallback)) {
        Assert-FunctionalCheck -Condition ($scan.Files -eq 2 -and $scan.Bytes -eq 3072 -and $scan.Dirs -eq 2) -Detail 'Walker counts or byte totals are incorrect'
        Assert-FunctionalCheck -Condition ($scan.SkippedLinks -eq 1 -and $scan.Errors -eq 0) -Detail 'Walker followed the junction or reported an error'
    }
    Assert-FunctionalCheck -Condition ($native.TopFiles(1)[0].Bytes -eq 2048) -Detail 'Largest-file ranking is incorrect'
    # Remove only the junction itself before recursive scratch cleanup.
    [IO.Directory]::Delete($loop)

    # Protected miner evidence must survive trusted-vendor damping; a normal HTTPS helper must stay below threshold.
    $fixtures = @(
        @{ Name = 'miner'; Command = 'fixture.exe --url=stratum+tcp://pool.example:3333 --password "secret phrase"'; Suspicious = $true; Inconclusive = $false },
        @{ Name = 'normal'; Command = 'fixture.exe --url=https://example.com'; Suspicious = $false; Inconclusive = $false },
        @{ Name = 'empty'; Command = ''; Empty = $true; Suspicious = $false; Inconclusive = $true },
        @{ Name = 'broken'; Command = 'fixture.exe'; Broken = $true; Suspicious = $false; Inconclusive = $true },
        @{ Name = 'broken-miner'; Command = 'fixture.exe --url=stratum+tcp://pool.example:3333 --password "secret phrase"'; Broken = $true; Suspicious = $true; Inconclusive = $false }
    )
    foreach ($fixture in $fixtures) {
        Reset-CheckState
        $session = New-AnalysisFixture -Name $fixture.Name -CommandLine $fixture.Command -Empty:([bool]$fixture.Empty) -Broken:([bool]$fixture.Broken)
        $report = Invoke-MonitorAnalysis -SessionPath $session -TopN 5
        $analysis = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([IO.Path]::Combine($session, 'analysis.json')))
        $markdown = [IO.File]::ReadAllText($report)
        Assert-FunctionalCheck -Condition ([bool]$analysis.Verdict.Inconclusive -eq $fixture.Inconclusive) -Detail ('Wrong data-quality verdict for ' + $fixture.Name)
        Assert-FunctionalCheck -Condition ((@($analysis.Verdict.Suspects).Count -gt 0) -eq $fixture.Suspicious) -Detail ('Wrong miner verdict for ' + $fixture.Name)
        Assert-FunctionalCheck -Condition ([bool]$analysis.Verdict.Clean -eq (-not $fixture.Suspicious -and -not $fixture.Inconclusive)) -Detail ('Wrong clean verdict for ' + $fixture.Name)
        if ($fixture.Inconclusive) {
            Assert-FunctionalCheck -Condition ($markdown.Contains('**Inconclusive**') -and -not $markdown.Contains('**Nothing suspicious found**')) -Detail 'Incomplete data produced a clean report'
        }
        if ($fixture.Suspicious) {
            $protectedHits = @($analysis.Verdict.Suspects[0].Indicators | Where-Object { $_.Id -eq 'I10' -and $_.Points -ge 20 -and $_.Group -eq 'Protected' })
            Assert-FunctionalCheck -Condition ($analysis.Verdict.Suspects[0].Score -ge 20 -and $protectedHits.Count -eq 1) -Detail 'Trusted signer damped protected miner evidence'
            foreach ($file in @('analysis.json', 'report.md', 'suspects.csv', 'process-summary.csv')) {
                Assert-FunctionalCheck -Condition (-not [IO.File]::ReadAllText([IO.Path]::Combine($session, $file)).Contains('secret phrase')) -Detail ('Secret leaked into ' + $file)
            }
        }
        if ($fixture.Broken) {
            Assert-FunctionalCheck -Condition ($analysis.Stats.ProcRows -eq 1 -and $analysis.CollectionErrors.Count -gt 0) -Detail 'Corrupt procsum did not fall back to CSV with a recorded error'
        }
    }

    # An unwritable output must fail rather than reporting success; preserve other files for diagnosis.
    Reset-CheckState
    $blockedSession = New-AnalysisFixture -Name 'blocked-export' -CommandLine 'fixture.exe'
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($blockedSession, 'analysis.json'))
    $exportFailed = $false
    try { Invoke-MonitorAnalysis -SessionPath $blockedSession -TopN 5 | Out-Null } catch { $exportFailed = $_.Exception.Message -like 'Report export failed*' }
    Assert-FunctionalCheck -Condition ($exportFailed -and [IO.File]::Exists([IO.Path]::Combine($blockedSession, 'report.md'))) -Detail 'Analyze hid an export failure or lost its partial report'
    Reset-CheckState
    $inventoryOutput = [IO.Path]::Combine($scratchRoot, 'inventory-export')
    [void][IO.Directory]::CreateDirectory([IO.Path]::Combine($inventoryOutput, 'installed-programs.csv'))
    $exportFailed = $false
    $script:WdInvCtx = @{ ProcessRows = @() }
    try {
        Export-WdInvCsvFiles -OutDir $inventoryOutput -Data @{ Software = @{}; Autostart = @{}; Devices = @{}; Events = @{} }
    } catch { $exportFailed = $_.Exception.Message -like 'Report export failed*' }
    Assert-FunctionalCheck -Condition ($exportFailed -and [IO.File]::Exists([IO.Path]::Combine($inventoryOutput, 'events.csv'))) -Detail 'Inventory hid a CSV export failure or lost its partial files'

    if ($IncludeMonitor) {
        if ($repoRoot.StartsWith('\\')) { throw 'Monitor lifecycle checks require a local checkout (UNC is unsupported)' }
        Reset-CheckState
        $outputRoot = [IO.Path]::Combine($scratchRoot, 'monitor-reports')
        $hostExe = [IO.Path]::Combine($PSHOME, 'powershell.exe')
        $entry = [IO.Path]::Combine($repoRoot, 'WinDebug.ps1')
        $arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File {0} -Mode Monitor -NoElevate -IntervalSeconds 5 -DurationMinutes 1 -OutputRoot {1}' -f (ConvertTo-CommandLineArgument -Text $entry), (ConvertTo-CommandLineArgument -Text $outputRoot)
        $monitorProcess = Start-Process -FilePath $hostExe -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput ([IO.Path]::Combine($scratchRoot, 'monitor-stdout.txt')) -RedirectStandardError ([IO.Path]::Combine($scratchRoot, 'monitor-stderr.txt'))
        # Hold the process handle before exit; otherwise PS 5.1 can lose the exit code of a PassThru process.
        [void]$monitorProcess.Handle
        $deadline = (Get-Date).AddSeconds(45)
        $session = $null
        $samples = @()
        while ((Get-Date) -lt $deadline -and -not $monitorProcess.HasExited) {
            $live = @(Get-WdMonRunningSessions -OutputRoot $outputRoot)
            if ($live.Count -gt 0) {
                $session = $live[0].Folder
                $sampleFiles = @([IO.Directory]::GetFiles($session, 'samples_*.csv'))
                if ($sampleFiles.Count -gt 0) { $samples = @(Import-Csv -LiteralPath $sampleFiles[0]); if ($samples.Count -ge 2) { break } }
            }
            Start-Sleep -Milliseconds 500
        }
        Assert-FunctionalCheck -Condition ($samples.Count -ge 2) -Detail ('Monitor did not collect two samples; see ' + $scratchRoot)
        $stopOutcome = Stop-ProcessMonitor -OutputRoot $outputRoot
        Assert-FunctionalCheck -Condition ($stopOutcome -eq 'Stopped') -Detail 'Monitor did not confirm STOP'
        $exited = $monitorProcess.WaitForExit(15000)
        Assert-FunctionalCheck -Condition ($exited -and $monitorProcess.ExitCode -eq 0) -Detail ('Monitor did not exit successfully (exited={0}, code={1}): {2}' -f $exited, $monitorProcess.ExitCode, [IO.File]::ReadAllText([IO.Path]::Combine($scratchRoot, 'monitor-stderr.txt')))
        Assert-FunctionalCheck -Condition (-not [IO.File]::Exists([IO.Path]::Combine($session, 'monitor.running'))) -Detail 'Monitor left a running marker'
        $run = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText([IO.Path]::Combine($session, 'run.json')))
        Assert-FunctionalCheck -Condition ($run.SamplesWritten -ge 2 -and $run.StopReason -eq 'STOP file') -Detail 'Monitor did not flush its final state'
        Reset-CheckState
        $report = Invoke-MonitorAnalysis -SessionPath $session -TopN 5
        Assert-FunctionalCheck -Condition ([IO.File]::Exists($report) -and $script:CollectionErrors.Count -eq 0) -Detail 'Recorded session could not be analyzed cleanly'
    }
    Write-Host ('All {0} functional checks passed.' -f $script:checkCount) -ForegroundColor Green
} finally {
    if ($null -ne $monitorProcess -and -not $monitorProcess.HasExited) {
        try { Stop-ProcessMonitor -OutputRoot ([IO.Path]::Combine($scratchRoot, 'monitor-reports')) | Out-Null } catch { }
        if (-not $monitorProcess.WaitForExit(10000)) { $monitorProcess.Kill(); $monitorProcess.WaitForExit() }
    }
    $loopPath = [IO.Path]::Combine($scratchRoot, 'tree', 'loop')
    if ([IO.Directory]::Exists($loopPath)) { [IO.Directory]::Delete($loopPath) }
    # The exact GUID-named scratch directory is owned by this test.
    if ([IO.Directory]::Exists($scratchRoot)) { [IO.Directory]::Delete($scratchRoot, $true) }
}
