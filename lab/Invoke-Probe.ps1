#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Probe,
    [Parameter(Mandatory)] [string] $BaselineConfig,
    [string] $Sysmon = 'Sysmon64.exe',
    [string] $Repository = (Split-Path -Parent $PSScriptRoot),
    [int] $SettleSeconds = 3,
    [int] $WaitSeconds = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Field {
    param([Parameter(Mandatory)] [object] $Object, [Parameter(Mandatory)] [string] $Name)
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }
    [string] $property.Value
}

function Write-Marked {
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Destination,
        [Parameter(Mandatory)] [string] $Marker
    )
    $text = [System.IO.File]::ReadAllText($Source).Replace('MARKER', $Marker)
    [System.IO.File]::WriteAllText($Destination, $text, (New-Object System.Text.UTF8Encoding($false)))
}

function Get-Prediction {
    param(
        [Parameter(Mandatory)] [string] $Project,
        [Parameter(Mandatory)] [string] $Config,
        [Parameter(Mandatory)] [string] $Events
    )
    $output = & uv run --project $Project sigma-blindspot check-event $Config $Events
    if ($LASTEXITCODE -ne 0) {
        throw "sigma-blindspot check-event failed with exit code $LASTEXITCODE"
    }
    $states = @{}
    foreach ($line in $output) {
        if ($line -match ':(\d+): EventID \d+ (LOGGED|DROPPED|UNKNOWN) ') {
            $states[[int] $Matches[1]] = $Matches[2]
        }
    }
    $states
}

function Test-Observed {
    param(
        [Parameter(Mandatory)] [object] $Expected,
        [Parameter(Mandatory)] [object] $Observed,
        [Parameter(Mandatory)] [int] $TriggerId
    )
    if ((Get-Field -Object $Observed -Name 'EventID') -ne (Get-Field -Object $Expected -Name 'EventID')) {
        return $false
    }
    $key = Get-Field -Object $Expected -Name 'ProbeKey'
    if ($key -eq 'PID') {
        $ids = @((Get-Field -Object $Observed -Name 'ProcessId'), (Get-Field -Object $Observed -Name 'SourceProcessId'))
        if ($ids -notcontains [string] $TriggerId) {
            return $false
        }
    }
    else {
        $values = @($Observed.PSObject.Properties | ForEach-Object { [string] $_.Value })
        if (-not ($values | Where-Object { $_.IndexOf($key, [StringComparison]::OrdinalIgnoreCase) -ge 0 })) {
            return $false
        }
    }
    $match = Get-Field -Object $Expected -Name 'ProbeMatch'
    foreach ($name in @(if ($match) { $match.Split(',') })) {
        if ((Get-Field -Object $Observed -Name $name) -ne (Get-Field -Object $Expected -Name $name)) {
            return $false
        }
    }
    $true
}

function Get-Version {
    $path = (Get-Command -Name $Sysmon).Source
    $binary = (Get-Item -LiteralPath $path).VersionInfo.ProductVersion
    $text = ((& $Sysmon -nobanner -s) -join "`n") -replace "`0", ''
    $schema = if ($text -match 'schemaversion="([0-9.]+)"') { $Matches[1] } else { 'unknown' }
    "Sysmon $binary, schema $schema"
}

$directory = Join-Path (Join-Path $PSScriptRoot 'probes') $Probe
foreach ($name in 'config.xml', 'trigger.ps1', 'expected.jsonl', 'README.md') {
    if (-not (Test-Path -LiteralPath (Join-Path $directory $name))) {
        throw "probe '$Probe' has no $name"
    }
}
$baseline = (Resolve-Path -LiteralPath $BaselineConfig).Path
$marker = 'sbprobe' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$run = Join-Path (Join-Path $PSScriptRoot 'out') "$Probe-$marker"
New-Item -ItemType Directory -Path $run | Out-Null
$config = Join-Path $run 'config.xml'
$expectedFile = Join-Path $run 'expected.jsonl'
$triggerScript = Join-Path $directory 'trigger.ps1'
$triggerLog = Join-Path $run 'trigger.log'
Write-Marked -Source (Join-Path $directory 'config.xml') -Destination $config -Marker $marker
Write-Marked -Source (Join-Path $directory 'expected.jsonl') -Destination $expectedFile -Marker $marker

$header = @("probe $Probe, marker $marker", (Get-Version))
$header | Write-Output
$predicted = Get-Prediction -Project $Repository -Config $config -Events $expectedFile
$applied = $false
$triggerId = 0
try {
    & $Sysmon -nobanner -c $config
    $applied = ($LASTEXITCODE -eq 0)
    if ($applied) {
        Start-Sleep -Seconds $SettleSeconds
        $since = Get-Date
        $shell = (Get-Process -Id $PID).Path
        $arguments = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass',
            '-File', $triggerScript, '-Marker', $marker
        )
        if ((Get-Command -Name $triggerScript).Parameters.ContainsKey('Log')) {
            $arguments += @('-Log', $triggerLog)
        }
        $trigger = Start-Process -FilePath $shell -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
        $triggerId = $trigger.Id
        if ($trigger.ExitCode -ne 0) {
            Write-Warning "trigger exited with code $($trigger.ExitCode)"
        }
        Start-Sleep -Seconds $WaitSeconds
        & (Join-Path $PSScriptRoot 'Export-SysmonEvents.ps1') -Since $since -OutFile (Join-Path $run 'observed.jsonl') | Out-Null
    }
}
finally {
    & $Sysmon -nobanner -c $baseline
    if ($LASTEXITCODE -ne 0) {
        Write-Error "could not restore the baseline config $baseline"
    }
}

$rows = New-Object System.Collections.Generic.List[string]
if (-not $applied) {
    $rows.Add("sysmon -c rejected the probe config, nothing was triggered")
}
else {
    $observed = @(Get-Content -LiteralPath (Join-Path $run 'observed.jsonl') -Encoding UTF8 | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    $rows.Add('| Line | EventID | Key | Predicted | Observed | |')
    $rows.Add('| --- | --- | --- | --- | --- | --- |')
    $number = 0
    foreach ($line in [System.IO.File]::ReadAllLines($expectedFile)) {
        $number += 1
        if (-not $line.Trim()) {
            continue
        }
        $expected = $line | ConvertFrom-Json
        $seen = @($observed | Where-Object { Test-Observed -Expected $expected -Observed $_ -TriggerId $triggerId })
        $state = if ($seen.Count -gt 0) { 'LOGGED' } else { 'DROPPED' }
        $prediction = $predicted[$number]
        $verdict = if ($prediction -eq $state) { 'agree' } else { 'DIFFER' }
        $rows.Add(("| {0} | {1} | {2} | {3} | {4} | {5} |" -f $number, (Get-Field -Object $expected -Name 'EventID'), (Get-Field -Object $expected -Name 'ProbeKey'), $prediction, $state, $verdict))
    }
    if (Test-Path -LiteralPath $triggerLog) {
        $rows.Add('')
        foreach ($entry in [System.IO.File]::ReadAllLines($triggerLog)) {
            $rows.Add("trigger: $entry")
        }
    }
}
$rows | Write-Output
$result = Join-Path $run 'result.md'
[System.IO.File]::WriteAllLines($result, [string[]] ($header + $rows), (New-Object System.Text.UTF8Encoding($false)))
Write-Output "result written to $result"
