#Requires -Version 5.1
[CmdletBinding()]
param(
    [datetime] $Since,
    [string] $Marker,
    [string] $OutFile = (Join-Path (Join-Path $PSScriptRoot 'out') 'events.jsonl')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertTo-FlatEvent {
    param([Parameter(Mandatory)] [System.Diagnostics.Eventing.Reader.EventRecord] $Record)
    $xml = [xml] $Record.ToXml()
    $flat = [ordered] @{ EventID = [int] $Record.Id }
    foreach ($data in @($xml.Event.EventData.Data)) {
        $flat[[string] $data.Name] = [string] $data.InnerText
    }
    $flat
}

function Test-Marker {
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Fields, [string] $Text)
    if (-not $Text) {
        return $true
    }
    foreach ($value in $Fields.Values) {
        if ($value -is [string] -and $value.IndexOf($Text, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $true
        }
    }
    $false
}

$filter = @{ LogName = 'Microsoft-Windows-Sysmon/Operational' }
if ($PSBoundParameters.ContainsKey('Since')) {
    $filter['StartTime'] = $Since
}
try {
    $records = @(Get-WinEvent -FilterHashtable $filter -Oldest)
}
catch {
    if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {
        throw
    }
    $records = @()
}

$lines = New-Object System.Collections.Generic.List[string]
foreach ($record in $records) {
    $flat = ConvertTo-FlatEvent -Record $record
    if (Test-Marker -Fields $flat -Text $Marker) {
        $lines.Add(($flat | ConvertTo-Json -Compress -Depth 2))
    }
}

$directory = Split-Path -Parent $OutFile
if ($directory -and -not (Test-Path -LiteralPath $directory)) {
    New-Item -ItemType Directory -Path $directory | Out-Null
}
$path = [System.IO.Path]::GetFullPath($OutFile)
[System.IO.File]::WriteAllLines($path, $lines, (New-Object System.Text.UTF8Encoding($false)))
Write-Verbose ("{0} events written to {1}" -f $lines.Count, $path)
Get-Item -LiteralPath $path
