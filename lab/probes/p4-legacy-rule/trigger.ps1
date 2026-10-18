#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $Marker)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$work = Join-Path $env:TEMP $Marker
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $renamed = Join-Path $work 'probe.exe'
    Copy-Item -LiteralPath $env:ComSpec -Destination $renamed
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c rem $Marker-1" -Wait -WindowStyle Hidden
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c rem $Marker-3" -Wait -WindowStyle Hidden
    Start-Process -FilePath $renamed -ArgumentList "/c rem $Marker-2" -Wait -WindowStyle Hidden
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
