#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $Marker, [string] $Log)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

& (Join-Path (Split-Path -Parent $PSScriptRoot) 'p1-defaults\trigger.ps1') -Marker $Marker -Log $Log
exit $LASTEXITCODE
