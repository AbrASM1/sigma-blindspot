#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $Marker)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($argument in "/c rem $Marker-1", "/c rem x$Marker-2", "/c rem $Marker-3") {
    Start-Process -FilePath $env:ComSpec -ArgumentList $argument -Wait -WindowStyle Hidden
}
