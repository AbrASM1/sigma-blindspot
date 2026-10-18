#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $Marker)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

foreach ($suffix in 1, 2, 3) {
    Start-Process -FilePath $env:ComSpec -ArgumentList "/c rem $Marker-$suffix" -Wait -WindowStyle Hidden
}
