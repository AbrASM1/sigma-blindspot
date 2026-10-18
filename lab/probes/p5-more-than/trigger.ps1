#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $Marker)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Write-Verbose "probe $Marker connects by port, the events carry no marker"

foreach ($port in 80, 443) {
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect('example.org', $port)
    }
    finally {
        $client.Dispose()
    }
}
