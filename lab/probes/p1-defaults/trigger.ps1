#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $Marker)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$work = Join-Path $env:TEMP $Marker
$registry = 'HKCU:\Software\SigmaBlindspotProbe'
$key = Join-Path $registry $Marker
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $command = Join-Path $work "$Marker-5.exe"
    Copy-Item -LiteralPath $env:ComSpec -Destination $command
    Start-Process -FilePath $command -ArgumentList "/c rem $Marker-1" -Wait -WindowStyle Hidden

    $timestamped = Join-Path $work "$Marker-2.txt"
    Set-Content -LiteralPath $timestamped -Value 'probe'
    (Get-Item -LiteralPath $timestamped).CreationTime = (Get-Date).AddDays(-1)

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $client.Connect('example.org', 80)
    }
    finally {
        $client.Dispose()
    }

    $library = Join-Path $work "$Marker-7.dll"
    Copy-Item -LiteralPath (Join-Path $env:windir 'System32\version.dll') -Destination $library
    Add-Type -Namespace SigmaBlindspotProbe -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern System.IntPtr LoadLibrary(string path);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FreeLibrary(System.IntPtr module);
'@
    $module = [SigmaBlindspotProbe.Native]::LoadLibrary($library)
    if ($module -ne [System.IntPtr]::Zero) {
        [SigmaBlindspotProbe.Native]::FreeLibrary($module) | Out-Null
    }

    $target = Join-Path $work "$Marker-10.exe"
    Copy-Item -LiteralPath $env:ComSpec -Destination $target
    $waiting = Start-Process -FilePath $target -ArgumentList '/c ping -n 4 127.0.0.1 > nul' -PassThru -WindowStyle Hidden
    $opened = [System.Diagnostics.Process]::GetProcessById($waiting.Id)
    $opened.Handle | Out-Null
    $opened.Dispose()
    $waiting.WaitForExit()

    Set-Content -LiteralPath (Join-Path $work "$Marker-11.txt") -Value 'probe'

    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name "$Marker-13" -Value 1 -PropertyType DWord | Out-Null
    Rename-Item -Path $key -NewName "$Marker-14"

    Set-Content -LiteralPath (Join-Path $work "$Marker-15.txt") -Stream 'probe' -Value 'probe'

    $server = New-Object System.IO.Pipes.NamedPipeServerStream("$Marker-17", [System.IO.Pipes.PipeDirection]::InOut, 1, [System.IO.Pipes.PipeTransmissionMode]::Byte, [System.IO.Pipes.PipeOptions]::Asynchronous)
    $pipe = New-Object System.IO.Pipes.NamedPipeClientStream('.', "$Marker-17", [System.IO.Pipes.PipeDirection]::InOut)
    try {
        $connection = $server.WaitForConnectionAsync()
        $pipe.Connect(5000)
        $connection.Wait(5000) | Out-Null
    }
    finally {
        $pipe.Dispose()
        $server.Dispose()
    }

    Resolve-DnsName -Name 'example.org' -Type A -DnsOnly | Out-Null

    $deleted = Join-Path $work "$Marker-23.txt"
    Set-Content -LiteralPath $deleted -Value 'probe'
    Remove-Item -LiteralPath $deleted

    Set-Clipboard -Value "$Marker-24"
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $registry -Recurse -Force -ErrorAction SilentlyContinue
}
