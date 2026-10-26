#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)] [string] $Marker, [string] $Log)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$work = Join-Path $env:TEMP $Marker
$registry = 'HKCU:\Software\SigmaBlindspotProbe'
$key = Join-Path $registry $Marker
$outcomes = New-Object System.Collections.Generic.List[string]

function Invoke-Step {
    param([Parameter(Mandatory)] [string] $EventIds, [Parameter(Mandatory)] [scriptblock] $Action)
    try {
        . $Action
        $outcomes.Add("events ${EventIds}: done")
    }
    catch {
        $outcomes.Add("events ${EventIds}: failed, $($_.Exception.Message -replace '\s+', ' ')")
    }
}

New-Item -ItemType Directory -Path $work | Out-Null
try {
    Invoke-Step '1, 5, 27, 29' {
        $command = Join-Path $work "$Marker-5.exe"
        Copy-Item -LiteralPath $env:ComSpec -Destination $command
        Start-Process -FilePath $command -ArgumentList "/c rem $Marker-1" -Wait -WindowStyle Hidden
    }

    Invoke-Step '2' {
        $timestamped = Join-Path $work "$Marker-2.txt"
        Set-Content -LiteralPath $timestamped -Value 'probe'
        (Get-Item -LiteralPath $timestamped).CreationTime = (Get-Date).AddDays(-1)
    }

    Invoke-Step '3' {
        $client = New-Object System.Net.Sockets.TcpClient
        try {
            $client.Connect('example.org', 80)
        }
        finally {
            $client.Dispose()
        }
    }

    Invoke-Step '7' {
        $library = Join-Path $work "$Marker-7.dll"
        Copy-Item -LiteralPath (Join-Path $env:windir 'System32\version.dll') -Destination $library
        Add-Type -Namespace SigmaBlindspotProbe -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
public static extern System.IntPtr LoadLibrary(string path);
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FreeLibrary(System.IntPtr module);
'@
        $module = [SigmaBlindspotProbe.Native]::LoadLibrary($library)
        if ($module -eq [System.IntPtr]::Zero) {
            throw "LoadLibrary failed with error $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
        [SigmaBlindspotProbe.Native]::FreeLibrary($module) | Out-Null
    }

    Invoke-Step '10' {
        $target = Join-Path $work "$Marker-10.exe"
        Copy-Item -LiteralPath $env:ComSpec -Destination $target
        $waiting = Start-Process -FilePath $target -ArgumentList '/c ping -n 4 127.0.0.1 > nul' -PassThru -WindowStyle Hidden
        $opened = [System.Diagnostics.Process]::GetProcessById($waiting.Id)
        $opened.Handle | Out-Null
        $opened.Dispose()
        $waiting.WaitForExit()
    }

    Invoke-Step '11' {
        Set-Content -LiteralPath (Join-Path $work "$Marker-11.txt") -Value 'probe'
    }

    Invoke-Step '12, 13, 14' {
        New-Item -Path $key -Force | Out-Null
        New-ItemProperty -Path $key -Name "$Marker-13" -Value 1 -PropertyType DWord | Out-Null
        Rename-Item -Path $key -NewName "$Marker-14"
    }

    Invoke-Step '15' {
        Set-Content -LiteralPath (Join-Path $work "$Marker-15.txt") -Stream 'probe' -Value 'probe'
    }

    Invoke-Step '17, 18' {
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
    }

    Invoke-Step '22' {
        Resolve-DnsName -Name 'example.org' -Type A -DnsOnly | Out-Null
    }

    Invoke-Step '23, 26' {
        $deleted = Join-Path $work "$Marker-23.txt"
        Set-Content -LiteralPath $deleted -Value 'probe'
        Remove-Item -LiteralPath $deleted
    }

    Invoke-Step '24' {
        Set-Clipboard -Value "$Marker-24"
    }
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $registry -Recurse -Force -ErrorAction SilentlyContinue
    if ($Log) {
        [System.IO.File]::WriteAllLines($Log, [string[]] $outcomes, (New-Object System.Text.UTF8Encoding($false)))
    }
}
exit @($outcomes | Where-Object { $_ -like '*: failed,*' }).Count
