function Connect-TcpWithTimeout {
<#
.SYNOPSIS
    Opens a TcpClient and connects with a timeout.

.OUTPUTS
    PSCustomObject { TcpClient, NetworkStream }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Hostname,
        [Parameter(Mandatory)][int]$Port,
        [int]$TimeoutMs = 10000
    )
    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $TimeoutMs = [Math]::Max(1000, $TimeoutMs)
    Write-Verbose "[$fn] Begin (Target=$Hostname :$Port, TimeoutMs=$TimeoutMs)"
    $tcp = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.NoDelay = $true

        $task = $tcp.ConnectAsync($Hostname, $Port)
        if (-not $task.Wait($TimeoutMs)) {
            throw [System.TimeoutException]::new("Connection timeout after ${TimeoutMs}ms to $Hostname :$Port")
        }
        $netStream = $tcp.GetStream()
        Write-Verbose "[$fn] Connected to $Hostname :$Port"
        [PSCustomObject]@{ TcpClient = $tcp; NetworkStream = $netStream }
    } catch {
        try { if ($tcp) { $tcp.Dispose() } } catch {}
        throw
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
