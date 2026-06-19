function Connect-TcpWithTimeout {
<#
.SYNOPSIS
    Opens a TcpClient and connects with a timeout.

.OUTPUTS
    PSCustomObject { TcpClient, NetworkStream }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Alias('Host')]
        [ValidateNotNullOrEmpty()]
        [string]$Hostname,

        [Parameter(Mandatory)]
        [ValidateRange(1,65535)]
        [int]$Port,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Target=$($Hostname):$($Port), TimeoutMs=$TimeoutMs)"

    $tcp = $null
    try {
        $tcp = [System.Net.Sockets.TcpClient]::new()
        $tcp.NoDelay = $true

        $task = $tcp.ConnectAsync($Hostname, $Port)
        if (-not $task.Wait($TimeoutMs)) {
            throw (New-TlsTimeoutException `
                -Operation 'TCP connection' `
                -TimeoutMs $TimeoutMs `
                -Hostname $Hostname `
                -Port $Port)
        }

        $netStream = $tcp.GetStream()
        Write-Verbose "[$fn] Connected to $($Hostname):$($Port)"
        [PSCustomObject]@{ TcpClient = $tcp; NetworkStream = $netStream }
    }
    catch {
        Close-TlsResource -Resource $tcp -ResourceName 'TcpClient' -OwnerName $fn

        $errorToThrow = Resolve-TlsException -Exception $_.Exception
        $throwOriginal = [object]::ReferenceEquals($errorToThrow, $_.Exception)

        $null = Add-TlsErrorContext `
            -Exception $errorToThrow `
            -Stage 'Connection' `
            -Operation 'TCP connection' `
            -Hostname $Hostname `
            -Port $Port

        if (-not $throwOriginal) {
            throw $errorToThrow
        }

        throw
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
