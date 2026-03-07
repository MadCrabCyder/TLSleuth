function Close-NetworkResources {
<#
.SYNOPSIS
    Safely disposes network resources used during TLS operations.
#>
    [CmdletBinding()]
    param(
        [psobject]$Connection
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $sslStream = $null
    $networkStream = $null
    $tcpClient = $null
    if ($Connection) {
        if ($Connection.PSObject.Properties['SslStream']) { $sslStream = $Connection.SslStream }
        if ($Connection.PSObject.Properties['NetworkStream']) { $networkStream = $Connection.NetworkStream }
        if ($Connection.PSObject.Properties['TcpClient']) { $tcpClient = $Connection.TcpClient }
    }

    Write-Verbose "[$fn] Begin (SslStream=$($null -ne $sslStream), NetworkStream=$($null -ne $networkStream), TcpClient=$($null -ne $tcpClient))"

    try {
        foreach ($resource in @($sslStream, $networkStream, $tcpClient)) {
            if ($null -eq $resource) { continue }

            try {
                if ($resource -is [System.IDisposable]) {
                    $resource.Dispose()
                    Write-Verbose "[$fn] Disposed $($resource.GetType().FullName)"
                }
            }
            catch {
                Write-Debug "[$fn] Dispose failed: $($_.Exception.GetType().FullName)"
            }
        }
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
