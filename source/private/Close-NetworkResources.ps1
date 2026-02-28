function Close-NetworkResources {
<#
.SYNOPSIS
    Safely disposes network resources used during TLS operations.
#>
    [CmdletBinding()]
    param(
        [System.Net.Security.SslStream]$SslStream,
        [System.IO.Stream]$NetworkStream,
        [System.Net.Sockets.TcpClient]$TcpClient
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (SslStream=$($null -ne $SslStream), NetworkStream=$($null -ne $NetworkStream), TcpClient=$($null -ne $TcpClient))"

    try {
        foreach ($resource in @($SslStream, $NetworkStream, $TcpClient)) {
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
