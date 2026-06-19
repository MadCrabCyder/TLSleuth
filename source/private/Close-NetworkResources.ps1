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
        foreach ($resource in @(
            [PSCustomObject]@{ Name = 'SslStream'; Value = $sslStream }
            [PSCustomObject]@{ Name = 'NetworkStream'; Value = $networkStream }
            [PSCustomObject]@{ Name = 'TcpClient'; Value = $tcpClient }
        )) {
            Close-TlsResource -Resource $resource.Value -ResourceName $resource.Name -OwnerName $fn
        }
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
