function ConvertTo-TlsProtocolOptions {
<#
.SYNOPSIS
    Converts user protocol names into an SslProtocols flag enum.

.OUTPUTS
    System.Security.Authentication.SslProtocols
#>
    [CmdletBinding()]
    [OutputType([System.Security.Authentication.SslProtocols])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$TlsProtocols
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (TlsProtocols=$($TlsProtocols -join ','))"

    try {
        $explicitProtocolNames = @('Ssl3','Tls','Tls11','Tls12','Tls13')

        if ($TlsProtocols -contains 'SystemDefault') {
            if ($TlsProtocols.Count -gt 1) {
                throw [System.ArgumentException]::new('SystemDefault cannot be combined with explicit protocol values.')
            }

            Write-Verbose "[$fn] Using SystemDefault TLS policy."
            return [System.Security.Authentication.SslProtocols]::None
        }

        $availableProtocolMap = @{}
        foreach ($protocol in Get-TlsRuntimeProtocol -ProtocolName $explicitProtocolNames) {
            $availableProtocolMap[$protocol.ToString()] = $protocol
        }

        $result = [System.Security.Authentication.SslProtocols]::None
        foreach ($name in $TlsProtocols) {
            if ($explicitProtocolNames -notcontains $name) {
                throw [System.ArgumentException]::new("Unsupported TLS protocol value: $name")
            }

            if (-not $availableProtocolMap.ContainsKey($name)) {
                throw [System.PlatformNotSupportedException]::new("TLS protocol value '$name' is not available on this runtime.")
            }

            $result = $result -bor $availableProtocolMap[$name]
        }

        Write-Verbose "[$fn] Resolved protocols: $result"
        $result
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
