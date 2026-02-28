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
        $map = @{
            SystemDefault = [System.Security.Authentication.SslProtocols]::None
            Ssl3          = [System.Security.Authentication.SslProtocols]::Ssl3
            Tls           = [System.Security.Authentication.SslProtocols]::Tls
            Tls11         = [System.Security.Authentication.SslProtocols]::Tls11
            Tls12         = [System.Security.Authentication.SslProtocols]::Tls12
            Tls13         = [System.Security.Authentication.SslProtocols]::Tls13
        }

        $result = [System.Security.Authentication.SslProtocols]::None
        foreach ($name in $TlsProtocols) {
            if (-not $map.ContainsKey($name)) {
                throw [System.ArgumentException]::new("Unsupported TLS protocol value: $name")
            }

            if ($name -eq 'SystemDefault') {
                if ($TlsProtocols.Count -gt 1) {
                    throw [System.ArgumentException]::new('SystemDefault cannot be combined with explicit protocol values.')
                }

                Write-Verbose "[$fn] Using SystemDefault TLS policy."
                return [System.Security.Authentication.SslProtocols]::None
            }

            $result = $result -bor $map[$name]
        }

        Write-Verbose "[$fn] Resolved protocols: $result"
        $result
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
