function Get-TlsRuntimeProtocol {
<#
.SYNOPSIS
    Returns explicit TLS protocol enum values supported by the current runtime.

.OUTPUTS
    System.Security.Authentication.SslProtocols
#>
    [CmdletBinding()]
    [OutputType([System.Security.Authentication.SslProtocols])]
    param(
        [ValidateNotNullOrEmpty()]
        [string[]]$ProtocolName = @('Ssl3','Tls','Tls11','Tls12','Tls13')
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (ProtocolName=$($ProtocolName -join ','))"

    try {
        $enumNames = [System.Enum]::GetNames([System.Security.Authentication.SslProtocols])
        $availableProtocols = @(
            foreach ($name in $ProtocolName) {
                if ($enumNames -contains $name) {
                    [System.Enum]::Parse([System.Security.Authentication.SslProtocols], $name)
                }
            }
        )

        if (-not $availableProtocols -or $availableProtocols.Count -eq 0) {
            throw [System.InvalidOperationException]::new('No explicit SslProtocols values are available on this runtime.')
        }

        Write-Verbose "[$fn] Available protocols: $($availableProtocols -join ',')"
        $availableProtocols
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
