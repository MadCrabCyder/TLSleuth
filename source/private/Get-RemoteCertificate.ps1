function Get-RemoteCertificate {
<#
.SYNOPSIS
    Extracts the remote certificate from an authenticated SslStream.

.OUTPUTS
    System.Security.Cryptography.X509Certificates.X509Certificate2
#>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Connection
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $sslStream = $null
    if ($Connection.PSObject.Properties['SslStream']) {
        $sslStream = $Connection.SslStream
    }
    if ($null -eq $sslStream) {
        throw [System.InvalidOperationException]::new('Connection context does not contain an authenticated SslStream.')
    }

    Write-Verbose "[$fn] Begin (IsAuthenticated=$($sslStream.IsAuthenticated))"

    try {
        if (-not $sslStream.RemoteCertificate) {
            throw [System.InvalidOperationException]::new('Remote endpoint did not provide a certificate.')
        }

        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($sslStream.RemoteCertificate)
        Write-Verbose "[$fn] Retrieved certificate Subject='$($certificate.Subject)'"
        $certificate
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
