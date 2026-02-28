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
        [System.Net.Security.SslStream]$SslStream
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (IsAuthenticated=$($SslStream.IsAuthenticated))"

    try {
        if (-not $SslStream.RemoteCertificate) {
            throw [System.InvalidOperationException]::new('Remote endpoint did not provide a certificate.')
        }

        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($SslStream.RemoteCertificate)
        Write-Verbose "[$fn] Retrieved certificate Subject='$($certificate.Subject)'"
        $certificate
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
