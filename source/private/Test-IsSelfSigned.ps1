function Test-IsSelfSigned {
<#
.SYNOPSIS
    Returns $true if the certificate is self-signed (subject == issuer).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )
    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Thumbprint=$($Cert.Thumbprint))"
    try {
        return $Cert.Subject -eq $Cert.Issuer
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
