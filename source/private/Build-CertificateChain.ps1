function Build-CertificateChain {
<#
.SYNOPSIS
    Builds a trust chain for a certificate with optional revocation checking.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [switch]$CheckRevocation
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Revocation=$([bool]$CheckRevocation), Thumbprint=$($Certificate.Thumbprint))"
    try {
        $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
        $chain.ChainPolicy.RevocationMode = if ($CheckRevocation) {
            [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        } else {
            [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        }
        $chain.ChainPolicy.RevocationFlag    = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EndCertificateOnly
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag

        $isTrusted = $chain.Build($Certificate)
        Write-Verbose "[$fn] Chain Status = $($chain.ChainStatus)"
        $status = if ($chain.ChainStatus) { ,@($chain.ChainStatus) } else { ,@() }
        $subjects = if ($chain.ChainElements) {
            ,@($chain.ChainElements | ForEach-Object { $_.Certificate.Subject })
        } else { ,@() }

        Write-Verbose "[$fn] Chain built. IsTrusted=$isTrusted; StatusCount=$($status.Count)"
        [PSCustomObject]@{
            Chain         = $chain
            IsTrusted     = $isTrusted
            ChainStatus   = $status
            ChainSubjects = $subjects
        }
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
