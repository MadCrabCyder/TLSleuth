function Test-TlsCertificateValidity {
<#
.SYNOPSIS
    Evaluates date-based validity of an X509 certificate.

.OUTPUTS
    PSCustomObject { IsValidNow, NotBefore, NotAfter, DaysUntilExpiry }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [datetime]$AsOf = (Get-Date)
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Subject=$($Certificate.Subject), AsOf=$AsOf)"

    try {
        $notBefore = $Certificate.NotBefore
        $notAfter = $Certificate.NotAfter
        $isValid = ($AsOf -ge $notBefore) -and ($AsOf -le $notAfter)
        $daysUntilExpiry = [int][Math]::Floor(($notAfter - $AsOf).TotalDays)

        Write-Verbose "[$fn] Validity computed (IsValidNow=$isValid, DaysUntilExpiry=$daysUntilExpiry)."
        [PSCustomObject]@{
            IsValidNow      = $isValid
            NotBefore       = $notBefore
            NotAfter        = $notAfter
            DaysUntilExpiry = $daysUntilExpiry
        }
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
