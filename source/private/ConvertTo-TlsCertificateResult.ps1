function ConvertTo-TlsCertificateResult {
<#
.SYNOPSIS
    Builds a stable output object for certificate retrieval results.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Hostname,

        [Parameter(Mandatory)]
        [ValidateRange(1,65535)]
        [int]$Port,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetHost,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [pscustomobject]$Validity,

        [System.Security.Authentication.SslProtocols]$NegotiatedProtocol,

        $CipherAlgorithm,

        [int]$CipherStrength,

        [timespan]$Elapsed = [timespan]::Zero
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Target=$Hostname :$Port, TargetHost=$TargetHost)"

    try {
        $result = [PSCustomObject]@{
            PSTypeName         = 'TLSleuth.CertificateResult'
            Hostname           = $Hostname
            Port               = $Port
            TargetHost         = $TargetHost
            Subject            = $Certificate.Subject
            Issuer             = $Certificate.Issuer
            Thumbprint         = $Certificate.Thumbprint
            SerialNumber       = $Certificate.SerialNumber
            NotBefore          = $Certificate.NotBefore
            NotAfter           = $Certificate.NotAfter
            IsValidNow         = $Validity.IsValidNow
            DaysUntilExpiry    = $Validity.DaysUntilExpiry
            NegotiatedProtocol = $NegotiatedProtocol
            CipherAlgorithm    = $CipherAlgorithm
            CipherStrength     = $CipherStrength
            ElapsedMs          = [int][Math]::Round($Elapsed.TotalMilliseconds)
            Certificate        = $Certificate
        }

        Write-Verbose "[$fn] Built result for Subject='$($Certificate.Subject)' with protocol '$NegotiatedProtocol'."
        $result
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
