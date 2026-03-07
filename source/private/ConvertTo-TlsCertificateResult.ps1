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

        $NegotiatedCipherSuite,

        $HashAlgorithm,

        [int]$HashStrength,

        $KeyExchangeAlgorithm,

        [int]$KeyExchangeStrength,

        [bool]$IsMutuallyAuthenticated = $false,

        [bool]$IsEncrypted = $false,

        [bool]$IsSigned = $false,

        $NegotiatedApplicationProtocol,

        [bool]$ForwardSecrecy = $false,

        [timespan]$Elapsed = [timespan]::Zero,

        [bool]$CertificateValidationPassed = $true,

        [System.Net.Security.SslPolicyErrors]$CertificatePolicyErrors = [System.Net.Security.SslPolicyErrors]::None,

        [string[]]$CertificatePolicyErrorFlags = @(),

        [string[]]$CertificateChainStatus = @()
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Target=$($Hostname):$($Port), TargetHost=$TargetHost)"

    try {
        $policyErrorFlags = if ($null -eq $CertificatePolicyErrorFlags) { ,([string[]]@()) } else { ,([string[]]$CertificatePolicyErrorFlags) }
        $chainStatus = if ($null -eq $CertificateChainStatus) { ,([string[]]@()) } else { ,([string[]]$CertificateChainStatus) }

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
            CertificateValidationPassed = $CertificateValidationPassed
            CertificatePolicyErrors     = $CertificatePolicyErrors
            CertificatePolicyErrorFlags = $policyErrorFlags
            CertificateChainStatus      = $chainStatus
            NegotiatedProtocol = $NegotiatedProtocol
            CipherAlgorithm    = $CipherAlgorithm
            CipherStrength     = $CipherStrength
            NegotiatedCipherSuite = $NegotiatedCipherSuite
            HashAlgorithm         = $HashAlgorithm
            HashStrength          = $HashStrength
            KeyExchangeAlgorithm  = $KeyExchangeAlgorithm
            KeyExchangeStrength   = $KeyExchangeStrength
            IsMutuallyAuthenticated = $IsMutuallyAuthenticated
            IsEncrypted             = $IsEncrypted
            IsSigned                = $IsSigned
            NegotiatedApplicationProtocol = $NegotiatedApplicationProtocol
            ForwardSecrecy = $ForwardSecrecy
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
