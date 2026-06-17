function ConvertTo-TlsSessionInfo {
<#
.SYNOPSIS
    Builds the shared TLS/session result property map used by public outputs.

.OUTPUTS
    OrderedDictionary
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        $NegotiatedProtocol,

        [AllowNull()]
        $CipherAlgorithm,

        [AllowNull()]
        [Nullable[int]]$CipherStrength,

        [AllowNull()]
        $NegotiatedCipherSuite,

        [AllowNull()]
        $HashAlgorithm,

        [AllowNull()]
        [Nullable[int]]$HashStrength,

        [AllowNull()]
        $KeyExchangeAlgorithm,

        [AllowNull()]
        [Nullable[int]]$KeyExchangeStrength,

        [AllowNull()]
        [Nullable[bool]]$IsMutuallyAuthenticated,

        [AllowNull()]
        [Nullable[bool]]$IsEncrypted,

        [AllowNull()]
        [Nullable[bool]]$IsSigned,

        [AllowNull()]
        $NegotiatedApplicationProtocol,

        [AllowNull()]
        [Nullable[bool]]$ForwardSecrecy,

        [AllowNull()]
        [Nullable[bool]]$CertificateValidationPassed,

        [AllowNull()]
        $CertificatePolicyErrors,

        [AllowNull()]
        [string[]]$CertificatePolicyErrorFlags = @(),

        [AllowNull()]
        [string[]]$CertificateChainStatus = @()
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin"

    try {
        $policyErrorFlags = if ($null -eq $CertificatePolicyErrorFlags) { ,([string[]]@()) } else { ,([string[]]$CertificatePolicyErrorFlags) }
        $chainStatus = if ($null -eq $CertificateChainStatus) { ,([string[]]@()) } else { ,([string[]]$CertificateChainStatus) }

        [ordered]@{
            CertificateValidationPassed   = $CertificateValidationPassed
            CertificatePolicyErrors       = $CertificatePolicyErrors
            CertificatePolicyErrorFlags   = $policyErrorFlags
            CertificateChainStatus        = $chainStatus
            NegotiatedProtocol            = $NegotiatedProtocol
            CipherAlgorithm               = $CipherAlgorithm
            CipherStrength                = $CipherStrength
            NegotiatedCipherSuite         = $NegotiatedCipherSuite
            HashAlgorithm                 = $HashAlgorithm
            HashStrength                  = $HashStrength
            KeyExchangeAlgorithm          = $KeyExchangeAlgorithm
            KeyExchangeStrength           = $KeyExchangeStrength
            IsMutuallyAuthenticated       = $IsMutuallyAuthenticated
            IsEncrypted                   = $IsEncrypted
            IsSigned                      = $IsSigned
            NegotiatedApplicationProtocol = $NegotiatedApplicationProtocol
            ForwardSecrecy                = $ForwardSecrecy
        }
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
