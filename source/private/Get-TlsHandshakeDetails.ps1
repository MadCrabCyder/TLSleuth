function Get-TlsHandshakeDetails {
<#
.SYNOPSIS
    Returns negotiated TLS/certificate validation details for an authenticated SslStream.

.OUTPUTS
    PSCustomObject {
        NegotiatedProtocol, CipherAlgorithm, CipherStrength,
        NegotiatedCipherSuite, HashAlgorithm, HashStrength, KeyExchangeAlgorithm, KeyExchangeStrength,
        IsMutuallyAuthenticated, IsEncrypted, IsSigned, NegotiatedApplicationProtocol, ForwardSecrecy,
        CertificateValidationPassed, CertificatePolicyErrors, CertificatePolicyErrorFlags, CertificateChainStatus
    }
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Net.Security.SslStream]$SslStream
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (IsAuthenticated=$($SslStream.IsAuthenticated))"

    try {
        $validationState = $null
        if ('TLSleuth.CertificateValidationCallbacksV2' -as [type]) {
            $validationState = [TLSleuth.CertificateValidationCallbacksV2]::GetState($SslStream)
        }

        $policyErrors = [System.Net.Security.SslPolicyErrors]::None
        $chainStatus = [string[]]@()
        if ($validationState) {
            $policyErrors = $validationState.PolicyErrors
            $chainStatus = [string[]]$validationState.ChainStatus
        }

        $policyErrorFlags = [System.Collections.Generic.List[string]]::new()
        if (($policyErrors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNotAvailable) -ne 0) {
            $policyErrorFlags.Add('RemoteCertificateNotAvailable')
        }
        if (($policyErrors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -ne 0) {
            $policyErrorFlags.Add('RemoteCertificateNameMismatch')
        }
        if (($policyErrors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors) -ne 0) {
            $policyErrorFlags.Add('RemoteCertificateChainErrors')
        }

        $validationPassed = ($policyErrors -eq [System.Net.Security.SslPolicyErrors]::None)
        $negotiatedCipherSuite = $null
        if ($SslStream.PSObject.Properties['NegotiatedCipherSuite']) {
            $negotiatedCipherSuite = $SslStream.NegotiatedCipherSuite
        }

        $negotiatedApplicationProtocol = $null
        if ($SslStream.PSObject.Properties['NegotiatedApplicationProtocol']) {
            $negotiatedApplicationProtocol = $SslStream.NegotiatedApplicationProtocol
        }

        $keyExchangeAlgorithm = $SslStream.KeyExchangeAlgorithm
        $forwardSecrecy = [string]$keyExchangeAlgorithm -match 'ECDHE|DHE'
        if (-not $forwardSecrecy -and $null -ne $negotiatedCipherSuite) {
            $forwardSecrecy = [string]$negotiatedCipherSuite -match 'ECDHE|DHE'
        }

        Write-Verbose "[$fn] Extracted details (Protocol=$($SslStream.SslProtocol), Cipher=$($SslStream.CipherAlgorithm), Strength=$($SslStream.CipherStrength), ValidationPassed=$validationPassed, PolicyErrors=$policyErrors, ForwardSecrecy=$forwardSecrecy)."
        [PSCustomObject]@{
            NegotiatedProtocol          = $SslStream.SslProtocol
            CipherAlgorithm             = $SslStream.CipherAlgorithm
            CipherStrength              = $SslStream.CipherStrength
            NegotiatedCipherSuite       = $negotiatedCipherSuite
            HashAlgorithm               = $SslStream.HashAlgorithm
            HashStrength                = $SslStream.HashStrength
            KeyExchangeAlgorithm        = $keyExchangeAlgorithm
            KeyExchangeStrength         = $SslStream.KeyExchangeStrength
            IsMutuallyAuthenticated     = $SslStream.IsMutuallyAuthenticated
            IsEncrypted                 = $SslStream.IsEncrypted
            IsSigned                    = $SslStream.IsSigned
            NegotiatedApplicationProtocol = $negotiatedApplicationProtocol
            ForwardSecrecy              = $forwardSecrecy
            CertificateValidationPassed = $validationPassed
            CertificatePolicyErrors     = $policyErrors
            CertificatePolicyErrorFlags = [string[]]$policyErrorFlags
            CertificateChainStatus      = [string[]]$chainStatus
        }
    }
    finally {
        try {
            if ('TLSleuth.CertificateValidationCallbacksV2' -as [type]) {
                [TLSleuth.CertificateValidationCallbacksV2]::Cleanup($SslStream)
            }
        }
        catch {}

        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
