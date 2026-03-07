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
        $validationState = $null
        if ('TLSleuth.CertificateValidationCallbacksV2' -as [type]) {
            $validationState = [TLSleuth.CertificateValidationCallbacksV2]::GetState($sslStream)
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
        if ($sslStream.PSObject.Properties['NegotiatedCipherSuite']) {
            $negotiatedCipherSuite = $sslStream.NegotiatedCipherSuite
        }

        $negotiatedApplicationProtocol = $null
        if ($sslStream.PSObject.Properties['NegotiatedApplicationProtocol']) {
            $negotiatedApplicationProtocol = $sslStream.NegotiatedApplicationProtocol
        }

        $keyExchangeAlgorithm = $sslStream.KeyExchangeAlgorithm
        $forwardSecrecy = [string]$keyExchangeAlgorithm -match 'ECDHE|DHE'
        if (-not $forwardSecrecy -and $null -ne $negotiatedCipherSuite) {
            $forwardSecrecy = [string]$negotiatedCipherSuite -match 'ECDHE|DHE'
        }

        Write-Verbose "[$fn] Extracted details (Protocol=$($sslStream.SslProtocol), Cipher=$($sslStream.CipherAlgorithm), Strength=$($sslStream.CipherStrength), ValidationPassed=$validationPassed, PolicyErrors=$policyErrors, ForwardSecrecy=$forwardSecrecy)."
        [PSCustomObject]@{
            NegotiatedProtocol          = $sslStream.SslProtocol
            CipherAlgorithm             = $sslStream.CipherAlgorithm
            CipherStrength              = $sslStream.CipherStrength
            NegotiatedCipherSuite       = $negotiatedCipherSuite
            HashAlgorithm               = $sslStream.HashAlgorithm
            HashStrength                = $sslStream.HashStrength
            KeyExchangeAlgorithm        = $keyExchangeAlgorithm
            KeyExchangeStrength         = $sslStream.KeyExchangeStrength
            IsMutuallyAuthenticated     = $sslStream.IsMutuallyAuthenticated
            IsEncrypted                 = $sslStream.IsEncrypted
            IsSigned                    = $sslStream.IsSigned
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
                [TLSleuth.CertificateValidationCallbacksV2]::Cleanup($sslStream)
            }
        }
        catch {}

        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
