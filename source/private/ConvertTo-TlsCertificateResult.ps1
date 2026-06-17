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
        $sessionInfo = ConvertTo-TlsSessionInfo `
            -CertificateValidationPassed $CertificateValidationPassed `
            -CertificatePolicyErrors $CertificatePolicyErrors `
            -CertificatePolicyErrorFlags $CertificatePolicyErrorFlags `
            -CertificateChainStatus $CertificateChainStatus `
            -NegotiatedProtocol $NegotiatedProtocol `
            -CipherAlgorithm $CipherAlgorithm `
            -CipherStrength $CipherStrength `
            -NegotiatedCipherSuite $NegotiatedCipherSuite `
            -HashAlgorithm $HashAlgorithm `
            -HashStrength $HashStrength `
            -KeyExchangeAlgorithm $KeyExchangeAlgorithm `
            -KeyExchangeStrength $KeyExchangeStrength `
            -IsMutuallyAuthenticated $IsMutuallyAuthenticated `
            -IsEncrypted $IsEncrypted `
            -IsSigned $IsSigned `
            -NegotiatedApplicationProtocol $NegotiatedApplicationProtocol `
            -ForwardSecrecy $ForwardSecrecy

        $properties = [ordered]@{
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
        }

        foreach ($entry in $sessionInfo.GetEnumerator()) {
            $properties[$entry.Key] = $entry.Value
        }

        $properties['ElapsedMs'] = [int][Math]::Round($Elapsed.TotalMilliseconds)
        $properties['Certificate'] = $Certificate

        $result = [PSCustomObject]$properties

        Write-Verbose "[$fn] Built result for Subject='$($Certificate.Subject)' with protocol '$NegotiatedProtocol'."
        $result
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
