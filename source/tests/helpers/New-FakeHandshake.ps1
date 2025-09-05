function New-FakeHandshakeResult {
<#
.SYNOPSIS
    Creates a fake Start-TlsHandshake result object for tests.
.PARAMETER Certificate
    X509Certificate2 to return as RemoteCertificate (defaults to a generated self-signed cert).
.PARAMETER ValidationErrors
    Array of validation error strings.
#>
    [CmdletBinding()]
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string[]]$ValidationErrors = @()
    )

    if (-not $Certificate) {
        # Fallback to a throwaway self-signed cert (requires tests/helpers/New-TestCertificate.ps1)
        if (-not (Get-Command New-TestCertificate -ErrorAction SilentlyContinue)) {
            throw "New-FakeHandshakeResult requires New-TestCertificate helper to be dot-sourced first."
        }
        $Certificate = New-TestCertificate -SubjectCN 'FakeHandshake'
    }

    # We only need *an* object for SslStream param passing; tests will mock Get-HandshakeInfo.
    $dummySsl = New-Object PSObject -Property @{ IsDummy = $true }

    [PSCustomObject]@{
        SslStream         = $dummySsl
        RemoteCertificate = $Certificate
        CapturedChain     = $null
        ValidationErrors  = ,@($ValidationErrors)
    }
}

function New-FakeHandshakeInfo {
<#
.SYNOPSIS
    Creates a fake Get-HandshakeInfo output object for tests.
#>
    [CmdletBinding()]
    param(
        [string]$Protocol = 'Tls12',
        [string]$CipherSuite = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        [int]$CipherStrengthBits = 128,
        [string]$HashAlgorithm = 'SHA256',
        [string]$KeyExchangeAlgorithm = 'ECDHE',
        [Nullable[int]]$KeyExchangeStrength = $null
    )

    [PSCustomObject]@{
        Protocol             = $Protocol
        CipherSuite          = $CipherSuite
        CipherStrengthBits   = $CipherStrengthBits
        HashAlgorithm        = $HashAlgorithm
        KeyExchangeAlgorithm = $KeyExchangeAlgorithm
        KeyExchangeStrength  = $KeyExchangeStrength
    }
}
