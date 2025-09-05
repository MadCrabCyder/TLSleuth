function Get-HandshakeInfo {
<#
.SYNOPSIS
    Extracts negotiated TLS protocol and cipher details from an SslStream.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Net.Security.SslStream]$SslStream
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin"
    try {
        $supports = Test-NegotiatedCipherSuiteSupport

        $negProtocol = $SslStream.SslProtocol
        $cipherName = $null
        $cipherStrength = $null
        $hashAlgorithm = $null
        $kexAlgorithm = $null
        $kexStrength  = $null

        if ($supports -and $SslStream.NegotiatedCipherSuite) {
            try { $cipherName = $SslStream.NegotiatedCipherSuite.ToString() } catch {}
            try { $cipherStrength = $SslStream.CipherStrength } catch {}
            try { $hashAlgorithm  = $SslStream.HashAlgorithm.ToString() } catch {}
            try { $kexAlgorithm   = $SslStream.KeyExchangeAlgorithm.ToString() } catch {}
            try { $kexStrength    = $SslStream.KeyExchangeStrength } catch {}
        } else {
            try { $cipherName = $SslStream.CipherAlgorithm.ToString() } catch {}
            try { $cipherStrength = $SslStream.CipherStrength } catch {}
            try { $hashAlgorithm  = $SslStream.HashAlgorithm.ToString() } catch {}
            try { $kexAlgorithm   = $SslStream.KeyExchangeAlgorithm.ToString() } catch {}
            try { $kexStrength    = $SslStream.KeyExchangeStrength } catch {}
        }

        [PSCustomObject]@{
            Protocol            = $negProtocol.ToString()
            CipherSuite         = $cipherName
            CipherStrengthBits  = $cipherStrength
            HashAlgorithm       = $hashAlgorithm
            KeyExchangeAlgorithm= $kexAlgorithm
            KeyExchangeStrength = $kexStrength
        }
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
