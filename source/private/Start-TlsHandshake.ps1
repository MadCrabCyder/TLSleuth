function Start-TlsHandshake {
<#
.SYNOPSIS
    Starts a TLS handshake on an existing network stream.

.OUTPUTS
    PSCustomObject { SslStream, NegotiatedProtocol, CipherAlgorithm, CipherStrength }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.Stream]$NetworkStream,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetHost,

        [Parameter(Mandatory)]
        [System.Security.Authentication.SslProtocols]$SslProtocols,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000,

        [switch]$SkipCertificateValidation
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Target=$TargetHost, Protocols=$SslProtocols, TimeoutMs=$TimeoutMs, SkipValidation=$SkipCertificateValidation)"
    $ssl = $null

    $validationCallback = $null
    if ($SkipCertificateValidation) {
        if (-not ('TLSleuth.CertificateValidationCallbacks' -as [type])) {
            Add-Type -TypeDefinition @"
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace TLSleuth
{
    public static class CertificateValidationCallbacks
    {
        public static bool AcceptAll(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }
    }
}
"@
        }
        $validationCallback = [System.Net.Security.RemoteCertificateValidationCallback][TLSleuth.CertificateValidationCallbacks]::AcceptAll
    }

    try {
        $ssl = [System.Net.Security.SslStream]::new($NetworkStream, $false, $validationCallback)
        $task = $ssl.AuthenticateAsClientAsync($TargetHost, $null, $SslProtocols, $false)

        if (-not $task.Wait($TimeoutMs)) {
            throw [System.TimeoutException]::new("TLS handshake timeout after ${TimeoutMs}ms for $TargetHost")
        }

        Write-Verbose "[$fn] Handshake succeeded (Protocol=$($ssl.SslProtocol), Cipher=$($ssl.CipherAlgorithm), Strength=$($ssl.CipherStrength))."
        [PSCustomObject]@{
            SslStream          = $ssl
            NegotiatedProtocol = $ssl.SslProtocol
            CipherAlgorithm    = $ssl.CipherAlgorithm
            CipherStrength     = $ssl.CipherStrength
        }
    }
    catch {
        Write-Debug "[$fn] Handshake failed for ${TargetHost}: $($_.Exception.GetType().FullName)"
        try { if ($ssl) { $ssl.Dispose() } } catch {}

        $errorToThrow = $_.Exception
        if ($errorToThrow -is [System.AggregateException] -and $errorToThrow.InnerException) {
            throw $errorToThrow.InnerException
        }
        throw
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
