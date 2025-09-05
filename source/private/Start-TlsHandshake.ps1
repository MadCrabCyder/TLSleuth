function Start-TlsHandshake {
<#
.SYNOPSIS
    Performs an SNI-aware TLS handshake over an existing NetworkStream.

.OUTPUTS
    PSCustomObject { SslStream, RemoteCertificate, CapturedChain, ValidationErrors }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][System.IO.Stream]$NetworkStream,
        [Parameter(Mandatory)][string]$TargetHost,
        [Parameter(Mandatory)][System.Security.Authentication.SslProtocols]$Protocols,
        [switch]$CheckRevocation,
        [int]$TimeoutMs = 10000
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $TimeoutMs = [Math]::Max(1000, $TimeoutMs)
    Write-Verbose "[$fn] Begin (SNI=$TargetHost, Protocols=$Protocols, TimeoutMs=$TimeoutMs, Revocation=$([bool]$CheckRevocation))"
    $sslStream = $null
    try {
        $certErrors = New-Object System.Collections.Generic.List[string]
        $capturedChain = $null

        $validationCallback = {
            param(
                [object]$sender,
                [System.Security.Cryptography.X509Certificates.X509Certificate]$certificate,
                [System.Security.Cryptography.X509Certificates.X509Chain]$chain,
                [System.Net.Security.SslPolicyErrors]$sslPolicyErrors
            )
            try {
                if ($chain -and $certificate) {
                    $tmp = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                    $tmp.ChainPolicy.RevocationMode   = $chain.ChainPolicy.RevocationMode
                    $tmp.ChainPolicy.RevocationFlag   = $chain.ChainPolicy.RevocationFlag
                    $tmp.ChainPolicy.VerificationFlags= $chain.ChainPolicy.VerificationFlags
                    $tmp.ChainPolicy.VerificationTime = $chain.ChainPolicy.VerificationTime
                    [void]$tmp.Build([System.Security.Cryptography.X509Certificates.X509Certificate2]$certificate)
                    $script:capturedChain = $tmp
                }
            } catch {}
            if ($sslPolicyErrors -ne [System.Net.Security.SslPolicyErrors]::None) {
                [void]$certErrors.Add($sslPolicyErrors.ToString())
            }
            return $true
        }

        $sslStream = [System.Net.Security.SslStream]::new($NetworkStream, $false, $validationCallback)

        try {
            $opts = [System.Net.Security.SslClientAuthenticationOptions]::new()
            $opts.TargetHost = $TargetHost
            $opts.EnabledSslProtocols = $Protocols
            $opts.CertificateRevocationCheckMode = if ($CheckRevocation) {
                [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
            } else {
                [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
            }
            $cts = [System.Threading.CancellationTokenSource]::new()
            try {
                $task = $sslStream.AuthenticateAsClientAsync($opts, $cts.Token)
                if (-not $task.Wait($TimeoutMs)) {
                    throw [System.TimeoutException]::new("TLS handshake timeout after ${TimeoutMs}ms")
                }
            } finally { try { $cts.Dispose() } catch {} }
        } catch {
            # Legacy path
            $sslStream.ReadTimeout  = $TimeoutMs
            $sslStream.WriteTimeout = $TimeoutMs
            $clientCerts = [System.Security.Cryptography.X509Certificates.X509CertificateCollection]::new()
            $rev = [bool]$CheckRevocation
            $sslStream.AuthenticateAsClient($TargetHost, $clientCerts, $Protocols, $rev)
        }

        $remoteCert = $sslStream.RemoteCertificate
        if (-not $remoteCert) { throw "No certificate was presented by the server." }
        if ($remoteCert -isnot [System.Security.Cryptography.X509Certificates.X509Certificate2]) {
            $remoteCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($remoteCert)
        }

        Write-Verbose "[$fn] Handshake complete. Protocol=$($sslStream.SslProtocol); CertCN=$($remoteCert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::DnsName, $false))"
        [PSCustomObject]@{
            SslStream         = $sslStream
            RemoteCertificate = $remoteCert
            CapturedChain     = $capturedChain
            ValidationErrors  = ,@($certErrors)
        }
    } catch {
        try { if ($sslStream) { $sslStream.Dispose() } } catch {}
        throw
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
