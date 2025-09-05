function Get-TLSleuthCertificate {
<#
.SYNOPSIS
    Retrieves the SSL/TLS certificate from a remote server and reports handshake details.

.DESCRIPTION
    Orchestrates smaller private helpers to connect, handshake, collect details,
    optionally build a validation chain, and assemble a TLSleuth report.

.PARAMETER Hostname
    DNS name or IP of the server.

.PARAMETER Port
    TCP port to connect to. Defaults to 443.

.PARAMETER ServerName
    SNI server name (TargetHost). Defaults to -Host.

.PARAMETER TlsProtocols
    TLS protocol(s) to allow. Defaults to SystemDefault.

.PARAMETER TimeoutSec
    Connection + handshake timeout in seconds. Default: 10.

.PARAMETER IncludeChain
    If specified, builds chain/trust info locally.

.PARAMETER CheckRevocation
    If specified, attempts revocation checking (OCSP/CRL).

.PARAMETER RawCertificate
    If specified, outputs the raw X509Certificate2.

.OUTPUTS
    TLSleuth.CertificateReport or X509Certificate2
#>
[CmdletBinding()]
    [OutputType([pscustomobject], [System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('DnsName','ComputerName','Target','Name','CN')]
        [string]$Hostname,

        [int]$Port = 443,
        [string]$ServerName,

        [ValidateSet('SystemDefault','Ssl3','Tls','Tls11','Tls12','Tls13')]
        [string[]]$TlsProtocols = @('SystemDefault'),

        [int]$TimeoutSec = 10,

        [switch]$IncludeChain,
        [switch]$CheckRevocation,
        [switch]$RawCertificate
    )

    begin {
        $fn = $MyInvocation.MyCommand.Name
        $pipelineSw = [System.Diagnostics.Stopwatch]::StartNew()
        Write-Verbose "[$fn] Begin (TimeoutSec=$TimeoutSec, Protocols=$($TlsProtocols -join ','))"

        $sslProtocolsEnum = Get-SslProtocolsEnum -Names $TlsProtocols
        $processed = 0
    }
    process {
        $processed++
        Write-Verbose "[$fn] Processing Host=$Hostname"
        $targetHost = if ($ServerName) { $ServerName } else { $Hostname }
        if ([string]::IsNullOrWhiteSpace($targetHost)) {
            throw "ServerName/Host is empty."
        }

        $resolvedIp = Resolve-Endpoint -Host $Hostname
        Write-Verbose "[$fn] Resolved $Hostname=$resolvedIp"
        $timeoutMs  = [Math]::Max(1000, $TimeoutSec * 1000)

        $tcp = $null; $net = $null; $sslInfo = $null
        try {
            $conn = Connect-TcpWithTimeout -Host $resolvedIp -Port $Port -TimeoutMs $timeoutMs
            $tcp  = $conn.TcpClient
            $net  = $conn.NetworkStream

            $sslInfo = Start-TlsHandshake -NetworkStream $net -TargetHost $targetHost -Protocols $sslProtocolsEnum -CheckRevocation:$CheckRevocation -TimeoutMs $timeoutMs

            $remoteCert = $sslInfo.RemoteCertificate
            if ($RawCertificate) { $remoteCert; return }

            $hs   = Get-HandshakeInfo -SslStream $sslInfo.SslStream
            $aia  = Get-AIAUrls    -Cert $remoteCert
            $cdp  = Get-CDPUrls    -Cert $remoteCert
            $sans = Get-CertificateSAN -Cert $remoteCert

            $chainInfo = $null
            if ($IncludeChain) {
                $chainInfo = Build-CertificateChain -Certificate $remoteCert -CheckRevocation:$CheckRevocation
            }

            $report = New-TLSleuthCertificateReport `
                -Host $Hostname -Port $Port -ConnectedIp $resolvedIp.ToString() -SNI $targetHost `
                -Handshake $hs -Certificate $remoteCert -ChainInfo $chainInfo `
                -CapturedChain $sslInfo.CapturedChain -ValidationErrors $sslInfo.ValidationErrors `
                -SANs $sans -AIA $aia -CDP $cdp

            $report

        } catch {
            $err = $_
            $msg = if ($err.Exception) { $err.Exception.Message } else { $err.ToString() }
            $ex  = [System.Exception]::new("Get-TLSleuthCertificate failed for $Hostname :$Port - $msg", $err.Exception)
            $record = New-Object System.Management.Automation.ErrorRecord(
                $ex, 'TLSleuth.GetTLSleuthCertificateFailed',
                [System.Management.Automation.ErrorCategory]::InvalidOperation, $Hostname
            )
            Write-Error $record
        } finally {
            try { if ($sslInfo -and $sslInfo.SslStream) { $sslInfo.SslStream.Dispose() } } catch {}
            try { if ($net) { $net.Dispose() } } catch {}
            try { if ($tcp) { $tcp.Close(); $tcp.Dispose() } } catch {}
        }
    }
    end {
        $pipelineSw.Stop()
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Complete (Processed=$processed) in $($pipelineSw.Elapsed)"
    }
}