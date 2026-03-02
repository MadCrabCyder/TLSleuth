function Get-TLSleuthCertificate {

[CmdletBinding()]
[OutputType([pscustomobject])]

    param(
        # Accepts strings directly from the pipeline AND by matching property name
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Host','DnsName','ComputerName','Target','Name')]
        [ValidateNotNullOrEmpty()]
        [string]$Hostname,

        # Accepts values from objects with a matching property name in the pipeline
        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,65535)]
        [int]$Port = 443,

        # Accepts values from objects with a matching property name in the pipeline
        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('SNI','ServerName')]
        [string]$TargetHost,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('ImplicitTls','SmtpStartTls','ImapStartTls','Pop3StartTls')]
        [string]$Transport = 'ImplicitTls',

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('EhloName','ClientName')]
        [string]$SmtpEhloName,

        [ValidateSet('SystemDefault','Ssl3','Tls','Tls11','Tls12','Tls13')]
        [string[]]$TlsProtocols = @('SystemDefault'),

        [ValidateRange(1,600)]
        [int]$TimeoutSec = 10,

        [switch]$SkipCertificateValidation = $true

    )

    begin {
        $fn = $MyInvocation.MyCommand.Name
        $pipelineSw = [System.Diagnostics.Stopwatch]::StartNew()
        $processed = 0
        $timeoutMs = $TimeoutSec * 1000

        $sslProtocols = ConvertTo-TlsProtocolOptions -TlsProtocols $TlsProtocols
        Write-Verbose "[$fn] Begin (Transport=$Transport, TimeoutSec=$TimeoutSec, Protocols=$($TlsProtocols -join ','))"

    }

    process {
        $itemSw = [System.Diagnostics.Stopwatch]::StartNew()
        $processed++

        $target = if ([string]::IsNullOrWhiteSpace($TargetHost)) { $Hostname } else { $TargetHost }

        $tcpConnection = $null
        $tlsSession = $null
        $certificate = $null

        try {
            $tcpConnection = Invoke-WithRetry -ScriptBlock {
                Connect-TcpWithTimeout -Hostname $Hostname -Port $Port -TimeoutMs $timeoutMs
            }

            if ($Transport -eq 'SmtpStartTls') {
                $ehloName = $SmtpEhloName
                if ([string]::IsNullOrWhiteSpace($ehloName)) {
                    $ehloName = [System.Net.Dns]::GetHostName()
                    if ([string]::IsNullOrWhiteSpace($ehloName)) {
                        $ehloName = 'localhost'
                    }
                }

                Invoke-SmtpStartTlsNegotiation `
                    -NetworkStream $tcpConnection.NetworkStream `
                    -EhloName $ehloName `
                    -TimeoutMs $timeoutMs | Out-Null
            }
            elseif ($Transport -eq 'ImapStartTls') {
                Invoke-ImapStartTlsNegotiation `
                    -NetworkStream $tcpConnection.NetworkStream `
                    -TimeoutMs $timeoutMs | Out-Null
            }
            elseif ($Transport -eq 'Pop3StartTls') {
                Invoke-Pop3StartTlsNegotiation `
                    -NetworkStream $tcpConnection.NetworkStream `
                    -TimeoutMs $timeoutMs | Out-Null
            }

            $tlsSession = Start-TlsHandshake `
                -NetworkStream $tcpConnection.NetworkStream `
                -TargetHost $target `
                -SslProtocols $sslProtocols `
                -TimeoutMs $timeoutMs `
                -SkipCertificateValidation:$SkipCertificateValidation

            $certificate = Get-RemoteCertificate -SslStream $tlsSession.SslStream

            $validity = Test-TlsCertificateValidity -Certificate $certificate

            ConvertTo-TlsCertificateResult `
                -Hostname $Hostname `
                -Port $Port `
                -TargetHost $target `
                -Certificate $certificate `
                -Validity $validity `
                -CertificateValidationPassed $tlsSession.CertificateValidationPassed `
                -CertificatePolicyErrors $tlsSession.CertificatePolicyErrors `
                -CertificatePolicyErrorFlags $tlsSession.CertificatePolicyErrorFlags `
                -CertificateChainStatus $tlsSession.CertificateChainStatus `
                -NegotiatedProtocol $tlsSession.NegotiatedProtocol `
                -CipherAlgorithm $tlsSession.CipherAlgorithm `
                -CipherStrength $tlsSession.CipherStrength `
                -Elapsed $itemSw.Elapsed
        }
        finally {
            $itemSw.Stop()
            Close-NetworkResources -SslStream $tlsSession.SslStream -NetworkStream $tcpConnection.NetworkStream -TcpClient $tcpConnection.TcpClient
        }

    }

    end {
        $pipelineSw.Stop()
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Complete (Processed=$processed) in $($pipelineSw.Elapsed)"
    }
}
