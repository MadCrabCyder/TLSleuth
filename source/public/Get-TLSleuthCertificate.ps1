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
        $sslProtocols = ConvertTo-TlsProtocolOptions -TlsProtocols $TlsProtocols
        Write-Verbose "[$fn] Begin (Transport=$Transport, TimeoutSec=$TimeoutSec, Protocols=$($TlsProtocols -join ','))"

    }

    process {
        $itemSw = [System.Diagnostics.Stopwatch]::StartNew()
        $processed++

        $connection = $null
        $tlsDetails = $null
        $certificate = $null
        $context = New-TlsOperationContext `
            -Hostname $Hostname `
            -Port $Port `
            -TargetHost $TargetHost `
            -Transport $Transport `
            -SmtpEhloName $SmtpEhloName `
            -TimeoutSec $TimeoutSec

        try {
            $connection = New-TlsConnectionContext `
                -Hostname $context.Hostname `
                -Port $context.Port `
                -TimeoutMs $context.TimeoutMs

            Invoke-TlsTransportNegotiation `
                -Transport $context.Transport `
                -Connection $connection `
                -Options $context.TransportOptions

            $handshakeStream = Start-TlsHandshake `
                -Connection $connection `
                -TargetHost $context.TargetHost `
                -SslProtocols $sslProtocols `
                -TimeoutMs $context.TimeoutMs `
                -SkipCertificateValidation:$SkipCertificateValidation
            $connection.SslStream = $handshakeStream

            $tlsDetails = Get-TlsHandshakeDetails -Connection $connection
            $certificate = Get-RemoteCertificate -Connection $connection

            $validity = Test-TlsCertificateValidity -Certificate $certificate

            ConvertTo-TlsCertificateResult `
                -Hostname $context.Hostname `
                -Port $context.Port `
                -TargetHost $context.TargetHost `
                -Certificate $certificate `
                -Validity $validity `
                -CertificateValidationPassed $tlsDetails.CertificateValidationPassed `
                -CertificatePolicyErrors $tlsDetails.CertificatePolicyErrors `
                -CertificatePolicyErrorFlags $tlsDetails.CertificatePolicyErrorFlags `
                -CertificateChainStatus $tlsDetails.CertificateChainStatus `
                -NegotiatedProtocol $tlsDetails.NegotiatedProtocol `
                -CipherAlgorithm $tlsDetails.CipherAlgorithm `
                -CipherStrength $tlsDetails.CipherStrength `
                -NegotiatedCipherSuite $tlsDetails.NegotiatedCipherSuite `
                -HashAlgorithm $tlsDetails.HashAlgorithm `
                -HashStrength $tlsDetails.HashStrength `
                -KeyExchangeAlgorithm $tlsDetails.KeyExchangeAlgorithm `
                -KeyExchangeStrength $tlsDetails.KeyExchangeStrength `
                -IsMutuallyAuthenticated $tlsDetails.IsMutuallyAuthenticated `
                -IsEncrypted $tlsDetails.IsEncrypted `
                -IsSigned $tlsDetails.IsSigned `
                -NegotiatedApplicationProtocol $tlsDetails.NegotiatedApplicationProtocol `
                -ForwardSecrecy $tlsDetails.ForwardSecrecy `
                -Elapsed $itemSw.Elapsed
        }
        finally {
            $itemSw.Stop()
            Close-NetworkResources -Connection $connection
        }

    }

    end {
        $pipelineSw.Stop()
        Write-Verbose "[$($MyInvocation.MyCommand.Name)] Complete (Processed=$processed) in $($pipelineSw.Elapsed)"
    }
}
