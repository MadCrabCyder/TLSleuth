function Test-TLSleuthProtocol {

[CmdletBinding()]
[OutputType([pscustomobject])]

    param(
        [Parameter(Mandatory, Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Host','DnsName','ComputerName','Target','Name')]
        [ValidateNotNullOrEmpty()]
        [string]$Hostname,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateRange(1,65535)]
        [int]$Port = 443,

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('SNI','ServerName')]
        [string]$TargetHost,

        [Parameter(ValueFromPipelineByPropertyName)]
        [ValidateSet('ImplicitTls','SmtpStartTls','ImapStartTls','Pop3StartTls')]
        [string]$Transport = 'ImplicitTls',

        [Parameter(ValueFromPipelineByPropertyName)]
        [Alias('EhloName','ClientName')]
        [string]$SmtpEhloName,

        [ValidateRange(1,600)]
        [int]$TimeoutSec = 10,

        [switch]$SkipCertificateValidation = $true
    )

    begin {
        $fn = $MyInvocation.MyCommand.Name
        $pipelineSw = [System.Diagnostics.Stopwatch]::StartNew()
        $processed = 0
        $availableProtocols = @(Get-TlsRuntimeProtocol)

        Write-Verbose "[$fn] Begin (Transport=$Transport, TimeoutSec=$TimeoutSec, Protocols=$($availableProtocols -join ','))"
    }

    process {
        $processed++
        $context = New-TlsOperationContext `
            -Hostname $Hostname `
            -Port $Port `
            -TargetHost $TargetHost `
            -Transport $Transport `
            -SmtpEhloName $SmtpEhloName `
            -TimeoutSec $TimeoutSec

        foreach ($protocol in $availableProtocols) {
            $itemSw = [System.Diagnostics.Stopwatch]::StartNew()
            $connection = $null
            $tlsDetails = $null
            $connectionSuccessful = $false
            $errorMessage = $null

            try {
                $connection = New-TlsConnectionContext `
                    -Hostname $context.Hostname `
                    -Port $context.Port `
                    -TimeoutMs $context.TimeoutMs

                $null = Invoke-TlsTransportNegotiation `
                    -Transport $context.Transport `
                    -Connection $connection `
                    -Options $context.TransportOptions

                $handshakeStream = Start-TlsHandshake `
                    -Connection $connection `
                    -TargetHost $context.TargetHost `
                    -SslProtocols $protocol `
                    -TimeoutMs $context.TimeoutMs `
                    -SkipCertificateValidation:$SkipCertificateValidation
                $connection.SslStream = $handshakeStream

                $tlsDetails = Get-TlsHandshakeDetails -Connection $connection
                $connectionSuccessful = $true
            }
            catch {
                $errorToReport = Resolve-TlsException -Exception $_.Exception
                $errorMessage = $errorToReport.Message
                Write-Debug "[$fn] Protocol $protocol failed for ${Hostname}:$Port - $($errorToReport.GetType().FullName): $errorMessage"
            }
            finally {
                $itemSw.Stop()
                Close-NetworkResources -Connection $connection
            }

            if ($tlsDetails) {
                $sessionInfo = ConvertTo-TlsSessionInfo `
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
                    -CertificateValidationPassed $tlsDetails.CertificateValidationPassed `
                    -CertificatePolicyErrors $tlsDetails.CertificatePolicyErrors `
                    -CertificatePolicyErrorFlags $tlsDetails.CertificatePolicyErrorFlags `
                    -CertificateChainStatus $tlsDetails.CertificateChainStatus
            }
            else {
                $sessionInfo = ConvertTo-TlsSessionInfo
            }

            $properties = [ordered]@{
                PSTypeName                    = 'TLSleuth.ProtocolTestResult'
                Hostname                      = $context.Hostname
                Port                          = $context.Port
                TargetHost                    = $context.TargetHost
                Transport                     = $context.Transport
                Protocol                      = $protocol
                ConnectionSuccessful          = $connectionSuccessful
                ErrorMessage                  = $errorMessage
            }

            foreach ($key in @(
                'NegotiatedProtocol'
                'CipherAlgorithm'
                'CipherStrength'
                'NegotiatedCipherSuite'
                'HashAlgorithm'
                'HashStrength'
                'KeyExchangeAlgorithm'
                'KeyExchangeStrength'
                'IsMutuallyAuthenticated'
                'IsEncrypted'
                'IsSigned'
                'NegotiatedApplicationProtocol'
                'ForwardSecrecy'
                'CertificateValidationPassed'
                'CertificatePolicyErrors'
                'CertificatePolicyErrorFlags'
                'CertificateChainStatus'
            )) {
                $properties[$key] = $sessionInfo[$key]
            }

            $properties['ElapsedMs'] = [int][Math]::Round($itemSw.Elapsed.TotalMilliseconds)

            [PSCustomObject]$properties
        }
    }

    end {
        $pipelineSw.Stop()
        Write-Verbose "[$fn] Complete (Processed=$processed) in $($pipelineSw.Elapsed)"
    }
}
