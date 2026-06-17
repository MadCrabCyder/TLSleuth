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
        $timeoutMs = $TimeoutSec * 1000

        $knownProtocols = @('Ssl3','Tls','Tls11','Tls12','Tls13')
        $enumNames = [System.Enum]::GetNames([System.Security.Authentication.SslProtocols])
        $availableProtocols = @(
            foreach ($name in $knownProtocols) {
                if ($enumNames -contains $name) {
                    [System.Security.Authentication.SslProtocols]::$name
                }
            }
        )

        if (-not $availableProtocols -or $availableProtocols.Count -eq 0) {
            throw [System.InvalidOperationException]::new('No explicit SslProtocols values are available on this runtime.')
        }

        Write-Verbose "[$fn] Begin (Transport=$Transport, TimeoutSec=$TimeoutSec, Protocols=$($availableProtocols -join ','))"
    }

    process {
        $processed++
        $target = if ([string]::IsNullOrWhiteSpace($TargetHost)) { $Hostname } else { $TargetHost }

        foreach ($protocol in $availableProtocols) {
            $itemSw = [System.Diagnostics.Stopwatch]::StartNew()
            $connection = $null
            $tlsDetails = $null
            $connectionSuccessful = $false
            $errorMessage = $null

            try {
                $connection = Invoke-WithRetry -ScriptBlock {
                    Connect-TcpWithTimeout -Hostname $Hostname -Port $Port -TimeoutMs $timeoutMs
                }
                if (-not $connection.PSObject.Properties['SslStream']) {
                    $connection | Add-Member -NotePropertyName 'SslStream' -NotePropertyValue $null
                }

                $transportOptions = [PSCustomObject]@{
                    TimeoutMs    = $timeoutMs
                    SmtpEhloName = $SmtpEhloName
                }

                Invoke-TlsTransportNegotiation `
                    -Transport $Transport `
                    -Connection $connection `
                    -Options $transportOptions

                $handshakeStream = Start-TlsHandshake `
                    -Connection $connection `
                    -TargetHost $target `
                    -SslProtocols $protocol `
                    -TimeoutMs $timeoutMs `
                    -SkipCertificateValidation:$SkipCertificateValidation
                $connection.SslStream = $handshakeStream

                $tlsDetails = Get-TlsHandshakeDetails -Connection $connection
                $connectionSuccessful = $true
            }
            catch {
                $errorMessage = $_.Exception.Message
                Write-Debug "[$fn] Protocol $protocol failed for ${Hostname}:$Port - $errorMessage"
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
                Hostname                      = $Hostname
                Port                          = $Port
                TargetHost                    = $target
                Transport                     = $Transport
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
