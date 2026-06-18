BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }

    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-TlsRuntimeProtocol.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Connect-TcpWithTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportNegotiationResult.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportOptionSet.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsOperationContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsConnectionContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Read-TextProtocolLine.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Send-TextProtocolCommand.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithStreamTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImapStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-Pop3StartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-TlsTransportNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Start-TlsHandshake.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-TlsHandshakeDetails.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-TlsSessionInfo.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-NetworkResources.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithRetry.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\public') 'Test-TLSleuthProtocol.ps1')

    $script:expectedProtocols = @(Get-TlsRuntimeProtocol)
}

Describe 'Test-TLSleuthProtocol' {
    BeforeEach {
        Mock Connect-TcpWithTimeout {
            [PSCustomObject]@{
                TcpClient = $null
                NetworkStream = [System.IO.MemoryStream]::new()
            }
        }

        Mock Invoke-WithRetry {
            & $ScriptBlock
        }

        Mock Invoke-SmtpStartTlsNegotiation {
            [PSCustomObject]@{ StartTlsCode = 220 }
        }

        Mock Invoke-ImapStartTlsNegotiation {
            [PSCustomObject]@{ StartTlsStatus = 'OK' }
        }

        Mock Invoke-Pop3StartTlsNegotiation {
            [PSCustomObject]@{ StlsStatus = '+OK' }
        }

        Mock Start-TlsHandshake {
            [System.Net.Security.SslStream]::new([System.IO.MemoryStream]::new())
        }

        Mock Get-TlsHandshakeDetails {
            [PSCustomObject]@{
                NegotiatedProtocol = [System.Security.Authentication.SslProtocols]::Tls12
                CipherAlgorithm = 'Aes256'
                CipherStrength = 256
                NegotiatedCipherSuite = 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384'
                HashAlgorithm = 'Sha256'
                HashStrength = 256
                KeyExchangeAlgorithm = 'ECDHE'
                KeyExchangeStrength = 256
                IsMutuallyAuthenticated = $false
                IsEncrypted = $true
                IsSigned = $true
                NegotiatedApplicationProtocol = 'h2'
                ForwardSecrecy = $true
                CertificateValidationPassed = $true
                CertificatePolicyErrors = [System.Net.Security.SslPolicyErrors]::None
                CertificatePolicyErrorFlags = @()
                CertificateChainStatus = @()
            }
        }

        Mock Close-NetworkResources {}
    }

    It 'tests every available explicit TLS protocol and returns handshake details' {
        $result = Test-TLSleuthProtocol -Hostname 'example.test' -Port 443 -TimeoutSec 10

        $result.Count | Should -Be $script:expectedProtocols.Count
        ($result.Protocol | ForEach-Object { $_.ToString() }) | Should -Be ($script:expectedProtocols | ForEach-Object { $_.ToString() })

        foreach ($row in $result) {
            $row.PSTypeNames | Should -Contain 'TLSleuth.ProtocolTestResult'
            $row.PSObject.Properties.Name | Should -Be @(
                'Hostname'
                'Port'
                'TargetHost'
                'Transport'
                'Protocol'
                'ConnectionSuccessful'
                'ErrorMessage'
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
                'ElapsedMs'
            )
            $row.ConnectionSuccessful | Should -BeTrue
            $row.TargetHost | Should -Be 'example.test'
            $row.NegotiatedProtocol | Should -Be ([System.Security.Authentication.SslProtocols]::Tls12)
            $row.ForwardSecrecy | Should -BeTrue
            $row.ErrorMessage | Should -Be $null
        }

        Assert-MockCalled Start-TlsHandshake -Times $script:expectedProtocols.Count -Scope It
        Assert-MockCalled Get-TlsHandshakeDetails -Times $script:expectedProtocols.Count -Scope It
    }

    It 'continues testing remaining protocols when a protocol handshake fails' {
        $failureProtocol = if ($script:expectedProtocols -contains [System.Security.Authentication.SslProtocols]::Tls12) {
            [System.Security.Authentication.SslProtocols]::Tls12
        }
        else {
            $script:expectedProtocols[0]
        }

        Mock Start-TlsHandshake {
            if ($SslProtocols -eq $failureProtocol) {
                throw [System.InvalidOperationException]::new("handshake failed for $SslProtocols")
            }

            [System.Net.Security.SslStream]::new([System.IO.MemoryStream]::new())
        } -ParameterFilter { $true }

        $result = Test-TLSleuthProtocol -Hostname 'example.test' -Port 443 -TimeoutSec 10

        $failed = $result | Where-Object { $_.Protocol -eq $failureProtocol }
        $failed | Should -Not -BeNullOrEmpty
        $failed.ConnectionSuccessful | Should -BeFalse
        $failed.ErrorMessage | Should -Match 'handshake failed'
        $failed.NegotiatedProtocol | Should -Be $null

        $successfulCount = ($result | Where-Object { $_.ConnectionSuccessful }).Count
        $successfulCount | Should -Be ($script:expectedProtocols.Count - 1)

        Assert-MockCalled Get-TlsHandshakeDetails -Times ($script:expectedProtocols.Count - 1) -Scope It
    }

    It 'performs SMTP STARTTLS negotiation before each protocol attempt for SmtpStartTls transport' {
        $null = Test-TLSleuthProtocol `
            -Hostname 'mail.example.test' `
            -Port 587 `
            -Transport 'SmtpStartTls' `
            -TimeoutSec 10 `
            -SkipCertificateValidation

        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times $script:expectedProtocols.Count -Scope It
        Assert-MockCalled Invoke-ImapStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-Pop3StartTlsNegotiation -Times 0 -Scope It
    }

    It 'uses pipeline-bound connection and transport values through the operation context' {
        $inputObject = [PSCustomObject]@{
            Hostname     = 'mail.example.test'
            Port         = 587
            TargetHost   = 'sni.example.test'
            Transport    = 'SmtpStartTls'
            SmtpEhloName = 'client.example.test'
        }

        $result = $inputObject | Test-TLSleuthProtocol -TimeoutSec 12 -SkipCertificateValidation

        $result.Count | Should -Be $script:expectedProtocols.Count
        foreach ($row in $result) {
            $row.Hostname | Should -Be 'mail.example.test'
            $row.Port | Should -Be 587
            $row.TargetHost | Should -Be 'sni.example.test'
            $row.Transport | Should -Be 'SmtpStartTls'
        }

        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times $script:expectedProtocols.Count -Scope It -ParameterFilter {
            $EhloName -eq 'client.example.test' -and
            $TimeoutMs -eq 12000
        }
        Assert-MockCalled Start-TlsHandshake -Times $script:expectedProtocols.Count -Scope It -ParameterFilter {
            $TargetHost -eq 'sni.example.test' -and
            $TimeoutMs -eq 12000
        }
    }
}
