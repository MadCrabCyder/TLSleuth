BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }

    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Connect-TcpWithTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Read-TextProtocolLine.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Send-TextProtocolCommand.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithStreamTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImapStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-Pop3StartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-TlsTransportNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Start-TlsHandshake.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-TlsHandshakeDetails.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-NetworkResources.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithRetry.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\public') 'Test-TLSleuthProtocol.ps1')

    $script:expectedProtocols = @(
        foreach ($name in @('Ssl3','Tls','Tls11','Tls12','Tls13')) {
            if ([System.Enum]::GetNames([System.Security.Authentication.SslProtocols]) -contains $name) {
                [System.Security.Authentication.SslProtocols]::$name
            }
        }
    )
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
            $row.ConnectionSuccessful | Should -BeTrue
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
}
