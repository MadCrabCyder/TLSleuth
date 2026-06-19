BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }

    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-TlsRuntimeProtocol.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-TlsProtocolOptions.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Add-TlsErrorContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-TlsResource.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Connect-TcpWithTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportNegotiationResult.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportOptionSet.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsTransport.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsOperationContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsConnectionContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Read-TextProtocolLine.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Send-TextProtocolCommand.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithStreamTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImapStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-Pop3StartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-RdpTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsTimeoutMs.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-SmtpEhloName.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImplicitTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImapStartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-Pop3StartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-RdpTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-TlsTransportNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Start-TlsHandshake.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-TlsHandshakeDetails.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-RemoteCertificate.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Test-TlsCertificateValidity.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-TlsSessionInfo.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-TlsCertificateResult.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-NetworkResources.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithRetry.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\public') 'Get-TLSleuthCertificate.ps1')

    $script:testCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new()
}

AfterAll {
    if ($script:testCertificate) { $script:testCertificate.Dispose() }
}

Describe 'Get-TLSleuthCertificate transport selection' {
    BeforeEach {
        Mock ConvertTo-TlsProtocolOptions {
            [System.Security.Authentication.SslProtocols]::Tls12
        }

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

        Mock Invoke-RdpTlsNegotiation {
            [PSCustomObject]@{
                Type                 = 'Response'
                TpktLength           = 19
                SelectedProtocolMask = [uint32]1
                SelectedProtocol     = 'Ssl'
            }
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

        Mock Get-RemoteCertificate {
            $script:testCertificate
        }

        Mock Test-TlsCertificateValidity {
            [PSCustomObject]@{
                IsValidNow = $true
                DaysUntilExpiry = 10
            }
        }

        Mock ConvertTo-TlsCertificateResult {
            [PSCustomObject]@{
                Hostname = $Hostname
                Port = $Port
                TargetHost = $TargetHost
            }
        }

        Mock Close-NetworkResources {}
    }

    It 'calls SMTP STARTTLS negotiation for SmtpStartTls transport' {
        $result = Get-TLSleuthCertificate `
            -Hostname 'mail.example.test' `
            -Port 587 `
            -TargetHost 'mail.example.test' `
            -Transport 'SmtpStartTls' `
            -TlsProtocols 'Tls12' `
            -SkipCertificateValidation `
            -TimeoutSec 10

        $result | Should -Not -BeNullOrEmpty
        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times 1 -Scope It
        Assert-MockCalled Invoke-ImapStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-Pop3StartTlsNegotiation -Times 0 -Scope It
    }

    It 'calls IMAP STARTTLS negotiation for ImapStartTls transport' {
        $result = Get-TLSleuthCertificate `
            -Hostname 'imap.example.test' `
            -Port 143 `
            -TargetHost 'imap.example.test' `
            -Transport 'ImapStartTls' `
            -TlsProtocols 'Tls12' `
            -SkipCertificateValidation `
            -TimeoutSec 10

        $result | Should -Not -BeNullOrEmpty
        Assert-MockCalled Invoke-ImapStartTlsNegotiation -Times 1 -Scope It
        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-Pop3StartTlsNegotiation -Times 0 -Scope It
    }

    It 'calls POP3 STLS negotiation for Pop3StartTls transport' {
        $result = Get-TLSleuthCertificate `
            -Hostname 'pop3.example.test' `
            -Port 110 `
            -TargetHost 'pop3.example.test' `
            -Transport 'Pop3StartTls' `
            -TlsProtocols 'Tls12' `
            -SkipCertificateValidation `
            -TimeoutSec 10

        $result | Should -Not -BeNullOrEmpty
        Assert-MockCalled Invoke-Pop3StartTlsNegotiation -Times 1 -Scope It
        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-ImapStartTlsNegotiation -Times 0 -Scope It
    }

    It 'calls RDP TLS negotiation for RdpTls transport' {
        $result = Get-TLSleuthCertificate `
            -Hostname 'rdp.example.test' `
            -Port 3389 `
            -TargetHost 'rdp.example.test' `
            -Transport 'RdpTls' `
            -TlsProtocols 'Tls12' `
            -SkipCertificateValidation `
            -TimeoutSec 10

        $result | Should -Not -BeNullOrEmpty
        Assert-MockCalled Invoke-RdpTlsNegotiation -Times 1 -Scope It -ParameterFilter {
            $TimeoutMs -eq 10000
        }
        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-ImapStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-Pop3StartTlsNegotiation -Times 0 -Scope It
    }

    It 'infers RDP TLS transport from port 3389 when transport is omitted' {
        $result = Get-TLSleuthCertificate `
            -Hostname 'rdp.example.test' `
            -Port 3389 `
            -TargetHost 'rdp.example.test' `
            -TlsProtocols 'Tls12' `
            -SkipCertificateValidation `
            -TimeoutSec 10

        $result | Should -Not -BeNullOrEmpty
        Assert-MockCalled Invoke-RdpTlsNegotiation -Times 1 -Scope It -ParameterFilter {
            $TimeoutMs -eq 10000
        }
        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-ImapStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-Pop3StartTlsNegotiation -Times 0 -Scope It
    }

    It 'does not call SMTP STARTTLS negotiation for ImplicitTls transport' {
        $null = Get-TLSleuthCertificate `
            -Hostname 'mail.example.test' `
            -Port 465 `
            -TargetHost 'mail.example.test' `
            -Transport 'ImplicitTls' `
            -TlsProtocols 'Tls12' `
            -SkipCertificateValidation `
            -TimeoutSec 10

        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-ImapStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-Pop3StartTlsNegotiation -Times 0 -Scope It
    }

    It 'does not infer RDP TLS when ImplicitTls is explicit on port 3389' {
        $null = Get-TLSleuthCertificate `
            -Hostname 'rdp.example.test' `
            -Port 3389 `
            -TargetHost 'rdp.example.test' `
            -Transport 'ImplicitTls' `
            -TlsProtocols 'Tls12' `
            -SkipCertificateValidation `
            -TimeoutSec 10

        Assert-MockCalled Invoke-RdpTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-ImapStartTlsNegotiation -Times 0 -Scope It
        Assert-MockCalled Invoke-Pop3StartTlsNegotiation -Times 0 -Scope It
    }

    It 'defaults TargetHost to Hostname and converts TimeoutSec for connection and handshake' {
        $result = Get-TLSleuthCertificate `
            -Hostname 'default.example.test' `
            -TlsProtocols 'Tls12' `
            -SkipCertificateValidation `
            -TimeoutSec 7

        $result.TargetHost | Should -Be 'default.example.test'

        Assert-MockCalled Connect-TcpWithTimeout -Times 1 -Scope It -ParameterFilter {
            $Hostname -eq 'default.example.test' -and
            $Port -eq 443 -and
            $TimeoutMs -eq 7000
        }
        Assert-MockCalled Start-TlsHandshake -Times 1 -Scope It -ParameterFilter {
            $TargetHost -eq 'default.example.test' -and
            $TimeoutMs -eq 7000
        }
    }

    It 'uses pipeline-bound connection and transport values through the operation context' {
        $inputObject = [PSCustomObject]@{
            Hostname     = 'mail.example.test'
            Port         = 587
            TargetHost   = 'sni.example.test'
            Transport    = 'SmtpStartTls'
            SmtpEhloName = 'client.example.test'
        }

        $result = $inputObject | Get-TLSleuthCertificate `
            -TlsProtocols 'Tls12' `
            -SkipCertificateValidation `
            -TimeoutSec 12

        $result.Hostname | Should -Be 'mail.example.test'
        $result.Port | Should -Be 587
        $result.TargetHost | Should -Be 'sni.example.test'

        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times 1 -Scope It -ParameterFilter {
            $EhloName -eq 'client.example.test' -and
            $TimeoutMs -eq 12000
        }
        Assert-MockCalled Start-TlsHandshake -Times 1 -Scope It -ParameterFilter {
            $TargetHost -eq 'sni.example.test' -and
            $TimeoutMs -eq 12000
        }
    }

    It 'does not leak internal transport negotiation results into public output' {
        Mock Invoke-SmtpStartTlsNegotiation {
            [PSCustomObject]@{
                GreetingCode = 220
                EhloCode     = 250
                StartTlsCode = 220
            }
        }

        $result = Get-TLSleuthCertificate `
            -Hostname 'mail.example.test' `
            -Port 587 `
            -TargetHost 'mail.example.test' `
            -Transport 'SmtpStartTls' `
            -TlsProtocols 'Tls12' `
            -SkipCertificateValidation `
            -TimeoutSec 10

        @($result).Count | Should -Be 1
        $result.PSTypeNames | Should -Not -Contain 'TLSleuth.TransportNegotiationResult'
    }
}
