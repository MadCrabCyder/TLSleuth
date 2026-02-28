BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }

    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-TlsProtocolOptions.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Connect-TcpWithTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Start-TlsHandshake.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-RemoteCertificate.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Test-TlsCertificateValidity.ps1')
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

        Mock Start-TlsHandshake {
            [PSCustomObject]@{
                SslStream = [System.Net.Security.SslStream]::new([System.IO.MemoryStream]::new())
                NegotiatedProtocol = [System.Security.Authentication.SslProtocols]::Tls12
                CipherAlgorithm = 'Aes256'
                CipherStrength = 256
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
    }
}
