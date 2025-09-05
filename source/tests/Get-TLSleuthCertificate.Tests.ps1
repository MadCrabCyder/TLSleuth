# source/tests/Get-TLSleuthCertificate.Tests.ps1 (fixed vars & filters)

BeforeAll {
    $scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    $sourceRoot = Split-Path -Parent $scriptRoot
    $private    = Join-Path $sourceRoot 'private'
    $public     = Join-Path $sourceRoot 'public'
    $helpersDir = Join-Path $scriptRoot 'helpers'

    . (Join-Path $public  'Get-TLSleuthCertificate.ps1')
    . (Join-Path $private 'Get-SslProtocolsEnum.ps1')
    . (Join-Path $private 'Resolve-Endpoint.ps1')
    . (Join-Path $private 'Connect-TcpWithTimeout.ps1')
    . (Join-Path $private 'Start-TlsHandshake.ps1')
    . (Join-Path $private 'Get-HandshakeInfo.ps1')
    . (Join-Path $private 'Build-CertificateChain.ps1')
    . (Join-Path $private 'Get-CertificateSAN.ps1')
    . (Join-Path $private 'Get-AIAUrls.ps1')
    . (Join-Path $private 'Get-CDPUrls.ps1')
    . (Join-Path $private 'New-TLSleuthCertificateReport.ps1')
    . (Join-Path $private 'Test-IsSelfSigned.ps1')
    . (Join-Path $private 'Format-ChainStatusStrings.ps1')

    . (Join-Path $helpersDir 'New-TestCertificate.ps1')
    . (Join-Path $helpersDir 'New-FakeHandshake.ps1')
}

Describe 'Get-TLSleuthCertificate (mocked)' {

    It 'assembles a full report without touching network' {
        # Arrange
        $TestHost = 'unit.test'
        $TestPort = 8443
        $cn   = 'unit.test'
        $dns  = @('unit.test','www.unit.test')
        $cert = New-TestCertificate -SubjectCN $cn -DnsNames $dns

        Mock -CommandName Resolve-Endpoint -MockWith {
            [System.Net.IPAddress]::Parse('192.0.2.10')
        } -Verifiable -ParameterFilter {
            $Hostname -eq $TestHost
        }

        Mock -CommandName Connect-TcpWithTimeout -MockWith {
            [pscustomobject]@{
                TcpClient=$null
                NetworkStream=[System.IO.MemoryStream]::new()
            }
        } -Verifiable -ParameterFilter {
            $Hostname -eq $TestHost
            $Port -eq $TestPort
        }

        Mock -CommandName Start-TlsHandshake -MockWith {
            [pscustomobject]@{
                SslStream         = [System.Net.Security.SslStream]::new([System.IO.MemoryStream]::new())
                RemoteCertificate = $cert
                CapturedChain     = $null
                ValidationErrors  = @('RemoteCertificateNameMismatch')
            }
        } -Verifiable -ParameterFilter {
                $TargetHost -eq $TestHost
        }

        Mock -CommandName Get-HandshakeInfo -MockWith {
            New-FakeHandshakeInfo -Protocol 'Tls13' -CipherSuite 'TLS_AES_256_GCM_SHA384' -CipherStrengthBits 256 -HashAlgorithm 'SHA384' -KeyExchangeAlgorithm 'ECDHE'
        } -Verifiable

        Mock -CommandName Build-CertificateChain -MockWith {
            [pscustomobject]@{
                Chain         = $null
                IsTrusted     = $false
                ChainStatus   = ,@()
                ChainSubjects = ,@($cert.Subject)
            }
        } -Verifiable

        # Act

        $report = Get-TLSleuthCertificate -Hostname $TestHost -Port $TestPort -IncludeChain
        # $report = Get-TLSleuthCertificate -Hostname 'unit.test' -Port $TestPort -IncludeChain
        # Assert

        Should -BeOfType 'System.Management.Automation.PSCustomObject' -ActualValue $report
        # $report.PSTypeName  | Should -Be 'TLSleuth.CertificateReport'
        $report.Host        | Should -Be $TestHost
        $report.Port        | Should -Be $TestPort
        $report.ConnectedIp | Should -Be '192.0.2.10'
        $report.Protocol    | Should -Be 'Tls13'
        $report.CipherSuite | Should -Be 'TLS_AES_256_GCM_SHA384'
        $report.IsTrusted   | Should -BeFalse
        $report.Certificate.CommonName | Should -Be $cn
        ( $report.Certificate.SANs | Sort-Object ) | Should -Be (@($dns | Sort-Object))
        Should -BeNullOrEmpty -ActualValue $report.Certificate.AIA
        Should -BeNullOrEmpty -ActualValue $report.Certificate.CRLDistribution

        $report.ValidationErrors | Should -Contain 'RemoteCertificateNameMismatch'

        Assert-MockCalled Resolve-Endpoint     -Times 1 -Exactly -ParameterFilter { $Hostname -eq $TestHost }
        Assert-MockCalled Start-TlsHandshake   -Times 1 -Exactly -ParameterFilter { $TargetHost -eq $TestHost }
        Assert-MockCalled Get-HandshakeInfo    -Times 1 -Exactly
        Assert-MockCalled Connect-TcpWithTimeout -Times 1 -Exactly -ParameterFilter { $Hostname -eq $TestHost; $Port -eq $TestPort }
        Assert-MockCalled Build-CertificateChain -Times 1 -Exactly -ParameterFilter { $Certificate.Thumbprint -eq $cert.Thumbprint }
    }

    It 'returns raw certificate when -RawCertificate is used (skips report assembly)' {
        $TestHost = 'raw.test'
        $cert     = New-TestCertificate -SubjectCN 'RawCN'

        Mock -CommandName Resolve-Endpoint    -MockWith { [System.Net.IPAddress]::Parse('192.0.2.10') }
        Mock -CommandName Connect-TcpWithTimeout -MockWith { [pscustomobject]@{ TcpClient=$null; NetworkStream=[System.IO.MemoryStream]::new() } }
        Mock -CommandName Start-TlsHandshake  -MockWith { New-FakeHandshakeResult -Certificate $cert }
        Mock -CommandName Get-HandshakeInfo   -MockWith { throw 'Should not be called' }
        Mock -CommandName Build-CertificateChain -MockWith { throw 'Should not be called' }
        Mock -CommandName New-TLSleuthCertificateReport -MockWith { throw 'Should not be called' }

        $raw = Get-TLSleuthCertificate -Hostname $TestHost -RawCertificate

        $raw | Should -BeOfType 'System.Security.Cryptography.X509Certificates.X509Certificate2'
        $raw.Subject | Should -Match 'CN=RawCN'

        Assert-MockCalled Get-HandshakeInfo -Times 0
        Assert-MockCalled Build-CertificateChain -Times 0
        Assert-MockCalled New-TLSleuthCertificateReport -Times 0
    }
}
