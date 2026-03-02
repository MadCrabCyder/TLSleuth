BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-TlsCertificateResult.ps1')

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=tlsleuth-result-test',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:cert = $request.CreateSelfSigned((Get-Date).AddDays(-1), (Get-Date).AddDays(30))
}

AfterAll {
    if ($script:cert) { $script:cert.Dispose() }
    if ($rsa) { $rsa.Dispose() }
}

Describe 'ConvertTo-TlsCertificateResult' {
    It 'builds a stable result contract' {
        $validity = [PSCustomObject]@{
            IsValidNow = $true
            DaysUntilExpiry = 10
        }

        $result = ConvertTo-TlsCertificateResult `
            -Hostname 'example.test' `
            -Port 443 `
            -TargetHost 'example.test' `
            -Certificate $script:cert `
            -Validity $validity `
            -NegotiatedProtocol ([System.Security.Authentication.SslProtocols]::Tls12) `
            -CipherAlgorithm 'Aes256' `
            -CipherStrength 256 `
            -Elapsed ([timespan]::FromMilliseconds(123.4))

        $result.PSTypeNames | Should -Contain 'TLSleuth.CertificateResult'
        $result.Hostname | Should -Be 'example.test'
        $result.Port | Should -Be 443
        $result.TargetHost | Should -Be 'example.test'
        $result.Thumbprint | Should -Be $script:cert.Thumbprint
        $result.IsValidNow | Should -BeTrue
        $result.DaysUntilExpiry | Should -Be 10
        $result.CertificateValidationPassed | Should -BeTrue
        $result.CertificatePolicyErrors | Should -Be ([System.Net.Security.SslPolicyErrors]::None)
        ($result.CertificatePolicyErrorFlags -is [array]) | Should -BeTrue
        ($result.CertificateChainStatus -is [array]) | Should -BeTrue
        $result.ElapsedMs | Should -Be 123
        $result.Certificate | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Certificate2])
    }
}
