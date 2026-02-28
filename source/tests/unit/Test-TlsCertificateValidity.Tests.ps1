BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Test-TlsCertificateValidity.ps1')

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=tlsleuth-validity-test',
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $script:cert = $request.CreateSelfSigned((Get-Date).AddDays(-2), (Get-Date).AddDays(10))
}

AfterAll {
    if ($script:cert) { $script:cert.Dispose() }
    if ($rsa) { $rsa.Dispose() }
}

Describe 'Test-TlsCertificateValidity' {
    It 'returns expected validity properties for current date' {
        $result = Test-TlsCertificateValidity -Certificate $script:cert -AsOf (Get-Date)
        $result.IsValidNow | Should -BeTrue
        $result.NotBefore | Should -Be $script:cert.NotBefore
        $result.NotAfter | Should -Be $script:cert.NotAfter
        $result.PSObject.Properties.Name | Should -Contain 'DaysUntilExpiry'
    }

    It 'marks certificate invalid when AsOf is after expiration' {
        $future = $script:cert.NotAfter.AddDays(1)
        $result = Test-TlsCertificateValidity -Certificate $script:cert -AsOf $future
        $result.IsValidNow | Should -BeFalse
        $result.DaysUntilExpiry | Should -BeLessThan 0
    }
}