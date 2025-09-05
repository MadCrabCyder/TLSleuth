BeforeDiscovery {
    try { [void][System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]; $Script:HasSANBuilder = $true }
    catch { $Script:HasSANBuilder = $false }
}

BeforeAll {
    $scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    $private = Join-Path $scriptRoot '..\private'
    . (Join-Path $private 'Get-CertificateSAN.ps1')
    . (Join-Path $scriptRoot 'helpers\New-TestCertificate.ps1')
}

Describe 'Get-CertificateSAN' {
    It 'returns an empty array when SAN is absent' {
        $cert = New-TestCertificate -SubjectCN 'NoSAN'
        $result = Get-CertificateSAN -Cert $cert
        ,$result | Should -BeOfType 'System.Object[]'
        $result | Should -HaveCount 0
    }

    It 'extracts multiple DNS names' -Skip:(-not $Script:HasSANBuilder) {
        $dns = @('example.com','www.example.com','api.example.com')
        $cert = New-TestCertificate -SubjectCN 'Multi' -DnsNames $dns
        (Get-CertificateSAN -Cert $cert | Sort-Object) | Should -Be (@($dns | Sort-Object))
    }

    It 'extracts a single DNS as array[1]' -Skip:(-not $Script:HasSANBuilder) {
        $dns = @('example.com')
        $cert = New-TestCertificate -SubjectCN 'Single' -DnsNames $dns
        $r = Get-CertificateSAN -Cert $cert
        Should -BeOfType 'System.Object[]' -ActualValue $r
        $r | Should -HaveCount 1
        $r[0] | Should -Be 'example.com'
    }
}
