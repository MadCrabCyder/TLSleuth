BeforeAll {
    $scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    $private = Join-Path $scriptRoot '..\private'
    . (Join-Path $private 'Build-CertificateChain.ps1')
    . (Join-Path $private 'Format-ChainStatusStrings.ps1')
    . (Join-Path $scriptRoot 'helpers\New-TestCertificate.ps1')
}

Describe 'Build-CertificateChain' {
    It 'returns untrusted for self-signed helper cert' {
        $cert = New-TestCertificate -SubjectCN 'Self'
        $res  = Build-CertificateChain -Certificate $cert
        $res.IsTrusted | Should -BeFalse
        $res.ChainSubjects | Should -Contain $cert.Subject
        $strings = Format-ChainStatusStrings -ChainStatus $res.ChainStatus
        ,$strings | Should -BeOfType 'System.Object[]'
    }
}
