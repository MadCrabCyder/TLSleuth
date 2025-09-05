BeforeAll {
    $scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\private') 'Get-CDPUrls.ps1')
    . (Join-Path $scriptRoot 'helpers\New-TestCertificate.ps1')
}
Describe 'Get-CDPUrls' {
    It 'returns @() when the extension is absent (helper cert)' {
        $cert = New-TestCertificate -SubjectCN 'NoCDP'
        $urls = Get-CDPUrls -Cert $cert
        Should -BeOfType 'System.Object[]' -ActualValue $urls
        $urls | Should -HaveCount 0
    }
}