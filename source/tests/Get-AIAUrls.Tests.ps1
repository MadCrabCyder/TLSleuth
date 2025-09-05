BeforeAll {
    $scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\private') 'Get-AIAUrls.ps1')
    . (Join-Path $scriptRoot 'helpers\New-TestCertificate.ps1')
}
Describe 'Get-AIAUrls' {
    It 'returns @() when the extension is absent (helper cert)' {
        $cert = New-TestCertificate -SubjectCN 'NoAIA'
        $urls = Get-AIAUrls -Cert $cert
        Should -BeOfType 'System.Object[]' -ActualValue $urls
        $urls | Should -HaveCount 0
    }
}