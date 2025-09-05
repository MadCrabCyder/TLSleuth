BeforeAll {
    $scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\private') 'Test-IsSelfSigned.ps1')
    . (Join-Path $scriptRoot 'helpers\New-TestCertificate.ps1')
}
Describe 'Test-IsSelfSigned' {
    It 'returns $true for helper self-signed cert' {
        Test-IsSelfSigned -Cert (New-TestCertificate -SubjectCN 'Self') | Should -BeTrue
    }
}