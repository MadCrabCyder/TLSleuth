BeforeAll {
    $scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\private') 'Test-NegotiatedCipherSuiteSupport.ps1')
}
Describe 'Test-NegotiatedCipherSuiteSupport' {
    It 'returns boolean' {
        (Test-NegotiatedCipherSuiteSupport) | Should -BeOfType 'System.Boolean'
    }
}