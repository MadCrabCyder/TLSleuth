BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-TlsRuntimeProtocol.ps1')
}

Describe 'Get-TlsRuntimeProtocol' {
    It 'returns explicit TLS protocols supported by the current runtime' {
        $actual = @(Get-TlsRuntimeProtocol)

        $actual.Count | Should -BeGreaterThan 0
        foreach ($protocol in $actual) {
            $protocol | Should -BeOfType ([System.Security.Authentication.SslProtocols])
        }
    }

    It 'ignores requested protocol names that are not present on the runtime' {
        $actual = @(Get-TlsRuntimeProtocol -ProtocolName @('Tls12', 'TlsDefinitelyMissing'))

        $actual.Count | Should -Be 1
        $actual[0] | Should -Be ([System.Security.Authentication.SslProtocols]::Tls12)
    }

    It 'throws when none of the requested protocol names are available' {
        { Get-TlsRuntimeProtocol -ProtocolName @('TlsDefinitelyMissing') } |
            Should -Throw -ExpectedMessage '*No explicit SslProtocols values*'
    }
}
