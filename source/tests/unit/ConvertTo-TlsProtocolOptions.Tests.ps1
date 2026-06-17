BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-TlsRuntimeProtocol.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-TlsProtocolOptions.ps1')
}

Describe 'ConvertTo-TlsProtocolOptions' {
    It 'returns None for SystemDefault' {
        $actual = ConvertTo-TlsProtocolOptions -TlsProtocols @('SystemDefault')
        $actual | Should -Be ([System.Security.Authentication.SslProtocols]::None)
    }

    It 'combines explicit protocol values' {
        $actual = ConvertTo-TlsProtocolOptions -TlsProtocols @('Tls12', 'Tls13')
        $expected = [System.Security.Authentication.SslProtocols]::Tls12 -bor [System.Security.Authentication.SslProtocols]::Tls13
        $actual | Should -Be $expected
    }

    It 'throws when SystemDefault is combined with explicit values' {
        { ConvertTo-TlsProtocolOptions -TlsProtocols @('SystemDefault', 'Tls12') } | Should -Throw
    }

    It 'throws for unsupported value' {
        { ConvertTo-TlsProtocolOptions -TlsProtocols @('Tls99') } | Should -Throw
    }

    It 'throws when a known protocol is not available on the runtime' {
        Mock Get-TlsRuntimeProtocol {
            [System.Security.Authentication.SslProtocols]::Tls12
        }

        { ConvertTo-TlsProtocolOptions -TlsProtocols @('Tls13') } |
            Should -Throw -ExpectedMessage "*not available on this runtime*"
    }
}
