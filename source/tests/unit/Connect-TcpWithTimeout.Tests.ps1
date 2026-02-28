BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Connect-TcpWithTimeout.ps1')
}

Describe 'Connect-TcpWithTimeout unit' {
    It 'accepts -Host alias explicitly' {
        { Connect-TcpWithTimeout -Host '127.0.0.1' -Port 65535 -TimeoutMs 1000 } | Should -Throw
    }

    It 'rejects invalid port values' {
        { Connect-TcpWithTimeout -Hostname '127.0.0.1' -Port 0 -TimeoutMs 1000 } | Should -Throw
        { Connect-TcpWithTimeout -Hostname '127.0.0.1' -Port 70000 -TimeoutMs 1000 } | Should -Throw
    }

    It 'rejects timeout below supported minimum' {
        { Connect-TcpWithTimeout -Hostname '127.0.0.1' -Port 443 -TimeoutMs 999 } | Should -Throw
    }
}