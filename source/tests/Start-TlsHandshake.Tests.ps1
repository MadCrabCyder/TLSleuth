BeforeAll {
    $scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    $private = Join-Path $scriptRoot '..\private'
    . (Join-Path $private 'Start-TlsHandshake.ps1')
    . (Join-Path $private 'Get-SslProtocolsEnum.ps1')
}

Describe 'Start-TlsHandshake' {
    It 'throws when given a non-network stream (helper-only test)' {
        $ms = [System.IO.MemoryStream]::new()
        $proto = Get-SslProtocolsEnum -Names @('SystemDefault')
        { Start-TlsHandshake -NetworkStream $ms -TargetHost 'example.com' -Protocols $proto -TimeoutMs 1000 } | Should -Throw
    }
}
