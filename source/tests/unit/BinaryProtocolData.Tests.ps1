BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithStreamTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Read-BinaryProtocolData.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Send-BinaryProtocolData.ps1')
}

Describe 'Binary protocol data helpers' {
    It 'writes binary protocol bytes without text encoding' {
        $stream = [System.IO.MemoryStream]::new()
        $bytes = [byte[]]@(0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00)

        try {
            Send-BinaryProtocolData -Stream $stream -Bytes $bytes -TimeoutMs 1000 -ProtocolName 'RDP'

            $stream.ToArray() | Should -Be $bytes
        }
        finally {
            $stream.Dispose()
        }
    }

    It 'reads an exact number of binary protocol bytes' {
        $bytes = [byte[]]@(0x03, 0x00, 0x00, 0x0b, 0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00)
        $stream = [System.IO.MemoryStream]::new($bytes)

        try {
            $header = Read-BinaryProtocolData -Stream $stream -Length 4 -TimeoutMs 1000 -ProtocolName 'RDP'
            $payload = Read-BinaryProtocolData -Stream $stream -Length 7 -TimeoutMs 1000 -ProtocolName 'RDP'

            $header | Should -Be ([byte[]]@(0x03, 0x00, 0x00, 0x0b))
            $payload | Should -Be ([byte[]]@(0x06, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00))
        }
        finally {
            $stream.Dispose()
        }
    }

    It 'throws when the stream ends before the requested byte count' {
        $stream = [System.IO.MemoryStream]::new([byte[]]@(0x03, 0x00))

        try {
            { Read-BinaryProtocolData -Stream $stream -Length 4 -TimeoutMs 1000 -ProtocolName 'RDP' } |
                Should -Throw -ExpectedMessage '*ended before 4 bytes*'
        }
        finally {
            $stream.Dispose()
        }
    }
}
