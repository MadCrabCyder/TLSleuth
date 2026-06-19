BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Add-TlsErrorContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Test-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithStreamTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Read-BinaryProtocolData.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Send-BinaryProtocolData.ps1')

    if (-not ('TLSleuth.Tests.TimeoutReadStream' -as [type])) {
        Add-Type -TypeDefinition @"
namespace TLSleuth.Tests
{
    public sealed class TimeoutReadStream : System.IO.MemoryStream
    {
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new System.IO.IOException(
                "read timed out",
                new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.TimedOut));
        }
    }

    public sealed class TimeoutWriteStream : System.IO.MemoryStream
    {
        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new System.IO.IOException(
                "write timed out",
                new System.Net.Sockets.SocketException((int)System.Net.Sockets.SocketError.TimedOut));
        }
    }
}
"@
    }
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

    It 'normalizes binary read socket timeouts' {
        $stream = [TLSleuth.Tests.TimeoutReadStream]::new()

        try {
            { Read-BinaryProtocolData -Stream $stream -Length 4 -TimeoutMs 1000 -ProtocolName 'RDP' } |
                Should -Throw -ExpectedMessage '*RDP binary read timed out after 1000ms*'
        }
        finally {
            $stream.Dispose()
        }
    }

    It 'normalizes binary write socket timeouts' {
        $stream = [TLSleuth.Tests.TimeoutWriteStream]::new()
        $bytes = [byte[]]@(0x03, 0x00, 0x00, 0x0b)

        try {
            { Send-BinaryProtocolData -Stream $stream -Bytes $bytes -TimeoutMs 1000 -ProtocolName 'RDP' } |
                Should -Throw -ExpectedMessage '*RDP binary write timed out after 1000ms*'
        }
        finally {
            $stream.Dispose()
        }
    }
}
