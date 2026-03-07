BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-NetworkResources.ps1')
}

Describe 'Close-NetworkResources' {
    It 'handles null resource inputs without throwing' {
        { Close-NetworkResources } | Should -Not -Throw
    }

    It 'disposes a memory stream safely' {
        $stream = [System.IO.MemoryStream]::new()
        $connection = [PSCustomObject]@{
            SslStream = $null
            NetworkStream = $stream
            TcpClient = $null
        }
        Close-NetworkResources -Connection $connection
        $stream.CanRead | Should -BeFalse
    }

    It 'is idempotent for already disposed resources' {
        $stream = [System.IO.MemoryStream]::new()
        $connection = [PSCustomObject]@{
            SslStream = $null
            NetworkStream = $stream
            TcpClient = $null
        }
        Close-NetworkResources -Connection $connection
        { Close-NetworkResources -Connection $connection } | Should -Not -Throw
    }
}
