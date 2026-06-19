BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Test-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsTimeoutMs.ps1')
}

Describe 'TLS timeout helpers' {
    It 'creates timeout exceptions with operation and endpoint context' {
        $exception = New-TlsTimeoutException `
            -Operation 'TCP connection' `
            -TimeoutMs 1500 `
            -Hostname 'example.test' `
            -Port 443

        $exception | Should -BeOfType ([System.TimeoutException])
        $exception.Message | Should -Be 'TCP connection timed out after 1500ms. Context: endpoint=example.test:443.'
    }

    It 'detects socket timeouts wrapped by IO exceptions' {
        $socketException = [System.Net.Sockets.SocketException]::new([int][System.Net.Sockets.SocketError]::TimedOut)
        $ioException = [System.IO.IOException]::new('transport timeout', $socketException)

        Test-TlsTimeoutException -Exception $ioException | Should -BeTrue
    }

    It 'does not treat unrelated IO exceptions as timeouts' {
        $ioException = [System.IO.IOException]::new('transport failure')

        Test-TlsTimeoutException -Exception $ioException | Should -BeFalse
    }

    It 'resolves timeout from normalized transport options' {
        $options = [PSCustomObject]@{
            Common = [PSCustomObject]@{
                TimeoutMs = 12000
            }
            TimeoutMs = 7000
        }

        Resolve-TlsTimeoutMs -Options $options | Should -Be 12000
    }

    It 'resolves timeout from legacy transport options' {
        $options = [PSCustomObject]@{
            TimeoutMs = 7000
        }

        Resolve-TlsTimeoutMs -Options $options | Should -Be 7000
    }

    It 'uses default timeout when options do not include timeout values' {
        $options = [PSCustomObject]@{}

        Resolve-TlsTimeoutMs -Options $options -DefaultTimeoutMs 9000 | Should -Be 9000
    }
}
