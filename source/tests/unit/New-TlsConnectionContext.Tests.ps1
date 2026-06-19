BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Add-TlsErrorContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-TlsResource.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Connect-TcpWithTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithRetry.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsConnectionContext.ps1')
}

Describe 'New-TlsConnectionContext' {
    BeforeEach {
        Mock Invoke-WithRetry {
            & $ScriptBlock
        }
    }

    It 'opens a TCP connection and adds the SslStream slot when it is missing' {
        Mock Connect-TcpWithTimeout {
            [PSCustomObject]@{
                TcpClient     = $null
                NetworkStream = [System.IO.MemoryStream]::new()
            }
        }

        $connection = New-TlsConnectionContext -Hostname 'example.test' -Port 443 -TimeoutMs 7000

        $connection.NetworkStream | Should -BeOfType ([System.IO.MemoryStream])
        $connection.PSObject.Properties.Name | Should -Contain 'SslStream'
        $connection.SslStream | Should -Be $null
        Assert-MockCalled Connect-TcpWithTimeout -Times 1 -Scope It -ParameterFilter {
            $Hostname -eq 'example.test' -and
            $Port -eq 443 -and
            $TimeoutMs -eq 7000
        }
    }

    It 'preserves an existing SslStream property' {
        $sentinel = [System.IO.MemoryStream]::new()
        Mock Connect-TcpWithTimeout {
            [PSCustomObject]@{
                TcpClient     = $null
                NetworkStream = [System.IO.MemoryStream]::new()
                SslStream     = $sentinel
            }
        }

        $connection = New-TlsConnectionContext -Hostname 'example.test' -Port 443 -TimeoutMs 7000

        $connection.SslStream | Should -Be $sentinel
        $sentinel.Dispose()
    }
}
