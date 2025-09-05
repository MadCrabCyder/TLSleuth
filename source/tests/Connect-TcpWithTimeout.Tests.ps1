BeforeAll {
    $scriptRoot = $PSScriptRoot; if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\private') 'Connect-TcpWithTimeout.ps1')
}

Describe 'Connect-TcpWithTimeout' {
    It 'connects to a local listener (helper-based, no external net)' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        try {
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            $acceptTask = $listener.AcceptTcpClientAsync()
            $conn = Connect-TcpWithTimeout -Host '127.0.0.1' -Port $port -TimeoutMs 3000
            try {
                $conn.NetworkStream | Should -Not -BeNullOrEmpty
                $client = $acceptTask.Result
                $client.Dispose()
            } finally {
                try { $conn.NetworkStream.Dispose() } catch {}
                try { $conn.TcpClient.Close(); $conn.TcpClient.Dispose() } catch {}
            }
        } finally { $listener.Stop() }
    }

    It 'throws on non-routable address quickly' {
        { Connect-TcpWithTimeout -Host '203.0.113.255' -Port 9 -TimeoutMs 800 } | Should -Throw
    }
}
