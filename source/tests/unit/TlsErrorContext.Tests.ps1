BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Add-TlsErrorContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-TlsResource.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsTimeoutMs.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Test-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Connect-TcpWithTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-TlsTransportNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Start-TlsHandshake.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-RemoteCertificate.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithStreamTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Read-BinaryProtocolData.ps1')
}

Describe 'TLSleuth error context' {
    It 'adds operation metadata without changing exception type' {
        $exception = [System.InvalidOperationException]::new('failure')

        $result = Add-TlsErrorContext `
            -Exception $exception `
            -Stage 'TransportNegotiation' `
            -Operation 'RDP transport negotiation' `
            -Transport 'RDP'

        [object]::ReferenceEquals($result, $exception) | Should -BeTrue
        $exception.Data['TLSleuth.Stage'] | Should -Be 'TransportNegotiation'
        $exception.Data['TLSleuth.Operation'] | Should -Be 'RDP transport negotiation'
        $exception.Data['TLSleuth.Transport'] | Should -Be 'RDP'
    }

    It 'categorizes TCP connection failures' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
        $listener.Stop()

        try {
            Connect-TcpWithTimeout -Hostname '127.0.0.1' -Port $port -TimeoutMs 1000
            throw 'Expected connection failure did not occur.'
        }
        catch {
            $_.Exception.Data['TLSleuth.Stage'] | Should -Be 'Connection'
            $_.Exception.Data['TLSleuth.Operation'] | Should -Be 'TCP connection'
            $_.Exception.Data['TLSleuth.Hostname'] | Should -Be '127.0.0.1'
            $_.Exception.Data['TLSleuth.Port'] | Should -Be $port
        }
    }

    It 'categorizes transport negotiation validation failures' {
        try {
            Invoke-TlsTransportNegotiation `
                -Transport 'SmtpStartTls' `
                -Connection ([PSCustomObject]@{}) `
                -Options ([PSCustomObject]@{})
            throw 'Expected transport negotiation failure did not occur.'
        }
        catch {
            $_.Exception.Data['TLSleuth.Stage'] | Should -Be 'TransportNegotiation'
            $_.Exception.Data['TLSleuth.Operation'] | Should -Be 'SmtpStartTls transport negotiation'
            $_.Exception.Data['TLSleuth.Transport'] | Should -Be 'SmtpStartTls'
        }
    }

    It 'categorizes TLS handshake validation failures' {
        try {
            Start-TlsHandshake `
                -Connection ([PSCustomObject]@{}) `
                -TargetHost 'example.test' `
                -SslProtocols ([System.Security.Authentication.SslProtocols]::Tls12)
            throw 'Expected TLS handshake failure did not occur.'
        }
        catch {
            $_.Exception.Data['TLSleuth.Stage'] | Should -Be 'TlsHandshake'
            $_.Exception.Data['TLSleuth.Operation'] | Should -Be 'TLS handshake'
            $_.Exception.Data['TLSleuth.TargetHost'] | Should -Be 'example.test'
        }
    }

    It 'categorizes certificate extraction failures' {
        try {
            Get-RemoteCertificate -Connection ([PSCustomObject]@{})
            throw 'Expected certificate extraction failure did not occur.'
        }
        catch {
            $_.Exception.Data['TLSleuth.Stage'] | Should -Be 'CertificateExtraction'
            $_.Exception.Data['TLSleuth.Operation'] | Should -Be 'Remote certificate extraction'
        }
    }

    It 'categorizes binary protocol read failures' {
        $stream = [System.IO.MemoryStream]::new([byte[]]@(0x03, 0x00))

        try {
            Read-BinaryProtocolData -Stream $stream -Length 4 -TimeoutMs 1000 -ProtocolName 'RDP'
            throw 'Expected binary protocol read failure did not occur.'
        }
        catch {
            $_.Exception.Data['TLSleuth.Stage'] | Should -Be 'BinaryProtocol'
            $_.Exception.Data['TLSleuth.Operation'] | Should -Be 'RDP binary read'
            $_.Exception.Data['TLSleuth.Transport'] | Should -Be 'RDP'
        }
        finally {
            $stream.Dispose()
        }
    }
}
