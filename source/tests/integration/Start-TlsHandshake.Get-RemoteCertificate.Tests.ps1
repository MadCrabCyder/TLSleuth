BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }

    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Connect-TcpWithTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Start-TlsHandshake.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-RemoteCertificate.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-NetworkResources.ps1')

    $script:rsa = [System.Security.Cryptography.RSA]::Create(2048)
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        'CN=localhost',
        $script:rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
    $san.AddDnsName('localhost')
    $request.CertificateExtensions.Add($san.Build())

    $ephemeralCert = $request.CreateSelfSigned((Get-Date).AddDays(-1), (Get-Date).AddDays(10))
    $pfxPassword = 'tlsleuth-test'
    $pfxBytes = $ephemeralCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $pfxPassword)
    $script:serverCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
        $pfxBytes,
        $pfxPassword,
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet
    )
    $ephemeralCert.Dispose()
}

AfterAll {
    if ($script:serverCertificate) { $script:serverCertificate.Dispose() }
    if ($script:rsa) { $script:rsa.Dispose() }
}

Describe 'Start-TlsHandshake and Get-RemoteCertificate integration' {
    It 'performs TLS handshake and returns remote certificate on loopback' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()

        $serverClient = $null
        $serverStream = $null
        $serverSsl = $null
        $clientConn = $null
        $clientSslResult = $null

        try {
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            $acceptTask = $listener.AcceptTcpClientAsync()

            $clientConn = Connect-TcpWithTimeout -Hostname '127.0.0.1' -Port $port -TimeoutMs 3000

            $serverClient = $acceptTask.Result
            $serverStream = $serverClient.GetStream()
            $serverSsl = [System.Net.Security.SslStream]::new($serverStream, $false)

            $serverHandshakeTask = $serverSsl.AuthenticateAsServerAsync(
                $script:serverCertificate,
                $false,
                [System.Security.Authentication.SslProtocols]::Tls12,
                $false
            )

            $clientSslResult = Start-TlsHandshake `
                -NetworkStream $clientConn.NetworkStream `
                -TargetHost 'localhost' `
                -SslProtocols ([System.Security.Authentication.SslProtocols]::Tls12) `
                -TimeoutMs 5000 `
                -SkipCertificateValidation

            $serverHandshakeTask.Wait(5000) | Should -BeTrue
            $remoteCertificate = Get-RemoteCertificate -SslStream $clientSslResult.SslStream

            $remoteCertificate | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Certificate2])
            $remoteCertificate.Subject | Should -Match 'CN=localhost'
            $clientSslResult.NegotiatedProtocol | Should -Be ([System.Security.Authentication.SslProtocols]::Tls12)

            $remoteCertificate.Dispose()
        }
        finally {
            Close-NetworkResources -SslStream $clientSslResult.SslStream -NetworkStream $clientConn.NetworkStream -TcpClient $clientConn.TcpClient
            Close-NetworkResources -SslStream $serverSsl -NetworkStream $serverStream -TcpClient $serverClient
            $listener.Stop()
        }
    }

    It 'throws if remote certificate is unavailable on unauthenticated SslStream' {
        $memoryStream = [System.IO.MemoryStream]::new()
        $ssl = [System.Net.Security.SslStream]::new($memoryStream)
        try {
            { Get-RemoteCertificate -SslStream $ssl } | Should -Throw
        }
        finally {
            $ssl.Dispose()
            $memoryStream.Dispose()
        }
    }
}
