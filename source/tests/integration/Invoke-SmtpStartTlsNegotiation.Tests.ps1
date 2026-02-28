BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }

    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Connect-TcpWithTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Start-TlsHandshake.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-RemoteCertificate.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-NetworkResources.ps1')

    function Send-SmtpResponses {
        param(
            [Parameter(Mandatory)]
            [System.IO.Stream]$Stream,

            [Parameter(Mandatory)]
            [string[]]$Lines
        )

        $payload = (($Lines -join "`r`n") + "`r`n")
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($payload)
        $Stream.Write($bytes, 0, $bytes.Length)
        $Stream.Flush()
    }

    function Read-SmtpLine {
        param(
            [Parameter(Mandatory)]
            [System.IO.Stream]$Stream
        )

        $bytes = [System.Collections.Generic.List[byte]]::new()
        $buffer = New-Object byte[] 1

        while ($true) {
            $read = $Stream.Read($buffer, 0, 1)
            if ($read -eq 0) {
                throw [System.IO.EndOfStreamException]::new('Stream closed unexpectedly while reading SMTP line.')
            }

            $b = $buffer[0]
            if ($b -eq 10) {
                break
            }

            if ($b -ne 13) {
                $bytes.Add($b)
            }
        }

        [System.Text.Encoding]::ASCII.GetString($bytes.ToArray())
    }

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
    $pfxPassword = 'tlsleuth-starttls'
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

Describe 'Invoke-SmtpStartTlsNegotiation integration' {
    It 'negotiates STARTTLS and allows certificate retrieval from the upgraded stream' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()

        $serverClient = $null
        $serverStream = $null
        $serverSsl = $null
        $serverHandshakeTask = $null
        $clientConn = $null
        $clientSslResult = $null
        $remoteCertificate = $null

        try {
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            $acceptTask = $listener.AcceptTcpClientAsync()

            $clientConn = Connect-TcpWithTimeout -Hostname '127.0.0.1' -Port $port -TimeoutMs 3000

            $serverClient = $acceptTask.Result
            $serverStream = $serverClient.GetStream()

            Send-SmtpResponses -Stream $serverStream -Lines @(
                '220 localhost ESMTP test',
                '250-localhost',
                '250-STARTTLS',
                '250 PIPELINING',
                '220 Ready to start TLS'
            )

            Invoke-SmtpStartTlsNegotiation -NetworkStream $clientConn.NetworkStream -EhloName 'localhost' -TimeoutMs 5000 | Should -Not -BeNullOrEmpty

            $serverStream.ReadTimeout = 3000
            (Read-SmtpLine -Stream $serverStream) | Should -Be 'EHLO localhost'
            (Read-SmtpLine -Stream $serverStream) | Should -Be 'STARTTLS'

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
        }
        finally {
            if ($remoteCertificate) { $remoteCertificate.Dispose() }
            Close-NetworkResources -SslStream $clientSslResult.SslStream -NetworkStream $clientConn.NetworkStream -TcpClient $clientConn.TcpClient
            Close-NetworkResources -SslStream $serverSsl -NetworkStream $serverStream -TcpClient $serverClient
            $listener.Stop()
        }
    }

    It 'throws when EHLO response does not advertise STARTTLS' {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
        $listener.Start()

        $serverClient = $null
        $serverStream = $null
        $clientConn = $null

        try {
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            $acceptTask = $listener.AcceptTcpClientAsync()

            $clientConn = Connect-TcpWithTimeout -Hostname '127.0.0.1' -Port $port -TimeoutMs 3000

            $serverClient = $acceptTask.Result
            $serverStream = $serverClient.GetStream()

            Send-SmtpResponses -Stream $serverStream -Lines @(
                '220 localhost ESMTP test',
                '250-localhost',
                '250 PIPELINING'
            )

            { Invoke-SmtpStartTlsNegotiation -NetworkStream $clientConn.NetworkStream -EhloName 'localhost' -TimeoutMs 5000 } | Should -Throw '*STARTTLS*'
        }
        finally {
            Close-NetworkResources -NetworkStream $clientConn.NetworkStream -TcpClient $clientConn.TcpClient
            Close-NetworkResources -NetworkStream $serverStream -TcpClient $serverClient
            $listener.Stop()
        }
    }

}
