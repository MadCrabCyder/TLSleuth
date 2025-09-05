function New-LoopbackTlsPair {
    [CmdletBinding()]
    param(
        [string]$TargetHost = 'localhost',
        [System.Security.Authentication.SslProtocols]$Protocols = [System.Security.Authentication.SslProtocols]::Tls12,
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ServerCertificate,
        [int]$TimeoutMs = 10000
    )

    if (-not $ServerCertificate) {
        if (-not (Get-Command New-TestCertificate -ErrorAction SilentlyContinue)) {
            throw "New-LoopbackTlsPair requires the New-TestCertificate helper to be loaded."
        }
        # Add EKU + SAN for the host
        $ServerCertificate = New-TestCertificate -SubjectCN $TargetHost -DnsNames @($TargetHost) -ServerAuth
    }

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port

    $acceptTask = $listener.AcceptTcpClientAsync()

    $client = [System.Net.Sockets.TcpClient]::new()
    $client.NoDelay = $true
    $client.Connect('127.0.0.1', $port)
    $clientStream = $client.GetStream()

    $clientValidation = { param($s,$c,$ch,$e) $true } # accept self-signed
    $clientSsl = [System.Net.Security.SslStream]::new($clientStream, $false, $clientValidation)

    $serverClient = $acceptTask.Result
    $serverStream = $serverClient.GetStream()
    $serverSsl    = [System.Net.Security.SslStream]::new($serverStream, $false)

    $serverTask = $null
    $clientTask = $null
    try {
        try {
            $serverTask = $serverSsl.AuthenticateAsServerAsync($ServerCertificate, $false, $Protocols, $false)
        } catch {
            $serverTask = [System.Threading.Tasks.Task]::Run({
                $serverSsl.AuthenticateAsServer($ServerCertificate, $false, $Protocols, $false)
            })
        }

        try {
            $clientTask = $clientSsl.AuthenticateAsClientAsync($TargetHost, $null, $Protocols, $false)
        } catch {
            $clientSsl.AuthenticateAsClient($TargetHost, $null, $Protocols, $false)
            $clientTask = [System.Threading.Tasks.Task]::CompletedTask
        }

        if (-not [System.Threading.Tasks.Task]::WaitAll(@($serverTask, $clientTask), [Math]::Max(1000,$TimeoutMs))) {
            throw [System.TimeoutException]::new("TLS handshake timed out after ${TimeoutMs}ms")
        }
    } catch {
        foreach ($o in @($clientSsl,$serverSsl)) { try { if ($o) { $o.Dispose() } } catch {} }
        foreach ($o in @($serverClient,$client)) { try { if ($o) { $o.Close(); $o.Dispose() } } catch {} }
        try { $listener.Stop() } catch {}
        throw
    }

    $dispose = {
        param($lst,$srvCli,$cli,$srvSsl,$cliSsl)
        foreach ($o in @($cliSsl,$srvSsl)) { try { if ($o) { $o.Dispose() } } catch {} }
        foreach ($o in @($srvCli,$cli))   { try { if ($o) { $o.Close(); $o.Dispose() } } catch {} }
        try { if ($lst) { $lst.Stop() } } catch {}
    }.GetNewClosure()

    [pscustomobject]@{
        Listener        = $listener
        ServerClient    = $serverClient
        Client          = $client
        ServerSslStream = $serverSsl
        ClientSslStream = $clientSsl
        Dispose         = { & $dispose $listener $serverClient $client $serverSsl $clientSsl }
    }
}
