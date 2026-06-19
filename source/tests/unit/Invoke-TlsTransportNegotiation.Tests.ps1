BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportNegotiationResult.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportOptionSet.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsTimeoutMs.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-SmtpEhloName.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImapStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-Pop3StartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImplicitTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImapStartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-Pop3StartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-TlsTransportNegotiation.ps1')
}

Describe 'Invoke-TlsTransportNegotiation' {
    BeforeEach {
        $script:connection = [PSCustomObject]@{
            TcpClient     = $null
            NetworkStream = [System.IO.MemoryStream]::new()
            SslStream     = $null
        }
    }

    AfterEach {
        if ($script:connection -and $script:connection.NetworkStream) {
            $script:connection.NetworkStream.Dispose()
        }
    }

    It 'returns a structured result for implicit TLS' {
        $options = New-TlsTransportOptionSet -Transport 'ImplicitTls' -TimeoutMs 7000

        $result = Invoke-TlsTransportNegotiation `
            -Transport 'ImplicitTls' `
            -Connection $script:connection `
            -Options $options

        $result.PSTypeNames | Should -Contain 'TLSleuth.TransportNegotiationResult'
        $result.Transport | Should -Be 'ImplicitTls'
        $result.Negotiated | Should -BeTrue
        $result.SelectedProtocol | Should -Be 'ImplicitTls'
        $result.Details.Message | Should -Be 'No plaintext negotiation required.'
    }

    It 'returns transport helper details for SMTP STARTTLS' {
        Mock Invoke-SmtpStartTlsNegotiation {
            [PSCustomObject]@{
                GreetingCode = 220
                EhloCode     = 250
                StartTlsCode = 220
            }
        }

        $options = New-TlsTransportOptionSet `
            -Transport 'SmtpStartTls' `
            -TimeoutMs 12000 `
            -SmtpEhloName 'client.example.test'

        $result = Invoke-TlsTransportNegotiation `
            -Transport 'SmtpStartTls' `
            -Connection $script:connection `
            -Options $options

        $result.Transport | Should -Be 'SmtpStartTls'
        $result.Negotiated | Should -BeTrue
        $result.SelectedProtocol | Should -Be 'STARTTLS'
        $result.Details.StartTlsCode | Should -Be 220

        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times 1 -Scope It -ParameterFilter {
            $EhloName -eq 'client.example.test' -and
            $TimeoutMs -eq 12000
        }
    }

    It 'returns transport helper details for IMAP STARTTLS' {
        Mock Invoke-ImapStartTlsNegotiation {
            [PSCustomObject]@{
                GreetingTag       = '*'
                CapabilityTag     = 'A001'
                StartTlsResultTag = 'A002'
            }
        }

        $options = New-TlsTransportOptionSet `
            -Transport 'ImapStartTls' `
            -TimeoutMs 11000

        $result = Invoke-TlsTransportNegotiation `
            -Transport 'ImapStartTls' `
            -Connection $script:connection `
            -Options $options

        $result.Transport | Should -Be 'ImapStartTls'
        $result.Negotiated | Should -BeTrue
        $result.SelectedProtocol | Should -Be 'STARTTLS'
        $result.Details.StartTlsResultTag | Should -Be 'A002'

        Assert-MockCalled Invoke-ImapStartTlsNegotiation -Times 1 -Scope It -ParameterFilter {
            $TimeoutMs -eq 11000
        }
    }

    It 'returns transport helper details for POP3 STLS' {
        Mock Invoke-Pop3StartTlsNegotiation {
            [PSCustomObject]@{
                GreetingStatus = '+OK'
                CapaStatus     = '+OK'
                StlsStatus     = '+OK'
            }
        }

        $options = New-TlsTransportOptionSet `
            -Transport 'Pop3StartTls' `
            -TimeoutMs 9000

        $result = Invoke-TlsTransportNegotiation `
            -Transport 'Pop3StartTls' `
            -Connection $script:connection `
            -Options $options

        $result.Transport | Should -Be 'Pop3StartTls'
        $result.Negotiated | Should -BeTrue
        $result.SelectedProtocol | Should -Be 'STLS'
        $result.Details.StlsStatus | Should -Be '+OK'

        Assert-MockCalled Invoke-Pop3StartTlsNegotiation -Times 1 -Scope It -ParameterFilter {
            $TimeoutMs -eq 9000
        }
    }
}
