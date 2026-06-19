BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportNegotiationResult.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportOptionSet.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-SmtpEhloName.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImapStartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-Pop3StartTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImplicitTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImapStartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-Pop3StartTlsTransportAdapter.ps1')
}

Describe 'TLS transport adapters' {
    BeforeEach {
        $script:connection = [PSCustomObject]@{
            NetworkStream = [System.IO.MemoryStream]::new()
        }
    }

    AfterEach {
        if ($script:connection -and $script:connection.NetworkStream) {
            $script:connection.NetworkStream.Dispose()
        }
    }

    It 'builds the implicit TLS result without plaintext negotiation' {
        $result = Invoke-ImplicitTlsTransportAdapter

        $result.Transport | Should -Be 'ImplicitTls'
        $result.Negotiated | Should -BeTrue
        $result.SelectedProtocol | Should -Be 'ImplicitTls'
        $result.Details.Message | Should -Be 'No plaintext negotiation required.'
    }

    It 'builds the SMTP STARTTLS result using resolved EHLO options' {
        Mock Invoke-SmtpStartTlsNegotiation {
            [PSCustomObject]@{
                StartTlsCode = 220
            }
        }

        $options = New-TlsTransportOptionSet `
            -Transport 'SmtpStartTls' `
            -TimeoutMs 8000 `
            -SmtpEhloName 'client.example.test'

        $result = Invoke-SmtpStartTlsTransportAdapter `
            -Connection $script:connection `
            -Options $options `
            -TimeoutMs 8000

        $result.Transport | Should -Be 'SmtpStartTls'
        $result.SelectedProtocol | Should -Be 'STARTTLS'
        $result.Details.StartTlsCode | Should -Be 220

        Assert-MockCalled Invoke-SmtpStartTlsNegotiation -Times 1 -Scope It -ParameterFilter {
            $EhloName -eq 'client.example.test' -and
            $TimeoutMs -eq 8000
        }
    }

    It 'builds the IMAP STARTTLS result' {
        Mock Invoke-ImapStartTlsNegotiation {
            [PSCustomObject]@{
                StartTlsResultTag = 'A002'
            }
        }

        $result = Invoke-ImapStartTlsTransportAdapter `
            -Connection $script:connection `
            -TimeoutMs 9000

        $result.Transport | Should -Be 'ImapStartTls'
        $result.SelectedProtocol | Should -Be 'STARTTLS'
        $result.Details.StartTlsResultTag | Should -Be 'A002'

        Assert-MockCalled Invoke-ImapStartTlsNegotiation -Times 1 -Scope It -ParameterFilter {
            $TimeoutMs -eq 9000
        }
    }

    It 'builds the POP3 STLS result' {
        Mock Invoke-Pop3StartTlsNegotiation {
            [PSCustomObject]@{
                StlsStatus = '+OK'
            }
        }

        $result = Invoke-Pop3StartTlsTransportAdapter `
            -Connection $script:connection `
            -TimeoutMs 7000

        $result.Transport | Should -Be 'Pop3StartTls'
        $result.SelectedProtocol | Should -Be 'STLS'
        $result.Details.StlsStatus | Should -Be '+OK'

        Assert-MockCalled Invoke-Pop3StartTlsNegotiation -Times 1 -Scope It -ParameterFilter {
            $TimeoutMs -eq 7000
        }
    }
}
