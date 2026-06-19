BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportOptionSet.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsTransport.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsOperationContext.ps1')
}

Describe 'New-TlsOperationContext' {
    It 'defaults TargetHost to Hostname and converts TimeoutSec to TimeoutMs' {
        $context = New-TlsOperationContext `
            -Hostname 'example.test' `
            -Port 443 `
            -Transport 'ImplicitTls' `
            -TimeoutSec 7

        $context.Hostname | Should -Be 'example.test'
        $context.Port | Should -Be 443
        $context.TargetHost | Should -Be 'example.test'
        $context.Transport | Should -Be 'ImplicitTls'
        $context.TimeoutSec | Should -Be 7
        $context.TimeoutMs | Should -Be 7000
        $context.TransportOptions.Common.TimeoutMs | Should -Be 7000
        $context.TransportOptions.SmtpStartTls.EhloName | Should -BeNullOrEmpty
    }

    It 'preserves explicit target host and SMTP EHLO options' {
        $context = New-TlsOperationContext `
            -Hostname '192.0.2.10' `
            -Port 587 `
            -TargetHost 'mail.example.test' `
            -Transport 'SmtpStartTls' `
            -SmtpEhloName 'client.example.test' `
            -TimeoutSec 12

        $context.TargetHost | Should -Be 'mail.example.test'
        $context.Transport | Should -Be 'SmtpStartTls'
        $context.TimeoutMs | Should -Be 12000
        $context.TransportOptions.Common.TimeoutMs | Should -Be 12000
        $context.TransportOptions.SmtpStartTls.EhloName | Should -Be 'client.example.test'
    }

    It 'builds RDP transport options' {
        $context = New-TlsOperationContext `
            -Hostname 'rdp.example.test' `
            -Port 3389 `
            -Transport 'RdpTls' `
            -TimeoutSec 9

        $context.Transport | Should -Be 'RdpTls'
        $context.Port | Should -Be 3389
        $context.TransportOptions.Rdp.RequestedSecurityProtocol | Should -Be @('Ssl','Hybrid','HybridEx')
    }

    It 'infers transport from common ports when transport was not specified' -TestCases @(
        @{ Port = 25; ExpectedTransport = 'SmtpStartTls' }
        @{ Port = 110; ExpectedTransport = 'Pop3StartTls' }
        @{ Port = 143; ExpectedTransport = 'ImapStartTls' }
        @{ Port = 443; ExpectedTransport = 'ImplicitTls' }
        @{ Port = 587; ExpectedTransport = 'SmtpStartTls' }
        @{ Port = 3389; ExpectedTransport = 'RdpTls' }
    ) {
        param(
            [int]$Port,
            [string]$ExpectedTransport
        )

        $context = New-TlsOperationContext `
            -Hostname 'service.example.test' `
            -Port $Port `
            -Transport 'ImplicitTls' `
            -TimeoutSec 5

        $context.Transport | Should -Be $ExpectedTransport
        $context.TransportOptions.Transport | Should -Be $ExpectedTransport
    }

    It 'preserves explicit transport over port inference' {
        $context = New-TlsOperationContext `
            -Hostname 'rdp.example.test' `
            -Port 3389 `
            -Transport 'ImplicitTls' `
            -TransportSpecified `
            -TimeoutSec 5

        $context.Transport | Should -Be 'ImplicitTls'
        $context.TransportOptions.Transport | Should -Be 'ImplicitTls'
    }

    It 'falls back to provided transport for unknown ports' {
        $context = New-TlsOperationContext `
            -Hostname 'custom.example.test' `
            -Port 8443 `
            -Transport 'ImplicitTls' `
            -TimeoutSec 5

        $context.Transport | Should -Be 'ImplicitTls'
    }
}
