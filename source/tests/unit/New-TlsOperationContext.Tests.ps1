BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportOptionSet.ps1')
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
}
