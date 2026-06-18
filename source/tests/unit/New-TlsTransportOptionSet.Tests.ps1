BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportOptionSet.ps1')
}

Describe 'New-TlsTransportOptionSet' {
    It 'separates shared timeout from protocol-specific options' {
        $options = New-TlsTransportOptionSet `
            -Transport 'SmtpStartTls' `
            -TimeoutMs 12000 `
            -SmtpEhloName 'client.example.test'

        $options.PSTypeNames | Should -Contain 'TLSleuth.TransportOptionSet'
        $options.Transport | Should -Be 'SmtpStartTls'
        $options.Common.TimeoutMs | Should -Be 12000
        $options.SmtpStartTls.EhloName | Should -Be 'client.example.test'
        $options.Rdp.PSObject.Properties.Name | Should -Contain 'RequestedSecurityProtocol'
        $options.Rdp.RequestedSecurityProtocol | Should -Be $null
    }

    It 'keeps protocol-specific options empty when they are not supplied' {
        $options = New-TlsTransportOptionSet `
            -Transport 'ImplicitTls' `
            -TimeoutMs 7000

        $options.Common.TimeoutMs | Should -Be 7000
        $options.SmtpStartTls.EhloName | Should -BeNullOrEmpty
    }
}
