BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportNegotiationResult.ps1')
}

Describe 'New-TlsTransportNegotiationResult' {
    It 'builds a stable internal transport negotiation result shape' {
        $details = [ordered]@{
            GreetingCode = 220
            StartTlsCode = 220
        }

        $result = New-TlsTransportNegotiationResult `
            -Transport 'SmtpStartTls' `
            -Negotiated $true `
            -SelectedProtocol 'STARTTLS' `
            -Details $details

        $result.PSTypeNames | Should -Contain 'TLSleuth.TransportNegotiationResult'
        $result.PSObject.Properties.Name | Should -Be @(
            'Transport'
            'Negotiated'
            'SelectedProtocol'
            'Details'
        )
        $result.Transport | Should -Be 'SmtpStartTls'
        $result.Negotiated | Should -BeTrue
        $result.SelectedProtocol | Should -Be 'STARTTLS'
        $result.Details.GreetingCode | Should -Be 220
        $result.Details.StartTlsCode | Should -Be 220
    }

    It 'uses an empty details object when details are omitted' {
        $result = New-TlsTransportNegotiationResult -Transport 'ImplicitTls'

        $result.Transport | Should -Be 'ImplicitTls'
        $result.Negotiated | Should -BeTrue
        ($null -eq $result.Details) | Should -BeFalse
        @($result.Details.PSObject.Properties).Count | Should -Be 0
    }
}
