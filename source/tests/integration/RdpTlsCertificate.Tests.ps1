$script:skipRdpIntegration = [string]::IsNullOrWhiteSpace($env:TLSLEUTH_RDP_HOST)

BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }

    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-TlsRuntimeProtocol.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-TlsProtocolOptions.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Add-TlsErrorContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Test-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-TlsResource.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Connect-TcpWithTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportNegotiationResult.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTransportOptionSet.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsTransport.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsOperationContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsConnectionContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithStreamTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Send-BinaryProtocolData.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Read-BinaryProtocolData.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-RdpSecurityProtocolMask.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertFrom-RdpSecurityProtocolMask.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-RdpNegotiationRequest.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Read-RdpNegotiationResponse.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-RdpTlsNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-TlsTimeoutMs.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Resolve-SmtpEhloName.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImplicitTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-SmtpStartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-ImapStartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-Pop3StartTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-RdpTlsTransportAdapter.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-TlsTransportNegotiation.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Start-TlsHandshake.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-TlsHandshakeDetails.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Get-RemoteCertificate.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Test-TlsCertificateValidity.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-TlsSessionInfo.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-TlsCertificateResult.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Close-NetworkResources.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\public') 'Get-TLSleuthCertificate.ps1')
}

Describe 'RDP TLS certificate integration' {
    It 'retrieves a certificate from a configured RDP endpoint' -Skip:$script:skipRdpIntegration {
        $port = 3389
        if (-not [string]::IsNullOrWhiteSpace($env:TLSLEUTH_RDP_PORT)) {
            $port = [int]$env:TLSLEUTH_RDP_PORT
        }

        $targetHost = $env:TLSLEUTH_RDP_HOST
        if (-not [string]::IsNullOrWhiteSpace($env:TLSLEUTH_RDP_TARGETHOST)) {
            $targetHost = $env:TLSLEUTH_RDP_TARGETHOST
        }

        $result = Get-TLSleuthCertificate `
            -Hostname $env:TLSLEUTH_RDP_HOST `
            -Port $port `
            -TargetHost $targetHost `
            -Transport RdpTls `
            -SkipCertificateValidation `
            -TimeoutSec 15

        $result.PSTypeNames | Should -Contain 'TLSleuth.CertificateResult'
        $result.Hostname | Should -Be $env:TLSLEUTH_RDP_HOST
        $result.Port | Should -Be $port
        $result.TargetHost | Should -Be $targetHost
        $result.Certificate | Should -BeOfType ([System.Security.Cryptography.X509Certificates.X509Certificate2])
        $result.NegotiatedProtocol | Should -Not -BeNullOrEmpty
    }
}
