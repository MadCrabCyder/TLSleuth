BeforeAll {
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) { $scriptRoot = Split-Path -Parent $PSCommandPath }
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Add-TlsErrorContext.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Test-TlsTimeoutException.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-WithStreamTimeout.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Read-BinaryProtocolData.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Send-BinaryProtocolData.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertTo-RdpSecurityProtocolMask.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'ConvertFrom-RdpSecurityProtocolMask.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'New-RdpNegotiationRequest.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Read-RdpNegotiationResponse.ps1')
    . (Join-Path (Join-Path $scriptRoot '..\..\private') 'Invoke-RdpTlsNegotiation.ps1')
}

Describe 'RDP TLS negotiation helpers' {
    It 'builds an RDP negotiation request for TLS-capable security modes' {
        $request = New-RdpNegotiationRequest

        $request | Should -Be ([byte[]]@(
            0x03, 0x00, 0x00, 0x13,
            0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x08, 0x00,
            0x0b, 0x00, 0x00, 0x00
        ))
    }

    It 'converts RDP security protocol names and masks' {
        $mask = ConvertTo-RdpSecurityProtocolMask -SecurityProtocol @('Ssl','Hybrid')

        $mask | Should -Be 3
        ConvertFrom-RdpSecurityProtocolMask -Mask $mask | Should -Be @('Ssl','Hybrid')
        ConvertFrom-RdpSecurityProtocolMask -Mask 0 | Should -Be 'StandardRdp'
        ConvertFrom-RdpSecurityProtocolMask -Mask 16 | Should -Be 'Unknown0x00000010'
    }

    It 'parses an RDP negotiation response' {
        $bytes = [byte[]]@(
            0x03, 0x00, 0x00, 0x13,
            0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x02, 0x00, 0x08, 0x00,
            0x02, 0x00, 0x00, 0x00
        )
        $stream = [System.IO.MemoryStream]::new($bytes)

        try {
            $response = Read-RdpNegotiationResponse -Stream $stream -TimeoutMs 1000

            $response.Type | Should -Be 'Response'
            $response.SelectedProtocolMask | Should -Be 2
            $response.SelectedProtocol | Should -Be 'Hybrid'
            $response.TpktLength | Should -Be 19
        }
        finally {
            $stream.Dispose()
        }
    }

    It 'parses an RDP negotiation failure' {
        $bytes = [byte[]]@(
            0x03, 0x00, 0x00, 0x13,
            0x0e, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x08, 0x00,
            0x05, 0x00, 0x00, 0x00
        )
        $stream = [System.IO.MemoryStream]::new($bytes)

        try {
            $response = Read-RdpNegotiationResponse -Stream $stream -TimeoutMs 1000

            $response.Type | Should -Be 'Failure'
            $response.FailureCode | Should -Be 5
            $response.FailureReason | Should -Be 'HYBRID_REQUIRED_BY_SERVER'
        }
        finally {
            $stream.Dispose()
        }
    }

    It 'returns a negotiation response from the RDP transport flow' {
        Mock Send-BinaryProtocolData {}
        Mock Read-RdpNegotiationResponse {
            [PSCustomObject]@{
                Type                 = 'Response'
                TpktLength           = 19
                SelectedProtocolMask = [uint32]8
                SelectedProtocol     = 'HybridEx'
            }
        }

        $stream = [System.IO.MemoryStream]::new()
        try {
            $connection = [PSCustomObject]@{ NetworkStream = $stream }

            $response = Invoke-RdpTlsNegotiation -Connection $connection -TimeoutMs 4000

            $response.SelectedProtocol | Should -Be 'HybridEx'
            Assert-MockCalled Send-BinaryProtocolData -Times 1 -Scope It -ParameterFilter {
                $ProtocolName -eq 'RDP' -and
                $TimeoutMs -eq 4000 -and
                $Bytes.Length -eq 19
            }
            Assert-MockCalled Read-RdpNegotiationResponse -Times 1 -Scope It -ParameterFilter {
                $TimeoutMs -eq 4000
            }
        }
        finally {
            $stream.Dispose()
        }
    }

    It 'throws when the RDP server rejects negotiation' {
        Mock Send-BinaryProtocolData {}
        Mock Read-RdpNegotiationResponse {
            [PSCustomObject]@{
                Type                 = 'Failure'
                SelectedProtocolMask = [uint32]0
                FailureCode          = [uint32]5
                FailureReason        = 'HYBRID_REQUIRED_BY_SERVER'
            }
        }

        $stream = [System.IO.MemoryStream]::new()
        try {
            $connection = [PSCustomObject]@{ NetworkStream = $stream }

            { Invoke-RdpTlsNegotiation -Connection $connection -TimeoutMs 4000 } |
                Should -Throw -ExpectedMessage '*RDP server rejected TLS negotiation*HYBRID_REQUIRED_BY_SERVER*'
        }
        finally {
            $stream.Dispose()
        }
    }

    It 'throws when the RDP server selects non-TLS RDP security' {
        Mock Send-BinaryProtocolData {}
        Mock Read-RdpNegotiationResponse {
            [PSCustomObject]@{
                Type                 = 'Response'
                SelectedProtocolMask = [uint32]0
                SelectedProtocol     = 'StandardRdp'
            }
        }

        $stream = [System.IO.MemoryStream]::new()
        try {
            $connection = [PSCustomObject]@{ NetworkStream = $stream }

            { Invoke-RdpTlsNegotiation -Connection $connection -TimeoutMs 4000 } |
                Should -Throw -ExpectedMessage "*RDP server selected 'StandardRdp'*"
        }
        finally {
            $stream.Dispose()
        }
    }
}
