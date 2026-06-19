function Read-RdpNegotiationResponse {
<#
.SYNOPSIS
    Reads and parses the RDP X.224 connection confirm negotiation response.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.Stream]$Stream,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000
    )

    $header = Read-BinaryProtocolData -Stream $Stream -Length 4 -TimeoutMs $TimeoutMs -ProtocolName 'RDP'
    if ($header[0] -ne 0x03 -or $header[1] -ne 0x00) {
        throw [System.InvalidOperationException]::new('RDP negotiation response did not start with a valid TPKT header.')
    }

    $tpktLength = ([int]$header[2] -shl 8) -bor [int]$header[3]
    if ($tpktLength -lt 11) {
        throw [System.InvalidOperationException]::new("RDP negotiation response length $tpktLength is too short.")
    }

    $payload = Read-BinaryProtocolData -Stream $Stream -Length ($tpktLength - 4) -TimeoutMs $TimeoutMs -ProtocolName 'RDP'
    if ($payload.Length -lt 7 -or $payload[1] -ne 0xd0) {
        throw [System.InvalidOperationException]::new('RDP negotiation response did not include an X.224 connection confirm.')
    }

    $negotiationOffset = $null
    for ($index = 7; $index -le ($payload.Length - 8); $index++) {
        $type = $payload[$index]
        if (($type -eq 0x02 -or $type -eq 0x03) -and
            $payload[$index + 2] -eq 0x08 -and
            $payload[$index + 3] -eq 0x00) {
            $negotiationOffset = $index
            break
        }
    }

    if ($null -eq $negotiationOffset) {
        throw [System.InvalidOperationException]::new('RDP negotiation response did not include a negotiation response or failure structure.')
    }

    $responseType = $payload[$negotiationOffset]
    $value = [uint32]$payload[$negotiationOffset + 4] `
        -bor ([uint32]$payload[$negotiationOffset + 5] -shl 8) `
        -bor ([uint32]$payload[$negotiationOffset + 6] -shl 16) `
        -bor ([uint32]$payload[$negotiationOffset + 7] -shl 24)

    if ($responseType -eq 0x03) {
        $reason = switch ($value) {
            0x00000001 { 'SSL_REQUIRED_BY_SERVER' }
            0x00000002 { 'SSL_NOT_ALLOWED_BY_SERVER' }
            0x00000003 { 'SSL_CERT_NOT_ON_SERVER' }
            0x00000004 { 'INCONSISTENT_FLAGS' }
            0x00000005 { 'HYBRID_REQUIRED_BY_SERVER' }
            0x00000006 { 'SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER' }
            default { "UNKNOWN_FAILURE_0x$($value.ToString('x8'))" }
        }

        return [PSCustomObject]@{
            Type                 = 'Failure'
            TpktLength           = $tpktLength
            SelectedProtocolMask = [uint32]0
            SelectedProtocol     = $null
            FailureCode          = $value
            FailureReason        = $reason
        }
    }

    $selectedProtocols = @(ConvertFrom-RdpSecurityProtocolMask -Mask $value)
    [PSCustomObject]@{
        Type                 = 'Response'
        TpktLength           = $tpktLength
        SelectedProtocolMask = $value
        SelectedProtocol     = ($selectedProtocols -join ',')
        FailureCode          = $null
        FailureReason        = $null
    }
}
