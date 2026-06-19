function New-RdpNegotiationRequest {
<#
.SYNOPSIS
    Builds an RDP X.224 connection request with an RDP Negotiation Request.

.OUTPUTS
    System.Byte[]
#>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Ssl','Hybrid','HybridEx')]
        [string[]]$RequestedSecurityProtocol = @('Ssl','Hybrid','HybridEx')
    )

    $protocolMask = ConvertTo-RdpSecurityProtocolMask -SecurityProtocol $RequestedSecurityProtocol

    $bytes = [byte[]]@(
        0x03, 0x00, 0x00, 0x13,
        0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x08, 0x00,
        [byte]($protocolMask -band 0xff),
        [byte](($protocolMask -shr 8) -band 0xff),
        [byte](($protocolMask -shr 16) -band 0xff),
        [byte](($protocolMask -shr 24) -band 0xff)
    )

    Write-Output -InputObject $bytes -NoEnumerate
}
