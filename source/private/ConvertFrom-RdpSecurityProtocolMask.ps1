function ConvertFrom-RdpSecurityProtocolMask {
<#
.SYNOPSIS
    Converts an RDP security protocol mask to protocol names.

.OUTPUTS
    System.String[]
#>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [uint32]$Mask
    )

    $protocols = @()
    if (($Mask -band [uint32]0x00000001) -ne 0) { $protocols += 'Ssl' }
    if (($Mask -band [uint32]0x00000002) -ne 0) { $protocols += 'Hybrid' }
    if (($Mask -band [uint32]0x00000008) -ne 0) { $protocols += 'HybridEx' }

    if ($protocols.Count -eq 0 -and $Mask -eq 0) {
        $protocols += 'StandardRdp'
    }
    elseif ($protocols.Count -eq 0) {
        $protocols += "Unknown0x$($Mask.ToString('x8'))"
    }

    $protocols
}
