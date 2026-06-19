function ConvertTo-RdpSecurityProtocolMask {
<#
.SYNOPSIS
    Converts RDP security protocol names to the negotiation request bitmask.

.OUTPUTS
    System.UInt32
#>
    [CmdletBinding()]
    [OutputType([uint32])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('Ssl','Hybrid','HybridEx')]
        [string[]]$SecurityProtocol
    )

    $mask = [uint32]0
    foreach ($protocol in $SecurityProtocol) {
        switch ($protocol) {
            'Ssl'      { $mask = $mask -bor [uint32]0x00000001 }
            'Hybrid'   { $mask = $mask -bor [uint32]0x00000002 }
            'HybridEx' { $mask = $mask -bor [uint32]0x00000008 }
        }
    }

    $mask
}
