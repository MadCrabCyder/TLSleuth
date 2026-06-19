function Invoke-RdpTlsNegotiation {
<#
.SYNOPSIS
    Negotiates an RDP TLS-capable security mode before starting TLS.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Connection,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000,

        [ValidateNotNullOrEmpty()]
        [ValidateSet('Ssl','Hybrid','HybridEx')]
        [string[]]$RequestedSecurityProtocol = @('Ssl','Hybrid','HybridEx')
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (TimeoutMs=$TimeoutMs, RequestedSecurityProtocol=$($RequestedSecurityProtocol -join ','))"

    try {
        if (-not $Connection.PSObject.Properties['NetworkStream'] -or $null -eq $Connection.NetworkStream) {
            throw [System.InvalidOperationException]::new('RDP TLS negotiation requires a connection with a non-null NetworkStream.')
        }

        $request = New-RdpNegotiationRequest -RequestedSecurityProtocol $RequestedSecurityProtocol
        Send-BinaryProtocolData -Stream $Connection.NetworkStream -Bytes $request -TimeoutMs $TimeoutMs -ProtocolName 'RDP'

        $response = Read-RdpNegotiationResponse -Stream $Connection.NetworkStream -TimeoutMs $TimeoutMs
        if ($response.Type -eq 'Failure') {
            $failureCode = ([uint32]$response.FailureCode).ToString('x8')
            throw [System.InvalidOperationException]::new(
                "RDP server rejected TLS negotiation: $($response.FailureReason) (0x$failureCode).")
        }

        if (($response.SelectedProtocolMask -band [uint32]0x0000000b) -eq 0) {
            throw [System.InvalidOperationException]::new(
                "RDP server selected '$($response.SelectedProtocol)'; TLS certificate retrieval requires TLS-capable RDP security.")
        }

        $response
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
