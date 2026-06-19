function Invoke-RdpTlsTransportAdapter {
<#
.SYNOPSIS
    Builds the transport negotiation result for RDP TLS.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('RdpTls')]
        [string]$Transport = 'RdpTls',

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Connection,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Options,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Transport=$Transport, TimeoutMs=$TimeoutMs)"

    try {
        $requestedSecurityProtocol = @('Ssl','Hybrid','HybridEx')
        if ($Options.PSObject.Properties['Rdp'] -and
            $Options.Rdp.PSObject.Properties['RequestedSecurityProtocol'] -and
            $Options.Rdp.RequestedSecurityProtocol) {
            $requestedSecurityProtocol = @($Options.Rdp.RequestedSecurityProtocol)
        }

        $response = Invoke-RdpTlsNegotiation `
            -Connection $Connection `
            -TimeoutMs $TimeoutMs `
            -RequestedSecurityProtocol $requestedSecurityProtocol

        New-TlsTransportNegotiationResult `
            -Transport $Transport `
            -Negotiated $true `
            -SelectedProtocol $response.SelectedProtocol `
            -Details ([ordered]@{
                RequestedSecurityProtocol = $requestedSecurityProtocol
                SelectedProtocolMask      = $response.SelectedProtocolMask
                TpktLength                = $response.TpktLength
            })
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
