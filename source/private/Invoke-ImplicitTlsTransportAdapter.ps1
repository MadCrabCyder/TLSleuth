function Invoke-ImplicitTlsTransportAdapter {
<#
.SYNOPSIS
    Builds the transport negotiation result for implicit TLS.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('ImplicitTls')]
        [string]$Transport = 'ImplicitTls'
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Transport=$Transport)"

    try {
        New-TlsTransportNegotiationResult `
            -Transport $Transport `
            -Negotiated $true `
            -SelectedProtocol 'ImplicitTls' `
            -Details ([ordered]@{
                Message = 'No plaintext negotiation required.'
            })
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
