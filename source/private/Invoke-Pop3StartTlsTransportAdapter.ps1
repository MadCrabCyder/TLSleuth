function Invoke-Pop3StartTlsTransportAdapter {
<#
.SYNOPSIS
    Performs POP3 STLS transport negotiation and builds the adapter result.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('Pop3StartTls')]
        [string]$Transport = 'Pop3StartTls',

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Connection,

        [Parameter(Mandatory)]
        [ValidateRange(1000,600000)]
        [int]$TimeoutMs
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Transport=$Transport, TimeoutMs=$TimeoutMs)"

    try {
        $details = Invoke-Pop3StartTlsNegotiation `
            -NetworkStream $Connection.NetworkStream `
            -TimeoutMs $TimeoutMs

        New-TlsTransportNegotiationResult `
            -Transport $Transport `
            -Negotiated $true `
            -SelectedProtocol 'STLS' `
            -Details $details
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
