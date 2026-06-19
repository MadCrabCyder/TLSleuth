function Invoke-ImapStartTlsTransportAdapter {
<#
.SYNOPSIS
    Performs IMAP STARTTLS transport negotiation and builds the adapter result.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('ImapStartTls')]
        [string]$Transport = 'ImapStartTls',

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
        $details = Invoke-ImapStartTlsNegotiation `
            -NetworkStream $Connection.NetworkStream `
            -TimeoutMs $TimeoutMs

        New-TlsTransportNegotiationResult `
            -Transport $Transport `
            -Negotiated $true `
            -SelectedProtocol 'STARTTLS' `
            -Details $details
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
