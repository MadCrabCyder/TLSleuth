function Invoke-SmtpStartTlsTransportAdapter {
<#
.SYNOPSIS
    Performs SMTP STARTTLS transport negotiation and builds the adapter result.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [ValidateSet('SmtpStartTls')]
        [string]$Transport = 'SmtpStartTls',

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Connection,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Options,

        [Parameter(Mandatory)]
        [ValidateRange(1000,600000)]
        [int]$TimeoutMs
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Transport=$Transport, TimeoutMs=$TimeoutMs)"

    try {
        $ehloName = Resolve-SmtpEhloName -Options $Options

        $details = Invoke-SmtpStartTlsNegotiation `
            -NetworkStream $Connection.NetworkStream `
            -EhloName $ehloName `
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
