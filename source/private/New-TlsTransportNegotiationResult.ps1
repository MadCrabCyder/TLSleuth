function New-TlsTransportNegotiationResult {
<#
.SYNOPSIS
    Builds structured metadata for transport negotiation outcomes.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ImplicitTls','SmtpStartTls','ImapStartTls','Pop3StartTls')]
        [string]$Transport,

        [bool]$Negotiated = $true,

        [AllowNull()]
        [string]$SelectedProtocol,

        [AllowNull()]
        [psobject]$Details
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Transport=$Transport, Negotiated=$Negotiated, SelectedProtocol=$SelectedProtocol)"

    try {
        $normalizedDetails = if ($null -eq $Details) {
            [PSCustomObject]@{}
        }
        elseif ($Details -is [hashtable] -or $Details -is [System.Collections.Specialized.OrderedDictionary]) {
            [PSCustomObject]$Details
        }
        else {
            $Details
        }

        [PSCustomObject]@{
            PSTypeName       = 'TLSleuth.TransportNegotiationResult'
            Transport        = $Transport
            Negotiated       = $Negotiated
            SelectedProtocol = $SelectedProtocol
            Details          = $normalizedDetails
        }
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
