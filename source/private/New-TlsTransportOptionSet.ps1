function New-TlsTransportOptionSet {
<#
.SYNOPSIS
    Builds normalized shared and protocol-specific transport options.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ImplicitTls','SmtpStartTls','ImapStartTls','Pop3StartTls')]
        [string]$Transport,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$SmtpEhloName
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Transport=$Transport, TimeoutMs=$TimeoutMs)"

    try {
        [PSCustomObject]@{
            PSTypeName  = 'TLSleuth.TransportOptionSet'
            Transport   = $Transport
            Common      = [PSCustomObject]@{
                TimeoutMs = $TimeoutMs
            }
            SmtpStartTls = [PSCustomObject]@{
                EhloName = $SmtpEhloName
            }
            Rdp          = [PSCustomObject]@{
                RequestedSecurityProtocol = $null
            }
        }
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
