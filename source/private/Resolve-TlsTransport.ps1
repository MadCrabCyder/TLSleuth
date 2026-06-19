function Resolve-TlsTransport {
<#
.SYNOPSIS
    Resolves the effective TLS transport for a target port.

.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateRange(1,65535)]
        [int]$Port,

        [Parameter(Mandatory)]
        [ValidateSet('ImplicitTls','SmtpStartTls','ImapStartTls','Pop3StartTls','RdpTls')]
        [string]$Transport,

        [switch]$TransportSpecified
    )

    if ($TransportSpecified) {
        return $Transport
    }

    $transportByPort = @{
        25   = 'SmtpStartTls'
        110  = 'Pop3StartTls'
        143  = 'ImapStartTls'
        443  = 'ImplicitTls'
        587  = 'SmtpStartTls'
        3389 = 'RdpTls'
    }

    if ($transportByPort.ContainsKey($Port)) {
        return $transportByPort[$Port]
    }

    $Transport
}
