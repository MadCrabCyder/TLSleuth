function Invoke-TlsTransportNegotiation {
<#
.SYNOPSIS
    Dispatches transport-specific plaintext negotiation before TLS handshake.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('ImplicitTls','SmtpStartTls','ImapStartTls','Pop3StartTls')]
        [string]$Transport,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Connection,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Options
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()

    $timeoutMs = 10000
    if ($Options.PSObject.Properties['Common'] -and $Options.Common.PSObject.Properties['TimeoutMs']) {
        $timeoutMs = [int]$Options.Common.TimeoutMs
    }
    elseif ($Options.PSObject.Properties['TimeoutMs']) {
        $timeoutMs = [int]$Options.TimeoutMs
    }
    Write-Verbose "[$fn] Begin (Transport=$Transport, TimeoutMs=$timeoutMs)"

    if (-not $Connection.PSObject.Properties['NetworkStream'] -or $null -eq $Connection.NetworkStream) {
        throw [System.InvalidOperationException]::new('Transport negotiation requires a connection with a non-null NetworkStream.')
    }

    try {
        switch -Exact ($Transport) {
            'ImplicitTls' {
                Write-Verbose "[$fn] Transport $Transport selected; no plaintext negotiation required."
                Invoke-ImplicitTlsTransportAdapter -Transport $Transport
            }

            'SmtpStartTls' {
                Invoke-SmtpStartTlsTransportAdapter `
                    -Transport $Transport `
                    -Connection $Connection `
                    -Options $Options `
                    -TimeoutMs $timeoutMs
            }

            'ImapStartTls' {
                Invoke-ImapStartTlsTransportAdapter `
                    -Transport $Transport `
                    -Connection $Connection `
                    -TimeoutMs $timeoutMs
            }

            'Pop3StartTls' {
                Invoke-Pop3StartTlsTransportAdapter `
                    -Transport $Transport `
                    -Connection $Connection `
                    -TimeoutMs $timeoutMs
            }

            default {
                throw [System.InvalidOperationException]::new("No transport adapter is configured for '$Transport'.")
            }
        }
    }
    catch {
        Write-Debug "[$fn] Transport negotiation failed (Transport=$Transport): $($_.Exception.GetType().FullName)"
        throw
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
