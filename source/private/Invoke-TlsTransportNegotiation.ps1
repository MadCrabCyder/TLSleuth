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
                New-TlsTransportNegotiationResult `
                    -Transport $Transport `
                    -Negotiated $true `
                    -SelectedProtocol 'ImplicitTls' `
                    -Details ([ordered]@{
                        Message = 'No plaintext negotiation required.'
                    })
            }

            'SmtpStartTls' {
                $ehloName = Resolve-SmtpEhloName -Options $Options

                $details = Invoke-SmtpStartTlsNegotiation `
                    -NetworkStream $Connection.NetworkStream `
                    -EhloName $ehloName `
                    -TimeoutMs $timeoutMs

                New-TlsTransportNegotiationResult `
                    -Transport $Transport `
                    -Negotiated $true `
                    -SelectedProtocol 'STARTTLS' `
                    -Details $details
            }

            'ImapStartTls' {
                $details = Invoke-ImapStartTlsNegotiation `
                    -NetworkStream $Connection.NetworkStream `
                    -TimeoutMs $timeoutMs

                New-TlsTransportNegotiationResult `
                    -Transport $Transport `
                    -Negotiated $true `
                    -SelectedProtocol 'STARTTLS' `
                    -Details $details
            }

            'Pop3StartTls' {
                $details = Invoke-Pop3StartTlsNegotiation `
                    -NetworkStream $Connection.NetworkStream `
                    -TimeoutMs $timeoutMs

                New-TlsTransportNegotiationResult `
                    -Transport $Transport `
                    -Negotiated $true `
                    -SelectedProtocol 'STLS' `
                    -Details $details
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
