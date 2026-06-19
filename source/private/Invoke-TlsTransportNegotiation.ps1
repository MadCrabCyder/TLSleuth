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

    $adapterContext = [PSCustomObject]@{
        Connection = $Connection
        Options    = $Options
        TimeoutMs  = $timeoutMs
        Transport  = $Transport
    }

    # Declarative transport adapter table keeps public orchestration logic transport-agnostic.
    $protocolAdapters = @{
        ImplicitTls = {
            param(
                [Parameter(Mandatory)]
                [psobject]$AdapterContext
            )

            Write-Verbose "[$fn] Transport $($AdapterContext.Transport) selected; no plaintext negotiation required."
            New-TlsTransportNegotiationResult `
                -Transport $AdapterContext.Transport `
                -Negotiated $true `
                -SelectedProtocol 'ImplicitTls' `
                -Details ([ordered]@{
                    Message = 'No plaintext negotiation required.'
                })
        }
        SmtpStartTls = {
            param(
                [Parameter(Mandatory)]
                [psobject]$AdapterContext
            )

            $ehloName = Resolve-SmtpEhloName -Options $AdapterContext.Options

            $details = Invoke-SmtpStartTlsNegotiation `
                -NetworkStream $AdapterContext.Connection.NetworkStream `
                -EhloName $ehloName `
                -TimeoutMs $AdapterContext.TimeoutMs

            New-TlsTransportNegotiationResult `
                -Transport $AdapterContext.Transport `
                -Negotiated $true `
                -SelectedProtocol 'STARTTLS' `
                -Details $details
        }
        ImapStartTls = {
            param(
                [Parameter(Mandatory)]
                [psobject]$AdapterContext
            )

            $details = Invoke-ImapStartTlsNegotiation `
                -NetworkStream $AdapterContext.Connection.NetworkStream `
                -TimeoutMs $AdapterContext.TimeoutMs

            New-TlsTransportNegotiationResult `
                -Transport $AdapterContext.Transport `
                -Negotiated $true `
                -SelectedProtocol 'STARTTLS' `
                -Details $details
        }
        Pop3StartTls = {
            param(
                [Parameter(Mandatory)]
                [psobject]$AdapterContext
            )

            $details = Invoke-Pop3StartTlsNegotiation `
                -NetworkStream $AdapterContext.Connection.NetworkStream `
                -TimeoutMs $AdapterContext.TimeoutMs

            New-TlsTransportNegotiationResult `
                -Transport $AdapterContext.Transport `
                -Negotiated $true `
                -SelectedProtocol 'STLS' `
                -Details $details
        }
    }

    try {
        $adapter = $protocolAdapters[$Transport]
        if ($null -eq $adapter) {
            throw [System.InvalidOperationException]::new("No transport adapter is configured for '$Transport'.")
        }

        & $adapter -AdapterContext $adapterContext
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
