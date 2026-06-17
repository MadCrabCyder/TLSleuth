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

    $timeoutMs = if ($Options.PSObject.Properties['TimeoutMs']) { [int]$Options.TimeoutMs } else { 10000 }
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
        }
        SmtpStartTls = {
            param(
                [Parameter(Mandatory)]
                [psobject]$AdapterContext
            )

            $ehloName = $null
            if ($AdapterContext.Options.PSObject.Properties['SmtpEhloName']) {
                $ehloName = $AdapterContext.Options.SmtpEhloName
            }

            if ([string]::IsNullOrWhiteSpace($ehloName)) {
                $ehloName = [System.Net.Dns]::GetHostName()
                if ([string]::IsNullOrWhiteSpace($ehloName)) {
                    $ehloName = 'localhost'
                }
            }

            Invoke-SmtpStartTlsNegotiation `
                -NetworkStream $AdapterContext.Connection.NetworkStream `
                -EhloName $ehloName `
                -TimeoutMs $AdapterContext.TimeoutMs | Out-Null
        }
        ImapStartTls = {
            param(
                [Parameter(Mandatory)]
                [psobject]$AdapterContext
            )

            Invoke-ImapStartTlsNegotiation `
                -NetworkStream $AdapterContext.Connection.NetworkStream `
                -TimeoutMs $AdapterContext.TimeoutMs | Out-Null
        }
        Pop3StartTls = {
            param(
                [Parameter(Mandatory)]
                [psobject]$AdapterContext
            )

            Invoke-Pop3StartTlsNegotiation `
                -NetworkStream $AdapterContext.Connection.NetworkStream `
                -TimeoutMs $AdapterContext.TimeoutMs | Out-Null
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
