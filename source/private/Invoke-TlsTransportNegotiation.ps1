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

    # Declarative transport adapter table keeps public orchestration logic transport-agnostic.
    $protocolAdapters = @{
        ImplicitTls = {
            param($AdapterConnection, $AdapterOptions)
            Write-Verbose "[$fn] Transport ImplicitTls selected; no plaintext negotiation required."
        }
        SmtpStartTls = {
            param($AdapterConnection, $AdapterOptions)
            $ehloName = $null
            if ($AdapterOptions.PSObject.Properties['SmtpEhloName']) {
                $ehloName = $AdapterOptions.SmtpEhloName
            }

            if ([string]::IsNullOrWhiteSpace($ehloName)) {
                $ehloName = [System.Net.Dns]::GetHostName()
                if ([string]::IsNullOrWhiteSpace($ehloName)) {
                    $ehloName = 'localhost'
                }
            }

            Invoke-SmtpStartTlsNegotiation `
                -NetworkStream $AdapterConnection.NetworkStream `
                -EhloName $ehloName `
                -TimeoutMs $timeoutMs | Out-Null
        }
        ImapStartTls = {
            param($AdapterConnection, $AdapterOptions)
            Invoke-ImapStartTlsNegotiation `
                -NetworkStream $AdapterConnection.NetworkStream `
                -TimeoutMs $timeoutMs | Out-Null
        }
        Pop3StartTls = {
            param($AdapterConnection, $AdapterOptions)
            Invoke-Pop3StartTlsNegotiation `
                -NetworkStream $AdapterConnection.NetworkStream `
                -TimeoutMs $timeoutMs | Out-Null
        }
    }

    try {
        $adapter = $protocolAdapters[$Transport]
        if ($null -eq $adapter) {
            throw [System.InvalidOperationException]::new("No transport adapter is configured for '$Transport'.")
        }

        & $adapter $Connection $Options
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

