function Invoke-Pop3StartTlsNegotiation {
<#
.SYNOPSIS
    Performs POP3 STLS negotiation over an existing plaintext stream.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.Stream]$NetworkStream,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (TimeoutMs=$TimeoutMs)"

    if (-not $NetworkStream.CanRead -or -not $NetworkStream.CanWrite) {
        throw [System.InvalidOperationException]::new('POP3 STLS negotiation requires a readable and writable stream.')
    }

    function Parse-Pop3StatusLine {
        param(
            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Line
        )

        if ($Line.StartsWith('+OK', [System.StringComparison]::OrdinalIgnoreCase)) {
            return [PSCustomObject]@{
                IsOk    = $true
                Status  = '+OK'
                Message = $Line
            }
        }

        if ($Line.StartsWith('-ERR', [System.StringComparison]::OrdinalIgnoreCase)) {
            return [PSCustomObject]@{
                IsOk    = $false
                Status  = '-ERR'
                Message = $Line
            }
        }

        throw [System.InvalidOperationException]::new("Invalid POP3 status line: '$Line'")
    }

    function Read-Pop3MultilineData {
        param(
            [Parameter(Mandatory)]
            [System.IO.Stream]$Stream,

            [Parameter(Mandatory)]
            [int]$ReadTimeoutMs
        )

        $lines = [System.Collections.Generic.List[string]]::new()

        while ($true) {
            $line = Read-TextProtocolLine -Stream $Stream -ReadTimeoutMs $ReadTimeoutMs -ProtocolName 'POP3'
            if ($line -eq '.') {
                break
            }

            # POP3 dot-stuffing: leading '..' represents literal '.'
            if ($line.StartsWith('..', [System.StringComparison]::Ordinal)) {
                $line = $line.Substring(1)
            }

            $lines.Add($line)
        }

        [string[]]$lines
    }

    try {
        Invoke-WithStreamTimeout -Stream $NetworkStream -TimeoutMs $TimeoutMs -ScriptBlock {
            $greetingLine = Read-TextProtocolLine -Stream $NetworkStream -ReadTimeoutMs $TimeoutMs -ProtocolName 'POP3'
            $greeting = Parse-Pop3StatusLine -Line $greetingLine
            if (-not $greeting.IsOk) {
                throw [System.InvalidOperationException]::new("POP3 server did not return +OK greeting. Received: $($greeting.Message)")
            }
            Write-Verbose "[$fn] Received POP3 greeting status $($greeting.Status)."

            Send-TextProtocolCommand -Stream $NetworkStream -Command 'CAPA'
            $capaStatusLine = Read-TextProtocolLine -Stream $NetworkStream -ReadTimeoutMs $TimeoutMs -ProtocolName 'POP3'
            $capaStatus = Parse-Pop3StatusLine -Line $capaStatusLine
            if (-not $capaStatus.IsOk) {
                throw [System.InvalidOperationException]::new("POP3 CAPA command failed. Received: $($capaStatus.Message)")
            }
            $capabilityLines = Read-Pop3MultilineData -Stream $NetworkStream -ReadTimeoutMs $TimeoutMs
            Write-Verbose "[$fn] CAPA accepted with status $($capaStatus.Status)."

            $supportsStls = $false
            foreach ($capability in $capabilityLines) {
                if ($capability -match '^(?i)STLS(?:\s|$)') {
                    $supportsStls = $true
                    break
                }
            }

            if (-not $supportsStls) {
                throw [System.InvalidOperationException]::new('POP3 server does not advertise STLS in CAPA response.')
            }

            Send-TextProtocolCommand -Stream $NetworkStream -Command 'STLS'
            $stlsStatusLine = Read-TextProtocolLine -Stream $NetworkStream -ReadTimeoutMs $TimeoutMs -ProtocolName 'POP3'
            $stlsStatus = Parse-Pop3StatusLine -Line $stlsStatusLine
            if (-not $stlsStatus.IsOk) {
                throw [System.InvalidOperationException]::new("POP3 STLS command was not accepted. Received: $($stlsStatus.Message)")
            }
            Write-Verbose "[$fn] STLS accepted with status $($stlsStatus.Status)."

            [PSCustomObject]@{
                GreetingStatus = $greeting.Status
                CapaStatus     = $capaStatus.Status
                StlsStatus     = $stlsStatus.Status
            }
        }
    }
    catch {
        Write-Debug "[$fn] STLS negotiation failed: $($_.Exception.GetType().FullName)"
        throw
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
