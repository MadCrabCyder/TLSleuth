function Invoke-SmtpStartTlsNegotiation {
<#
.SYNOPSIS
    Performs SMTP STARTTLS negotiation over an existing plaintext stream.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.Stream]$NetworkStream,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$EhloName,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (EhloName=$EhloName, TimeoutMs=$TimeoutMs)"

    if (-not $NetworkStream.CanRead -or -not $NetworkStream.CanWrite) {
        throw [System.InvalidOperationException]::new('SMTP STARTTLS negotiation requires a readable and writable stream.')
    }

    function Read-SmtpLine {
        param(
            [Parameter(Mandatory)]
            [System.IO.Stream]$Stream,

            [Parameter(Mandatory)]
            [int]$ReadTimeoutMs
        )

        $bytes = [System.Collections.Generic.List[byte]]::new()
        $buffer = New-Object byte[] 1

        while ($true) {
            try {
                $read = $Stream.Read($buffer, 0, 1)
            }
            catch [System.IO.IOException] {
                $inner = $_.Exception.InnerException
                if ($inner -is [System.Net.Sockets.SocketException] -and
                    $inner.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
                    throw [System.TimeoutException]::new("SMTP negotiation timed out after ${ReadTimeoutMs}ms.")
                }
                throw
            }

            if ($read -eq 0) {
                throw [System.IO.EndOfStreamException]::new('SMTP server closed the connection unexpectedly.')
            }

            $b = $buffer[0]
            if ($b -eq 10) {
                break
            }

            if ($b -ne 13) {
                $bytes.Add($b)
            }

            if ($bytes.Count -gt 4096) {
                throw [System.InvalidOperationException]::new('SMTP response line exceeded 4096 bytes.')
            }
        }

        [System.Text.Encoding]::ASCII.GetString($bytes.ToArray())
    }

    function Read-SmtpResponse {
        param(
            [Parameter(Mandatory)]
            [System.IO.Stream]$Stream,

            [Parameter(Mandatory)]
            [int]$ReadTimeoutMs
        )

        $lines = [System.Collections.Generic.List[string]]::new()
        $firstLine = Read-SmtpLine -Stream $Stream -ReadTimeoutMs $ReadTimeoutMs
        $lines.Add($firstLine)

        $statusCode = 0
        if ($firstLine.Length -lt 3 -or -not [int]::TryParse($firstLine.Substring(0, 3), [ref]$statusCode)) {
            throw [System.InvalidOperationException]::new("Invalid SMTP response line: '$firstLine'")
        }

        $statusPrefix = '{0:D3}' -f $statusCode
        $isMultiline = ($firstLine.Length -ge 4 -and $firstLine[3] -eq '-')

        if ($isMultiline) {
            while ($true) {
                $line = Read-SmtpLine -Stream $Stream -ReadTimeoutMs $ReadTimeoutMs
                $lines.Add($line)

                if ($line.Length -ge 4 -and $line.StartsWith($statusPrefix) -and $line[3] -eq '-') {
                    continue
                }

                if ($line.Length -ge 4 -and $line.StartsWith($statusPrefix) -and $line[3] -eq ' ') {
                    break
                }

                throw [System.InvalidOperationException]::new("Invalid SMTP multiline response continuation: '$line'")
            }
        }

        [PSCustomObject]@{
            Code    = $statusCode
            Lines   = [string[]]$lines
            Message = ($lines -join "`n")
        }
    }

    function Send-SmtpCommand {
        param(
            [Parameter(Mandatory)]
            [System.IO.Stream]$Stream,

            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Command
        )

        $payload = [System.Text.Encoding]::ASCII.GetBytes("$Command`r`n")
        $Stream.Write($payload, 0, $payload.Length)
        $Stream.Flush()
    }

    $originalReadTimeout = $null
    $originalWriteTimeout = $null
    $timeoutsApplied = $false

    try {
        if ($NetworkStream.CanTimeout) {
            $originalReadTimeout = $NetworkStream.ReadTimeout
            $originalWriteTimeout = $NetworkStream.WriteTimeout

            $NetworkStream.ReadTimeout = $TimeoutMs
            $NetworkStream.WriteTimeout = $TimeoutMs
            $timeoutsApplied = $true
        }

        $banner = Read-SmtpResponse -Stream $NetworkStream -ReadTimeoutMs $TimeoutMs
        if ($banner.Code -ne 220) {
            throw [System.InvalidOperationException]::new("SMTP server did not return 220 greeting. Received: $($banner.Message)")
        }
        Write-Verbose "[$fn] Received SMTP greeting code $($banner.Code)."

        Send-SmtpCommand -Stream $NetworkStream -Command "EHLO $EhloName"
        $ehloResponse = Read-SmtpResponse -Stream $NetworkStream -ReadTimeoutMs $TimeoutMs
        if ($ehloResponse.Code -ne 250) {
            throw [System.InvalidOperationException]::new("SMTP EHLO failed. Received: $($ehloResponse.Message)")
        }
        Write-Verbose "[$fn] EHLO accepted with code $($ehloResponse.Code)."

        $supportsStartTls = $false
        foreach ($line in $ehloResponse.Lines) {
            if ($line.Length -lt 4) { continue }
            $capability = $line.Substring(4).Trim()
            if ($capability -match '^(?i)STARTTLS(?:\s|$)') {
                $supportsStartTls = $true
                break
            }
        }

        if (-not $supportsStartTls) {
            throw [System.InvalidOperationException]::new('SMTP server does not advertise STARTTLS in EHLO response.')
        }

        Send-SmtpCommand -Stream $NetworkStream -Command 'STARTTLS'
        $startTlsResponse = Read-SmtpResponse -Stream $NetworkStream -ReadTimeoutMs $TimeoutMs
        if ($startTlsResponse.Code -ne 220) {
            throw [System.InvalidOperationException]::new("SMTP STARTTLS command was not accepted. Received: $($startTlsResponse.Message)")
        }
        Write-Verbose "[$fn] STARTTLS accepted with code $($startTlsResponse.Code)."

        [PSCustomObject]@{
            GreetingCode = $banner.Code
            EhloCode     = $ehloResponse.Code
            StartTlsCode = $startTlsResponse.Code
        }
    }
    catch {
        Write-Debug "[$fn] STARTTLS negotiation failed for EHLO name '$EhloName': $($_.Exception.GetType().FullName)"
        throw
    }
    finally {
        if ($timeoutsApplied) {
            try { $NetworkStream.ReadTimeout = $originalReadTimeout } catch {}
            try { $NetworkStream.WriteTimeout = $originalWriteTimeout } catch {}
        }
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
