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

    function Read-SmtpResponse {
        param(
            [Parameter(Mandatory)]
            [System.IO.Stream]$Stream,

            [Parameter(Mandatory)]
            [int]$ReadTimeoutMs
        )

        $lines = [System.Collections.Generic.List[string]]::new()
        $firstLine = Read-TextProtocolLine -Stream $Stream -ReadTimeoutMs $ReadTimeoutMs -ProtocolName 'SMTP'
        $lines.Add($firstLine)

        $statusCode = 0
        if ($firstLine.Length -lt 3 -or -not [int]::TryParse($firstLine.Substring(0, 3), [ref]$statusCode)) {
            throw [System.InvalidOperationException]::new("Invalid SMTP response line: '$firstLine'")
        }

        $statusPrefix = '{0:D3}' -f $statusCode
        $isMultiline = ($firstLine.Length -ge 4 -and $firstLine[3] -eq '-')

        if ($isMultiline) {
            while ($true) {
                $line = Read-TextProtocolLine -Stream $Stream -ReadTimeoutMs $ReadTimeoutMs -ProtocolName 'SMTP'
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

    try {
        Invoke-WithStreamTimeout -Stream $NetworkStream -TimeoutMs $TimeoutMs -ScriptBlock {
            $banner = Read-SmtpResponse -Stream $NetworkStream -ReadTimeoutMs $TimeoutMs
            if ($banner.Code -ne 220) {
                throw [System.InvalidOperationException]::new("SMTP server did not return 220 greeting. Received: $($banner.Message)")
            }
            Write-Verbose "[$fn] Received SMTP greeting code $($banner.Code)."

            Send-TextProtocolCommand -Stream $NetworkStream -Command "EHLO $EhloName"
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

            Send-TextProtocolCommand -Stream $NetworkStream -Command 'STARTTLS'
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
    }
    catch {
        Write-Debug "[$fn] STARTTLS negotiation failed for EHLO name '$EhloName': $($_.Exception.GetType().FullName)"
        throw
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
