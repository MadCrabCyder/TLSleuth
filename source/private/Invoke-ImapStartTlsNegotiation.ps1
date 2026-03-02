function Invoke-ImapStartTlsNegotiation {
<#
.SYNOPSIS
    Performs IMAP STARTTLS negotiation over an existing plaintext stream.

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
        throw [System.InvalidOperationException]::new('IMAP STARTTLS negotiation requires a readable and writable stream.')
    }

    function Read-ImapTaggedResponse {
        param(
            [Parameter(Mandatory)]
            [System.IO.Stream]$Stream,

            [Parameter(Mandatory)]
            [ValidateNotNullOrEmpty()]
            [string]$Tag,

            [Parameter(Mandatory)]
            [int]$ReadTimeoutMs
        )

        $lines = [System.Collections.Generic.List[string]]::new()
        $completionLine = $null
        $status = $null

        while ($true) {
            $line = Read-TextProtocolLine -Stream $Stream -ReadTimeoutMs $ReadTimeoutMs -ProtocolName 'IMAP'
            $lines.Add($line)

            if ($line.StartsWith("$Tag ", [System.StringComparison]::OrdinalIgnoreCase)) {
                $completionLine = $line
                $tail = $line.Substring($Tag.Length).TrimStart()

                if ($tail -notmatch '^(?<status>[A-Za-z]+)(?:\s+(?<text>.*))?$') {
                    throw [System.InvalidOperationException]::new("Invalid IMAP tagged completion line: '$line'")
                }

                $status = $matches['status'].ToUpperInvariant()
                break
            }
        }

        [PSCustomObject]@{
            Tag            = $Tag
            Status         = $status
            Lines          = [string[]]$lines
            CompletionLine = $completionLine
            Message        = ($lines -join "`n")
        }
    }

    try {
        Invoke-WithStreamTimeout -Stream $NetworkStream -TimeoutMs $TimeoutMs -ScriptBlock {
            $greetingLine = Read-TextProtocolLine -Stream $NetworkStream -ReadTimeoutMs $TimeoutMs -ProtocolName 'IMAP'
            if ($greetingLine -notmatch '^\*\s+(?<status>[A-Za-z]+)\b') {
                throw [System.InvalidOperationException]::new("Invalid IMAP greeting line: '$greetingLine'")
            }

            $greetingStatus = $matches['status'].ToUpperInvariant()
            if ($greetingStatus -ne 'OK' -and $greetingStatus -ne 'PREAUTH') {
                throw [System.InvalidOperationException]::new("IMAP server did not return OK or PREAUTH greeting. Received: $greetingLine")
            }
            Write-Verbose "[$fn] Received IMAP greeting status $greetingStatus."

            $capabilityTag = 'A001'
            Send-TextProtocolCommand -Stream $NetworkStream -Command "$capabilityTag CAPABILITY"
            $capabilityResponse = Read-ImapTaggedResponse -Stream $NetworkStream -Tag $capabilityTag -ReadTimeoutMs $TimeoutMs
            if ($capabilityResponse.Status -ne 'OK') {
                throw [System.InvalidOperationException]::new("IMAP CAPABILITY command failed. Received: $($capabilityResponse.Message)")
            }
            Write-Verbose "[$fn] CAPABILITY completed with status $($capabilityResponse.Status)."

            $supportsStartTls = $false
            foreach ($line in $capabilityResponse.Lines) {
                if ($line -notmatch '^\*\s+CAPABILITY\s+(?<caps>.+)$') { continue }
                $capabilities = $matches['caps'].Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
                foreach ($capability in $capabilities) {
                    if ($capability.Equals('STARTTLS', [System.StringComparison]::OrdinalIgnoreCase)) {
                        $supportsStartTls = $true
                        break
                    }
                }
                if ($supportsStartTls) { break }
            }

            if (-not $supportsStartTls -and $capabilityResponse.CompletionLine -match '\[CAPABILITY\s+(?<caps>[^\]]+)\]') {
                $capsInCode = $matches['caps'].Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries)
                foreach ($capability in $capsInCode) {
                    if ($capability.Equals('STARTTLS', [System.StringComparison]::OrdinalIgnoreCase)) {
                        $supportsStartTls = $true
                        break
                    }
                }
            }

            if (-not $supportsStartTls) {
                throw [System.InvalidOperationException]::new('IMAP server does not advertise STARTTLS in CAPABILITY response.')
            }

            $startTlsTag = 'A002'
            Send-TextProtocolCommand -Stream $NetworkStream -Command "$startTlsTag STARTTLS"
            $startTlsResponse = Read-ImapTaggedResponse -Stream $NetworkStream -Tag $startTlsTag -ReadTimeoutMs $TimeoutMs
            if ($startTlsResponse.Status -ne 'OK') {
                throw [System.InvalidOperationException]::new("IMAP STARTTLS command was not accepted. Received: $($startTlsResponse.Message)")
            }
            Write-Verbose "[$fn] STARTTLS accepted with status $($startTlsResponse.Status)."

            [PSCustomObject]@{
                GreetingStatus   = $greetingStatus
                CapabilityStatus = $capabilityResponse.Status
                StartTlsStatus   = $startTlsResponse.Status
            }
        }
    }
    catch {
        Write-Debug "[$fn] STARTTLS negotiation failed: $($_.Exception.GetType().FullName)"
        throw
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
