function Read-TextProtocolLine {
<#
.SYNOPSIS
    Reads one ASCII CRLF-terminated line from a text protocol stream.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.Stream]$Stream,

        [Parameter(Mandatory)]
        [ValidateRange(1,600000)]
        [int]$ReadTimeoutMs,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$ProtocolName,

        [ValidateRange(1,65535)]
        [int]$MaxLineBytes = 4096
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Protocol=$ProtocolName, TimeoutMs=$ReadTimeoutMs, MaxLineBytes=$MaxLineBytes)"

    try {
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
                    throw [System.TimeoutException]::new("$ProtocolName negotiation timed out after ${ReadTimeoutMs}ms.")
                }
                throw
            }

            if ($read -eq 0) {
                throw [System.IO.EndOfStreamException]::new("$ProtocolName server closed the connection unexpectedly.")
            }

            $b = $buffer[0]
            if ($b -eq 10) {
                break
            }

            if ($b -ne 13) {
                $bytes.Add($b)
            }

            if ($bytes.Count -gt $MaxLineBytes) {
                throw [System.InvalidOperationException]::new("$ProtocolName response line exceeded $MaxLineBytes bytes.")
            }
        }

        $line = [System.Text.Encoding]::ASCII.GetString($bytes.ToArray())
        Write-Verbose "[$fn] Read: $line"

        $line
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
