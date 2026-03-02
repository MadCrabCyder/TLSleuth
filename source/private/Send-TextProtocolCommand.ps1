function Send-TextProtocolCommand {
<#
.SYNOPSIS
    Sends one ASCII command line terminated with CRLF.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.Stream]$Stream,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Command
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Length=$($Command.Length))"

    try {
        $payload = [System.Text.Encoding]::ASCII.GetBytes("$Command`r`n")
        $Stream.Write($payload, 0, $payload.Length)
        $Stream.Flush()
        Write-Verbose "[$fn] Sent: $Command"
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
