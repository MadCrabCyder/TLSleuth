function Invoke-WithRetry {
<#
.SYNOPSIS
    Invokes a script block with bounded retry behavior for transient operations.

.OUTPUTS
    Any output from the script block.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock,

        [ValidateRange(1,10)]
        [int]$MaxAttempts = 3,

        [ValidateRange(0,60000)]
        [int]$DelayMs = 250,

        [string[]]$RetryOnExceptionType = @(
            'System.TimeoutException',
            'System.Net.Sockets.SocketException',
            'System.IO.IOException'
        )
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (MaxAttempts=$MaxAttempts, DelayMs=$DelayMs)"

    try {
        $attempt = 0
        while ($true) {
            $attempt++
            try {
                Write-Verbose "[$fn] Attempt $attempt of $MaxAttempts."
                return & $ScriptBlock
            }
            catch {
                $exceptionType = $_.Exception.GetType().FullName
                $canRetry = ($attempt -lt $MaxAttempts) -and ($RetryOnExceptionType -contains $exceptionType)
                if (-not $canRetry) {
                    Write-Verbose "[$fn] Stopping retries after $exceptionType on attempt $attempt."
                    throw
                }

                Write-Verbose "[$fn] Retrying after $exceptionType (attempt $attempt of $MaxAttempts)."
                Write-Debug "[$fn] Retrying after $exceptionType (attempt $attempt of $MaxAttempts)."
                if ($DelayMs -gt 0) {
                    Start-Sleep -Milliseconds $DelayMs
                }
            }
        }
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
