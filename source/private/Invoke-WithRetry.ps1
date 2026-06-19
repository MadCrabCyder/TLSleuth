function Invoke-WithRetry {
<#
.SYNOPSIS
    Runs a script block with bounded retry behavior.

.DESCRIPTION
    Invoke-WithRetry runs a script block and retries it when the script block
    throws one of the configured exception types. Retry matching includes
    derived exception types, so configuring a base type such as
    System.IO.IOException also retries exceptions that inherit from it.

    The function returns the script block output from the first successful
    attempt. If all attempts fail, or the exception type is not configured for
    retry, the original exception is rethrown.

.EXAMPLE
    $attempt = 0

    Invoke-WithRetry -MaxAttempts 3 -DelayMs 100 -ScriptBlock {
        $attempt++

        if ($attempt -lt 3) {
            throw [System.TimeoutException]::new('Temporary timeout.')
        }

        'success'
    }

    Retries a transient timeout and returns success on the third attempt.

.EXAMPLE
    Invoke-WithRetry -MaxAttempts 5 -DelayMs 250 -RetryOnExceptionType @(
        'System.IO.IOException'
    ) -ScriptBlock {
        [System.IO.File]::ReadAllText('C:\Temp\input.txt')
    }

    Retries IO failures, including exception types derived from
    System.IO.IOException.

.EXAMPLE
    Invoke-WithRetry -MaxAttempts 3 -DelayMs 500 -RetryOnExceptionType @(
        'System.Net.Http.HttpRequestException',
        'System.Net.WebException',
        'System.TimeoutException'
    ) -ScriptBlock {
        Invoke-RestMethod -Uri 'https://example.com' -TimeoutSec 10
    }

    Retries transient web request failures while calling Invoke-RestMethod.

.EXAMPLE
    Invoke-WithRetry -MaxAttempts 3 -DelayMs 0 -RetryOnExceptionType @(
        'System.TimeoutException'
    ) -ScriptBlock {
        throw [System.InvalidOperationException]::new('Fatal error.')
    }

    Does not retry because InvalidOperationException is not in the configured
    retry exception type list.

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
        $retryExceptionTypes = @(
            foreach ($typeName in $RetryOnExceptionType) {
                $type = $typeName -as [type]
                if ($null -eq $type) {
                    throw [System.ArgumentException]::new("Retry exception type '$typeName' could not be resolved.")
                }

                if (-not [System.Exception].IsAssignableFrom($type)) {
                    throw [System.ArgumentException]::new("Retry exception type '$typeName' must derive from System.Exception.")
                }

                $type
            }
        )

        $attempt = 0
        while ($true) {
            $attempt++
            try {
                Write-Verbose "[$fn] Attempt $attempt of $MaxAttempts."
                return & $ScriptBlock
            }
            catch {
                $exceptionType = $_.Exception.GetType().FullName
                $isRetryableException = $false
                foreach ($retryExceptionType in $retryExceptionTypes) {
                    if ($retryExceptionType.IsInstanceOfType($_.Exception)) {
                        $isRetryableException = $true
                        break
                    }
                }

                $canRetry = ($attempt -lt $MaxAttempts) -and $isRetryableException
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
