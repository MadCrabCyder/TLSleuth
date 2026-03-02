function Invoke-WithStreamTimeout {
<#
.SYNOPSIS
    Temporarily applies stream read/write timeouts while invoking a script block.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.Stream]$Stream,

        [Parameter(Mandatory)]
        [ValidateRange(1000,600000)]
        [int]$TimeoutMs,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [scriptblock]$ScriptBlock
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (CanTimeout=$($Stream.CanTimeout), TimeoutMs=$TimeoutMs)"

    $originalReadTimeout = $null
    $originalWriteTimeout = $null
    $timeoutsApplied = $false

    try {
        if ($Stream.CanTimeout) {
            $originalReadTimeout = $Stream.ReadTimeout
            $originalWriteTimeout = $Stream.WriteTimeout

            $Stream.ReadTimeout = $TimeoutMs
            $Stream.WriteTimeout = $TimeoutMs
            $timeoutsApplied = $true
        }

        & $ScriptBlock
    }
    finally {
        if ($timeoutsApplied) {
            try { $Stream.ReadTimeout = $originalReadTimeout } catch {}
            try { $Stream.WriteTimeout = $originalWriteTimeout } catch {}
        }

        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
