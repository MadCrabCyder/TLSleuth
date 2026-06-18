function Send-BinaryProtocolData {
<#
.SYNOPSIS
    Writes binary protocol bytes to a stream.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.Stream]$Stream,

        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [byte[]]$Bytes,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000,

        [ValidateNotNullOrEmpty()]
        [string]$ProtocolName = 'Binary'
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Protocol=$ProtocolName, Length=$($Bytes.Length), TimeoutMs=$TimeoutMs)"

    try {
        if (-not $Stream.CanWrite) {
            throw [System.InvalidOperationException]::new("$ProtocolName binary write requires a writable stream.")
        }

        Invoke-WithStreamTimeout -Stream $Stream -TimeoutMs $TimeoutMs -ScriptBlock {
            $Stream.Write($Bytes, 0, $Bytes.Length)
            $Stream.Flush()
        }
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
