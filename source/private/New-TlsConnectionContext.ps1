function New-TlsConnectionContext {
<#
.SYNOPSIS
    Opens a TCP connection and prepares the shared TLSleuth connection context.

.OUTPUTS
    PSCustomObject
#>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Hostname,

        [Parameter(Mandatory)]
        [ValidateRange(1,65535)]
        [int]$Port,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Target=$($Hostname):$($Port), TimeoutMs=$TimeoutMs)"

    try {
        $connection = Invoke-WithRetry -ScriptBlock {
            Connect-TcpWithTimeout -Hostname $Hostname -Port $Port -TimeoutMs $TimeoutMs
        }

        if ($null -eq $connection) {
            throw [System.InvalidOperationException]::new('TCP connection helper returned a null connection context.')
        }

        if (-not $connection.PSObject.Properties['SslStream']) {
            $connection | Add-Member -NotePropertyName 'SslStream' -NotePropertyValue $null
        }

        $connection
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
