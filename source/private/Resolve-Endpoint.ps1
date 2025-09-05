function Resolve-Endpoint {
<#
.SYNOPSIS
    Best-effort DNS resolution of a host to an IP address.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Hostname
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Hostname=$Hostname)"
    try {
        try {
            $ips = [System.Net.Dns]::GetHostAddresses($Hostname)
            $ip = if ($ips -and $ips.Length -gt 0) { $ips[0] } else { $null }
            if ($ip) { Write-Verbose "[$fn] Resolved $Hostname -> $ip" }
            return $ip
        } catch {
            Write-Verbose "[$fn] Resolution failed: $($_.Exception.Message)"
            return $null
        }
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
