function Test-NegotiatedCipherSuiteSupport {
<#
.SYNOPSIS
    Detects whether .NET exposes SslStream.NegotiatedCipherSuite property.
#>
    [CmdletBinding()]
    param()

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin"
    try {
        try {
            $prop = [System.Net.Security.SslStream].GetProperty('NegotiatedCipherSuite')
            return [bool]$prop
        } catch {
            return $false
        }
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
