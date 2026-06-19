function Test-TlsTimeoutException {
<#
.SYNOPSIS
    Detects timeout exceptions, including socket timeouts wrapped by IO exceptions.

.OUTPUTS
    System.Boolean
#>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Exception]$Exception
    )

    $current = $Exception
    while ($current) {
        if ($current -is [System.TimeoutException]) {
            return $true
        }

        if ($current -is [System.Net.Sockets.SocketException] -and
            $current.SocketErrorCode -eq [System.Net.Sockets.SocketError]::TimedOut) {
            return $true
        }

        $current = $current.InnerException
    }

    $false
}
