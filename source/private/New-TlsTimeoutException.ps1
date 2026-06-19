function New-TlsTimeoutException {
<#
.SYNOPSIS
    Creates a consistent timeout exception for TLSleuth operations.

.OUTPUTS
    System.TimeoutException
#>
    [CmdletBinding()]
    [OutputType([System.TimeoutException])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Operation,

        [Parameter(Mandatory)]
        [ValidateRange(1,600000)]
        [int]$TimeoutMs,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$Hostname,

        [ValidateRange(0,65535)]
        [int]$Port = 0,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$TargetHost,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$Transport,

        [AllowNull()]
        [System.Exception]$InnerException
    )

    $contextParts = [System.Collections.Generic.List[string]]::new()
    if (-not [string]::IsNullOrWhiteSpace($Hostname)) {
        if ($Port -gt 0) {
            $contextParts.Add("endpoint=$($Hostname):$Port")
        }
        else {
            $contextParts.Add("hostname=$Hostname")
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($TargetHost)) {
        $contextParts.Add("targetHost=$TargetHost")
    }

    if (-not [string]::IsNullOrWhiteSpace($Transport)) {
        $contextParts.Add("transport=$Transport")
    }

    $message = "$Operation timed out after ${TimeoutMs}ms."
    if ($contextParts.Count -gt 0) {
        $message = "$message Context: $($contextParts -join ', ')."
    }

    if ($InnerException) {
        return [System.TimeoutException]::new($message, $InnerException)
    }

    [System.TimeoutException]::new($message)
}
