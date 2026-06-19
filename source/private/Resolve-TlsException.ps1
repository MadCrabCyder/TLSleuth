function Resolve-TlsException {
<#
.SYNOPSIS
    Unwraps common PowerShell and task wrapper exceptions to the actionable TLSleuth failure.

.OUTPUTS
    System.Exception
#>
    [CmdletBinding()]
    [OutputType([System.Exception])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Exception]$Exception
    )

    $current = $Exception
    while ($current) {
        if ($current -is [System.Management.Automation.MethodInvocationException] -and $current.InnerException) {
            $current = $current.InnerException
            continue
        }

        if ($current -is [System.Reflection.TargetInvocationException] -and $current.InnerException) {
            $current = $current.InnerException
            continue
        }

        if ($current -is [System.AggregateException]) {
            $flattened = $current.Flatten()
            if ($flattened.InnerExceptions.Count -eq 1) {
                $current = $flattened.InnerExceptions[0]
                continue
            }
        }

        break
    }

    $current
}
