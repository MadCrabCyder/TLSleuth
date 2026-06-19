function Resolve-TlsTimeoutMs {
<#
.SYNOPSIS
    Resolves timeout milliseconds from normalized or legacy transport options.

.OUTPUTS
    System.Int32
#>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Options,

        [ValidateRange(1000,600000)]
        [int]$DefaultTimeoutMs = 10000
    )

    if ($Options.PSObject.Properties['Common'] -and
        $null -ne $Options.Common -and
        $Options.Common.PSObject.Properties['TimeoutMs']) {
        return [int]$Options.Common.TimeoutMs
    }

    if ($Options.PSObject.Properties['TimeoutMs']) {
        return [int]$Options.TimeoutMs
    }

    $DefaultTimeoutMs
}
