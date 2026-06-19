function Close-TlsResource {
<#
.SYNOPSIS
    Safely disposes a single TLSleuth-owned resource.
#>
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Resource,

        [ValidateNotNullOrEmpty()]
        [string]$ResourceName = 'Resource',

        [AllowNull()]
        [AllowEmptyString()]
        [string]$OwnerName
    )

    $fn = if ([string]::IsNullOrWhiteSpace($OwnerName)) {
        $MyInvocation.MyCommand.Name
    }
    else {
        $OwnerName
    }

    if ($null -eq $Resource) {
        return
    }

    $resourceType = $Resource.GetType().FullName
    if ($Resource -isnot [System.IDisposable]) {
        Write-Debug "[$fn] $ResourceName is not disposable: $resourceType"
        return
    }

    try {
        $Resource.Dispose()
        Write-Verbose "[$fn] Disposed $ResourceName ($resourceType)"
    }
    catch {
        Write-Debug "[$fn] Failed to dispose $ResourceName ($resourceType): $($_.Exception.GetType().FullName)"
    }
}
