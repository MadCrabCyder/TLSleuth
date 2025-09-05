function Format-ChainStatusStrings {
<#
.SYNOPSIS
    Converts X509ChainStatus[] into human-readable strings.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509ChainStatus[]]$ChainStatus
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Count=$($ChainStatus?.Count))"
    try {
        if (-not $ChainStatus -or $ChainStatus.Count -eq 0) { return ,@() }
        ,@(
            foreach ($s in $ChainStatus) {
                "{0}: {1}" -f $s.Status, ($s.StatusInformation.Trim())
            }
        )
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
