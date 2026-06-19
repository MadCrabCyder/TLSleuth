function Resolve-SmtpEhloName {
<#
.SYNOPSIS
    Resolves the EHLO name used for SMTP STARTTLS negotiation.

.OUTPUTS
    System.String
#>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Options,

        [Parameter()]
        [ValidateNotNull()]
        [scriptblock]$HostNameResolver = { [System.Net.Dns]::GetHostName() }
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin"

    try {
        $ehloName = $null
        if ($Options.PSObject.Properties['SmtpStartTls'] -and
            $null -ne $Options.SmtpStartTls -and
            $Options.SmtpStartTls.PSObject.Properties['EhloName']) {
            $ehloName = $Options.SmtpStartTls.EhloName
        }
        elseif ($Options.PSObject.Properties['SmtpEhloName']) {
            $ehloName = $Options.SmtpEhloName
        }

        if ([string]::IsNullOrWhiteSpace($ehloName)) {
            $ehloName = & $HostNameResolver
            if ([string]::IsNullOrWhiteSpace($ehloName)) {
                $ehloName = 'localhost'
            }
        }

        Write-Verbose "[$fn] Resolved EHLO name '$ehloName'."
        $ehloName
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
