function New-TlsOperationContext {
<#
.SYNOPSIS
    Builds normalized per-target TLS command options.

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

        [AllowNull()]
        [AllowEmptyString()]
        [string]$TargetHost,

        [Parameter(Mandatory)]
        [ValidateSet('ImplicitTls','SmtpStartTls','ImapStartTls','Pop3StartTls')]
        [string]$Transport,

        [AllowNull()]
        [AllowEmptyString()]
        [string]$SmtpEhloName,

        [ValidateRange(1,600)]
        [int]$TimeoutSec = 10
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Target=$($Hostname):$($Port), Transport=$Transport, TimeoutSec=$TimeoutSec)"

    try {
        $resolvedTargetHost = if ([string]::IsNullOrWhiteSpace($TargetHost)) { $Hostname } else { $TargetHost }
        $timeoutMs = $TimeoutSec * 1000

        $transportOptions = New-TlsTransportOptionSet `
            -Transport $Transport `
            -TimeoutMs $timeoutMs `
            -SmtpEhloName $SmtpEhloName

        [PSCustomObject]@{
            Hostname         = $Hostname
            Port             = $Port
            TargetHost       = $resolvedTargetHost
            Transport        = $Transport
            TimeoutSec       = $TimeoutSec
            TimeoutMs        = $timeoutMs
            TransportOptions = $transportOptions
        }
    }
    finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
