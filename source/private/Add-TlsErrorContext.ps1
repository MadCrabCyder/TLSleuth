function Add-TlsErrorContext {
<#
.SYNOPSIS
    Adds TLSleuth operation context to an exception without changing its type.

.OUTPUTS
    System.Exception
#>
    [CmdletBinding()]
    [OutputType([System.Exception])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.Exception]$Exception,

        [Parameter(Mandatory)]
        [ValidateSet('Connection','TransportNegotiation','TlsHandshake','CertificateExtraction','BinaryProtocol')]
        [string]$Stage,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Operation,

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
        [string]$Transport
    )

    $values = [ordered]@{
        'TLSleuth.Stage'     = $Stage
        'TLSleuth.Operation' = $Operation
    }

    if (-not [string]::IsNullOrWhiteSpace($Hostname)) {
        $values['TLSleuth.Hostname'] = $Hostname
    }

    if ($Port -gt 0) {
        $values['TLSleuth.Port'] = $Port
    }

    if (-not [string]::IsNullOrWhiteSpace($TargetHost)) {
        $values['TLSleuth.TargetHost'] = $TargetHost
    }

    if (-not [string]::IsNullOrWhiteSpace($Transport)) {
        $values['TLSleuth.Transport'] = $Transport
    }

    foreach ($entry in $values.GetEnumerator()) {
        if ($Exception.Data.Contains($entry.Key)) {
            $Exception.Data[$entry.Key] = $entry.Value
        }
        else {
            $Exception.Data.Add($entry.Key, $entry.Value)
        }
    }

    $Exception
}
