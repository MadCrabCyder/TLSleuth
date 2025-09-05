function Get-SslProtocolsEnum {
<#
.SYNOPSIS
    Maps string names to [System.Security.Authentication.SslProtocols] flags.

.DESCRIPTION
    Accepts names like 'SystemDefault','Tls12','Tls13' and returns the enum.
    'SystemDefault' maps to ::None to let .NET choose defaults.

.PARAMETER Names
    Array of protocol names.

.OUTPUTS
    System.Security.Authentication.SslProtocols
#>
[CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$Names
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Names=$($Names -join ','))"
    try {
        $enumType = [System.Security.Authentication.SslProtocols]
        if ($Names -contains 'SystemDefault' -and $Names.Count -eq 1) {
            return [System.Security.Authentication.SslProtocols]::None
        }

        $value = [System.Security.Authentication.SslProtocols]::None
        foreach ($n in $Names) {
            if ($n -eq 'SystemDefault') { continue }
            $value = $value -bor [System.Enum]::Parse($enumType, $n)
        }
        if ($value -eq [System.Security.Authentication.SslProtocols]::None) {
            return [System.Security.Authentication.SslProtocols]::None
        }
        return $value
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}