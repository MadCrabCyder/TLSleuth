function Get-CertificateSAN {
<#
.SYNOPSIS
    Returns DNS Subject Alternative Names from a certificate as an array (possibly empty).
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Thumbprint=$($Cert.Thumbprint))"
    try {
        # Prefer modern property when available
        $dnsProp = [System.Security.Cryptography.X509Certificates.X509Certificate2].GetProperty('DnsNameList')
        if ($dnsProp) {
            try {
                $val = $dnsProp.GetValue($Cert, $null)
                if ($val) {
                    $names = @($val) | ForEach-Object { $_.ToString().Trim() } |
                             Where-Object { $_ } | Select-Object -Unique
                    return ,@($names)
                }
            } catch { }
        }

        # Fallback: parse SAN extension text
        $sanOid = '2.5.29.17'
        $ext = $Cert.Extensions | Where-Object { $_.Oid.Value -eq $sanOid } | Select-Object -First 1
        if (-not $ext) { return ,@() }

        try {
            $data = New-Object System.Security.Cryptography.AsnEncodedData($ext.Oid, $ext.RawData)
            $txt  = $data.Format($true)
            $names =
                ($txt -split '(,|\r?\n)') |
                ForEach-Object {
                    $line = $_.Trim()
                    if ($line -match 'DNS Name\=(.+)$') { $Matches[1].Trim(); return }
                    if ($line -match 'DNS:(.+)$')       { $Matches[1].Trim(); return }
                } |
                Where-Object { $_ } |
                Sort-Object -Unique   # <- ensures deterministic order
            if ($names) { return ,@($names) } else { return ,@() }
        } catch {
            return ,@()
        }
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
