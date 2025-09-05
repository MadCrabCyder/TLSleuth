function Get-CDPUrls {
<#
.SYNOPSIS
    Extracts CRL Distribution Point (CDP) URLs from a certificate.
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
        $oid = '2.5.29.31'
        $ext = $Cert.Extensions | Where-Object { $_.Oid.Value -eq $oid } | Select-Object -First 1
        if (-not $ext) { return ,@() }
        try {
            $data = [System.Security.Cryptography.AsnEncodedData]::new($ext.Oid, $ext.RawData)
            $txt  = $data.Format($true)
            $uris =
                ($txt -split '(,|\r?\n)') |
                Where-Object { $_ -match '(http|ldap)s?://' } |
                ForEach-Object { $_.Trim() } |
                Select-Object -Unique
            if ($uris) { return ,@($uris) } else { return ,@() }
        } catch {
            return ,@()
        }
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
