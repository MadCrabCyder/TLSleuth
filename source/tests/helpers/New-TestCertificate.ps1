function New-TestCertificate {
    [CmdletBinding()]
    param(
        [string]$SubjectCN = 'TEST',
        [string[]]$DnsNames,
        [Nullable[DateTimeOffset]]$NotBefore,
        [Nullable[DateTimeOffset]]$NotAfter,
        [switch]$ServerAuth,   # add Server Authentication EKU
        [switch]$ClientAuth    # optional: client auth EKU
    )

    $nb = if ($NotBefore) { $NotBefore } else { [DateTimeOffset]::UtcNow.AddDays(-1) }
    $na = if ($NotAfter)  { $NotAfter  } else { $nb.AddYears(1) }

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)

    $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        "CN=$SubjectCN",
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )

    # Basic constraints & key usage
    $req.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false,$false,0,$true)
    )
    $req.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            ([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature `
             -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment),
            $true
        )
    )

    # EKU: ServerAuth / ClientAuth as requested (ServerAuth is key for SslStream server)
    if ($ServerAuth -or $ClientAuth) {
        $oids = New-Object System.Security.Cryptography.OidCollection
        if ($ServerAuth) { [void]$oids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.1','Server Authentication')) }
        if ($ClientAuth) { [void]$oids.Add([System.Security.Cryptography.Oid]::new('1.3.6.1.5.5.7.3.2','Client Authentication')) }
        $eku = [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids,$false)
        $req.CertificateExtensions.Add($eku)
    }

    # SANs (recommended for hostname matching)
    if ($DnsNames -and $DnsNames.Count -gt 0) {
        try {
            $san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
            foreach ($dns in $DnsNames) {
                if ([string]::IsNullOrWhiteSpace($dns)) { continue }
                $san.AddDnsName($dns.Trim())
            }
            $req.CertificateExtensions.Add($san.Build())
        } catch {
            # older runtimes w/o SAN builder: continue without SAN
        }
    }

    $cert = $req.CreateSelfSigned($nb, $na)
    return $cert
}
