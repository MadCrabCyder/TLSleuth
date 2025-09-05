# Tests for test-only helper: New-TestCertificate
# Keep these lightweight. Purpose: catch runtime regressions, not to deeply validate crypto.

# Discovery vs run note:
# Only simple flags in BeforeDiscovery. Create [Type]s in BeforeAll.
BeforeDiscovery {
    # Detect if SubjectAlternativeNameBuilder exists on this runtime
    try {
        [void][System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]
        $Script:HasSANBuilder = $true
    } catch {
        $Script:HasSANBuilder = $false
    }
}

BeforeAll {
    # Locate helpers folder next to this test file
    $scriptRoot = $PSScriptRoot
    if (-not $scriptRoot) {
        if ($PSCommandPath) { $scriptRoot = Split-Path -Parent $PSCommandPath }
        elseif ($MyInvocation.MyCommand.Path) { $scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path }
        else { throw "Cannot determine script root. Run with -Path." }
    }
    $helpersPath = Join-Path $scriptRoot '.'
    # support .../tests/Helpers layout as well
    if (-not (Test-Path (Join-Path $helpersPath 'New-TestCertificate.ps1'))) {
        $helpersPath = $scriptRoot
    }

    . (Join-Path $helpersPath 'New-TestCertificate.ps1')

    # Types for run-time assertions
    $Script:CertType = [System.Security.Cryptography.X509Certificates.X509Certificate2]
}

Describe 'New-TestCertificate (test helper)' {
    It 'creates a valid in-memory X509Certificate2 without SANs' {
        $nb = [DateTimeOffset]::UtcNow.AddDays(-2)
        $na = $nb.AddYears(1)

        $cert = New-TestCertificate -SubjectCN 'NoSAN' -NotBefore $nb -NotAfter $na

        $cert | Should -BeOfType $Script:CertType
        $cert.Subject | Should -Match 'CN=NoSAN'
        # Validity matches inputs (to the minute; avoid flakiness with rounding)
        [DateTimeOffset]$cert.NotBefore.ToUniversalTime() | Should -BeLessOrEqual $nb.AddMinutes(1)
        [DateTimeOffset]$cert.NotAfter.ToUniversalTime()  | Should -BeGreaterOrEqual $na.AddMinutes(-1)
    }

    It 'adds DNS SANs when SAN builder is available' -Skip:(-not $Script:HasSANBuilder) {
        $dns  = @('example.com','api.example.com')
        $cert = New-TestCertificate -SubjectCN 'WithSAN' -DnsNames $dns

        # Parse SAN extension using AsnEncodedData like production code would
        $sanOid = '2.5.29.17'
        $ext = $cert.Extensions | Where-Object { $_.Oid.Value -eq $sanOid } | Select-Object -First 1
        $ext | Should -Not -BeNullOrEmpty

        $data = [System.Security.Cryptography.AsnEncodedData]::new($ext.Oid, $ext.RawData)
        $txt  = $data.Format($true)

        (
            $txt -split '(,|\r?\n)' |
                ForEach-Object {
                    $line = $_.Trim()
                    if ($line -match 'DNS Name\=(.+)$') { $Matches[1].Trim() }
                    elseif ($line -match 'DNS:(.+)$')   { $Matches[1].Trim() }
                } |
                Where-Object { $_ } |
                Select-Object -Unique |
                Sort-Object
        ) | Should -Be (@($dns | Sort-Object))
    }

    It 'accepts and trims messy DNS names when SAN builder is available' -Skip:(-not $Script:HasSANBuilder) {
        $dns  = @('  www.example.com  ', 'www.example.com', "`tapi.example.com")
        $cert = New-TestCertificate -SubjectCN 'TrimSAN' -DnsNames $dns

        $sanOid = '2.5.29.17'
        $ext = $cert.Extensions | Where-Object { $_.Oid.Value -eq $sanOid } | Select-Object -First 1
        $ext | Should -Not -BeNullOrEmpty

        $data  = [System.Security.Cryptography.AsnEncodedData]::new($ext.Oid, $ext.RawData)
        $txt   = $data.Format($true)

        (
            $txt -split '(,|\r?\n)' |
                ForEach-Object {
                    $line = $_.Trim()
                    if ($line -match 'DNS Name\=(.+)$') { $Matches[1].Trim() }
                    elseif ($line -match 'DNS:(.+)$')   { $Matches[1].Trim() }
                } |
                Where-Object { $_ } |
                Select-Object -Unique |
                Sort-Object
        ) | Should -Be (@('www.example.com','api.example.com' | Sort-Object))

    }
}
