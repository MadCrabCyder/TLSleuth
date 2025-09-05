function New-TLSleuthCertificateReport {
<#
.SYNOPSIS
    Creates the final TLSleuth certificate report object.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Hostname,
        [Parameter(Mandatory)][int]$Port,
        [string]$ConnectedIp,
        [Parameter(Mandatory)][string]$SNI,
        [Parameter(Mandatory)][psobject]$Handshake,
        [Parameter(Mandatory)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [psobject]$ChainInfo,
        [System.Security.Cryptography.X509Certificates.X509Chain]$CapturedChain,
        [string[]]$ValidationErrors = @(),
        [string[]]$SANs = @(),
        [string[]]$AIA  = @(),
        [string[]]$CDP  = @()
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Host=$Hostname :$Port, Protocol=$($Handshake.Protocol))"
    try {
        $now = [DateTimeOffset]::UtcNow
        $pubKeyAlgo = $Certificate.PublicKey.Oid.FriendlyName
        $keySize    = $Certificate.PublicKey.Key.KeySize
        $sigAlgo    = $Certificate.SignatureAlgorithm.FriendlyName

        $isTrusted     = $null
        $chainSubjects = ,@()
        $chainStatus   = ,@()

        if ($ChainInfo) {
            $isTrusted     = $ChainInfo.IsTrusted
            $chainSubjects = $ChainInfo.ChainSubjects
            $chainStatus   = $ChainInfo.ChainStatus
        } elseif ($CapturedChain) {
            $isTrusted     = ($CapturedChain.ChainStatus.Count -eq 0)
            $chainSubjects = if ($CapturedChain.ChainElements) {
                ,@($CapturedChain.ChainElements | ForEach-Object { $_.Certificate.Subject })
            } else { ,@() }
            $chainStatus   = if ($CapturedChain.ChainStatus) { ,@($CapturedChain.ChainStatus) } else { ,@() }
        }

        $chainStatusStrings = if ($chainStatus) { Format-ChainStatusStrings -ChainStatus $chainStatus } else { ,@() }
        $keyExchange = if ($Handshake.KeyExchangeStrength) {
            "{0} ({1}-bit)" -f $Handshake.KeyExchangeAlgorithm, $Handshake.KeyExchangeStrength
        } else { $Handshake.KeyExchangeAlgorithm }

        Write-Verbose "[$fn] Hello from Report"
        [PSCustomObject]@{
            PSTypeName         = 'TLSleuth.CertificateReport'
            Host               = $Hostname
            Port               = $Port
            ConnectedIp        = $ConnectedIp
            SNI                = $SNI
            Protocol           = $Handshake.Protocol
            CipherSuite        = $Handshake.CipherSuite
            CipherStrengthBits = $Handshake.CipherStrengthBits
            HashAlgorithm      = $Handshake.HashAlgorithm
            KeyExchange        = $keyExchange
            Certificate        = [PSCustomObject]@{
                Subject            = $Certificate.Subject
                CommonName         = ($Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false))
                Issuer             = $Certificate.Issuer
                SerialNumber       = $Certificate.SerialNumber
                Thumbprint         = $Certificate.Thumbprint
                NotBefore          = $Certificate.NotBefore
                NotAfter           = $Certificate.NotAfter
                DaysUntilExpiry    = [int]([Math]::Floor(($Certificate.NotAfter.ToUniversalTime() - $now.UtcDateTime).TotalDays))
                SignatureAlgorithm = $sigAlgo
                PublicKeyAlgorithm = $pubKeyAlgo
                KeySize            = $keySize
                SANs               = @($SANs)
                AIA                = @($AIA)
                CRLDistribution    = @($CDP)
                IsSelfSigned       = Test-IsSelfSigned -Cert $Certificate
            }
            IsTrusted          = $isTrusted
            ChainSubjects      = $chainSubjects
            ChainStatus        = $chainStatusStrings
            ValidationErrors   = @($ValidationErrors | ForEach-Object { $_ })
            RawCertificate     = $Certificate
        }
    } catch {
        Write-Verbose "[$fn] Report failed: $($_.Exception.Message)"
    } finally {
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
