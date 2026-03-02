function Start-TlsHandshake {
<#
.SYNOPSIS
    Starts a TLS handshake on an existing network stream.

.OUTPUTS
    PSCustomObject {
        SslStream, NegotiatedProtocol, CipherAlgorithm, CipherStrength,
        CertificateValidationPassed, CertificatePolicyErrors, CertificatePolicyErrorFlags, CertificateChainStatus
    }
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [System.IO.Stream]$NetworkStream,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$TargetHost,

        [Parameter(Mandatory)]
        [System.Security.Authentication.SslProtocols]$SslProtocols,

        [ValidateRange(1000,600000)]
        [int]$TimeoutMs = 10000,

        [switch]$SkipCertificateValidation
    )

    $fn = $MyInvocation.MyCommand.Name
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    Write-Verbose "[$fn] Begin (Target=$TargetHost, Protocols=$SslProtocols, TimeoutMs=$TimeoutMs, SkipValidation=$SkipCertificateValidation)"
    $ssl = $null

    if (-not ('TLSleuth.CertificateValidationCallbacksV2' -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;

namespace TLSleuth
{
    public sealed class CertificateValidationStateV2
    {
        public SslPolicyErrors PolicyErrors { get; set; }
        public string[] ChainStatus { get; set; } = new string[0];
    }

    public static class CertificateValidationCallbacksV2
    {
        private static readonly ConcurrentDictionary<int, bool> SkipValidationBySender = new ConcurrentDictionary<int, bool>();
        private static readonly ConcurrentDictionary<int, CertificateValidationStateV2> StateBySender = new ConcurrentDictionary<int, CertificateValidationStateV2>();

        private static int GetSenderId(object sender)
        {
            return sender == null ? 0 : RuntimeHelpers.GetHashCode(sender);
        }

        public static void Register(object sender, bool skipValidation)
        {
            var id = GetSenderId(sender);
            SkipValidationBySender[id] = skipValidation;
            CertificateValidationStateV2 removed;
            StateBySender.TryRemove(id, out removed);
        }

        public static CertificateValidationStateV2 GetState(object sender)
        {
            var id = GetSenderId(sender);
            CertificateValidationStateV2 state;
            StateBySender.TryGetValue(id, out state);
            return state;
        }

        public static void Cleanup(object sender)
        {
            var id = GetSenderId(sender);
            bool removedSkip;
            SkipValidationBySender.TryRemove(id, out removedSkip);
            CertificateValidationStateV2 removedState;
            StateBySender.TryRemove(id, out removedState);
        }

        public static bool CaptureAndValidate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            var chainStatuses = new List<string>();
            if (chain != null && chain.ChainStatus != null)
            {
                foreach (var status in chain.ChainStatus)
                {
                    if (status.Status != X509ChainStatusFlags.NoError)
                    {
                        chainStatuses.Add(status.Status.ToString());
                    }
                }
            }

            var id = GetSenderId(sender);
            StateBySender[id] = new CertificateValidationStateV2
            {
                PolicyErrors = sslPolicyErrors,
                ChainStatus = chainStatuses.ToArray()
            };

            bool skipValidation;
            if (!SkipValidationBySender.TryGetValue(id, out skipValidation))
            {
                skipValidation = false;
            }

            return skipValidation || sslPolicyErrors == SslPolicyErrors.None;
        }
    }
}
"@
    }

    try {
        $ssl = [System.Net.Security.SslStream]::new(
            $NetworkStream,
            $false,
            [System.Net.Security.RemoteCertificateValidationCallback][TLSleuth.CertificateValidationCallbacksV2]::CaptureAndValidate
        )

        [TLSleuth.CertificateValidationCallbacksV2]::Register($ssl, [bool]$SkipCertificateValidation)

        $task = $ssl.AuthenticateAsClientAsync($TargetHost, $null, $SslProtocols, $false)

        if (-not $task.Wait($TimeoutMs)) {
            throw [System.TimeoutException]::new("TLS handshake timeout after ${TimeoutMs}ms for $TargetHost")
        }

        $validationState = [TLSleuth.CertificateValidationCallbacksV2]::GetState($ssl)
        $policyErrors = [System.Net.Security.SslPolicyErrors]::None
        $chainStatus = [string[]]@()
        if ($validationState) {
            $policyErrors = $validationState.PolicyErrors
            $chainStatus = [string[]]$validationState.ChainStatus
        }

        $policyErrorFlags = [System.Collections.Generic.List[string]]::new()
        if (($policyErrors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNotAvailable) -ne 0) {
            $policyErrorFlags.Add('RemoteCertificateNotAvailable')
        }
        if (($policyErrors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateNameMismatch) -ne 0) {
            $policyErrorFlags.Add('RemoteCertificateNameMismatch')
        }
        if (($policyErrors -band [System.Net.Security.SslPolicyErrors]::RemoteCertificateChainErrors) -ne 0) {
            $policyErrorFlags.Add('RemoteCertificateChainErrors')
        }

        $validationPassed = ($policyErrors -eq [System.Net.Security.SslPolicyErrors]::None)

        Write-Verbose "[$fn] Handshake succeeded (Protocol=$($ssl.SslProtocol), Cipher=$($ssl.CipherAlgorithm), Strength=$($ssl.CipherStrength), ValidationPassed=$validationPassed, PolicyErrors=$policyErrors)."
        [PSCustomObject]@{
            SslStream                    = $ssl
            NegotiatedProtocol           = $ssl.SslProtocol
            CipherAlgorithm              = $ssl.CipherAlgorithm
            CipherStrength               = $ssl.CipherStrength
            CertificateValidationPassed  = $validationPassed
            CertificatePolicyErrors      = $policyErrors
            CertificatePolicyErrorFlags  = [string[]]$policyErrorFlags
            CertificateChainStatus       = [string[]]$chainStatus
        }
    }
    catch {
        Write-Debug "[$fn] Handshake failed for ${TargetHost}: $($_.Exception.GetType().FullName)"
        try { if ($ssl) { $ssl.Dispose() } } catch {}

        $errorToThrow = $_.Exception
        if ($errorToThrow -is [System.AggregateException] -and $errorToThrow.InnerException) {
            throw $errorToThrow.InnerException
        }
        throw
    }
    finally {
        try {
            if ($ssl) {
                [TLSleuth.CertificateValidationCallbacksV2]::Cleanup($ssl)
            }
        }
        catch {}
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
