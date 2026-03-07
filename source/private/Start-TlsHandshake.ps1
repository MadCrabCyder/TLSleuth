function Start-TlsHandshake {
<#
.SYNOPSIS
    Starts a TLS handshake on an existing network stream.

.OUTPUTS
    System.Net.Security.SslStream
#>
    [CmdletBinding()]
    [OutputType([System.Net.Security.SslStream])]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNull()]
        [psobject]$Connection,

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
    $handshakeSucceeded = $false

    $networkStream = $null
    if ($Connection.PSObject.Properties['NetworkStream']) {
        $networkStream = $Connection.NetworkStream
    }
    if ($null -eq $networkStream) {
        throw [System.InvalidOperationException]::new('Connection context must include a non-null NetworkStream.')
    }

    if (-not ('TLSleuth.CertificateValidationCallbacksV2' -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace TLSleuth
{
    public sealed class CertificateValidationStateV2
    {
        public SslPolicyErrors PolicyErrors { get; set; }
        public string[] ChainStatus { get; set; } = new string[0];
    }

    internal sealed class CertificateValidationOptionsV2
    {
        public bool SkipValidation { get; set; }
    }

    public static class CertificateValidationCallbacksV2
    {
        private static readonly ConditionalWeakTable<object, CertificateValidationOptionsV2> OptionsBySender =
            new ConditionalWeakTable<object, CertificateValidationOptionsV2>();
        private static readonly ConditionalWeakTable<object, CertificateValidationStateV2> StateBySender =
            new ConditionalWeakTable<object, CertificateValidationStateV2>();

        public static void Register(object sender, bool skipValidation)
        {
            if (sender == null)
            {
                return;
            }

            OptionsBySender.Remove(sender);
            StateBySender.Remove(sender);
            OptionsBySender.Add(sender, new CertificateValidationOptionsV2 { SkipValidation = skipValidation });
        }

        public static CertificateValidationStateV2 GetState(object sender)
        {
            if (sender == null)
            {
                return null;
            }

            CertificateValidationStateV2 state;
            return StateBySender.TryGetValue(sender, out state) ? state : null;
        }

        public static void Cleanup(object sender)
        {
            if (sender == null)
            {
                return;
            }

            OptionsBySender.Remove(sender);
            StateBySender.Remove(sender);
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

            if (sender != null)
            {
                StateBySender.Remove(sender);
                StateBySender.Add(sender, new CertificateValidationStateV2
                {
                    PolicyErrors = sslPolicyErrors,
                    ChainStatus = chainStatuses.ToArray()
                });

                CertificateValidationOptionsV2 options;
                var skipValidation = OptionsBySender.TryGetValue(sender, out options) &&
                                     options != null &&
                                     options.SkipValidation;

                return skipValidation || sslPolicyErrors == SslPolicyErrors.None;
            }

            return sslPolicyErrors == SslPolicyErrors.None;
        }
    }
}
"@
    }

    try {
        $ssl = [System.Net.Security.SslStream]::new(
            $networkStream,
            $false,
            [System.Net.Security.RemoteCertificateValidationCallback][TLSleuth.CertificateValidationCallbacksV2]::CaptureAndValidate
        )

        if ($Connection.PSObject.Properties['SslStream']) {
            $Connection.SslStream = $ssl
        }
        else {
            $Connection | Add-Member -NotePropertyName 'SslStream' -NotePropertyValue $ssl
        }

        [TLSleuth.CertificateValidationCallbacksV2]::Register($ssl, [bool]$SkipCertificateValidation)

        $task = $ssl.AuthenticateAsClientAsync($TargetHost, $null, $SslProtocols, $false)

        if (-not $task.Wait($TimeoutMs)) {
            throw [System.TimeoutException]::new("TLS handshake timeout after ${TimeoutMs}ms for $TargetHost")
        }

        Write-Verbose "[$fn] Handshake succeeded (Protocol=$($ssl.SslProtocol), Cipher=$($ssl.CipherAlgorithm), Strength=$($ssl.CipherStrength))."
        $handshakeSucceeded = $true
        $ssl
    }
    catch {
        Write-Debug "[$fn] Handshake failed for ${TargetHost}: $($_.Exception.GetType().FullName)"
        try {
            if ($ssl) {
                [TLSleuth.CertificateValidationCallbacksV2]::Cleanup($ssl)
                $ssl.Dispose()
            }
        }
        catch {}

        $errorToThrow = $_.Exception
        if ($errorToThrow -is [System.AggregateException] -and $errorToThrow.InnerException) {
            throw $errorToThrow.InnerException
        }
        throw
    }
    finally {
        try {
            if (-not $handshakeSucceeded -and $ssl) {
                [TLSleuth.CertificateValidationCallbacksV2]::Cleanup($ssl)
            }
        }
        catch {}
        $sw.Stop()
        Write-Verbose "[$fn] Complete in $($sw.Elapsed)"
    }
}
