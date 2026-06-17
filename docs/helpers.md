# Helper Functions

This file lists helper functions in source/private, what they do, and their parameters.

## Close-NetworkResources

- Synopsis: Safely disposes network resources used during TLS operations.
- File: source/private/Close-NetworkResources.ps1
- Signature: Close-NetworkResources([PSObject]$Connection)

| Parameter | Type | Default |
|---|---|---|
| $Connection | PSObject | - |

## Connect-TcpWithTimeout

- Synopsis: Opens a TcpClient and connects with a timeout.
- File: source/private/Connect-TcpWithTimeout.ps1
- Signature: Connect-TcpWithTimeout([String]$Hostname, [Int32]$Port, [Int32]$TimeoutMs = 10000)

| Parameter | Type | Default |
|---|---|---|
| $Hostname | String | - |
| $Port | Int32 | - |
| $TimeoutMs | Int32 | 10000 |

## ConvertTo-TlsCertificateResult

- Synopsis: Builds a stable output object for certificate retrieval results.
- File: source/private/ConvertTo-TlsCertificateResult.ps1
- Signature: ConvertTo-TlsCertificateResult([String]$Hostname, [Int32]$Port, [String]$TargetHost, [X509Certificate2]$Certificate, [PSObject]$Validity, [SslProtocols]$NegotiatedProtocol, $CipherAlgorithm, [Int32]$CipherStrength, $NegotiatedCipherSuite, $HashAlgorithm, [Int32]$HashStrength, $KeyExchangeAlgorithm, [Int32]$KeyExchangeStrength, [Boolean]$IsMutuallyAuthenticated = $false, [Boolean]$IsEncrypted = $false, [Boolean]$IsSigned = $false, $NegotiatedApplicationProtocol, [Boolean]$ForwardSecrecy = $false, [TimeSpan]$Elapsed = [timespan]::Zero, [Boolean]$CertificateValidationPassed = $true, [SslPolicyErrors]$CertificatePolicyErrors = [System.Net.Security.SslPolicyErrors]::None, [String[]]$CertificatePolicyErrorFlags = @(), [String[]]$CertificateChainStatus = @())

| Parameter | Type | Default |
|---|---|---|
| $Hostname | String | - |
| $Port | Int32 | - |
| $TargetHost | String | - |
| $Certificate | X509Certificate2 | - |
| $Validity | PSObject | - |
| $NegotiatedProtocol | SslProtocols | - |
| $CipherAlgorithm | - | - |
| $CipherStrength | Int32 | - |
| $NegotiatedCipherSuite | - | - |
| $HashAlgorithm | - | - |
| $HashStrength | Int32 | - |
| $KeyExchangeAlgorithm | - | - |
| $KeyExchangeStrength | Int32 | - |
| $IsMutuallyAuthenticated | Boolean | $false |
| $IsEncrypted | Boolean | $false |
| $IsSigned | Boolean | $false |
| $NegotiatedApplicationProtocol | - | - |
| $ForwardSecrecy | Boolean | $false |
| $Elapsed | TimeSpan | [timespan]::Zero |
| $CertificateValidationPassed | Boolean | $true |
| $CertificatePolicyErrors | SslPolicyErrors | [System.Net.Security.SslPolicyErrors]::None |
| $CertificatePolicyErrorFlags | String[] | @() |
| $CertificateChainStatus | String[] | @() |

## ConvertTo-TlsSessionInfo

- Synopsis: Builds the shared TLS/session result property map used by public outputs.
- File: source/private/ConvertTo-TlsSessionInfo.ps1
- Signature: ConvertTo-TlsSessionInfo($NegotiatedProtocol, $CipherAlgorithm, [Nullable[Int32]]$CipherStrength, $NegotiatedCipherSuite, $HashAlgorithm, [Nullable[Int32]]$HashStrength, $KeyExchangeAlgorithm, [Nullable[Int32]]$KeyExchangeStrength, [Nullable[Boolean]]$IsMutuallyAuthenticated, [Nullable[Boolean]]$IsEncrypted, [Nullable[Boolean]]$IsSigned, $NegotiatedApplicationProtocol, [Nullable[Boolean]]$ForwardSecrecy, [Nullable[Boolean]]$CertificateValidationPassed, $CertificatePolicyErrors, [String[]]$CertificatePolicyErrorFlags = @(), [String[]]$CertificateChainStatus = @())

| Parameter | Type | Default |
|---|---|---|
| $NegotiatedProtocol | - | - |
| $CipherAlgorithm | - | - |
| $CipherStrength | Nullable[Int32] | - |
| $NegotiatedCipherSuite | - | - |
| $HashAlgorithm | - | - |
| $HashStrength | Nullable[Int32] | - |
| $KeyExchangeAlgorithm | - | - |
| $KeyExchangeStrength | Nullable[Int32] | - |
| $IsMutuallyAuthenticated | Nullable[Boolean] | - |
| $IsEncrypted | Nullable[Boolean] | - |
| $IsSigned | Nullable[Boolean] | - |
| $NegotiatedApplicationProtocol | - | - |
| $ForwardSecrecy | Nullable[Boolean] | - |
| $CertificateValidationPassed | Nullable[Boolean] | - |
| $CertificatePolicyErrors | - | - |
| $CertificatePolicyErrorFlags | String[] | @() |
| $CertificateChainStatus | String[] | @() |

## ConvertTo-TlsProtocolOptions

- Synopsis: Converts user protocol names into an SslProtocols flag enum.
- File: source/private/ConvertTo-TlsProtocolOptions.ps1
- Signature: ConvertTo-TlsProtocolOptions([String[]]$TlsProtocols)

| Parameter | Type | Default |
|---|---|---|
| $TlsProtocols | String[] | - |

## Get-TlsRuntimeProtocol

- Synopsis: Returns explicit TLS protocol enum values supported by the current runtime.
- File: source/private/Get-TlsRuntimeProtocol.ps1
- Signature: Get-TlsRuntimeProtocol([String[]]$ProtocolName = @('Ssl3','Tls','Tls11','Tls12','Tls13'))

| Parameter | Type | Default |
|---|---|---|
| $ProtocolName | String[] | @('Ssl3','Tls','Tls11','Tls12','Tls13') |

## Get-RemoteCertificate

- Synopsis: Extracts the remote certificate from an authenticated SslStream.
- File: source/private/Get-RemoteCertificate.ps1
- Signature: Get-RemoteCertificate([PSObject]$Connection)

| Parameter | Type | Default |
|---|---|---|
| $Connection | PSObject | - |

## Get-TlsHandshakeDetails

- Synopsis: Returns negotiated TLS/certificate validation details for an authenticated SslStream.
- File: source/private/Get-TlsHandshakeDetails.ps1
- Signature: Get-TlsHandshakeDetails([PSObject]$Connection)

| Parameter | Type | Default |
|---|---|---|
| $Connection | PSObject | - |

## Invoke-ImapStartTlsNegotiation

- Synopsis: Performs IMAP STARTTLS negotiation over an existing plaintext stream.
- File: source/private/Invoke-ImapStartTlsNegotiation.ps1
- Signature: Invoke-ImapStartTlsNegotiation([Stream]$NetworkStream, [Int32]$TimeoutMs = 10000)

| Parameter | Type | Default |
|---|---|---|
| $NetworkStream | Stream | - |
| $TimeoutMs | Int32 | 10000 |

## Invoke-Pop3StartTlsNegotiation

- Synopsis: Performs POP3 STLS negotiation over an existing plaintext stream.
- File: source/private/Invoke-Pop3StartTlsNegotiation.ps1
- Signature: Invoke-Pop3StartTlsNegotiation([Stream]$NetworkStream, [Int32]$TimeoutMs = 10000)

| Parameter | Type | Default |
|---|---|---|
| $NetworkStream | Stream | - |
| $TimeoutMs | Int32 | 10000 |

## Invoke-SmtpStartTlsNegotiation

- Synopsis: Performs SMTP STARTTLS negotiation over an existing plaintext stream.
- File: source/private/Invoke-SmtpStartTlsNegotiation.ps1
- Signature: Invoke-SmtpStartTlsNegotiation([Stream]$NetworkStream, [String]$EhloName, [Int32]$TimeoutMs = 10000)

| Parameter | Type | Default |
|---|---|---|
| $NetworkStream | Stream | - |
| $EhloName | String | - |
| $TimeoutMs | Int32 | 10000 |

## Invoke-TlsTransportNegotiation

- Synopsis: Dispatches transport-specific plaintext negotiation before TLS handshake.
- File: source/private/Invoke-TlsTransportNegotiation.ps1
- Signature: Invoke-TlsTransportNegotiation([String]$Transport, [PSObject]$Connection, [PSObject]$Options)

| Parameter | Type | Default |
|---|---|---|
| $Transport | String | - |
| $Connection | PSObject | - |
| $Options | PSObject | - |

## Invoke-WithRetry

- Synopsis: Invokes a script block with bounded retry behavior for transient operations.
- File: source/private/Invoke-WithRetry.ps1
- Signature: Invoke-WithRetry([ScriptBlock]$ScriptBlock, [Int32]$MaxAttempts = 3, [Int32]$DelayMs = 250, [String[]]$RetryOnExceptionType = @(             'System.TimeoutException',             'System.Net.Sockets.SocketException',             'System.IO.IOException'         ))

| Parameter | Type | Default |
|---|---|---|
| $ScriptBlock | ScriptBlock | - |
| $MaxAttempts | Int32 | 3 |
| $DelayMs | Int32 | 250 |
| $RetryOnExceptionType | String[] | @(             'System.TimeoutException',             'System.Net.Sockets.SocketException',             'System.IO.IOException'         ) |

## Invoke-WithStreamTimeout

- Synopsis: Temporarily applies stream read/write timeouts while invoking a script block.
- File: source/private/Invoke-WithStreamTimeout.ps1
- Signature: Invoke-WithStreamTimeout([Stream]$Stream, [Int32]$TimeoutMs, [ScriptBlock]$ScriptBlock)

| Parameter | Type | Default |
|---|---|---|
| $Stream | Stream | - |
| $TimeoutMs | Int32 | - |
| $ScriptBlock | ScriptBlock | - |

## New-TlsConnectionContext

- Synopsis: Opens a TCP connection and prepares the shared TLSleuth connection context.
- File: source/private/New-TlsConnectionContext.ps1
- Signature: New-TlsConnectionContext([String]$Hostname, [Int32]$Port, [Int32]$TimeoutMs = 10000)

| Parameter | Type | Default |
|---|---|---|
| $Hostname | String | - |
| $Port | Int32 | - |
| $TimeoutMs | Int32 | 10000 |

## New-TlsOperationContext

- Synopsis: Builds normalized per-target TLS command options.
- File: source/private/New-TlsOperationContext.ps1
- Signature: New-TlsOperationContext([String]$Hostname, [Int32]$Port, [String]$TargetHost, [String]$Transport, [String]$SmtpEhloName, [Int32]$TimeoutSec = 10)

| Parameter | Type | Default |
|---|---|---|
| $Hostname | String | - |
| $Port | Int32 | - |
| $TargetHost | String | - |
| $Transport | String | - |
| $SmtpEhloName | String | - |
| $TimeoutSec | Int32 | 10 |

## Read-TextProtocolLine

- Synopsis: Reads one ASCII CRLF-terminated line from a text protocol stream.
- File: source/private/Read-TextProtocolLine.ps1
- Signature: Read-TextProtocolLine([Stream]$Stream, [Int32]$ReadTimeoutMs, [String]$ProtocolName, [Int32]$MaxLineBytes = 4096)

| Parameter | Type | Default |
|---|---|---|
| $Stream | Stream | - |
| $ReadTimeoutMs | Int32 | - |
| $ProtocolName | String | - |
| $MaxLineBytes | Int32 | 4096 |

## Send-TextProtocolCommand

- Synopsis: Sends one ASCII command line terminated with CRLF.
- File: source/private/Send-TextProtocolCommand.ps1
- Signature: Send-TextProtocolCommand([Stream]$Stream, [String]$Command)

| Parameter | Type | Default |
|---|---|---|
| $Stream | Stream | - |
| $Command | String | - |

## Start-TlsHandshake

- Synopsis: Starts a TLS handshake on an existing network stream.
- File: source/private/Start-TlsHandshake.ps1
- Signature: Start-TlsHandshake([PSObject]$Connection, [String]$TargetHost, [SslProtocols]$SslProtocols, [Int32]$TimeoutMs = 10000, [SwitchParameter]$SkipCertificateValidation)

| Parameter | Type | Default |
|---|---|---|
| $Connection | PSObject | - |
| $TargetHost | String | - |
| $SslProtocols | SslProtocols | - |
| $TimeoutMs | Int32 | 10000 |
| $SkipCertificateValidation | SwitchParameter | - |

## Test-TlsCertificateValidity

- Synopsis: Evaluates date-based validity of an X509 certificate.
- File: source/private/Test-TlsCertificateValidity.ps1
- Signature: Test-TlsCertificateValidity([X509Certificate2]$Certificate, [DateTime]$AsOf = (Get-Date))

| Parameter | Type | Default |
|---|---|---|
| $Certificate | X509Certificate2 | - |
| $AsOf | DateTime | (Get-Date) |

