# TLSleuth

![Published Version](https://img.shields.io/powershellgallery/v/TLSleuth.svg?style=flat&logo=powershell&label=Published%20Version)
![Downloads](https://img.shields.io/powershellgallery/dt/TLSleuth.svg?style=flat&logo=powershell&label=PSGallery%20Downloads)
![Pester Tests](https://github.com/MadCrabCyder/TLSleuth/actions/workflows/pester-tests.yml/badge.svg)


**TLSleuth** is an open-source PowerShell module for inspecting TLS
endpoints and certificate details from scripts or the command line.

It provides clean, structured, script-friendly output for operators,
engineers, and automation pipelines that need reliable TLS insight.

- 🔎 Fetch a server's certificate and handshake details
- 📋 View negotiated TLS protocol and cipher information
- ⚙ Designed for automation and testing

------------------------------------------------------------------------

## Features

- **SNI-aware** -- Automatically uses SNI based on `-Hostname` (or
    `-TargetHost` override).
- **Protocol selection** -- Constrain to `Tls12`, `Tls13`, etc.
    (OS/runtime permitting).
- **Structured output** -- Stable object model with custom
    `PSTypeName`.
- **Pipeline support** -- Designed for batch processing.
- **Verbose diagnostics** -- `-Verbose` provides helper-level timing
    insight.
- **Safe collections** -- Arrays are never `$null`.
- **Tested** -- Unit tests with mocks; optional integration tests.

## New Feature for Version 2 - Explicit Transport Support

- Added support for specifying the transport type
- New transport option: `SmtpStartTls`
- New transport option: `ImapStartTls`
- New transport option: `Pop3StartTls`

You can now retrieve certificates from SMTP, IMAP, and POP3 servers using `STARTTLS`/`STLS` negotiation, rather than assuming implicit TLS (e.g., SMTPS on port 465, IMAPS on port 993, or POP3S on port 995).

This allows TLSleuth to:
- Connect to SMTP services on port 25 or 587
- Connect to IMAP services on port 143
- Connect to POP3 services on port 110
- Issue the STARTTLS/STLS command
- Upgrade the connection to TLS
- Retrieve certificate and negotiated TLS details

For more information see this page: [Implicit vs Explicit TLS](https://tlsleuth.com/blog/implicit-vs-explicit-tls.html)

------------------------------------------------------------------------

- [TLSleuth](#tlsleuth)
  - [Features](#features)
  - [New Feature for Version 2 - Explicit Transport Support](#new-feature-for-version-2---explicit-transport-support)
  - [Limitations and When to Use a Dedicated TLS Scanner](#limitations-and-when-to-use-a-dedicated-tls-scanner)
  - [Installation and Updating](#installation-and-updating)
    - [Install from PowerShell Gallery](#install-from-powershell-gallery)
    - [Update from PowerShell Gallery](#update-from-powershell-gallery)
- [Quick Start](#quick-start)
- [Output Model](#output-model)
  - [Get-TLSleuthCertificate returns a structured object:](#get-tlsleuthcertificate-returns-a-structured-object)
- [Architecture Overview](#architecture-overview)
  - [Project Layout](#project-layout)
- [Building from Source](#building-from-source)
  - [Requirements](#requirements)
  - [Build](#build)
- [Testing](#testing)
  - [Run All Tests](#run-all-tests)
- [Contributing](#contributing)
  - [Guidelines](#guidelines)
- [License](#license)
- [Release Notes](#release-notes)
------------------------------------------------------------------------

## Limitations and When to Use a Dedicated TLS Scanner

TLSleuth is designed for practical, scriptable TLS inspection - retrieving the negotiated certificate, protocol, and cipher from PowerShell.

Because it relies on `.NET SslStream` and the underlying OS TLS stack (SChannel on Windows), it has intentional limitations:

- It only shows the negotiated cipher suite (no full enumeration)
- It cannot probe for TLS vulnerabilities (Heartbleed, ROBOT, etc.)
- It cannot craft custom ClientHello messages or test fallback behavior
- TLS version and cipher availability depend on OS policy

For full TLS posture analysis, cipher enumeration, downgrade testing, and vulnerability scanning, use a [Dedicated TLS Scanner](https://tlsleuth.com/blog/dedicated-scanners.html)


## Installation and Updating

### Install from PowerShell Gallery

``` powershell
Install-Module TLSleuth -Scope CurrentUser
Import-Module TLSleuth
```

### Update from PowerShell Gallery

``` powershell
Update-Module TLSleuth
```

> Recommended: **PowerShell 7+**
> Supported: Windows PowerShell 5.1 (reduced TLS/cipher detail)

------------------------------------------------------------------------

# Quick Start

``` powershell
# Fetch certificate + handshake details
Get-TLSleuthCertificate -Hostname github.com

# Constrain protocol
Get-TLSleuthCertificate -Hostname google.com -TlsProtocols Tls12

# Pipeline usage
'github.com','microsoft.com' |
  Get-TLSleuthCertificate |
  Select Hostname, NegotiatedProtocol, NegotiatedCipherSuite, CipherAlgorithm, CipherStrength, ForwardSecrecy, NotAfter

# Verbose tracing
Get-TLSleuthCertificate -Hostname microsoft.com -Verbose

# New in V2.0.0 - Retrieve certificate from SMTP server
Get-TLSleuthCertificate -Hostname smtp.gmail.com -port 25 -Transport SmtpStartTls

# New in V2.1.0 - Retrieve certificate from IMAP server
Get-TLSleuthCertificate -Hostname outlook.office365.com -Port 143 -Transport ImapStartTls

# New in V2.1.0 - Retrieve certificate from POP3 server
Get-TLSleuthCertificate -Hostname pop.gmail.com -Port 110 -Transport Pop3StartTls

# New in V2.3.0 - Test protocol support on an HTTPS endpoint
Test-TLSleuthProtocol -Hostname github.com |
  Select Protocol, ConnectionSuccessful, NegotiatedProtocol, NegotiatedCipherSuite, ErrorMessage

# New in V2.3.0 - Test protocol support for SMTP STARTTLS
Test-TLSleuthProtocol -Hostname smtp.gmail.com -Port 587 -Transport SmtpStartTls |
  Select Protocol, ConnectionSuccessful, NegotiatedProtocol, ErrorMessage

# New in V2.3.0 - Pipeline protocol testing across multiple hosts
'github.com','microsoft.com' |
  Test-TLSleuthProtocol |
  Where-Object ConnectionSuccessful |
  Select Hostname, Protocol, NegotiatedProtocol, NegotiatedCipherSuite

# Retrieve an invalid certificate but keep validation diagnostics
Get-TLSleuthCertificate -Hostname wrong.host.badssl.com -SkipCertificateValidation |
  Select Hostname, CertificateValidationPassed, CertificatePolicyErrors, CertificatePolicyErrorFlags
```

> When connecting by IP but requiring proper SNI, use `-TargetHost example.com`.

------------------------------------------------------------------------

# Output Model

## Get-TLSleuthCertificate

Example:

``` powershell
PSTypeName                  : TLSleuth.CertificateResult
Hostname                    : github.com
Port                        : 443
TargetHost                  : github.com
Subject                     : CN=github.com
Issuer                      : CN=Sectigo ECC Domain Validation Secure Server CA, O=Sectigo Limited, C=GB
Thumbprint                  : 0123456789ABCDEF0123456789ABCDEF01234567
SerialNumber                : 0ABC1234DEF56789ABC1234DEF56789A
NotBefore                   : 02/01/2026 12:00:00 AM
NotAfter                    : 01/04/2026 11:59:59 PM
IsValidNow                  : True
DaysUntilExpiry             : 25
CertificateValidationPassed : True
CertificatePolicyErrors     : None
CertificatePolicyErrorFlags : {}
CertificateChainStatus      : {}
NegotiatedProtocol          : Tls13
CipherAlgorithm             : Aes256
CipherStrength              : 256
NegotiatedCipherSuite       : TLS_AES_256_GCM_SHA384
HashAlgorithm               : Sha384
HashStrength                : 384
KeyExchangeAlgorithm        : None
KeyExchangeStrength         : 0
IsMutuallyAuthenticated     : False
IsEncrypted                 : True
IsSigned                    : True
NegotiatedApplicationProtocol : h2
ForwardSecrecy              : True
ElapsedMs                   : 48
Certificate                 : X509Certificate2
```

Properties include:

- `PSTypeName` (`TLSleuth.CertificateResult`)
- Endpoint identity: `Hostname`, `Port`, `TargetHost`
- Certificate identity: `Subject`, `Issuer`, `Thumbprint`, `SerialNumber`
- Certificate validity: `NotBefore`, `NotAfter`, `IsValidNow`, `DaysUntilExpiry`
- Validation details: `CertificateValidationPassed`, `CertificatePolicyErrors`, `CertificatePolicyErrorFlags`, `CertificateChainStatus`
- TLS/session details: `NegotiatedProtocol`, `CipherAlgorithm`, `CipherStrength`, `NegotiatedCipherSuite`, `HashAlgorithm`, `HashStrength`, `KeyExchangeAlgorithm`, `KeyExchangeStrength`, `IsMutuallyAuthenticated`, `IsEncrypted`, `IsSigned`, `NegotiatedApplicationProtocol`, `ForwardSecrecy`
- Timing and raw certificate: `ElapsedMs`, `Certificate`

`NegotiatedCipherSuite` and `NegotiatedApplicationProtocol` depend on runtime/OS support and may be `$null` on Windows PowerShell 5.1.

## Test-TLSleuthProtocol

`Test-TLSleuthProtocol` returns one `TLSleuth.ProtocolTestResult` object per protocol attempt.

Example output (one successful protocol attempt and one failed attempt):

``` powershell
PSTypeName                    : TLSleuth.ProtocolTestResult
Hostname                      : github.com
Port                          : 443
TargetHost                    : github.com
Transport                     : ImplicitTls
Protocol                      : Tls12
ConnectionSuccessful          : True
ErrorMessage                  :
NegotiatedProtocol            : Tls12
CipherAlgorithm               : Aes256
CipherStrength                : 256
NegotiatedCipherSuite         : TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
HashAlgorithm                 : Sha256
HashStrength                  : 256
KeyExchangeAlgorithm          : ECDHE
KeyExchangeStrength           : 256
IsMutuallyAuthenticated       : False
IsEncrypted                   : True
IsSigned                      : True
NegotiatedApplicationProtocol : h2
ForwardSecrecy                : True
CertificateValidationPassed   : True
CertificatePolicyErrors       : None
CertificatePolicyErrorFlags   : {}
CertificateChainStatus        : {}
ElapsedMs                     : 42

PSTypeName                    : TLSleuth.ProtocolTestResult
Hostname                      : github.com
Port                          : 443
TargetHost                    : github.com
Transport                     : ImplicitTls
Protocol                      : Tls11
ConnectionSuccessful          : False
ErrorMessage                  : Authentication failed because the remote party has closed the transport stream.
NegotiatedProtocol            :
CipherAlgorithm               :
CipherStrength                :
NegotiatedCipherSuite         :
HashAlgorithm                 :
HashStrength                  :
KeyExchangeAlgorithm          :
KeyExchangeStrength           :
IsMutuallyAuthenticated       :
IsEncrypted                   :
IsSigned                      :
NegotiatedApplicationProtocol :
ForwardSecrecy                :
CertificateValidationPassed   :
CertificatePolicyErrors       :
CertificatePolicyErrorFlags   : {}
CertificateChainStatus        : {}
ElapsedMs                     : 36
```

Properties include:

- `PSTypeName` (`TLSleuth.ProtocolTestResult`)
- Endpoint/protocol context: `Hostname`, `Port`, `TargetHost`, `Transport`, `Protocol`
- Outcome: `ConnectionSuccessful`, `ErrorMessage`, `ElapsedMs`
- Negotiated TLS/session details when successful: `NegotiatedProtocol`, `CipherAlgorithm`, `CipherStrength`, `NegotiatedCipherSuite`, `HashAlgorithm`, `HashStrength`, `KeyExchangeAlgorithm`, `KeyExchangeStrength`, `IsMutuallyAuthenticated`, `IsEncrypted`, `IsSigned`, `NegotiatedApplicationProtocol`, `ForwardSecrecy`
- Certificate validation details when successful: `CertificateValidationPassed`, `CertificatePolicyErrors`, `CertificatePolicyErrorFlags`, `CertificateChainStatus`

Designed for stable automation and predictable output contracts across both commands.

------------------------------------------------------------------------

# Architecture Overview

TLSleuth follows a **source-first modular design**:

- One function per file
- Clear separation of public vs private functions
- Pester-driven development
- Stable output contract
- Minimal side effects

## Project Layout

    TLSleuth/
    ├── docs/
    ├── examples/
    ├── output/
    └── source/
        ├── private/
        ├── public/
        └── tests/
            ├── integration/
            └── unit/

------------------------------------------------------------------------

# Building from Source

TLSleuth uses **ModuleBuilder (Build-Module)**.

The repository contains individual function files. During build:

- Functions are merged into a single `.psm1`
- The module manifest is generated/updated
- Public functions are auto-exported
- Build settings are read from `/build.psd1`
- Compiled output is written to `/output`

## Requirements

``` powershell
Install-Module ModuleBuilder -Scope CurrentUser
```

## Build

From project root:

``` powershell
Build-Module
```

Force clean rebuild:

``` powershell
Build-Module -Clean
```

Do not modify files in `/output` directly.

------------------------------------------------------------------------

# Testing

TLSleuth uses **Pester**.

## Run All Tests

``` powershell
Invoke-Pester -Path ./source/tests -Output Detailed
```

Unit tests use mocks for network calls.
Integration tests perform live TLS handshakes and may require internet
access.

------------------------------------------------------------------------

# Contributing

Contributions are welcome!

## Guidelines

- One function per file
- Public functions in `/source/public`
- Private helpers in `/source/private`
- Maintain structured output contract
- Add Pester tests for new functionality
- Run tests before submitting PR

------------------------------------------------------------------------

# License

MIT --- see LICENSE

------------------------------------------------------------------------

# Release Notes

> ### 2.3.0 (07-Mar-2026)
> * Introduced `Test-TLSleuthProtocol` to test endpoint protocol support across runtime-available TLS protocol versions
> * Added structured `TLSleuth.ProtocolTestResult` output per protocol attempt, including negotiated TLS details and per-attempt errors
> * Added unit tests for protocol iteration, failure continuation, and STARTTLS negotiation behavior

> ### 2.2.0 (03-Mar-2026)
> * Refactored TLS handshake detail extraction into `Get-TlsHandshakeDetails`
> * Added additional TLS/session fields to `Get-TLSleuthCertificate` output model

> ### 2.1.0 (02-Mar-2026)
> * Added `ImapStartTls` and `Pop3StartTls` transports
> * Refactored STARTTLS/STLS negotiation into shared reusable helpers
> * You can now retrieve invalid certs (when skipping validation) and still see explicit validation failure details

> ### 2.0.0 (28-Feb-2026)
> **Major Refactor**
> * Significant internal refactor to simplify and modularize helper functions
> * Improved separation of transport, handshake, and certificate extraction logic
> * Enhanced maintainability and extensibility of the TLS negotiation pipeline

> ### 1.0.2 (13-Sep-2025)
> * CHANGE: Rename SNI override parameter from **-ServerName** to **-TargetHost**
> * CHANGE: Pipeline binding tightened
>   * `Hostname`: accepts from pipeline (by value & property name)
>   * `Port`, `TargetHost`: accept **by property name** only
> * IMPROVED: Update Alias for **-TargetHost** to SNI and ServerName
> * ADD: `examples\Check-CertExpiry.ps1`

> ### 1.0.1 (06-Sep-2025)
> * Add MIT License
> * Add TLSleuth Icon and Site details to manifest

> ### 1.0.0 (05-Sep-2025)
> * Get-TLSleuthCertificate: fetch TLS handshake + certificate details
> * Optional chain build and revocation check
> * Extract SANs, AIA, CRL Distribution Points
> * Structured, script-friendly output; verbose diagnostics
> * Pester tests with mocks; optional integration tests
------------------------------------------------------------------------

Built with ❤️ for operators and automation engineers who need fast,
reliable TLS visibility from PowerShell.
