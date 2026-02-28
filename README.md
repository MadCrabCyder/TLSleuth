# TLSleuth

**TLSleuth** is an open-source PowerShell module for inspecting TLS
endpoints and certificate details from scripts or the command line.

It provides clean, structured, script-friendly output for operators,
engineers, and automation pipelines that need reliable TLS insight.

🔎 Fetch a server's certificate and handshake details\
📋 View negotiated TLS protocol and cipher information\
⚙ Designed for automation and testing

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

## New Feature for 2.0.0 - Explicit Transport Support

- Added support for specifying the transport type
- New transport option: `SmtpStartTls`

You can now retrieve certificates from SMTP servers using `STARTTLS` negotiation, rather than assuming implicit TLS (e.g., SMTPS on port 465).

This allows TLSleuth to:
- Connect to SMTP services on port 25 or 587
- Issue the STARTTLS command
- Upgrade the connection to TLS
- Retrieve certificate and negotiated TLS details

------------------------------------------------------------------------

- [TLSleuth](#tlsleuth)
  - [Features](#features)
  - [New Feature for 2.0.0 - Explicit Transport Support](#new-feature-for-200---explicit-transport-support)
- [Platform Notes \& Design Constraints](#platform-notes--design-constraints)
  - [Cipher Enumeration](#cipher-enumeration)
  - [Cipher Visibility Differences](#cipher-visibility-differences)
  - [TLS 1.3 Support](#tls-13-support)
- [Installation](#installation)
  - [From PowerShell Gallery](#from-powershell-gallery)
- [Quick Start](#quick-start)
- [Output Model](#output-model)
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
# Platform Notes & Design Constraints

TLSleuth relies on .NET and the OS TLS stack (SChannel on Windows).

## Cipher Enumeration

`SslStream` does **not** allow specifying an exact cipher list. TLSleuth
reports:

✔ The negotiated cipher\
❌ Not the full set supported by the server

## Cipher Visibility Differences

| Runtime                 | Detail Level                                        |
| ----------------------- | --------------------------------------------------- |
| PowerShell 7+ (.NET 5+) | Full named cipher suite via `NegotiatedCipherSuite` |
| Windows PowerShell 5.1  | Algorithm + strength only                           |
## TLS 1.3 Support

Depends on OS and runtime support. Older Windows versions and PS 5.1 may
not support TLS 1.3.

------------------------------------------------------------------------

# Installation

## From PowerShell Gallery

``` powershell
Install-Module TLSleuth -Scope CurrentUser
Import-Module TLSleuth
```

Recommended: **PowerShell 7+**\
Supported: Windows PowerShell 5.1 (reduced TLS/cipher detail)

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
  Select Hostname, NegotiatedProtocol, CipherAlgorithm, CipherStrength, NotAfter

# Verbose tracing
Get-TLSleuthCertificate -Hostname microsoft.com -Verbose

# New in V2.0.0 - REtrieve certificate from SMTP server
Get-TLSleuthCertificate -Hostname smtp.gmail.com -port 25 -Transport SmtpStartTls

```

> When connecting by IP but requiring proper SNI, use `-TargetHost`.

------------------------------------------------------------------------

# Output Model

TLSleuth returns a structured object:

Example:

``` powershell
Hostname           : microsoft.com
Port               : 443
TargetHost         : microsoft.com
Subject            : CN=microsoft.com, O=Microsoft Corporation...
Issuer             : CN=Microsoft Azure RSA TLS Issuing CA 04...
Thumbprint         : 40B3005534C15CC035B1F0061A813B8F91D1A02A
NotBefore          : 4/02/2026 11:21:49 AM
NotAfter           : 3/08/2026 10:21:49 AM
IsValidNow         : True
DaysUntilExpiry    : 155
NegotiatedProtocol : Tls13
CipherAlgorithm    : Aes256
CipherStrength     : 256
ElapsedMs          : 50
Certificate        : X509Certificate2
```

The object includes:

- Certificate metadata
- Validity status
- Negotiated TLS protocol
- Cipher algorithm & strength
- Timing information
- Raw `X509Certificate2` for advanced use

Designed for stable automation and predictable output contracts.

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

Unit tests use mocks for network calls.\
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
