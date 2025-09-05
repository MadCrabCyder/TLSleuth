# TLSleuth

**TLSleuth** is a PowerShell module for quickly inspecting TLS/SSL endpoints and certificates from the shell or in scripts. It’s a pragmatic, scriptable helper—**not** a full-blown TLS scanner.

* 🔎 Fetch a server’s certificate and handshake details
* 📋 See the negotiated TLS protocol and (when supported) the cipher suite
* 🧩 Parse SANs, AIA and CDP URLs, and basic chain/trust information
* 🧪 Built with unit tests and a clean, mockable design

> Need deep scanning (cipher enumeration, vulnerability tests, ALPN, etc.)? See **[When to use dedicated scanners](#when-to-use-dedicated-scanners)**.

---

## Table of Contents

- [TLSleuth](#tlsleuth)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Limitations (by design \& platform)](#limitations-by-design--platform)
  - [Install](#install)
  - [Quick Start](#quick-start)
  - [Commands](#commands)
    - [`Get-TLSleuthCertificate` *(public)*](#get-tlsleuthcertificate-public)
    - [Private helpers (internal, unit-testable)](#private-helpers-internal-unit-testable)
  - [Output shape](#output-shape)
  - [How it works](#how-it-works)
  - [Testing](#testing)
  - [When to use dedicated scanners](#when-to-use-dedicated-scanners)
  - [Security \& ethics](#security--ethics)
  - [Compatibility matrix](#compatibility-matrix)
  - [Roadmap](#roadmap)
  - [Contributing](#contributing)
  - [License](#license)

---

## Features

* **SNI-aware**: uses SNI automatically based on `-Hostname` (or `-ServerName` override).
* **Protocol selection**: constrain to `Tls12`, `Tls13`, etc. (OS/runtime permitting).
* **Certificate details**: Subject, Subject CN, *Primary DNS name* (SAN-first), SANs\[], issuer, validity, signature/public key algorithms, key size, thumbprint, self-signed boolean.
* **Chain/trust**: optional local chain build with status details.
* **Extension parsing**: DNS SANs, AIA URLs, CRL Distribution Point URLs (empty arrays when absent).
* **Verbose diagnostics**: `-Verbose` prints begin/end + timings per helper.
* **Script-friendly**: stable object model; safe arrays (never `$null` for collections).
* **Well-tested**: Pester tests use mocks; optional live (integration) tests.

---

## Limitations (by design & platform)

TLSleuth rides on .NET and the OS TLS stack (SChannel on Windows). That implies:

* **No full cipher enumeration**
  `SslStream` does **not** let you supply an exact cipher list; the negotiated cipher is whatever the client/OS offered and the server selected. TLSleuth reports **what was negotiated**, not the full set the server supports.

* **Cipher visibility varies**

  * .NET 5+/PowerShell 7+: `SslStream.NegotiatedCipherSuite` (named suite).
  * .NET Framework/PS 5.1: only algorithm names/strength (coarser detail).

* **TLS 1.3 availability** depends on OS/runtime (e.g., older Windows & PS 5.1 don’t have it).

* **Revocation checks** (`-CheckRevocation`) rely on OS chain engine; may be slow or blocked by proxies/firewalls.

* **SAN parsing**
  On newer .NET, TLSleuth uses `X509Certificate2.DnsNameList`. Otherwise it parses formatted SAN text robustly (DNS names only).

* **Not a vulnerability scanner**
  TLSleuth does **not** test for known TLS CVEs, renegotiation/compression weaknesses, ALPN/H2 behavior, session resumption/tickets, curve ordering, etc.

See **[When to use dedicated scanners](#when-to-use-dedicated-scanners)** for tool recommendations.

---

## Install

**From the PowerShell Gallery** (once published):

```powershell
Install-Module TLSleuth -Scope CurrentUser
Import-Module TLSleuth
```

**From source** (clone this repo):

```powershell
# From repo root
Import-Module "$PWD\TLSleuth.psd1" -Force
# or
Import-Module "$PWD\TLSleuth.psm1" -Force
```

> **Recommended:** PowerShell 7+.
> **Supported:** Windows PowerShell 5.1 (with reduced TLS/cipher detail).

---

## Quick Start

```powershell
# Fetch cert + handshake details
Get-TLSleuthCertificate -Hostname example.com

# Constrain protocol to TLS 1.2
Get-TLSleuthCertificate -Hostname example.com -TlsProtocols Tls12

# Include local chain build + revocation checks
Get-TLSleuthCertificate -Hostname example.com -IncludeChain -CheckRevocation

# Pipeline support
'github.com','microsoft.com' |
  Get-TLSleuthCertificate -IncludeChain |
  Select Host,Protocol,CipherSuite,@{n='PrimaryDNS';e={$_.Certificate.PrimaryDnsName}},IsTrusted

# Verbose tracing (timings per helper)
Get-TLSleuthCertificate -Hostname example.com -Verbose
```

> If you connect by IP but need proper SNI, pass `-ServerName example.com`.

---

## Commands

### `Get-TLSleuthCertificate` *(public)*

Connects to an endpoint and returns a structured report:

* **Endpoint:** Host, Port, Connected IP, SNI
* **Handshake:** Protocol, cipher suite (if supported), hash, key exchange, strength
* **Certificate:** Subject, SubjectCN, PrimaryDnsName, SANs\[], Issuer, Serial, Thumbprint, NotBefore/After, Signature/PublicKey algorithms, KeySize, IsSelfSigned
* **Chain:** IsTrusted, ChainSubjects\[], ChainStatus\[]
* **ValidationErrors\[]:** from handshake callback (informational)
* **RawCertificate:** the `X509Certificate2` (available via `-RawCertificate`)

**Key parameters**

* `-Hostname <string>` (pipeline). Aliases: `-Host`, `-DnsName`, `-ComputerName`, `-Target`, `-Name`, `-CN`
* `-Port <int>` (default: 443)
* `-ServerName <string>` (SNI override)
* `-TlsProtocols <string[]>` (e.g., `SystemDefault`, `Tls12`, `Tls13`)
* `-IncludeChain`
* `-CheckRevocation`
* `-RawCertificate`

### Private helpers (internal, unit-testable)

* `Resolve-Endpoint -Hostname` → IP or `$null`
* `Connect-TcpWithTimeout -Hostname -Port -TimeoutMs` → `{ TcpClient, NetworkStream }`
* `Start-TlsHandshake -NetworkStream -TargetHostname -Protocols [-CheckRevocation]` → `{ SslStream, RemoteCertificate, CapturedChain, ValidationErrors[] }`
* `Get-HandshakeInfo -SslStream` → `{ Protocol, CipherSuite, … }`
* `Build-CertificateChain -Certificate [-CheckRevocation]` → `{ Chain, IsTrusted, ChainStatus[], ChainSubjects[] }`
* `Format-ChainStatusStrings -ChainStatus[]` → string\[]
* `Get-CertificateSAN -Cert` → DNS SANs (string\[])
* `Get-AIAUrls -Cert` → AIA URLs (string\[])
* `Get-CDPUrls -Cert` → CRL Distribution Point URLs (string\[])
* `New-TLSleuthCertificateReport …` → final PSCustomObject

> **Design contract:** any “list” output is **always an array** (possibly empty), never `$null`.

---

## Output shape

Example (abridged):

```powershell
[pscustomobject]@{
  PSTypeName         = 'TLSleuth.CertificateReport'
  Host               = 'example.com'
  Port               = 443
  ConnectedIp        = '93.184.216.34'
  SNI                = 'example.com'
  Protocol           = 'Tls12'
  CipherSuite        = 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'
  CipherStrengthBits = 128
  HashAlgorithm      = 'SHA256'
  KeyExchange        = 'ECDHE'
  Certificate        = [pscustomobject]@{
    Subject            = 'CN=example.com, O=Example Inc, C=US'
    SubjectCN          = 'example.com'            # CN from Subject DN
    PrimaryDnsName     = 'example.com'            # SAN-first, CN fallback
    Issuer             = 'CN=Example CA'
    NotBefore          = '...'
    NotAfter           = '...'
    DaysUntilExpiry    = 83
    SignatureAlgorithm = 'sha256RSA'
    PublicKeyAlgorithm = 'RSA'
    KeySize            = 2048
    SANs               = @('example.com','www.example.com')
    AIA                = @('http://aia.example/...')
    CRLDistribution    = @('http://crl.example/...')
    IsSelfSigned       = $false
  }
  IsTrusted          = $true
  ChainSubjects      = @('CN=example.com,...','CN=Example CA,...','CN=Root CA,...')
  ChainStatus        = @()                         # empty means OK
  ValidationErrors   = @()                         # handshake policy notes
  RawCertificate     = [System.Security.Cryptography.X509Certificates.X509Certificate2]
}
```

---

## How it works

TLSleuth composes small, focused functions:

1. **Resolve & connect** → `Resolve-Endpoint` + `Connect-TcpWithTimeout`
2. **TLS handshake** → `Start-TlsHandshake` (SNI-aware `SslStream`; captures policy errors)
3. **Gather details** → `Get-HandshakeInfo` + certificate field extraction + SAN/AIA/CDP helpers
4. **Optional chain** → `Build-CertificateChain` (+ `Format-ChainStatusStrings`)
5. **Assemble report** → `New-TLSleuthCertificateReport`

**Design choices**

* No global state; everything parameterized and **mockable**
* **Verbose** begin/complete logs with timings in each helper (`-Verbose`)
* **Arrays, not `$null`** for collections (safer pipes & counting)

---

## Testing

We use **Pester 5** with **mocks** so unit tests run fast and hermetically.

* Mock externalities: DNS, TCP, and handshake.
* For mandatory typed params in mocks, return real types:

  * `NetworkStream = [System.IO.MemoryStream]::new()`
  * `SslStream     = [System.Net.Security.SslStream]::new([System.IO.MemoryStream]::new())`
* In `-ParameterFilter`, use the **parameter variables** (`$Hostname`, `$Port`, `$TargetHostname`) rather than `$PSBoundParameters`.
* Avoid `$Host` in tests (it’s a read-only automatic variable). Standardize on `-Hostname` in code and `$TestHostname` in tests.

**Run tests**

```powershell
Invoke-Pester -Path 'source/tests' -Output Detailed
```

**Optional live tests**

```powershell
$env:TLSLEUTH_TEST_ENDPOINT = 'example.com'
$env:TLSLEUTH_TEST_PORT     = '443'
Invoke-Pester -Path 'source/tests' -Output Detailed
```

---

## When to use dedicated scanners

TLSleuth is great for quick snapshots and scripting. For **deep TLS analysis**, use:

* **sslyze** — [https://github.com/nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze)
  Cipher enumeration, TLS extensions, resumption, OCSP stapling, compression/renegotiation checks, ticket/ALPN/H2, more.

* **sslscan** — [https://github.com/rbsec/sslscan](https://github.com/rbsec/sslscan)
  Fast OpenSSL-based scanner; enumerates supported ciphers and protocols.

* **testssl.sh** — [https://testssl.sh/](https://testssl.sh/)
  Shell script + OpenSSL battery: weak ciphers, CVEs (Heartbleed/ROBOT/etc.), curves, ALPN, STARTTLS, more.

**Switch to a scanner when you need:**

* **All supported ciphers/curves**, not just the negotiated one
* **Vulnerability probing**
* **ALPN/HTTP2**, session resumption, tickets analysis
* Client profile policy checks across different TLS stacks

---

## Security & ethics

* Only test systems you **own** or are **authorized** to assess.
* Be mindful with `-CheckRevocation` (may trigger outbound CA/OCSP traffic).
* Use conservative timeouts on production systems.

---

## Compatibility matrix

| Area                      | PowerShell 7+ (.NET 6/7)          | Windows PowerShell 5.1 (.NET Framework) |
| ------------------------- | --------------------------------- | --------------------------------------- |
| TLS 1.3                   | OS-dependent (e.g., Win 11/2022+) | No                                      |
| Named cipher suite        | `SslStream.NegotiatedCipherSuite` | Not available                           |
| SAN DNS list              | `X509Certificate2.DnsNameList`    | Not available (fallback parse)          |
| Null-conditional operator | Yes                               | No (TLSleuth uses safe fallbacks)       |

---

## Roadmap

* `Test-TLSNegotiation` — iterate protocols; capture negotiated suites per protocol (best-effort)
* `Test-TLSPort` — probe arbitrary ports for TLS capability (SMTP STARTTLS support later)
* `Analyze-TLSChain` — optional AIA/CRL retrieval for richer diagnostics
* Export/report helpers (JSON/CSV) and example dashboards
* ASN.1 parsing for SAN/AIA/CDP on all runtimes (reduce text parsing)

Have ideas? Open an issue! 💡

---

## Contributing

PRs welcome! Please:

1. Open an issue describing the change.

2. Follow the structure:

   ```
   source/
     classes/
     private/   # one function per file (internal helpers)
     public/    # exported commands
     tests/     # Pester tests (use mocks/helpers)
       helpers/
   ```

3. **Include tests** (prefer mocks; gate live tests behind env vars).

4. Keep outputs **stable & typed** (collections as arrays, not `$null`).

5. Run `Invoke-Pester -Path source/tests -Output Detailed` before submitting.

---

## License

MIT — see [LICENSE](LICENSE).

---

Built with ❤️ for operators and scripters who need quick TLS insight from PowerShell. If you find TLSleuth useful, consider leaving a ⭐ on GitHub!
