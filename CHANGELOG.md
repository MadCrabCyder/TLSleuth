# Changelog
## Unreleased
- Improved `Invoke-WithRetry` so configured base exception types also match derived exceptions, and expanded its standalone help examples.
- Added Invoke-Build tasks and a gist manifest for publishing standalone helper snippets, starting with `invoke-retry`.
- Extracted SMTP EHLO name resolution into a focused private helper with unit coverage.
- Simplified TLS transport dispatch by replacing the per-call adapter hashtable with explicit `switch -Exact` routing.
- Extracted per-transport negotiation adapter helpers for implicit TLS, SMTP STARTTLS, IMAP STARTTLS, and POP3 STLS.

## 2.3.4 (18-Jun-2026)
- Added contract snapshot coverage for public result objects and centralized shared TLS/session result property mapping.
- Centralized public command operation context, runtime TLS protocol discovery, and transport adapter invocation shape.
- Prepared RDP transport support by adding internal transport negotiation results, normalized transport option sets, and binary protocol data helpers.
- Moved release note extraction into Invoke-Build, added release checklist documentation, improved workflow dependency caching, and documented PowerShell runtime compatibility expectations.

## 2.3.3 (15-Jun-2026)
- Added Invoke-Build task orchestration for analysis, validation, unit tests, integration tests, build, rebuild, and clean operations.
- Updated build documentation to use Invoke-Build as the local CI entry point.
- Added PSScriptAnalyzer settings and addressed initial analyzer warnings that were safe to fix without changing public command contracts.
- Aligned the tag-driven GitHub release workflow with the TLSleuth manifest, build output, and Invoke-Build publish tasks.
- Added release metadata validation to require a `CHANGELOG.md` entry matching `source/TLSleuth.psd1` `ModuleVersion`.

## 2.3.2 (08-Mar-2026)
- Added `Invoke-TlsTransportNegotiation` to centralize transport negotiation dispatch for `ImplicitTls`, `SmtpStartTls`, `ImapStartTls`, and `Pop3StartTls`.
- Simplified `Get-TLSleuthCertificate` and `Test-TLSleuthProtocol` orchestration to: connect -> transport negotiation -> TLS handshake -> result processing.
- Removed protocol-specific STARTTLS branching from public command implementations; negotiation is now fully delegated to private transport negotiation helper(s).
- Preserved public parameters, output contracts, timeout behavior, and existing STARTTLS integration behavior.

## 2.3.1 (08-Mar-2026)
- Refactored internal TLS helpers to use a shared connection context object (`TcpClient`, `NetworkStream`, `SslStream`) instead of passing resources separately.
- Updated `Start-TlsHandshake` to create the TLS stream from `Connection.NetworkStream` and populate `Connection.SslStream`.
- Updated internal call paths in `Get-TLSleuthCertificate` and `Test-TLSleuthProtocol` to use connection-context based helpers.
- Updated helper-focused unit/integration tests for the new internal helper contract.
- No public command parameter or output contract changes.

## 2.3.0 (07-Mar-2026)
- Introduced `Test-TLSleuthProtocol` to test endpoint protocol support across runtime-available TLS protocol versions.
- Added structured `TLSleuth.ProtocolTestResult` output per protocol attempt, including negotiated TLS details and per-attempt errors.
- Added unit tests for protocol iteration, failure continuation, and STARTTLS negotiation behavior.

## 2.2.0 (03-Mar-2026)
- Refactored TLS handshake detail extraction into `Get-TlsHandshakeDetails`.
- Added additional TLS/session fields to `Get-TLSleuthCertificate` output model.

## 2.1.0 (02-Mar-2026)
- Added `ImapStartTls` and `Pop3StartTls` transports.
- Refactored STARTTLS/STLS negotiation into shared reusable helpers.
- You can now retrieve invalid certs when skipping validation and still see explicit validation failure details.

## 2.0.0 (28-Feb-2026)
- Major internal refactor to simplify and modularize helper functions.
- Improved separation of transport, handshake, and certificate extraction logic.
- Enhanced maintainability and extensibility of the TLS negotiation pipeline.

## 1.0.2 (13-Sep-2025)
- Changed SNI override parameter from `-ServerName` to `-TargetHost`.
- Tightened pipeline binding:
  - `Hostname`: accepts from pipeline by value and property name.
  - `Port`, `TargetHost`: accept by property name only.
- Improved alias for `-TargetHost` to include `SNI` and `ServerName`.
- Added `examples\Check-CertExpiry.ps1`.

## 1.0.1 (06-Sep-2025)
- Added MIT License.
- Added TLSleuth icon and site details to manifest.

## 1.0.0 (05-Sep-2025)
- Added `Get-TLSleuthCertificate` to fetch TLS handshake and certificate details.
- Added optional chain build and revocation check.
- Extracted SANs, AIA, and CRL Distribution Points.
- Added structured, script-friendly output and verbose diagnostics.
- Added Pester tests with mocks and optional integration tests.
