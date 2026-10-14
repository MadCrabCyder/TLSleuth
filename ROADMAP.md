# Roadmap

## Active

### Documentation Baseline
- Status: In progress
- Category: Documentation
- Complexity: Small
- Goal: Keep standard project docs aligned with the current module structure and development workflow.
- Success criteria:
  - `README.md`, `.codex/CONTEXT.md`, `ROADMAP.md`, and `docs/decisions/` exist and have distinct roles.
  - Existing architecture, testing, and contribution guidance remains discoverable.
  - Future changes have clear places for behavior docs, working context, roadmap items, and decisions.

## Near Term

### Keep Transport Negotiation Maintainable
- Status: Planned
- Category: Architecture
- Complexity: Medium
- Goal: Continue centralizing implicit TLS and STARTTLS negotiation behavior behind focused private helpers.
- Success criteria:
  - Public commands remain orchestration-focused.
  - New transport behavior is covered by unit tests and, where practical, integration tests.

### Inspect Presented Certificate Chain
- Status: Planned
- Category: Certificate Inspection
- Complexity: Medium
- Goal: Report whether the server presents a usable certificate chain during the TLS handshake.
- Success criteria:
  - Output distinguishes the leaf certificate from any presented intermediate certificates.
  - Chain status reports missing intermediates, untrusted roots, name mismatch, expiration, and other runtime chain errors where available.
  - Documentation explains that validation depends on the local trust store and OS/.NET chain-building behavior.
  - Tests cover complete-chain, missing-intermediate, and untrusted-chain scenarios using local test certificates where practical.

### Replace Runtime C# Certificate Validation Callback
- Status: Planned
- Category: Security Compatibility
- Complexity: Medium
- Goal: Reduce EDR false-positive risk by replacing the runtime `Add-Type` implementation of `TLSleuth.CertificateValidationCallbacksV2` with a PowerShell delegate or closure that captures certificate validation state.
- Success criteria:
  - `Start-TlsHandshake` no longer compiles embedded C# at runtime for certificate validation callbacks.
  - Certificate validation state is still captured per connection or per `SslStream` without leaking state between concurrent or repeated handshakes.
  - `Get-TlsHandshakeDetails` continues to report `CertificateValidationPassed`, `CertificatePolicyErrors`, `CertificatePolicyErrorFlags`, and `CertificateChainStatus`.
  - Existing public output contracts remain unchanged.
  - Tests cover successful validation, skipped validation with captured errors, strict validation failure, and cleanup/state-isolation behavior.

### Default To Strict Certificate Validation
- Status: Planned
- Category: Security
- Complexity: Medium
- Goal: Change public command defaults so certificate validation is not skipped unless the caller explicitly requests inspection of invalid certificates.
- Success criteria:
  - `Get-TLSleuthCertificate` and `Test-TLSleuthProtocol` no longer default `-SkipCertificateValidation` to enabled behavior.
  - Users can still explicitly retrieve invalid or self-signed certificates with `-SkipCertificateValidation`.
  - README examples, compatibility notes, and release notes clearly call out the behavior change and migration path.
  - Tests cover default strict validation, explicit skip-validation behavior, and protocol-test failure reporting when validation is not skipped.
  - The release notes identify the change as user-facing and potentially breaking for scripts that relied on the previous default.

### Support LDAP StartTLS Certificate Retrieval
- Status: Planned
- Category: Protocol Support
- Complexity: Medium
- Goal: Retrieve certificates from LDAP servers that require StartTLS negotiation before the TLS handshake.
- Success criteria:
  - Public commands can request LDAP StartTLS inspection without changing existing implicit TLS behavior.
  - LDAP StartTLS negotiation is isolated behind private helper(s) with clear timeout and error handling.
  - Tests cover transport dispatch, successful StartTLS negotiation, and representative LDAP failure responses.
  - Documentation distinguishes LDAP StartTLS on port 389 from LDAPS implicit TLS on port 636.

### Support FTP Explicit TLS Certificate Retrieval
- Status: Planned
- Category: Protocol Support
- Complexity: Medium
- Goal: Retrieve certificates from FTP servers that require explicit TLS negotiation with `AUTH TLS`.
- Success criteria:
  - Public commands can request FTP explicit TLS inspection without changing existing implicit TLS behavior.
  - FTP `AUTH TLS` negotiation is isolated behind private helper(s) with clear timeout and error handling.
  - Tests cover greeting handling, `AUTH TLS` acceptance, and representative FTP failure responses.
  - Documentation distinguishes explicit FTPS on port 21 from implicit FTPS on port 990.

### Support PostgreSQL TLS Certificate Retrieval
- Status: Planned
- Category: Protocol Support
- Complexity: Medium
- Goal: Retrieve certificates from PostgreSQL servers by sending the SSLRequest packet before the TLS handshake.
- Success criteria:
  - Public commands can request PostgreSQL TLS inspection without changing existing implicit TLS behavior.
  - PostgreSQL SSLRequest negotiation is isolated behind private helper(s) with clear timeout and error handling.
  - Tests cover SSLRequest acceptance, rejection, and negotiation dispatch.
  - Documentation explains PostgreSQL-specific TLS negotiation behavior and limitations.

### Reduce Test Helper Duplication
- Status: Planned
- Category: Test Maintainability
- Complexity: Medium
- Goal: Consolidate repeated loopback server, certificate, and text-protocol helper code across STARTTLS integration tests.
- Success criteria:
  - SMTP, IMAP, and POP3 integration tests share common setup helpers where behavior is identical.
  - Protocol-specific assertions remain easy to read in each test file.
  - Test failures still point clearly to the protocol and step that failed.

### Normalize Text Protocol Response Parsing
- Status: Planned
- Category: Refactoring
- Complexity: Medium
- Goal: Reduce duplicated line-oriented protocol parsing patterns across SMTP, IMAP, POP3, and future text transports.
- Success criteria:
  - Shared helpers handle common response-line reading, multiline detection, status extraction, and timeout behavior where protocols overlap.
  - Protocol-specific grammar remains isolated where behavior differs.
  - Tests cover representative single-line, multiline, malformed, and timeout responses.

### Add CI Matrix for PowerShell Versions
- Status: Planned
- Category: CI/CD
- Complexity: Medium
- Goal: Run validation on Windows PowerShell 5.1 and PowerShell 7+ where practical.
- Success criteria:
  - CI clearly separates PowerShell 5.1 checks from PowerShell 7+ checks.
  - Runtime-specific expectations are documented and tested where behavior differs.
  - Compatibility failures identify the affected PowerShell version.

### Automate Helper Inventory Documentation
- Status: Planned
- Category: Documentation
- Complexity: Small
- Goal: Keep `docs/helpers.md` accurate without manually updating every private helper signature.
- Success criteria:
  - A script or Invoke-Build task can regenerate the helper inventory from `source/private`.
  - Generated helper entries include synopsis, file path, parameters, and defaults where detectable.
  - Documentation clearly separates generated inventory from manually maintained guidance.

## Longer Term

### Harden Integration Test TLS Setup
- Status: Planned
- Category: Test Reliability
- Complexity: Large
- Goal: Make loopback TLS integration tests more reliable across Windows runner environments and local developer machines.
- Success criteria:
  - Self-signed test certificate creation avoids machine-specific credential-store failures.
  - Integration tests document any OS/runtime prerequisites they still require.
  - `Invoke-Build IntegrationTest` has a clear skip or failure mode when environment support is unavailable.

## Complete

### Extract SMTP EHLO Name Resolution
- Status: Complete (implemented in 2.3.5)
- Category: Refactoring
- Complexity: Small
- Goal: Move SMTP EHLO fallback logic out of `Invoke-TlsTransportNegotiation` into a focused private helper.
- Success criteria:
  - SMTP EHLO resolution handles explicit options, legacy option shape fallback, local hostname fallback, and `localhost` fallback in one place.
  - `Invoke-TlsTransportNegotiation` no longer contains SMTP-specific option normalization logic.
  - Unit tests cover explicit EHLO name, legacy option fallback, and empty-hostname fallback behavior.

### Simplify Transport Dispatch Control Flow
- Status: Complete (implemented in 2.3.5)
- Category: Refactoring
- Complexity: Small
- Goal: Replace the per-call transport adapter scriptblock hashtable in `Invoke-TlsTransportNegotiation` with a simpler explicit dispatcher.
- Success criteria:
  - Dispatcher logic uses `switch -Exact` or an equally clear static control-flow pattern.
  - Existing behavior for `ImplicitTls`, `SmtpStartTls`, `ImapStartTls`, and `Pop3StartTls` remains unchanged.
  - Transport-specific helper calls remain easy to find with text search and easy to mock in tests.
  - Dynamic function-name dispatch is avoided.

### Extract Per-Transport Negotiation Adapter Helpers
- Status: Complete (implemented in 2.3.5)
- Category: Architecture
- Complexity: Medium
- Goal: Keep `Invoke-TlsTransportNegotiation` thin as new transports are added by moving transport-specific adapter orchestration into dedicated helpers.
- Success criteria:
  - Existing SMTP, IMAP, POP3, and implicit TLS adapter logic can be represented by focused private helpers or a clearly equivalent pattern.
  - Future RDP, LDAP, FTP, and PostgreSQL transport additions do not require bulky inline dispatcher logic.
  - Shared adapter inputs such as connection context, timeout, and transport options remain consistent.
  - Tests verify dispatcher routing and representative per-transport adapter behavior.

### Consolidate Timeout Handling
- Status: Complete (implemented in 2.3.5)
- Category: Reliability
- Complexity: Medium
- Goal: Make connection, stream, and handshake timeout behavior consistent across helpers.
- Success criteria:
  - Timeout conversion and validation are centralized or consistently applied.
  - Timeout errors include operation name, host/port where available, and timeout duration.
  - Tests cover connection timeout, protocol read timeout, and TLS handshake timeout paths.

### Improve Error Categorization
- Status: Complete (implemented in 2.3.5)
- Category: Reliability
- Complexity: Medium
- Goal: Standardize terminating errors for connection, transport negotiation, TLS handshake, and certificate extraction failures.
- Success criteria:
  - Common failure paths use consistent exception types and actionable messages.
  - Tests cover representative errors for each major stage.
  - Public command behavior remains script-friendly and avoids swallowing original exception context.

### Verify Transport Registration Alignment
- Status: Complete (implemented in 2.3.5)
- Category: Test Coverage
- Complexity: Small
- Goal: Keep supported transport names aligned across public `ValidateSet` declarations, private helpers, and dispatch branches.
- Success criteria:
  - Unit tests compare transport `ValidateSet` declarations across public and private entry points.
  - Unit tests verify dispatcher branches match registered transports.
  - Adding a new transport fails tests when any static transport list is missed.

### Consolidate Cleanup And Disposal Helpers
- Status: Complete (implemented in 2.3.5)
- Category: Reliability
- Complexity: Small
- Goal: Reduce repeated safe-disposal patterns while preserving clear resource ownership.
- Success criteria:
  - Common cleanup patterns use a small helper where ownership is unambiguous.
  - Cleanup failures remain visible through debug output.
  - Refactoring does not obscure which function owns each network or TLS resource.

### Support RDP Certificate Retrieval
- Status: Complete (implemented in Unreleased)
- Category: Protocol Support
- Complexity: Large
- Goal: Retrieve certificates from RDP servers by adding an RDP-aware transport path.
- Success criteria:
  - Public commands can request RDP certificate inspection without breaking existing transport behavior.
  - RDP negotiation is isolated behind private helper(s) with clear timeout and error handling.
  - Tests cover parameter handling, negotiation dispatch, and representative failure paths.
  - Documentation explains any RDP protocol limitations and runtime assumptions.

### Infer Transport From Common Ports
- Status: Complete (implemented in Unreleased)
- Category: Usability
- Complexity: Medium
- Goal: Reduce manual transport selection by inferring the likely transport from well-known port numbers when it is safe and predictable.
- Success criteria:
  - Inference covers supported transports such as implicit TLS, SMTP STARTTLS, IMAP STARTTLS, POP3 STLS, and RDP TLS.
  - Ambiguous or unsupported ports continue to require explicit `-Transport` selection or fall back to documented behavior.
  - Explicit `-Transport` values always override any inferred value.
  - Tests cover common ports, unknown ports, and explicit override behavior.

### Document RDP Troubleshooting
- Status: Complete (implemented in Unreleased)
- Category: Documentation
- Complexity: Small
- Goal: Make RDP certificate retrieval behavior, prerequisites, and common failures easy to troubleshoot.
- Success criteria:
  - Documentation shows `RdpTls` examples for the default RDP port and custom ports.
  - Documentation explains firewall/connectivity failures, RDP security negotiation rejection, NLA-related caveats, and TLS handshake failures.
  - Documentation states that RDP certificate retrieval requires the server to accept a TLS-capable RDP security negotiation.

### Add Optional RDP Integration Test
- Status: Complete (implemented in Unreleased)
- Category: Test Reliability
- Complexity: Small
- Goal: Allow live RDP certificate retrieval validation without making normal CI depend on a reachable RDP server.
- Success criteria:
  - Integration test runs only when an explicit environment variable or Invoke-Build parameter provides an RDP endpoint.
  - Test validates that `Get-TLSleuthCertificate -Transport RdpTls` reaches RDP negotiation and TLS certificate retrieval.
  - Default unit and integration test runs remain deterministic when no RDP endpoint is configured.

### Improve Transport Failure Examples
- Status: Complete (implemented in Unreleased)
- Category: Documentation
- Complexity: Small
- Goal: Help users understand common transport negotiation and TLS failure messages across supported transports.
- Success criteria:
  - README or docs include examples for selecting `Hostname`, `Port`, `Transport`, and `TargetHost`.
  - Documentation describes common failure messages for connection failures, transport negotiation rejection, timeout, and TLS handshake failure.
  - RDP-specific negotiation failures are included once `RdpTls` is released.

### Invoke-Build CI Baseline
- Status: Complete (implemented in 2.3.3)
- Category: CI/CD
- Complexity: Medium
- Goal: Provide basic repeatable CI tasks for analysis, validation, tests, build, and cleanup.
- Success criteria:
  - `Invoke-Build ?` lists discoverable tasks.
  - `Invoke-Build Test` runs unit tests.
  - `Invoke-Build Build` delegates to ModuleBuilder.
  - `Invoke-Build Analyze` fails clearly when `PSScriptAnalyzer` is missing.
  - Analyzer suppressions for intentional naming/API choices are captured in `PSScriptAnalyzerSettings.psd1`.

### Tag-Driven Release Workflow
- Status: Complete (implemented in 2.3.3)
- Category: Release
- Complexity: Medium
- Goal: Publish built TLSleuth releases to PowerShell Gallery from GitHub tags.
- Success criteria:
  - Release workflow validates tag format and module version alignment.
  - `Invoke-Build ValidateReleaseMetadata` verifies that `CHANGELOG.md` has an entry for the manifest `ModuleVersion`.
  - Release workflow runs `Invoke-Build Validate`.
  - Release workflow publishes the ModuleBuilder output from `output/TLSleuth`.
  - GitHub release notes are extracted from `CHANGELOG.md`.

### Preserve Output Contract Coverage
- Status: Complete (implemented in 2.3.4)
- Category: Test Coverage
- Complexity: Medium
- Goal: Maintain stable object shapes for `Get-TLSleuthCertificate` and `Test-TLSleuthProtocol`.
- Success criteria:
  - Contract-sensitive changes include Pester assertions for key properties and failure paths.
  - README output model examples stay aligned with implementation.

### Add Contract Snapshot Tests
- Status: Complete (implemented in 2.3.4)
- Category: Test Coverage
- Complexity: Medium
- Goal: Protect `TLSleuth.CertificateResult` and `TLSleuth.ProtocolTestResult` property names and value types from accidental drift.
- Success criteria:
  - Tests assert expected property sets for both public output contracts.
  - Tests distinguish intentional contract changes from accidental implementation churn.
  - Any intentional contract change updates tests and README output model documentation in the same change.

### Move Release Notes Extraction Into Invoke-Build
- Status: Complete (implemented in 2.3.4)
- Category: Release
- Complexity: Small
- Goal: Avoid duplicate changelog parsing in GitHub Actions by making Invoke-Build responsible for writing release notes.
- Success criteria:
  - Invoke-Build exposes a task that validates release metadata and writes `release-notes.md`.
  - The release workflow calls the task instead of embedding changelog regex logic.
  - The task is reusable for local dry-runs and CI releases.

### Improve CI Dependency Efficiency
- Status: Complete (implemented in 2.3.4)
- Category: CI/CD
- Complexity: Small
- Goal: Reduce GitHub Actions setup time and network dependency during validation and release workflows.
- Success criteria:
  - Workflow dependency installation is centralized or cached where practical.
  - Required module versions are pinned or minimum-bounded for reproducible runs.
  - Release workflow avoids redundant build, validation, or module-install work.

### Improve Compatibility Documentation
- Status: Complete (implemented in 2.3.4)
- Category: Documentation
- Complexity: Small
- Goal: Make PowerShell 5.1 versus PowerShell 7+ behavior differences easy to understand.
- Success criteria:
  - Runtime-dependent TLS fields are documented near examples that use them.
  - Compatibility constraints are captured before behavior changes rely on newer runtime features.

### Release Hygiene
- Status: Complete (implemented in 2.3.3)
- Category: Release
- Complexity: Small
- Goal: Keep release notes, module version, and implementation changes aligned.
- Success criteria:
  - `CHANGELOG.md` and `source/TLSleuth.psd1` `ModuleVersion` are updated together for releases.
  - Generated output is rebuilt only through ModuleBuilder.

### Refactor Common TLS Session Result Mapping
- Status: Complete (implemented in 2.3.4)
- Category: Refactoring
- Complexity: Medium
- Goal: Reduce duplication and drift between certificate result and protocol test result TLS/session properties.
- Success criteria:
  - Common TLS/session fields are mapped by a shared private helper or clearly shared pattern.
  - `TLSleuth.CertificateResult` and `TLSleuth.ProtocolTestResult` output contracts remain unchanged unless intentionally versioned.
  - Contract snapshot tests are in place before refactoring shared result mapping.

### Normalize Transport Adapter Shape
- Status: Complete (implemented in 2.3.4)
- Category: Architecture
- Complexity: Medium
- Goal: Keep transport dispatch readable as more protocols are added by giving each transport a consistent private-helper contract.
- Success criteria:
  - `Invoke-TlsTransportNegotiation` remains a thin dispatcher.
  - Each transport helper has a consistent parameter shape for connection context, timeout, and protocol-specific options.
  - Adding a new transport does not require bulky scriptblock logic inside the dispatcher.

### Extract Public Command Operation Context
- Status: Complete (implemented in 2.3.4)
- Category: Refactoring
- Complexity: Medium
- Goal: Reduce duplicated setup logic between `Get-TLSleuthCertificate` and `Test-TLSleuthProtocol`.
- Success criteria:
  - Shared option normalization covers timeout conversion, target host resolution, transport options, and connection context preparation.
  - Public command parameter contracts remain unchanged.
  - Tests cover default handling and pipeline-bound values for both public commands.

### Centralize Runtime TLS Capability Discovery
- Status: Complete (implemented in 2.3.4)
- Category: Compatibility
- Complexity: Small
- Goal: Make runtime-supported TLS protocol discovery reusable and easier to reason about.
- Success criteria:
  - Explicit protocol enumeration logic lives in one private helper.
  - `Test-TLSleuthProtocol` and protocol-conversion logic share consistent runtime assumptions.
  - Tests cover runtimes with missing protocol enum names where practical.

### Add Transport Negotiation Result Object
- Status: Complete (implemented in 2.3.4)
- Category: Architecture
- Complexity: Medium
- Goal: Return structured metadata from transport negotiation without changing public command output by default.
- Success criteria:
  - `Invoke-TlsTransportNegotiation` returns a consistent internal result shape for implicit TLS, STARTTLS/STLS transports, and future binary transports.
  - Result metadata can capture transport name, negotiation outcome, selected protocol/security mode where applicable, and diagnostic details.
  - Existing public output contracts remain unchanged unless a future feature intentionally exposes new fields.
  - Unit tests cover implicit TLS and at least one explicit TLS transport result.

### Normalize Transport Option Model
- Status: Complete (implemented in 2.3.4)
- Category: Architecture
- Complexity: Medium
- Goal: Make transport-specific options explicit enough to support protocols beyond SMTP without turning `TransportOptions` into an unstructured property bag.
- Success criteria:
  - Shared options such as timeout are clearly separated from protocol-specific options.
  - SMTP EHLO behavior remains unchanged.
  - Future RDP options can be added without changing public command orchestration flow.
  - Unit tests cover default options and protocol-specific option mapping.

### Define Binary Transport Helper Boundary
- Status: Complete (implemented in 2.3.4)
- Category: Architecture
- Complexity: Medium
- Goal: Keep binary protocol negotiation helpers separate from the existing line-oriented text protocol helpers.
- Success criteria:
  - RDP packet construction/parsing lives behind RDP-specific or binary transport helpers, not text protocol helpers.
  - Existing SMTP, IMAP, and POP3 helpers continue using `Read-TextProtocolLine` and `Send-TextProtocolCommand`.
  - Unit tests cover representative binary packet encoding/decoding without requiring a live RDP server.


## Prioritization Fields

For future roadmap items, useful fields are:

- Impact: User or maintainer value, such as low, medium, or high.
- Risk: Chance of regressions, release friction, or workflow disruption.
- Dependencies: Other tasks, secrets, tools, or decisions needed first.
- Confidence: How well understood the work is before starting.
- Validation: The check that proves the item is done.

