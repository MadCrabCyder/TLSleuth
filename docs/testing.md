# Testing

## Test Strategy
- Unit tests verify pure logic and parameter behavior.
- Integration tests verify external interactions (network/filesystem) only when needed.
- Favor deterministic tests that run locally and in CI.

## Folder Convention
```text
source/tests/
  unit/
  integration/
```

If `unit` and `integration` do not exist yet, create them when adding the first tests.

## Pester Guidelines
- Use Pester 5 style `Describe`/`Context`/`It` blocks.
- Name tests to describe behavior, not implementation.
- Mock external calls aggressively in unit tests.
- Assert on object properties and error behavior.

## Coverage Priorities
- Parameter validation and defaults.
- Success-path object shape.
- Failure-path error messages and categories.
- Regression cases for reported defects.

## Running Tests
```powershell
Invoke-Build Test
```

`Test` runs unit tests only. Integration tests perform live TLS or STARTTLS handshakes and should be run explicitly:

```powershell
Invoke-Build IntegrationTest
```

The RDP integration test is opt-in because it requires a reachable RDP server.
Set `TLSLEUTH_RDP_HOST` before running integration tests. `TLSLEUTH_RDP_PORT`
defaults to `3389`, and `TLSLEUTH_RDP_TARGETHOST` can be set when connecting
by IP address but validating a DNS name:

```powershell
$env:TLSLEUTH_RDP_HOST = 'rdp.example.com'
$env:TLSLEUTH_RDP_PORT = '3389'
$env:TLSLEUTH_RDP_TARGETHOST = 'rdp.example.com'
Invoke-Build IntegrationTest
```

For a full local validation pass after installing all build dependencies:

```powershell
Invoke-Build Validate
```

PSScriptAnalyzer settings live in `PSScriptAnalyzerSettings.psd1`.
