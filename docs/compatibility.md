# Compatibility

## Supported PowerShell Versions

TLSleuth targets PowerShell 7+ first and supports Windows PowerShell 5.1 with reduced TLS/session detail where the runtime or OS does not expose newer properties.

## Runtime Differences

Some output fields depend on `.NET` and OS TLS stack support:

- `NegotiatedCipherSuite` may be unavailable on Windows PowerShell 5.1.
- `NegotiatedApplicationProtocol` may be unavailable on older runtimes.
- TLS protocol and cipher availability depends on OS policy.
- TLS 1.3 support depends on runtime and operating system support.

## Testing Expectations

Unit tests should avoid assuming runtime-specific TLS fields are always populated. Compatibility-sensitive changes should document expected PowerShell 5.1 and PowerShell 7+ behavior before implementation.
