# RDP Troubleshooting

`RdpTls` retrieves the certificate presented by an RDP service after the
initial RDP security negotiation succeeds. It is useful when port 3389 does
not start with TLS immediately, which means `ImplicitTls` cannot retrieve the
certificate directly.

## Basic Usage

Use the default RDP port:

```powershell
Get-TLSleuthCertificate -Hostname rdp.example.com -Port 3389 -Transport RdpTls
```

Use a custom RDP port:

```powershell
Get-TLSleuthCertificate -Hostname rdp.example.com -Port 3390 -Transport RdpTls
```

When connecting by IP address, use `-TargetHost` for SNI and certificate name
validation:

```powershell
Get-TLSleuthCertificate `
  -Hostname 192.0.2.10 `
  -Port 3389 `
  -Transport RdpTls `
  -TargetHost rdp.example.com
```

## Requirements

RDP certificate retrieval depends on the server accepting an RDP negotiation
request that includes TLS-capable security protocols. TLSleuth requests the
RDP `Ssl`, `Hybrid`, and `HybridEx` security protocols before starting the TLS
handshake.

If the server rejects that negotiation or only allows standard RDP security,
TLSleuth cannot retrieve a TLS certificate from that endpoint.

## Common Failures

### Connection Refused Or Timed Out

The host is unreachable, no service is listening on the requested port, or a
firewall is blocking the connection.

Check:

- The hostname or IP address.
- The port number.
- Local and remote firewall rules.
- Whether RDP is enabled on the target server.

### RDP Negotiation Rejected

The TCP connection succeeded, but the server rejected TLS-capable RDP security
negotiation before the TLS handshake started.

Common causes:

- The server requires a security mode TLSleuth does not request.
- The endpoint is not an RDP service.
- A gateway, proxy, or security appliance is responding instead of the RDP
  server.
- Server policy does not allow the requested RDP security negotiation.

### NLA Or Security Policy Caveats

Network Level Authentication usually occurs after the RDP security negotiation
selects a TLS-capable mode. TLSleuth does not authenticate to the RDP server;
it only negotiates far enough to start TLS and inspect the certificate.

If policy rejects negotiation before TLS starts, TLSleuth reports the
negotiation failure instead of a certificate result.

### TLS Handshake Failure

RDP negotiation succeeded, but the TLS handshake failed. Typical causes
include disabled TLS versions, OS TLS policy, unsupported cipher suites, or
certificate validation behavior.

Try:

```powershell
Test-TLSleuthProtocol -Hostname rdp.example.com -Port 3389 -Transport RdpTls
```

This returns one row per available TLS protocol so you can see which protocol
attempts succeed or fail.

## Optional Integration Test

TLSleuth includes an opt-in RDP integration test. It is skipped by default so
normal CI does not require access to an RDP server.

Set `TLSLEUTH_RDP_HOST` before running integration tests. Optionally set
`TLSLEUTH_RDP_PORT` and `TLSLEUTH_RDP_TARGETHOST`:

```powershell
$env:TLSLEUTH_RDP_HOST = 'rdp.example.com'
$env:TLSLEUTH_RDP_PORT = '3389'
$env:TLSLEUTH_RDP_TARGETHOST = 'rdp.example.com'
Invoke-Build IntegrationTest
```
