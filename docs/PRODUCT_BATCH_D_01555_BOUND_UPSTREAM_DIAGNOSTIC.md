# Wonhee 0.15.55 — bound encrypted DNS preflight diagnosis

**Status:** Draft diagnostic candidate. This does not fix an upstream connection. It tells us which upstream failure category occurs **before** starting the local relay, preserving all existing no-fallback and rollback behavior.

## Grounded failure / device evidence

- Root Home 0.15.54 selected two tunnels; encrypted DNS activation failed with `LOCAL_DNS_TIMEOUT`: the local UDP relay did not answer its health query within nine seconds.
- H.1 automatic Safe Stop reported two selected tunnels verified down, owned DNS verified off, owned split routes verified clear, and unattended recovery manually stopped.
- Independent H.2a **read-only** audit explicitly reported `CLEAN_STOPPED` (no stale owned state); Termux read-only check also found no Wonhee interfaces, local DNS listener, or matching DNS NAT rules. Android Private DNS **OFF**.
- **The cause is still unknown.** Go's strict local relay intentionally returns no DNS response if its encrypted upstream fails; therefore local timeout alone cannot distinguish TCP/TLS, device bind, HTTP response, DNS data, or slow local processing.

## New exact-stage preflight

After verifying the chosen WireGuard identity, exact root route to encrypted DNS bootstrap, firewall collision absence, and free local relay port, the controller prepares the *existing bundled native helper*. **Before spawning the relay** it runs the helper once in probe mode, with the same validated protocol, endpoint, bootstrap address and **selected kernel WireGuard interface**.

- The Go helper binds the transport socket to the exact interface using `SO_BINDTODEVICE`, validates TLS for the chosen hostname and verifies a DNS A-answer; DoH/DoH3/DoQ keep their original helper semantics.
- The Java adapter accepts **only a single strictly formatted helper result** and converts it to a privacy-safe stage; extra stdout, raw error text and arbitrary output are refused as `UPSTREAM_PROBE_UNAVAILABLE`.
- If the probe fails, **no local DNS process is launched, no owned DNS firewall rule is installed, no DNS ownership ledger is committed and no direct/plaintext alternative is tried**.
- The calling Home root flow retains its existing automatic H.1 `stopManagedStack` rollback, then shows a safe stage plus guidance. It does not disable Android Private DNS or propose insecure fallback.
- Only if the one-shot probe succeeds does Wonhee proceed to start the local relay, query loopback, test tracker blocking, commit ownership and install the existing DNS interception rules.

## Sanitized outcome categories

| Category | What it establishes | What it does **not** establish |
|---|---|---|
| `UPSTREAM_INTERFACE_UNAVAILABLE` | Selected WireGuard interface absent during probe | Cause of interface disappearance |
| `UPSTREAM_BIND_FAILED` | Native socket could not be bound to required interface | Root source of bind failure |
| `UPSTREAM_CONNECT_TLS` | Strict bound TCP/TLS/HTTPS connection did not complete | Whether route, TLS, ISP, upstream, or latency was root cause |
| `UPSTREAM_HTTP_INVALID` | Bound encrypted server responded with unexpected status or content type | Which backend component rejected the request |
| `UPSTREAM_REPLY_INVALID` | Server DNS answer was missing/malformed/oversized | Whether server is compromised |
| `UPSTREAM_PROBE_UNAVAILABLE` | Trusted one-shot result was not produced | Any specific upstream failure |
| `LOCAL_DNS_TIMEOUT` *after successful upstream probe* | Local relay still did not answer in its existing timeout | Whether loopback IPC, relay timing or subsequent upstream connectivity was responsible |

## Safety constraints

- No live capture, remote telemetry, private key logging, raw queried domain logging, resolver URL or bootstrap/IP output.
- No packet routing changes except the existing explicit user-approved Start workflow, with its existing rollback.
- Do not increase timeout or silently use device DNS, public DNS without a tunnel, Wi-Fi, cellular, or a different VPN.
- Retain existing exact-owned routing, DNS firewall and rollback controls unchanged.
- The all-traffic kill switch remains **paused**; this is *not* a kill-switch release.
- Repeated manual Start attempts are not evidence. One controlled test after CI + local original-signed install is sufficient to identify the next stage.

## Next on-device validation

1. Pass Android/native CI, pure sanitizer unit tests and verify the app uses versionCode **102** with the **existing release keystore**.
2. Stop and independently obtain `CLEAN_STOPPED` **before installing**; preserve original signed install data.
3. With USB/ADB recovery available and Private DNS OFF, select the same Internet and private tunnel once, explicitly press Start, and capture only the sanitized error screen.
4. If the bound probe returns `UPSTREAM_CONNECT_TLS` or `UPSTREAM_BIND_FAILED`, investigate the exact selected tunnel and port without attempting fallback.
5. If upstream probe passes but local relay still times out, investigate local UDP/relay scheduling and allowlist/parser separately.
6. Verify any failed Start ends with H.1 Safe Stop and an independent read-only H.2a `CLEAN_STOPPED`; stop testing if rollback is incomplete.
7. Do not label Product D or Product I (beta) complete from a successful diagnostic probe.

The parent UI PR remains a draft; develop this diagnostic in a child PR to avoid mixing the safe observed 0.15.54 Home UI with an unvalidated DNS change.
