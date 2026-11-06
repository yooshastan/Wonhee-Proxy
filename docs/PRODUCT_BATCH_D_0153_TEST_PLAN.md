# Wonhee Product Batch D: encrypted transport tests (0.15.3)

**Preview only.** Existing 0.15.2 verified kernel identities, split routes,
configured resolver routes, and one root-bound DoH query. Version 0.15.3 adds
optional **DoQ (UDP/QUIC)** and **DoH3 (HTTP/3/QUIC)** one-shot queries. Neither
build implements system-wide DNS forwarding, interception, DNS leak blocking, or
a network kill switch. **Batch D is not complete until those safeguards are
implemented and tested.** The security guide must continue reporting DNS
enforcement OFF and kill switch OFF.

## Before starting

1. Keep USB ADB ready. Do not remove the selected WireGuard profiles or the
   Wonhee-owned rollback ledger while routing overrides are installed.
2. Use an identity-verified, **UP** public Internet tunnel (for example
   `AirVPNEurope`). Do **not** route public DNS over a Home split tunnel unless
   that upstream destination is explicitly reachable through Home.
3. Open Multi-tunnel Lab, choose the selected/checked tunnel, and expand the
   advanced security controls. Choose a protocol under encrypted DNS:
   - **DoH**: Cloudflare `https://cloudflare-dns.com/dns-query`, bootstrap `1.1.1.1`, TCP 443.
   - **DoQ**: AdGuard `quic://dns.adguard-dns.com`, bootstrap `94.140.14.14`, UDP 853.
   - **DoH3**: Cloudflare `https://cloudflare-dns.com/dns-query`, bootstrap `1.1.1.1`, UDP 443.
4. Tap **Test ROOT-bound ...**, review the opt-in prompt, then test. The test
   never enables DNS service/forwarding, modifies route/DNS/firewall state,
   resolves the upstream hostname via Android, or retries on another tunnel.

## Expected results

- On a selected tunnel with a matching numeric upstream route: exactly one
  DNS A query for `example.com`, bound via `SO_BINDTODEVICE`, with verified
  TLS hostname, DNS question/transaction, and one or more IPv4 A answers.
- Select the Home split tunnel with a public resolver upstream: **REFUSED**
  if the upstream root route does not use the chosen Home interface.
- Bad numeric bootstrap, bad protocol URL, absent interface, TLS failure,
  or unreachable server: **REFUSED**. No direct/plaintext fallback.
- Protocol UDP transport may be unavailable on some networks. That is a
  refusal, **not** an invitation to try the system/default network.

## Read-only independent routes (both methods)

**Computer / USB ADB:**

```bash
adb shell su -c 'ip -4 route get 1.1.1.1'
adb shell su -c 'ip -4 route get 94.140.14.14'
adb shell su -c 'ip -4 route get 10.6.0.1'
adb shell su -c 'ip -4 rule show' | grep -E '^12[5-7][0-9][0-9]:'
```

**Termux directly on phone:**

```bash
su -c 'ip -4 route get 1.1.1.1'
su -c 'ip -4 route get 94.140.14.14'
su -c 'ip -4 route get 10.6.0.1'
su -c 'ip -4 rule show' | grep -E '^12[5-7][0-9][0-9]:'
```

These **UID-0 route lookups** do not establish application-level DNS routing,
absence of leaks, or kill-switch enforcement. They may differ from app traffic
because Android uses per-UID policy and network marks.
