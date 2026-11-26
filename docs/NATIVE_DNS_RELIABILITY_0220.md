# Wonhee 0.22.0 DNS reliability preview

Baseline: 0.21.0 device tests verified Quad9 DoQ, Quad9 DoH3, Cloudflare DoH3, local TCP DNS and cache/hosts operation. AdGuard DoQ failed its initial test; retry without queries was inconclusive.

- Up to four exclusively leased QUIC connections per relay generation, reused for at most 128 successful exchanges or 30 seconds idle. Each connection owns an exact VPN-bound connected UDP socket and native handle. No unbound socket, alternate destination, plaintext or protocol fallback.
- DoQ uses successive bidirectional streams; DoH3 uses persistent HTTP/3 transport with a single allowed dial per connection. Four independent worker slots permit parallel exchanges. No 0-RTT DNS requests.
- Failure discards the connection; consecutive QUIC failures trigger bounded 2–16 second backoff, with SERVFAIL for new uncached requests during backoff. Local HOSTS and cache remain available.
- Coalesce identical normalized wire queries excluding ID, at most 68 keys and 16 waiters per key. Restore each caller's ID. Distinct wire questions/flags never merge.
- New counters: QUIC attempts and verified/failed exchanges; opened/reused/closed connection counts; backoff, timeout, certificate, socket, invalid and other errors; DNS coalesced counts additional waiters. Authenticated and failed count upstream jobs, not each coalesced waiter. Idle registered sockets are intentional until expiry/stop/recovery.
- Startup reasons distinguish permission, native library, Private DNS, existing VPN and missing validated physical network. The last suggests checking firewall/connectivity; it does not identify AFWall+ with certainty. Android validation and fail-closed routing remain unchanged.
- Local TCP DNS and DoT remain supported. Independent leak tests, repeated real provider tests, backoff and lifecycle/recovery tests are still required. AdGuard endpoint unchanged; no claim of a provider-specific fix.

Successful upstream exchange latency is tracked separately from local answers, using sample count, total milliseconds and maximum. Packet-drop reports distinguish unknown TCP/UDP owners, fixed DNS (subset), IPv4 TCP/UDP parser rejection, other IPv4 protocols and invalid version/header. No new packets are admitted by the diagnostics.
