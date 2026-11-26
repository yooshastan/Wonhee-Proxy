# 0.22.3 DNS packet evidence

0.22.2: AdGuard DoQ timed out on both addresses and both exits; AdGuard DoT primary Exit A returned an authenticated answer. Quad9 DoQ and Cloudflare DoH3 passed. Do not raise retries or change endpoint automatically.

- Socket-boundary aggregate datagrams, size bounds and errors plus last timeout tx/rx. TUN counters are accepted injection and delivered return for registered relay tuples; not physical packet capture. Socket snapshots are taken at exchange completion and exclude later idle/close traffic. No packet payload or query names logged. Zero received at socket does not prove the upstream never sent a packet.
- Explicit experimental AdGuard DoH3: same configured primary/secondary IP, dns.adguard-dns.com, UDP 443, authenticated h3 only. No fallback. Reachability requires device testing.
- Existing circuit limits unchanged; health displays last handshake-timeout evidence.

- Protection offers an explicit functional TCP DNS and HOSTS probe. A separate bounded worker binds to the existing VPN Network and TUN source address; the service recognizes only the exact registered own-UID local port to virtual TCP DNS:53 and still applies DNS port policy. No new external routing permission. Tests one valid imported HOSTS entry for NXDOMAIN and a rising block counter (concurrent unrelated blocks may also contribute), then a fixed public name for a valid answer. Public response may be cached. No queried domain name logged. Empty or unusable list skips HOSTS. Test socket closed on relay retirement. Device verification required.
