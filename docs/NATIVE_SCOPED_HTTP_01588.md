# 0.15.88 concurrent scoped HTTP diagnostic

0.15.87 device passed three real peers, six protected sockets, TCP connect and one TUN packet in each direction per peer. Earlier bind failed; exact errno unknown. This increment waits for stable VPN visibility and retries only pre-connect binding, with per-slot stage names and bounded attempts. No unbound retry.

Two concurrent explicitly bound TCP sockets per peer, registered once in native session; exact local ports enforced by both Java and native. Bounded HTTP/1.1 header responses with fixed GET /, no credentials/cookies/redirects; exits layer verified TLS with cloudflare-dns.com over already-bound sockets, Home uses explicit private HTTP target. All flows require response status and positive payload counters both ways, then a three-second settling window. Counts include TLS records and retransmissions, not throughput. Does not read full body or prove long-lived streaming. No DNS lookup, UDP, general routing or production kill switch; deferred. Native queue enlarged to 128 for bounded test. Existing profiles still isolated in new debug package. Device validation required.

Home must be a user-controlled HTTP service, not arbitrary private service. No changes to original profiles or AllowedIPs beyond narrowing to the authorized host.
