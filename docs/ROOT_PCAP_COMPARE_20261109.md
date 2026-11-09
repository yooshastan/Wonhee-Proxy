# Wonhee 0.15.27 — sanitized comparative PCAP evidence, November 9, 2026

**Captured by PCAPdroid root mode, all interfaces, classic PCAP.** No raw PCAP, endpoint public addresses, credentials, tokens, private DNS queries, or application payloads are included in the repository. The source captures are user-provided and are not committed.

## Three test windows

| State | Duration | Packets | UDP DNS requests / responses | DNS NXDOMAIN responses | Home Navidrome TCP 4533 observed |
| --- | ---: | ---: | ---: | ---: | --- |
| Overnight state, before restart | 148.3 s | 98,699 | 13 / 13 | 0 | Yes |
| Safe Stop / tunnel refresh window | 92.5 s | 4,574 | 28 / 28 | 2 | No (other private TCP observed) |
| Refreshed, stable tunnels | 269.6 s | 145,390 | 46 / 46 | 20 | Yes, including HTTP 200 and 206 responses |

Packet numbers span multiple network interfaces, including tunnel-inner traffic. **Do not sum them as unique physical egress or use them to infer loss rate.**

## Positive evidence

- Two distinct WireGuard UDP transports were visible before and after refresh.
- Refreshed Internet tunnel carried TCP/HTTPS sessions; Home tunnel carried private Navidrome TCP in both directions with HTTP 200 / 206 (partial-content) responses.
- Refreshed capture recorded 46 DNS requests directed to localhost port 53535, with 46 associated responses. 20 NXDOMAIN responses are consistent with blocked tracker-like destinations; response code alone is not definitive blocklist attribution.
- During stable refreshed recording, no phone-address-to-public-IP TCP/80, TCP/443, or UDP/53 flow was observed outside the two known WireGuard transports. Two low-count UDP/4500 phone-to-public packets were observed, requiring app/process attribution before assigning meaning.

## Transient evidence that warrants follow-up

- During the 92.5-second tunnel refresh, two outgoing plaintext IPv6 UDP/53 queries targeted the local router resolver for the Internet VPN peer bootstrap hostname.
- The same transition window also showed short direct underlay public UDP/443 (QUIC) and IPv6 TCP/80,443 connections. This is compatible with the known absence of an all-traffic kill switch during managed Safe Stop / reconnect; it **does not** prove a leak while both tunnels were stable.
- Do not interpret the 20 DNS NXDOMAINs as a full ad-block score, device-wide DNS policy proof, or evidence that HTTPS-based app-specific DNS is covered.
- The dashboard's Batch H.1 “Full stack started” message verifies the initial startup operation, not uninterrupted overnight service.

## Proposed diagnostic follow-up (guard OFF)

1. While freshly connected, run read-only live DNS policy/relay and IPv4/IPv6 guard audits and record only redacted state, counters, and time.
2. Keep the stack running overnight. Before refreshing, repeat the same audits, handshake-age/byte-counter comparison, local DNS listener check, and PCAPdroid capture.
3. Compare DNS listener persistence, exact-owned DNS-port interception, VPN route/endpoint identity, post-refresh DNS reply counts, and blocker counter deltas. Distinguish relay-sourced from app-owned DNS-over-HTTPS where possible.
4. In a **separate** controlled browser test, compare Brave Secure DNS ON vs OFF without changing Android Private DNS (keep Android Private DNS OFF for this environment).
5. For underlay attribution, run a short, isolated physical-interface capture (`wlan0`) after verification; the all-interfaces file merges physical and tunnel-inner packets and lacks per-packet physical-interface labels. Avoid logging plaintext Navidrome HTTP headers.
6. Attribute the two UDP/4500 packets read-only, avoiding assumptions about their producer.

## Security boundaries

- **Do not re-enable Batch F guard**; issue #41 remains unresolved.
- Do not flush firewall rules, toggle Android Private DNS, or break healthy tunnels to create packet samples.
- PCAPdroid’s “Full payload” was ON when supplied: raw captures can include private Navidrome HTTP paths, tokens and other sensitive data. Keep raw PCAPs private; use sanitized summaries only. Prefer payload capture OFF for further firewall egress testing.
- No packet capture by itself can prove all-traffic fail-closed protection, Android netfilter OUTPUT provenance, or source UID of the IPv6 control traffic.

These findings belong to a follow-up **overnight lifecycle + firewall/DNS persistence** investigation, separate from PR #62's non-enforcing UI changes.
