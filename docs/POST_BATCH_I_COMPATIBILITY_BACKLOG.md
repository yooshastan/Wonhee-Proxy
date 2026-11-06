# Post–Product Batch I application compatibility backlog

This backlog **does not renumber or expand Product Batches A–I**. Address after completing and testing the agreed schedule in `docs/PRODUCT_BATCH_ROADMAP_A_I.md` (on main).

## Moka Music Player + simultaneous root tunnels

- **Reported:** Moka Navidrome network login works when the phone uses a conventional VPN, but fails when Wonhee runs independent Home + AirVPN WireGuard kernel tunnels together.
- **Observed comparison:** Browser reached `10.0.0.169:4533` via Home `wnma292ddb4b6da`; filtered tcpdump showed bidirectional TCP payload traffic. A later Moka connection attempt showed `0 packets` on that Home interface under a scoped `tcpdump` filter. Moka displayed a generic network connection failure, with no reported logcat error.
- **Do not conclude yet:** Whether Moka rejects the HTTP URL, uses a different Android network/fwmark, is blocked by Android cleartext policy, contacts another destination, or encounters Navidrome authentication. The browser success establishes server reachability from *that browser*, not Moka socket routing.
- **When due:** Compare Moka's actual app UID, URL normalization/scheme, `NetworkSecurityConfig`/cleartext allowance, per-socket `Network` binding, outgoing socket fwmarks/policy rules, and actual app-UID route with browser route. Capture scoped packet headers and detailed application network errors without credentials. Validate both LAN `http://10.0.0.169:4533` and an unrelated user's own HTTPS Navidrome endpoint.
- **Done when:** Multiple VPN tunnels can coexist while Moka connects and streams reliably to user-configured addresses (not hard-coded endpoints), and single VPN plus non-VPN operation remain unchanged. Provide a signed, certificate-continuous Moka update for its store distribution separately.

Owner: Moka/Wonhee integration regression. Priority: after Product Batch I beta validation, unless the user explicitly reprioritizes.
