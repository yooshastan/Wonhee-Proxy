# Wonhee 0.15.31 — Connected-but-no-Internet passive incident report

**Base:** 0.15.30 dashboard telemetry preview in PR #66, which is based on the successful locally signed 0.15.29 root dual-WireGuard stack (PR #65).

## Why this exists

The user's 2026-11-09 PCAP showed both WireGuard UDP transports exchanging packets, local DNS relay answering with filtered results, and at least two Internet TCP SYNs retransmitting without a captured response. Ordinary Internet service returned immediately upon the user's H.1 Safe Stop. That suggests a Wonhee-associated path/routing/peer problem but **does not prove a specific failure mode**. More in-app evidence is required before Safe Stop removes the live state.

## How to use it

With the connected tunnel stack still running, open **Advanced Controls → Connection Controls**, select **every active saved profile**, and tap **Connected but no Internet · read-only snapshot**. The on-device report includes:

- A local timestamp and selected vs unexpected running Wonhee interface count
- For each selected interface, strict public-key identity match, UP state, most recent handshake age, total WireGuard RX/TX and a short (1.5 second) passive byte-counter delta
- Read-only, mark-aware route prediction for its numeric WireGuard peer endpoint (endpoint address, port and keys withheld)
- Exact stored vs live reserved 12500–12799 Home split-routing rules and representative private/public IPv4/IPv6 route selection plus Android fwmark/UID simulations
- Active DNS ownership and exact live firewall rules, local relay process/listener status, verified aggregate relay counters (no domains)
- All-traffic guard ownership/preflight and a reminder that it remains paused

One button creates **no DNS query, TCP connection, ping or packet injection**. All probes are reads of existing kernel state (root shell, `wg show`, `ip route get`, `ip rule show`, firewall listing and relay statistics). It does not open a packet capture, rotate a VPN profile, reconnect peers, modify policies, write to SharedPreferences, stop the tunnel or enable any guard. If profile selection or tools are unavailable, the result includes a stage-specific refusal and prior evidence must not be interpreted as success. The user can use existing Safe Stop immediately instead of collecting diagnostics.

A short counter window is **not proof of Internet reachability**; idle tunnels may have no counter growth. Handshake >180 seconds is marked possibly idle/stale, never automatically diagnosed as broken. Even a report with all verified stages cannot establish leak-freedom or whole-device fail-closed behavior.

## On-device acceptance

1. Keep the proven local signed 0.15.29 or 0.15.30 running while review/CI completes. Do not install debug rootlab artifacts over the official package.
2. On a known healthy pair, select both Home + AirVPN profiles and run the new read-only snapshot, then verify that Internet, local DNS relay and Navidrome remain working. Output must contain no profile private keys, numeric VPN peer endpoints or DNS upstream URLs.
3. Confirm two short counter samples are captured (zero delta should say idle/inconclusive). Inspect routing 3/3 and Internet IPv4/IPv6 predictions, active DNS ownership and guard PAUSED.
4. If ordinary Internet next fails unintentionally, capture the snapshot once **only if quick and practical**, then use Batch H.1 Safe Stop for recovery. Do not deliberately break routing/Wi-Fi or enable Batch F for testing.
5. Store only a sanitized report. Do not post raw PCAP, WireGuard config or network endpoint addresses publicly.
6. Before installing any future signed candidate, use H.1 Safe Stop + H.2a CLEAN_STOPPED and the independently guarded Fedora APK installer. Confirm preserved profiles, AirVPN egress, Navidrome, DNS local filtering and safe-stop again.

## CI

`RootInternetIncidentEvidenceTest` confirms safe formatting, fail-closed counter resets, handshake warning semantics, and exact saved/live route-ownership conditions. Android build and native dual-WireGuard tests are mandatory. These unit tests do not substitute for Pixel 8a device QA.

**No automatic retry/recovery, kill switch, direct DNS fallback, or full-device leak-protection claim is introduced in 0.15.31.**
