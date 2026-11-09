# Wonhee 0.15.28 — read-only DNS coverage and overnight continuity

This batch extends the safety-paused firewall frontend from PR #62. It **does not install or modify any firewall, route, VPN or DNS configuration**. No root capture, background monitoring, automatic recovery, automatic browser-configuration changes or bypass blocking occurs.

## Trigger and reproduced observations

- Wonhee's explicitly queried local DNS relay at `127.0.0.1:53535` returned `NOERROR` for `example.com` and `NXDOMAIN` for known advertising and tracker domains, including suffix matches under `doubleclick.net` and `googlesyndication.com`.
- On the tested Brave installation, manually turning off Brave's Secure DNS increased Turtlecute's browser ad-block score to 126/130 (97%). This demonstrates a practical browser-DNS coverage issue; it is **not** a measure of system-wide traffic protection or a proof of packet routing.
- A user-supplied PCAP comparison previously showed working WireGuard transport and Home Navidrome TCP after refreshing the tunnels, with different DNS response counts across overnight vs refreshed snapshots. No causal persistence failure has yet been established.
- Batch F's experimental all-traffic OUTPUT guard remains **hard-paused** following issue #41. An owned DNS-port interception policy can be verified independently.

## What the UI adds

In the read-only Preview dashboard → **Protection**:
1. "DNS COVERAGE & OVERNIGHT CHECK" distinguishes observed local DNS relay and tracker state from **unverified** browser-specific encrypted DNS.
2. A manual guidance dialog explains where to find Brave's Secure DNS preference. Wonhee never toggles it or Android Private DNS on behalf of a user.
3. "Save verified DNS baseline" persists **only** aggregate received/blocked/forwarded/failed DNS counters, relay PID, verified tunnel count, wall-clock and boot-monotonic time to app-private SharedPreferences. No DNS questions, application identities, IP addresses, packet payloads, HTTP URLs, keys or resolver endpoints are saved.
4. A live read-only comparison attempts to recognize listener/relay unavailable, tracker off, tunnel count/identity health change, PID change, counter reset, apparent reboot/clock change, or monotonic aggregate changes over the elapsed time.
5. The baseline can be cleared from the same tab. It does not start any background work. The existing dashboard poll (while visible) remains eight seconds.

**Limitations:** PID continuity and monotonic counters cannot prove uninterrupted service. A short network capture cannot prove an absence of leaks. The snapshot's relay identity and loopback listener do not re-audit live DNS-port rules: use **Audit live DNS firewall + relay** in Advanced Controls separately. Neither a green ad-block score nor the DNS listener's existence is a full-device kill-switch attestation.

## On-device acceptance checklist

1. The *side-by-side debug/rootlab* artifact uses a **different application ID and separate private storage** from the signed official app. It cannot read the official app's saved profiles or DNS ownership ledger, and therefore **cannot inspect the official app's live stack as its own verified session**. Preserve the existing signed app and its settings. If you choose to test rootlab networking, first use the verified Safe Stop in the official app, then deliberately import the needed profiles into rootlab; do not start two network stacks simultaneously. A same-signature official release update is a separate release process and is **not** provided by this PR.
2. Open the rootlab Preview → Protection. Confirm Batch F is safety-paused and DNS-port rules require a live audit. A disconnected rootlab or missing imported profiles must show unavailable/unverified, **not** reuse status from the official installation.
3. Only after starting a verified rootlab DNS/tunnel session with the normal advanced manager, tap **Save verified DNS baseline for overnight comparison**. Check the confirmation; no personal endpoint/domain should be printed.
4. Visit a browser website with Brave Secure DNS manually disabled; verify local `dig @127.0.0.1 -p 53535 example.com A` resolves normally and `dig @127.0.0.1 -p 53535 ad.doubleclick.net A` returns the expected blocking code. Android Private DNS stays in the user's known-working OFF configuration.
5. Leave the existing stack untouched overnight. Before restarting it, re-open the **same app/installation** Preview → Protection and read the differential report. Run live DNS firewall/relay and owned-guard audits in Advanced Controls. If changed, save screenshots and sanitized counts *before* Safe Stop.
6. In PCAPdroid, choose **Capture as root**, **Full payload OFF**, **MITM off**, **physical interface** for an optional bounded egress sample; never upload raw authenticated Navidrome PCAPs publicly.
7. Test the new preview's status with the relay stopped only *after* the full safe-stop operation; verify no DNS or tunnel starts from rendering the page. Do not intentionally simulate kill-switch failure on the daily-use device.

## CI gates

- Java pure-model tests exercise valid checkpoint persistence, invalid data refusal, clock/reboot discontinuity, PID changes, missing relay, tunnel drift, counter resets and deltas.
- Existing Android :app:assembleDebug, Go helper tests and native WireGuard CI must pass.
- **No release claim** until screenshots and device validation of the read-only UI; a successful debug APK compile alone is not an integrated all-traffic firewall fix.

Related: PR #62, issue #41, and separate Moka interop PR #61.
