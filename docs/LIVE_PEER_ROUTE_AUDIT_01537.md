# Wonhee 0.15.37 — Read-only live public socket peer route selection

## Why this follows 0.15.35

The Pixel 8a owner captured public Wi-Fi underlay traffic attributed by PCAPdroid to Google Messages QUIC/UDP443 and Google Play services IPv6 TCP5228, alongside normal Android-owned carrier IPsec UDP500/4500 (Wi-Fi Calling enabled). KDE Connect to Fedora port 48874 is LOCAL LAN traffic, not an Internet bypass. No plain port-53 DNS or port-853 DoT was observed in reviewed physical captures.

0.15.35's short bounded watch then **observed an actual socket of Google Messages carrying mark 0xf009f (protected-from-VPN bit set)**, plus normal mark 0xc009f; Google Play services also had a protected-marked socket. But old fixed-public-address route simulations do not tell us what route would be selected for each live socket's actual peer.

This branch inspects the **numeric public peer address, observed UID, and explicit mark from the same live socket record** and performs a READ-ONLY kernel route lookup for that actual peer/UID/mark combination. It still does not observe packet egress or establish that the observed socket generated a specific historical PCAP flow.

## New opt-in control

Advanced Controls: select every active Home/Internet tunnel, then tap:

**Compare actual public socket peer routes · read only**

The bounded short watch uses existing root iproute2 ss to inspect TCP/UDP via kernel netlink, WITHOUT Internet or DNS probes. The existing Stop live socket watch button stops new sampling/route queries after the current read-only command finishes. Time cap: at most 48 samples OR a 15-second monotonic sampling deadline; the current command could finish after the deadline, so this is not a process-kill timer.

Before any inspection the app verifies each selected WireGuard identity is UP; every running Wonhee tunnel is selected; split-route ledger and exact live owner rules match; and current installed Android 1000, Google Messages, and GMS/compatible microG UIDs are resolved dynamically. Historic PCAP UID numbers are never guessed if packages are unavailable.

## Data minimization and safety

Each socket is considered only when there is precisely ONE readable target UID and explicit 32-bit fwmark, plus a strict numeric **global public IPv4/IPv6** peer and numeric port. Malformed/ambiguous inputs, missing marks, wildcard/unconnected sockets, private/LAN/CGNAT/ULA/link-local/multicast and documentation networks are skipped. Therefore KDE Connect, local Navidrome, and other private traffic do NOT get classified as public Internet egress.

Only 6 distinct candidate combinations per UID and 18 total candidates are kept transiently; only 18 read-only route lookups can be made per invocation. If caps or errors occur, report is PARTIAL, not 'safe'. The user-facing report shows only per-UID counts by normal/protected mark and predicted Internet VPN/physical Wi-Fi/other selected tunnel/unknown category, never endpoints.

Do not print, persist, export, or journal any peer IPs, local IPs, ports, private keys, RCS data, socket cookies/inodes, process IDs, DNS queries, or raw root shell output. Short-lived in-memory peer literals are used only for the local read-only route query.

## Important interpretive boundary

**Actual-peer route prediction is STILL NOT actual packet egress proof.** Apps may use network-bound sockets, Android fwmark selection, changed kernel rules, or connections which no longer exist. A previous PCAPdroid observation is independent evidence of public underlay traffic; without exact time/port/socket correlation, it cannot be linked to one sampled socket mark. Do not claim that RCS content was exposed or that the all-device VPN is leak-free.

## Preserved behavior and test process

- No changes to WireGuard, DNS relay/DoH, tracker filtering, iptables, split routes, app package settings, RCS, Google services, Wi-Fi Calling, KDE Connect, or Safestop.
- All-traffic Batch F guard stays PAUSED. Android Private DNS stays OFF for the user's Wi-Fi behavior.
- This is candidate version 0.15.37 / versionCode 84, based on 0.15.36 DNS diagnostics. Native, Android and pure Java parser tests must pass before on-device update.
- If opting in to a signed build, H.1 Safe Stop and H.2a CLEAN_STOPPED come FIRST. Build with the original release keystore and install only via the guarded Fedora updater; never replace the installed official app with a debug/rootlab build.
- After reconnecting, check DNS audit, Internet browsing, Navidrome and RCS/notification behavior. Run new audit once without provoking a network outage.
- Intermittent LOCAL_DNS_HEALTH/LOCAL_DNS_TIMEOUT/LOCAL_TRACKER_HEALTH/LOCAL_TRACKER_TIMEOUT startup failures remain separately tracked; this branch does not claim to fix them.

## Follow-up

Review on-device route-category counts. Any opt-in alerting/blocking policy needs separate compatibility testing for RCS, carrier IMS/Wi-Fi Calling and Android protected sockets. No blanket drops or automatic guard activation are introduced here.