# Wonhee 0.15.34 — Passive socket UID/fwmark evidence

## Reason for this batch

PCAPdroid captured phone-originated public traffic outside the recognized AirVPN/Home WireGuard UDP transports, including QUIC UDP/443 attributed to Google Messages, brief IPv6 TCP/5228 exchanges attributed to Google Play services / earlier microG, and Android system IPsec UDP/4500 consistent with Wi-Fi Calling. On-device 0.15.33's read-only kernel UID/mark route predictions reported expected AirVPN for unprotected marks and physical `wlan0` for Android's `protectedFromVpn` bit `0x20000`.

**That still does not demonstrate what marks the real sockets used.** The purpose of 0.15.34 is to attempt to observe live socket owner UIDs and fwmarks, without changing the network stack or reading payloads.

## New opt-in control

**Advanced Controls → Inspect live socket marks (Messages / Play / Android) · read only**, with all active profiles selected.

The procedure:
1. Verifies kernel WireGuard public identities, all selected running tunnels, and exact saved/live owned split routing before inspecting sockets.
2. Resolves current Google Messages and GMS package UIDs through Android's PackageManager, plus Android system UID 1000; never uses old screenshot UIDs as hardcoded assumptions.
3. Checks the existence of a read-only `ss` tool. It runs `ss -H -t -n -e` and `ss -H -u -n -e` **three times over approximately 2.2 seconds**. These ask iproute2/netlink for current TCP/UDP sockets and their extended information, which on supported kernels/tools may include `uid:` and `fwmark:`. Some Android root builds may not include `ss`, may restrict `inet_diag`, or may omit fwmark. Such cases are labeled **UNAVAILABLE / CHECK REQUIRED**; the feature does not install a replacement binary or bypass SELinux.
4. The pure Java parser groups output records, retains **only** counts and explicit UID/fwmark values for the three requested UIDs, and never prints or persists raw local/public addresses, ports, peer identity, socket cookie/inode or process data. An absent `fwmark` is **UNKNOWN, not zero**. Protected socket bit `0x20000` is reported when observed.
5. For at most four distinct explicitly observed marks per target UID, uses the established read-only `ip route get` fixed public IPv4/IPv6 probe addresses to show a **hypothetical** route selection for that UID/mark. Those probes are not packets and are not the socket's actual peer destinations.

The report includes only aggregate peak socket counts per sample (not unique flows); short-lived subsecond QUIC sessions can be missed. It does **not** prove any particular captured Messages, GMS or Wi-Fi Calling flow used a specific mark or physical egress; it only makes the earlier UID/mark simulations more informed by currently observable sockets.

## Safety and privacy boundaries

- **No packet generation, VPN restart, firewall changes, DNS modifications, route addition/deletion, per-app blocks, runtime app-permission changes, or persistent socket history.** Only the existing root shell is used; no new `ss` binary installed.
- No universal leak-free or kill-switch claim; Batch F remains PAUSED. Android Private DNS remains OFF on this user's device because Automatic/custom previously broke Wi-Fi.
- Do not disable RCS, Google Play services/microG, or Wi-Fi Calling. A legitimate carrier IPsec exception needs separate compatibility and bypass-policy design.
- Any `ss`/kernel exception is rendered as stage and exception class only; **never** raw tool output or endpoints. Kernel restrictions fail closed as diagnostics unavailable.

## Candidate QA on Pixel 8a / Axion Android 16

1. Review Android/native CI + pure Java `RootLiveSocketMarkEvidenceTest`. Android debug/rootlab CI artifact is **not** a replacement for the official signed app.
2. Only for an elective signed 0.15.34 versionCode 81 test: stop both tunnels using **H.1 Safe Stop**, confirm **H.2a CLEAN_STOPPED**, locally sign with the existing release key on Fedora, then use `scripts/install-wonhee-safe-update.sh`; do not circumvent a refusal.
3. Restart two original profiles using Safe Start, verify DNS, Home/Navidrome and AirVPN IPv4/IPv6. Run 0.15.33 route audit first to preserve the known baseline.
4. Run the new passive socket mark control once. If it says `ss`/inet_diag unsupported or shows zero target marks, **do not interpret that as clean traffic**. Report the sanitized output and investigate capability separately.
5. If socket marks are visible, compare protected vs ordinary counts to PCAPdroid's app/UID attribution. Do not equate a public fixed-destination route prediction with observed real socket egress. Do not provoke disconnects or force Google Messages traffic for this test.
6. Preserve Safe Stop, DNS ownership and original signing certificate across candidate builds; do not publish raw PCAP.

## Possible future work

If supported, design user-opted, bounded **socket-specific** attribution using kernel `inet_diag` inode/socket cookies and correlation to matching PCAP flows. That requires careful UID and endpoint validation and must not gather message contents. No per-app network enforcement should be added before proving RCS, FCM and IMS/Wi-Fi Calling compatibility.
