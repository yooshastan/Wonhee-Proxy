# Wonhee 0.15.33 — Read-only Android per-app route predictions

**Base:** 0.15.32 DNS stage diagnostics PR #68, itself following the tested dual-tunnel networking and 0.15.31 outage snapshot. Source-only candidate until originally signed, guarded on-device acceptance.

## Why

PCAPdroid captured actual physical Wi-Fi underlay traffic outside the two recognized UDP/51820 WireGuard transports:
- Google Messages (historical UID **10170**) initiated multiple public Google QUIC UDP/443 sessions during active use.
- Google Play services (historical UID **10180**) made public IPv6 TCP/5228 connection attempts, while an older capture attributed a separate TCP/5228 flow to microG Services (another UID).
- Android system UID **1000** emitted occasional IPsec UDP/500, UDP/4500 packets consistent with enabled Wi-Fi Calling.

These facts **disprove a blanket claim that all traffic is routed over AirVPN** in the current root-only, kill-switch-OFF architecture. They do not establish exposed RCS message contents, DNS-over-HTTPS, browser contents or malicious traffic.

## What was implemented

In Advanced Controls → Connection Controls, after the existing one-tap Internet incident snapshot, choose **Inspect Messages / Play services / Android routes · read only** with **all active tunnel profiles selected**.

The audit uses only the existing root shell's **read-only** kernel `ip -4/-6 route get DEST uid UID mark FW`, `ip rule show` and identity-verified WireGuard state. It checks exact saved vs live split-route ownership before presenting results.

1. Dynamically resolves installed `com.google.android.apps.messaging` and `com.google.android.gms` UIDs through Android PackageManager. This can represent Google Play services or a compatible microG provider of that package; it does **not** enumerate arbitrary installed apps or infer a UID from historic PCAP. Android UID 1000 is a system UID, not a specific carrier app.
2. For each supported UID, samples mark `0`, at most one **observed unprotected Android fwmark** from live rules, and the `protectedFromVpn` mark `0x20000` as a *separate* test. Public IPv4/IPv6 test destinations are fixed probe addresses, never actual packet destinations.
3. For regular unprotected marks, predicts whether public IPv4 and IPv6 would choose the selected Internet tunnel. For mark 0, checks all configured Home split-destination route probes.
4. Shows the **protected** mark separately, because Android-marked protected sockets may legitimately bypass the VPN. The report does **not** claim that particular Messages or Play services sockets are marked protected.
5. Reports missing/invisible package UIDs and unexpected routes without guessing. Never reads messages, private app data, DNS queries, credentials or destinations from the historical capture. Only current synthetic route predictions are displayed.

## Fundamental limitations

**This is not a real per-app socket tracer or firewall.** A kernel route lookup with `uid` and an example `mark` predicts a possible route *if* an app socket has exactly that mark. It cannot observe which marks actual RCS, GMS or IMS sockets use, nor can it prove fail-closed network egress, app-specific DoH, or the absence of leaks. A real PCAPdroid root capture has stronger observed-flow attribution, but classic PCAP lacks per-packet UID/interface metadata unless supplemented by the capture app.

Some apps may be invisible through package visibility constraints or installed in another Android user. The app reports `UNAVAILABLE` rather than extrapolating. Samples are bounded for acceptable phone performance and never imply an exhaustive list of fwmarks. Full support for UIDs beyond 99999 needs separate design because current split-rule UID range is 0-99999.

## Protected behavior

**Zero kernel/network changes.** No routing, DNS, firewall, WireGuard, tracker, Android Private DNS, RCS, microG/Google services, Wi-Fi Calling, packet capture, kill switch, or recovery policy changes. The optional report is not persisted verbatim to the session journal. Batch F all-traffic kill switch remains intentionally PAUSED; do not confuse a healthy route simulation with real system-wide enforcement.

## QA and installation gate

1. Android and native CI green, including `RootUidRouteAuditTest`. No debug/rootlab APK replacing the official installed app.
2. For elective official signed versionCode **80** build, only after on-device **H.1 Safe Stop** and **H.2a CLEAN_STOPPED**, use the *same original release keystore* and `scripts/install-wonhee-safe-update.sh` on Fedora. Never bypass the guarded installer.
3. Reconnect both selected profiles using Safe Start, verify DNS audit, Home Navidrome, AirVPN IPv4/IPv6 browsing, and exact 3/3 split-route ownership. Keep Android Private DNS OFF, matching the known working Wi-Fi behavior.
4. Run the new per-app simulation once while healthy, check on-device UID resolution and mark 0/protected predictions. If normal marks show an unexpected physical route, treat it as evidence to investigate, **not proof of one app's live data egress**.
5. Safe Stop must still clear both interfaces and DNS/route ledgers. Do not deliberately induce an outage or disable carrier/push/RCS apps.

**Future follow-on**: design safe per-socket fwmark/UID attribution and explicit opt-in per-app egress policy with rigorous compatibility testing; never silently block Wi-Fi Calling or RCS.
