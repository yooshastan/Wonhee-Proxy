# Wonhee 0.15.40 — Read-only direct-route classification

## Device evidence (Pixel 8a, Android 16)
Two user-triggered 0.15.39 audits independently reported an observed Google Play services/compatible microG UID 10180 socket with a protected-from-VPN mark whose **kernel route prediction** selected wlan0. One second-run Google Messages UID 10170 public peer/mark combination selected the Internet VPN. These are **observations, not packet-egress proof**; samples can repeatedly observe the same socket, and Android may intentionally exempt services.

## Changes
- A short classification summary precedes the existing detailed audit. Each app has counts for Internet VPN, protected-marked physical route, ordinary-marked physical route, other selected tunnel and unknown route.
- Ordinary-marked physical route predictions are labeled as unexpected and needing investigation.
- Protected-marked physical predictions are labeled as possible Android exemptions requiring review, not automatic leaks.
- Missing peers are not treated as success; unknown/other routes remain unresolved.
- Existing bounded same-socket UID, fwmark and numeric peer kernel lookup and privacy restrictions remain unchanged.

## Safety / exclusions
No network mutation, firewall/kill-switch activation, DNS change, VPN binding change, app blocking, RCS changes, or automated capture. No raw peer addresses, ports, keys or domains in reports or persistent logs. Android Private DNS stays OFF on the current test device.

## CI and device acceptance
- Android Java compilation and native tunnel tests must pass for the final branch head.
- Confirm no release signing secrets exist in PR jobs. The debug `.rootlab` artifact is not the official APK.
- Locally build with the original official keystore and verify signer/package/versionCode 87.
- Run H.1 Safe Stop, H.2a CLEAN_STOPPED and guarded ADB update before any installation.
- Run read-only audit with Home + AirVPN; compare summaries against detailed totals, including idle/no-peer, normal Internet route, protected Wi-Fi and unknown cases.
- Verify Messages/RCS/push, Wi-Fi Calling, DNS interception and blocker behavior remain working.
- Batch F all-traffic guard stays paused. A route prediction alone does not prove a leak.
