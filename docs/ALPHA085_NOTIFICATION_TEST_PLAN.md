# Wonhee Proxy Alpha 0.8.5 — Notification test plan

This is a foreground **WireGuard tunnel counters** notification, not a
VPN keep-alive mechanism, whole-device bandwidth meter, DNS leak test, or
packet capture. It never changes network configuration.

## Prerequisites

- Preserve an original working WireGuard .conf before attempting a differently
  signed build. CI debug certificates are temporary and may not allow an
  in-place upgrade. Never share private keys in issues or logs.
- Use a device with notification permission enabled for Wonhee (Android 13+).
- Keep Android's Always-on / Block connections without VPN choices unchanged
  during the initial test. Do not disable lockdown to make this notification appear.

## Foreground test

1. With the VPN off, verify no ongoing Wonhee throughput notification appears.
2. Turn the VPN on using a previously validated profile. Grant notification
   permission if requested. The Silent section should show an ongoing card
   titled "Wonhee VPN · Interface active". Tap it: Wonhee opens.
3. The first sample says "Measuring tunnel traffic..."; within roughly five
   seconds the notification shows download and upload rates. Idle activity may
   appear as "0 Kbps".
4. Generate ordinary internet traffic through the VPN. Speeds should rise,
   and WireGuard RX/TX totals should increase. Compare direction/units with
   the in-app counters. Rates come from two consecutive byte counter samples,
   so they are not instantaneous maximum speed.
5. Expand the notification and confirm no host IP, secret, private key,
   Wi-Fi SSID, endpoint or proxy credential appears. It should explicitly
   identify the data as tunnel counters, not a leak test.
6. Stop the VPN using Wonhee (only if Android Always-on does not control it).
   The notification should disappear. Make sure the VPN is actually stopped.
7. Start VPN again; the first counter sample must reset baseline rather than
   produce a huge, negative or fabricated speed.

## Background/reboot/lockdown

1. Start the VPN, return to the launcher, and leave Wonhee in the background
   for several minutes. If the service is permitted, its notification should
   continue to update without additional network probes.
2. Reboot with Android Always-on enabled. Confirm the tunnel reconnects,
   then inspect the notification. Android can prevent a new background
   foreground-service launch even if the VPN restored; open Wonhee to start
   the optional notification if missing.
3. With lockdown enabled, simulate a stopped/unavailable gateway safely.
   The notification must never be interpreted as proof that DNS or external
   traffic is blocked. Verify actual traffic blocking separately.
4. Deny or revoke Android 13+ notification permission. The VPN must continue
   functioning. Android can hide the notification from the drawer; restore
   the permission in system app settings.
5. Check low-storage/battery-constrained conditions and network transitions.
   The notification should either show unavailable stats or stop, not crash
   the app or reconnect the VPN without consent.

## Scope and limitations

- This app uses the official WireGuard GoBackend. Read-only
  Backend.getStatistics() counters are used; no traffic capture is added.
- The 5s refresh loop runs only with the optional foreground service active.
  Sampling does not inject keep-alive packets. Actual WireGuard
  PersistentKeepalive, when configured in a profile, is separate.
- Android foreground-service type is systemExempted for VPN applications. Some
  devices/ROMs may reject or suppress notification foreground services. A
  failure to create the optional notification is not a VPN connection failure.
- No actual on-device test, server-side packet capture, DNS/IPv6 leak audit or
  long-run battery benchmark is provided by passing GitHub Actions alone.
