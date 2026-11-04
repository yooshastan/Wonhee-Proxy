# Wonhee Alpha 0.9.2 tunnel-manager test plan

**Scope:** Android UI and encrypted saved-profile management. This is a
rootless, single-active-tunnel preview. It does **not** run two independent
WireGuard interfaces simultaneously and does **not** configure AirVPN on
Fedora/ASUS upstream.

## Test devices
- Pixel 8a (GrapheneOS).
- Samsung A36 (Android 16).

## Protect existing profiles
- Back up the original `.conf` files **privately**, off the phone if needed.
- Do not paste `PrivateKey` or `PresharedKey` into issues, screenshots or
  reports. Android debug APK signing keys may differ between builds;
  uninstalling a differently signed app can remove its locally encrypted
  profiles. Keep a safe copy of original configs before changing APKs.

## Import and manage

- [ ] With no tunnel active, tap **Import WireGuard .conf files**, select one
  complete home client `.conf`, and verify a new named row appears.
- [ ] Select multiple `.conf` files in one import action. Confirm every valid
  file appears separately and previous profiles remain unchanged.
- [ ] Import a file with an existing display name. Confirm a new numbered
  name appears; existing saved profile is **not replaced**.
- [ ] Rename one profile through advanced settings and save it; confirm
  persistence after force-stop/relaunch.
- [ ] Import an invalid or malformed `.conf`; verify it is rejected without
  overwriting any stored profile or showing private key data.
- [ ] Fill the eight-profile limit. Verify further imports fail safely and no
  existing entry is removed.
- [ ] Force-stop/relaunch; all encrypted profiles and last selection survive.

## Connection controls

- [ ] On each saved row, tap **Connect** and approve normal Android VPN
  consent and the app's confirmation. Verify the correct peer handshakes.
- [ ] On an active row tap **Disconnect**. Confirm Android VPN is DOWN and
  user-requested disconnect does not silently trigger auto-reconnect.
- [ ] With a tunnel active, tap **Switch to this tunnel** on a different row.
  Confirm first, verify the previous tunnel is DOWN before new connection.
  Only the selected interface is active, not both independent profiles.
- [ ] Cancel the switch confirmation. The existing tunnel stays active.
- [ ] Refuse Android VPN permission or trigger a bad config. Verify status
  accurately shows failure rather than claiming connected.
- [ ] With Android Always-on active, check that switching is blocked and
  provides a clear reason. Confirm manual disconnect and recovery semantics
  remain unchanged.

## Provider and services

- [ ] Connect a standalone AirVPN client `.conf`. Verify normal browsing,
  correct egress IP on a user-chosen check page, IPv4/IPv6 routing, and DNS.
- [ ] Switch to the standalone home WireGuard `.conf`. Verify reachability
  to `10.77.0.1:4533` in the phone browser and authenticated Navidrome
  playback in Moka. A failed Navidrome page does not necessarily mean the
  tunnel never handshook.
- [ ] Switch Wi-Fi ↔ cellular and leave overnight. Verify recovery and
  Android Always-on without unplanned direct fallback.
- [ ] Do not assume a successful handshake alone proves leak protection.

## Deliberately not automated by 0.9.2

To use **Home + AirVPN internet exit** at the same time without root, an
upstream WireGuard client must run on the Fedora/ASUS gateway and route the
desired phone traffic through AirVPN while preserving home service access
and return routes. That work requires separate gateway-specific network and
firewall testing, and is not silently applied by this APK.

The earlier Alpha 0.9.1 **peer-only import** can still be used for one
WireGuard interface with multiple peers sharing a client identity, provided
the home server has been configured appropriately. Never merge two
independent `[Interface]` private keys by appending `[Peer]` blocks.

## Acceptance criteria

All import/selection/switch paths pass on both devices; an invalid import or
failed switch never overwrites a saved configuration; no private keys or
endpoints appear in diagnostics; no false claim of simultaneous independent
tunnel support. Only after real-device validation should this branch be
considered for merging or release signing.
