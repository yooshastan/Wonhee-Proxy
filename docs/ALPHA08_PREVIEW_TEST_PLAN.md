# Combined Alpha 0.8.2 preview — test matrix

This branch is **foundational**, not a completed DNS/privacy or always-on
release. CI compiles a debug preview. Do not use for sensitive traffic.

## Saved profiles, one-tap control and Android Always-on

- Import a valid `.conf`; confirm it is immediately saved and highlighted in
  the saved-profile picker without a separate Save tap.
- Force stop through Android Settings, then manually relaunch the app.
  Confirm the last selected profile, routing mode, and DNS option reappear
  without reimporting a `.conf`. Force stop is NOT expected to keep the VPN up
  or silently restart it.
- Press Turn VPN On and Turn VPN Off; confirm each action toggles the actual
  WireGuard interface and survives activity rotation or ordinary app reopen.
- Without tapping Save, choose All internet, opt-in DNS and a numeric resolver;
  confirm Connect; force stop, relaunch and verify those exact settings return.
  Repeat with Home Access and DNS disabled. Confirm Cancel on the Connect
  warning does not save unsaved choices.
- Save changed route or home DNS settings with the explicit Save button, force
  stop, reopen, and confirm they remain selected (both DNS-enabled and disabled).
- Simulate encrypted profile storage failure and verify Connect is refused rather
  than starting a session that Always-on cannot restore consistently.
- Import a second `.conf` with the same desired name; ensure it is assigned
  a new name and does not silently replace the existing encrypted profile.
- Select the second profile, force stop, reopen, confirm that exact selection
  is restored. Delete it and verify the fallback is valid.
- Confirm private configuration keys never appear in logs, exceptions,
  ordinary app preferences or Android backup.
- In Android Settings > Network & internet > VPN > Wonhee Proxy, verify
  Always-on VPN is offered, rather than marked unsupported.
- Only **after** confirming full IPv4/IPv6 routing, Fedora forwarding/NAT and
  working DNS, enable Always-on and test system-initiated restoration after
  reboot/unlock, service removal, switching networks and a temporary outage.
- Finally test Android's "Block connections without VPN" on an isolated device
  and verify that app traffic is blocked whenever the tunnel is unavailable;
  confirm the user can recover in Android VPN Settings.
- Do not claim a guaranteed kill switch or auto-restart after explicit Force
  stop without device tests. Do not enable lockdown by default.

## App migration

- Upgrade an existing Alpha 0.6 profile without uninstalling if and only if
  its signing certificate matches. Old encrypted profiles should load with
  Home DNS **disabled**, preserving all existing WireGuard private fields.
- Enable a home DNS IP only if a DNS service is actually listening at that IP,
  e.g. 10.77.0.1 on the Fedora wg0 interface, and the phone has an AllowedIPs
  route covering it. Save profile, force-stop, relaunch and verify opt-in state.
- Disable the DNS override and verify the imported original DNS remains intact.
- Reject hostnames, invalid IPs and missing home DNS field without altering the
  saved .conf or leaking config parser errors.

## Network validation (Pixel 8a; repeat on Samsung A36)

- With cellular and WireGuard Home Access, verify 10.77.0.1 reachable.
- With a configured DNS service at 10.77.0.1, check Android app DNS requests
  actually arrive at the Fedora wg0 interface (capture on Fedora), then
  test DNS when the server is unavailable. A handshake is not DNS evidence.
- Check whether any DNS queries use the mobile network rather than the
  tunnel, separately for IPv4 and IPv6. Evaluate Android Private DNS settings.
- Do not claim DoH/DoQ: optional home DNS uses ordinary DNS **inside the
  encrypted WireGuard tunnel** and relies on the server for any blocking or
  encrypted upstream resolution.
- Do not claim tracker protection or leak-safe operation without a configured
  server-side filtering resolver, verified all-traffic forwarding, and explicit
  phone-side leak and failure-state evidence.
- System Always-on is now offered as an opt-in preview via the official
  GoBackend callback and encrypted-profile restoration on system service start.
  It must pass reboot, lockdown, and stale-key failure tests before a release
  can advertise persistent protection; auto-reconnect across every transport
  failure and an independent kill switch are not claimed.

## Signing

- Configure secrets following docs/SIGNING.md.
- Perform two consecutive signed dispatch builds. Their certificates must
  match and an in-place upgrade must retain saved profiles.
- Never replace an installed build with a different signing certificate
  by uninstalling until private WireGuard and proxy credentials are backed up.

## Pixel 8a field feedback (user-reported, 2026-10-26)

- Imported profile restored after force stop without reimporting the `.conf`.
- After explicitly saving All internet (experimental) and DNS override, routing
  mode and DNS settings restored after force stop.
- On cellular, Fedora WireGuard gateway and browser reported matching home WAN
  IPv4; WireGuard observed a distinct mobile peer endpoint.
- Android reported Always-on configured and lockdown=1. User reports web traffic
  stopped during force stop and resumed after reopening/reconnecting.
- User reports Wonhee VPN and Ultgram MTProto/SOCKS5 proxy connected automatically
  following a full phone reboot, with no manual recovery needed.
- User reports network-switching and connection-recovery tests successful. Exact
  transition timings and app/server logs were not independently inspected.
- Browser DNS leak test displayed the intentionally configured Cloudflare resolver
  addresses; browser IPv6 test reported no IPv6 address. Neither result by itself
  constitutes a comprehensive application-level DNS/IPv6 leak audit.
- Further release gates: regression test Connect auto-save, verify signed APK
  upgrades preserve encrypted profiles, and validate loss/recovery across
  separate networks and additional Android devices.
