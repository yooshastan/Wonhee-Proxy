# Combined Alpha 0.8 preview — test matrix

This branch is **foundational**, not a completed DNS/privacy or always-on
release. CI compiles a debug preview. Do not use for sensitive traffic.

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
- Always-on, boot recovery, network-change auto-reconnect, and kill switch
  remain intentionally disabled until the session can restore encrypted
  profiles without user interaction and fail securely during outages.

## Signing

- Configure secrets following docs/SIGNING.md.
- Perform two consecutive signed dispatch builds. Their certificates must
  match and an in-place upgrade must retain saved profiles.
- Never replace an installed build with a different signing certificate
  by uninstalling until private WireGuard and proxy credentials are backed up.
