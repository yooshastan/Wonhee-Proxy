# Wonhee Proxy Alpha 0.9.10.0 — DNS, Home routes and provider-side filtering

This builds on the user-tested 0.9.9.1 dual kernel pair. No firewall rules,
automatic recovery, DNS redirection, local domain blocklist, DoH or DoQ are added.
Do not present a selected DNS preset as proven Android resolver use or leak safety.

## Backup and profile policy

1. Before installing, preserve imported `.conf` profiles through your existing
   secure backup. GitHub debug signatures can vary between CI runs.
2. Stop both kernel tunnels. Pick the correct Internet / AirVPN profile.
3. Find **INTERNET DNS + TRACKER RESOLVER** and select **AdGuard (ads and
   trackers)**, then **SAVE INTERNET DNS POLICY FOR NEXT START**.
4. Confirm the app saves the policy, does not restart either tunnel, and has
   not modified the raw imported `.conf`. Reopening Root Lab should restore
   the AdGuard preset.
5. Select **Use imported profile DNS** and save again to verify rollback.
6. Try a malformed custom DNS string. The save must fail without changing the
   encrypted profile, imported keys or live network state.

## Route and DNS observations

1. Start the saved ASUS Home + AirVPN pair. Check both fresh handshakes and
   public IPv4/IPv6 routes through AirVPN with the existing root route audit.
2. Run **CHECK INTERNET DNS ROUTES (READ ONLY)**. A 2/2 result means the
   configured IP destinations select `wnair0` in a root route lookup; it does
   not prove any Android app actually uses those DNS resolvers.
3. Enter the private address of a Home service (e.g. `10.0.0.169`) and tap
   **CHECK HOME SERVICE ROUTE (READ ONLY)**. Expect `wnhome0` if routed;
   independently open Navidrome on its known TCP port to verify connectivity.
4. Invalid/public Home IPs, hostnames and shell metacharacters must be rejected.
5. Use external DNS and IPv4/IPv6 tests on the Pixel 8a while on cellular.
   Inspect actual resolvers, tracker-blocking behavior and fallback separately;
   neither the app nor a root route query can certify absence of leaks.

## Kill-switch research (read only)

1. Run **CHECK KILL-SWITCH ARMING READINESS (READ ONLY)**.
2. Confirm it reports numeric UDP endpoint availability for BOTH Home and
   AirVPN. This is useful for designing a narrowly scoped transport exception.
3. The shared Android `0x20000` mark remains unsuitable as a blanket
   exemption. Guard enforcement must remain OFF. Test endpoint changes,
   app crashes, DNS, reboots and network handoff before any future arming.

## Interpretation

- AdGuard public DNS offers upstream DNS-based blocking. It cannot block all
  trackers, hardcoded IPs or independent encrypted DNS inside other apps.
- Plain DNS addressed inside WireGuard may be protected by the WireGuard
  transport; it is not DoH/DoQ and is not proof of device-wide DNS isolation.
- Root kernel WireGuard is outside Android VpnService, so Android's native
  Always-on / Block outside VPN controls do not provide a root-mode kill switch.
