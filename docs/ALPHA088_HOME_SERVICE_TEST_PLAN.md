# Wonhee Proxy Alpha 0.8.8 — Manual VPN-Bound Home Service Test

**Draft feature on top of Alpha 0.8.7.** Nothing here configures a Fedora server,
opens a public firewall port, changes the WireGuard route, probes automatically,
or proves IP/DNS privacy. This is a one-shot user-consented TCP reachability check.

## Basic tests

1. Open the VPN dashboard. With VPN disconnected, enter `10.77.0.1` and
   `4533`. Press **Test home service through VPN**. Expect an explanation
   to connect WireGuard first, and no network attempt.
2. Connect a known-good WireGuard profile, with a handshake and routes to
   the destination. Enter the **private IP of your actual reachable home
   service** and the listening TCP port. Verify the consent dialog explains
   the connection and that **Cancel** sends nothing.
3. Approve one connection. If the service is reachable, expect a cautious
   **PASS: TCP port accepted a connection through the Android-reported VPN
   network**. This is not application login or leak validation.
4. If Navidrome listens on Fedora localhost only, a test to a LAN/WireGuard
   address may fail. That is normal until an explicit, authenticated
   binding/forwarding path is configured. Do not expose :4533 publicly.
5. Test a closed port: expect **FAILED**, without printed host/port, Java
   stack trace, secret or the app trying regular cellular/Wi-Fi.
6. Test from Wi-Fi and cellular, using explicit approval each time; no
   automatic retries or background probes.

## Input and network-safety cases

- `10.77.0.1`, `172.16.0.1`, `172.31.255.254`, `192.168.1.10`:
  accepted as private IPv4 with valid 1–65535 TCP port.
- `8.8.8.8`, `127.0.0.1`, `172.32.0.1`, `100.100.100.100`,
  malformed IPv4, leading-zero octets, hostnames and IPv6: rejected
  before any connection. This feature intentionally does not resolve DNS.
- When Android reports no VPN or multiple VPN transports, refuse the test.
- Force-stop or disconnect during a test: no reconnection and no sensitive
  details in failure wording. Existing tunnel controls must stay responsive.

## Regression gate

- Standalone PrivateIpv4TargetTest and all other Java tests pass.
- Android Gradle assembleDebug builds; test on Pixel 8a GrapheneOS and A36.
- Re-run 0.8.7 event/clipboard/Quick Settings tests.
- Confirm encrypted profiles, route/DNS presets, notification permission
  handling, Android Always-on, and Ultgram handoff remain unchanged.
- Keep this as a draft stacked PR until 0.8.7 is validated, merged and
  0.8.8 gets device acceptance. Use permanent signing cert for release.
