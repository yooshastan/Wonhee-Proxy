# Rooted Pixel 8a: two kernel WireGuard tunnels test

**Experimental, opt-in, manual only.** Tested prerequisites on the user's
Pixel 8a: root uid 0 and `/sys/module/wireguard` present. This is a
pre-integration verification of Android policy routing; it is **not** a
Wonhee dual-tunnel implementation or a leak/kill-switch certification.

The official WireGuard Android `WgQuickBackend` exposes
`setMultipleTunnels(true)` when kernel support and root tools are present.
The current Wonhee `GoBackend` remains single-tunnel and unchanged.

## Safest staged test

1. Keep copies of the original `pixel8a.conf` and AirVPN Europe `.conf`
   somewhere secure. Never publish a `PrivateKey` or `PresharedKey` in logs,
   GitHub, screenshots or chat.
2. Disconnect Wonhee's existing Android VPN and temporarily disable
   Always-on/lockdown only if you accept the risk of traffic escaping to the
   ordinary connection during this manual experiment.
3. In the official WireGuard Android app, enable the kernel backend where
   available and enable **Allow multiple simultaneous tunnels**.
4. Import *two separate* WireGuard profiles. Set the HOME peer's
   `AllowedIPs` to only the ASUS tunnel and LAN routes
   `10.6.0.0/24, 10.0.0.0/24`. Do not use `0.0.0.0/0` on HOME.
5. Leave AirVPN Europe's separate interface key and peer data intact.
   AirVPN should have `AllowedIPs = 0.0.0.0/0, ::/0` if that is what its
   provider config supplies. Use the provider's DNS policy.
6. Enable HOME only. Verify that the phone can access
   `http://10.0.0.169:4533` (Fedora Navidrome) from cellular.
7. Enable AirVPN Europe while HOME stays enabled. Confirm two interfaces
   appear with a fresh handshake using `adb shell su -c 'wg show'`.
8. Re-test Navidrome and check a public IP endpoint in the phone browser.
   Public egress should be AirVPN Europe while `10.0.0.0/24` remains reachable
   through the ASUS interface.
9. Test DNS resolution and both IP families; do not assume the route list
   proves no DNS/IPv6 leaks. Network-change, reconnect and fail-closed tests
   have **not** been completed.
10. Disconnect AirVPN first, then HOME, and restore the last working Wonhee
    single-tunnel profile if this experiment fails.

**Do not automatically route both full-tunnel profiles.** The Android system
VPN and the rooted kernel implementation have different Always-on/lockdown
behavior. One phone's verified kernel behavior does not guarantee the same
result on the unrooted Samsung A36.

## Engineering follow-up

If this test passes, integrate the official WireGuard library's rooted
`WgQuickBackend` into a separate, explicitly enabled Wonhee backend with
two different imported profiles, verified start/stop transactions, no
accidental collision with externally managed `wg` interfaces and clear
rollback. Continue the native userspace multiplexer for unrooted devices.
