# Wonhee 0.9.5 rooted Pixel dual-kernel test

This branch provides the **first manual, explicitly opted-in rooted dual-WireGuard APK**. It uses the official WireGuard Android library's `WgQuickBackend`, *not* the previous two disconnected Go memory TUNs. The original stable Android `GoBackend` path remains available in the regular VPN screen.

## Install without losing working profiles

- The CI debug APK uses a separate package ID, `com.yooshastan.wonheeproxy.rootlab`, so it can install alongside the signed stable Wonhee app. Its own encrypted store starts empty: **import both original `.conf` files again** into the lab app. Never paste private/preshared keys into GitHub or chat.
- On Pixel 8a, confirm `adb shell su -c 'id; ls -ld /sys/module/wireguard'` succeeds. In Magisk Superuser, **grant Wonhee Root Dual Lab root** when prompted.
- Temporarily disconnect any other active VPN and disable its Android Always-on/lockdown only if you accept the risk of traffic escaping through the normal network during this experiment. The kernel engine **does not implement** Android VpnService kill switch, fail-closed rules, reboot recovery, or DNS/IPv6 leak protection.
- In the lab app, import the ASUS Home profile and AirVPN Europe profile. Keep each profile's independent WireGuard keys, endpoint, and Address.
- ASUS Home must have only split `AllowedIPs`, e.g. `10.6.0.0/24, 10.0.0.0/24`. AirVPN Europe must have both IPv4 and IPv6 default routes (`0.0.0.0/0, ::/0`); the lab refuses otherwise.
- Tap **Experimental: Root dual-tunnel lab**, choose Home and AirVPN Europe, **Check root + kernel tools**, then **Start both**. The engine starts Home first, AirVPN second. It checks that both interfaces are UP; it tries to undo partial starts.

## Verify while both are UP

From a terminal on Fedora with the Pixel attached:

```bash
adb shell su -c 'ip -d link show type wireguard'
adb shell su -c 'wg show'   # if wg is present in the root shell's PATH
```

Look for `wnhome0` **and** `wnair0`. The app shows each interface's byte totals and whether a handshake has occurred; only handshakes and successful traffic tests establish reachability.

While the phone is on **cellular**, test:

1. `http://10.0.0.169:4533` (Navidrome via ASUS Home) and another private LAN host.
2. Public IPv4 **and IPv6** identity: both should be AirVPN Europe; a missing IPv6 route must not be silently treated as safe.
3. DNS lookup, live streaming, AirVPN stop/restart behavior, Wi-Fi ↔ cellular switch and tunnel recovery. The implementation does **not** promise a fail-closed network interruption.
4. Tap **Stop both**. Confirm `wnhome0` and `wnair0` are both absent.

**If the app crashes or is force-stopped**, the rooted kernel interfaces may outlive its process. Do not assume turning off the app removed routes. Inspect `ip -d link show type wireguard` and the routing table from root. Recovery must be performed carefully, on the named test interfaces only, before returning to the regular VPN. Do not remove interfaces managed by other apps.

## Scope / limits

- Two **independent** kernel WireGuard tunnels, two separate keys, serialized actions, readiness check, explicit stop and basic stats. No automatic fallback to the GoBackend on root denial.
- The upstream `WgQuickBackend`'s `wg-quick` is responsible for interface addresses, policy routes and DNS attempts. Actual behavior on GrapheneOS/Magisk remains a **device test**, not CI-testable. A build passing CI proves compilation, not connectivity.
- The prior Go native session experiment in PR #22 is a separate unrooted-device investigation; it is not wired to Android UDP sockets or to this test APK.
- Do not merge into stable release before successful dual handshake, routes, DNS, IPv4/IPv6, teardown and network-change testing. No code in the app alters your ASUS router or your AirVPN account.
