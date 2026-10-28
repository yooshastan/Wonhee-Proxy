# Wonhee Proxy Alpha 0.8.9 — VPN recovery and Navidrome manual test plan

This is an opt-in development preview, not verified security software. Test on the Pixel 8a (GrapheneOS) and, if available, the Samsung A36. Keep a separate copy of the original WireGuard .conf before installing an APK signed with a different certificate.

## Preconditions

1. Have a working saved WireGuard profile, with a manual Connect succeeding and a recent handshake.
2. In Android VPN settings, select Wonhee as **Always-on VPN**. The separate **Block connections without VPN** option should only be enabled after testing full-tunnel routing and DNS; do not change lockdown just for this preview.
3. Enable Android notifications for Wonhee if its optional traffic monitor is used.
4. In Wonhee, turn on **Retry if WireGuard interface stops**. It is disabled by default. Verify the label reports ARMED after a successful manual Connect.
5. Confirm that the gateway actually routes the phone's AllowedIPs and DNS. An interface-UP status does not prove Internet connectivity.

## Recovery scenarios

- **Manual stop is respected:** With auto-reconnect ON, tap Disconnect. Wait longer than five minutes, reopen the app and verify it remains disconnected. The periodic recovery job should be canceled. It must not secretly reconnect after a deliberate stop.
- **Normal reconnect re-arms:** Reconnect manually. Verify the checkbox remains enabled and status says ARMED.
- **Android Always-on OFF:** Switch Always-on OFF in system settings. The app must report that recovery is unavailable and must not start new unattended retries. Restore Always-on afterward.
- **Recovery setting OFF:** Disable the checkbox while connected. If the interface later goes DOWN, no Wonhee-initiated retry occurs; the Android system may independently manage its VPN lifecycle.
- **Interface actually DOWN:** Induce a *controlled* interface-down event without invoking Wonhee's user Disconnect (e.g., ordinary system VPN/service lifecycle). Observe whether the optional monitor attempts restoration with increasing 5/15/30/60/120/300-second delays. If Android tears down VPN permission, a fresh user confirmation may be necessary.
- **Stale peer:** Simulate gateway loss while WireGuard's interface remains UP. Confirm the app does **not** churn the tunnel just because the handshake ages. This is a known gap, not a pass for connectivity recovery.
- **Network handoff:** Switch Wi-Fi ↔ cellular and lock/unlock the screen. Verify no repeated permission requests, runaway reconnection loops, or direct-network fallbacks.
- **Overnight:** Leave connected, auto-reconnect ON and Android Always-on enabled overnight. Note morning interface UP/DOWN, most recent handshake, notification status, and whether a manual reconnect was necessary. Android may defer the persisted 15-minute job during Doze.
- **Force stop:** Force-stop Wonhee from Android app settings. Its VPN may remain unavailable until reopening; the app must not claim force-stop persistence.
- **Battery and reboot:** Reboot once without pressing Disconnect. Verify Always-on VPN and the saved profile restoration path. Some battery optimizations may still delay the optional monitor.

Never disable a production VPN/lockdown configuration merely to force a test. Normal cellular phone calls are not evidence that ordinary app data bypassed lockdown.

## Private Navidrome reachability (independent of auto-reconnect)

The Wonhee **Home service port check** is not a Navidrome server setup wizard. It only attempts a single VPN-bound TCP connection to a numeric RFC1918 address and port. To test the user's Fedora server, use the *actual WireGuard-reachable host IP* (often `10.77.0.1`) and `4533`.

On Fedora, inspect without changing firewall or Podman:
```bash
sudo podman port moka-navidrome
sudo ss -lntp | grep ':4533'
ip -br addr show wg0
sudo wg show
```
If Podman says `127.0.0.1:4533`, the Navidrome TCP listener is reachable only on Fedora loopback, not the phone's `10.77.0.1` WireGuard destination. Decide separately whether to bind it on the private WireGuard IP, add a narrowly scoped authenticated reverse proxy, or preserve the Tailscale HTTPS URL for Moka. Do not expose port 4533 on all public interfaces or open a router port forward as a quick fix.

In Wonhee, run the approved check:
1. Input the Fedora server's private **WireGuard IP** and TCP port `4533`.
2. A **PASS** only proves TCP accepts a connection; verify Navidrome's actual HTTPS/API/authentication separately in a client.
3. A **FAILED** result requires checking listener address, host firewall, WireGuard routes/AllowedIPs and VPN handshake. **UNAVAILABLE** means Android did not report a single VPN transport.
4. A Tailscale hostname will not work in this strict numeric-IP test. Wonhee replaces Tailscale as Android's active VPN.

## Exit criteria

- [ ] Standalone `VpnRecoveryBackoffTest` passes in CI.
- [ ] Android debug APK compiles and package manifest is valid.
- [ ] User confirms first-run toggle OFF and Android Always-on gating.
- [ ] Manual Disconnect never auto-reconnects.
- [ ] Recovery observed after actual interface DOWN without user action.
- [ ] Overnight behavior observed on a real device.
- [ ] Navidrome failure diagnosed as VPN route, server listener, firewall, or Android VPN network reporting.
- [ ] No unexpected sensitive logging or plaintext config.

Do not merge or release until the device-dependent cases are reviewed.