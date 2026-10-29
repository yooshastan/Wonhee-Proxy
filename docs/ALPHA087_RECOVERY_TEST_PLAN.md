# Wonhee Alpha 0.8.7 — reconnect preview field tests

**Both devices:** Pixel 8a GrapheneOS and Samsung A36 Android 16. This is a best-effort experimental recovery feature, not leak-free verification.

## Tunnel recovery

1. Install the debug preview with your existing WireGuard profile backed up securely. Signing identity may differ from your installed APK.
2. Connect Wonhee manually. Confirm it works with Moka's `http://10.77.0.1:4533` endpoint. Verify the existing RX/TX notification and traffic chart.
3. Open **Persistent VPN & Traffic Blocking**, enable **Retry unexpected disconnects**. Leave Android Always-on **OFF** for this first test to isolate in-app behavior.
4. Switch Wi-Fi ↔ cellular with the app running. Observe whether WireGuard's normal handshake recovers without a restart. Idle handshakes may remain old; do not interpret age alone as a failure.
5. With the app visible, simulate an actual interface-down event using an OS-level VPN stop (not the app's Turn VPN Off) and observe whether the notification service makes bounded attempts **only if Android still authorizes Wonhee**. If Android revokes authorization, manual reapproval is required.
6. Tap **Turn VPN Off** inside Wonhee. It must stay OFF; no background retry may override that explicit choice.
7. Enable **Retry unexpected disconnects** again while disconnected; this must **not** silently start the tunnel. Connect manually first.
8. Enable Android **Always-on VPN** for Wonhee under system VPN settings, with **Block connections without VPN OFF** until full-tunnel IPv4/IPv6/DNS/Fedora routing are verified. Reboot phone and test restore. Verify Moka again.
9. Test Wi-Fi ↔ LTE and overnight standby. Note exact phone, Android version, app version, Always-on state, and the last handshake/connection status the following morning.
10. If Always-on is active but restoration fails, test Android VPN authorization/force-stop state, WireGuard UDP 51820 reachability, and server `wg show`. Do not enable lockdown blindly; calls may continue while internet is blocked.

## Negative and regression tests

- No retries when switch is disabled, after manual Off, when another VPN owns authorization, or when no saved WireGuard profile can be recovered.
- A failed attempt should not display a fake Connected status or silently use the underlying network.
- Existing Ultgram MTProto/SOCKS5 proxy UI, profiles, DNS presets, route modes, and traffic chart should behave as in 0.8.6.
- Background notification service may be killed/rejected by Android; system Always-on is responsible for service restarts after process death and boot.
- Private Navidrome connection should remain reachable after a Fedora reboot **only after** the new systemd unit has been installed and enabled separately.

Never upload private WireGuard configuration, endpoint credentials, or signed Subsonic URLs in logs.
