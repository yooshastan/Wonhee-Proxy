# Wonhee Proxy Alpha 0.8.7 — Local Diagnostics and Quick Settings

Development preview only. No VPN routing, Fedora gateway, Android Always-on,
DNS resolver configuration or Telegram proxy semantics are changed in this build.
No independent DNS/IPv6 leak testing or automatic background network probes.

## Setup and update safety

1. Keep a private backup of your original WireGuard `.conf` and proxy login.
2. Install only an APK signed by the same signing key as the existing installation
   if you want a normal in-place update. Debug artifacts may have incompatible
   signatures and are not substitutes for a persistently signed release.
3. Before testing, verify the old VPN still connects, negotiates a handshake,
   accesses your intended home services, and disconnects normally.

## Connection events

1. Open VPN dashboard while disconnected. After the first local sample, see
   “VPN interface down” in Recent Connection Events.
2. Connect a working tunnel. See the interface/statistics/handshake status
   transition; any duplicate successive states should be collapsed.
3. Leave the dashboard open during live WireGuard traffic and a network handover.
   The event list must stay at or below 12 labels. It is not a record of
   every packet, transition while the dashboard is closed, or an outage alarm.
4. Leave and return: history remains within the existing Activity if retained;
   after a fresh Activity process it starts empty.
5. With unavailable statistics or a stale handshake, observe cautious wording:
   “statistics unavailable” or “may be stale,” not “blocked” or “protected.”
6. Confirm no IP, host, endpoint, peer public key, private key, SSID, secrets,
   credentials, or editable CIDRs appear.

## Redacted support report

1. Tap **Copy redacted support report** explicitly.
2. Paste into a private draft for inspection. It should include only local
   connection-health wording, routing-mode name and event labels.
3. Confirm it never contains the contents of your imported `.conf`, its
   Address/Endpoint/PrivateKey/PresharedKey, custom routes, DNS addresses,
   private profile names, proxy credentials or raw DNS test output.
4. Denied/unavailable clipboard access should show a safe error; VPN must
   continue unaffected.
5. Clear your clipboard when finished if using a shared or sensitive device.

## Quick Settings

1. Pull down Android Quick Settings, tap Edit and add **Wonhee VPN**.
2. Tap it while the phone is unlocked. It should open the Wonhee VPN dashboard.
3. Tapping the tile must never directly connect/disconnect a tunnel or change
   Android Always-on/lockdown.
4. Test from a locked device if permitted: Android must enforce its normal
   unlock policy and the app should not disclose credentials.
5. Check both Pixel 8a GrapheneOS and Samsung A36. If device policy hides the
   tile, the normal launcher must still work.

## Regression gate

- No change in WireGuard GoBackend state transitions or traffic notification.
- Existing encrypted profiles restore, DNS presets and home/full/profile route
  selectors behave the same.
- User-initiated VPN-bound DNS/HTTPS diagnostics retain their consent step.
- Verify both Android CI workflows pass standalone Java tests and assembleDebug.
- Signed release is a separate, maintainer-triggered action requiring private
  signing secrets and certificate fingerprint verification.
