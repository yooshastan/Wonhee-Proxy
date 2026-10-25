# Wonhee Proxy Alpha 0.5 — Pixel 8a / Samsung A36 validation

This is a **draft** Android UI and secure-storage increment stacked on
Alpha 0.4. It does **not** configure Fedora forwarding/NAT or prove a
full-tunnel privacy guarantee.

## Before install
- [ ] Back up existing MTProto/SOCKS5 and WireGuard secrets privately.
      GitHub Actions debug signing keys can change. Uninstalling a previous
      debug build loses non-exportable Android Keystore keys and thus the
      previously saved encrypted profiles.
- [ ] Keep a working non-VPN fallback. Activating Wonhee replaces any active
      Android VPN, including Tailscale.
- [ ] Confirm Fedora WireGuard still responds to the known working Pixel peer.
      Do not rotate keys or reconfigure the Telegram MTProxy.
- [ ] Do NOT enable Always-on/lockdown: Alpha 0.5 still opts out of both.

## VPN-first UI and profile storage
- [ ] Launch Wonhee and confirm the WireGuard dashboard appears immediately;
      Telegram proxy tools remain available through their own button.
- [ ] Confirm Connect stays disabled without a selected configuration.
- [ ] Import the known-good Pixel WireGuard .conf. Check the displayed route
      warning: split, IPv4-only full, or both IPv4/IPv6 full.
- [ ] Save with a distinct profile name. Force-stop/relaunch. Choose it from
      the saved profile picker **without re-importing**.
- [ ] Save a second profile; switch between them while disconnected.
- [ ] Saving a duplicate name prompts for confirmation; Cancel preserves it.
- [ ] Delete prompts for confirmation; cancel leaves the profile intact.
- [ ] A malformed or >64 KiB import shows a generic error without echoing
      private keys. Stored profiles must not be overwritten after a Keystore
      failure or corrupt ciphertext.
- [ ] Confirm configurations are encrypted at rest in app private preferences,
      while existing encrypted Telegram proxy profiles are unchanged.
- [ ] Verify that simply importing a config without pressing Save does not
      persist it after process termination.
- [ ] Attempt to switch, edit, import or delete while connected; controls
      should be disabled or operation refused.

## Connection and statistics (cellular first)
- [ ] With Fedora connected, press Connect and approve Android VPN takeover.
- [ ] Immediately after start, the interface may say "Waiting for handshake".
      It must not claim an authenticated peer before receiving valid stats.
- [ ] Verify a recent handshake and traffic counters by sending traffic
      through the tunnel (e.g. ping 10.77.0.1). Cross-check the server with
      sudo wg show without sharing private keys.
- [ ] Stop traffic and verify the handshake age increases; check stale
      indication after 180 seconds. A handshake does NOT validate DNS privacy.
- [ ] Change to an unreachable WireGuard server in a separate, non-critical
      profile; interface UP without handshake must not report peer success.
- [ ] Leave the activity and return; stats should resume updating but the
      foreground poll should not continue while hidden.
- [ ] Disconnect and confirm the Android VPN indicator clears.
- [ ] With VPN disconnected, confirm Ultgram handoff, MTProto profile save,
      LAN/public endpoint selection and TCP monitor still work.

## Platform/security regression
- [ ] Test Android VPN permission denial and another VPN already running.
- [ ] Test app backgrounding, process termination, screen rotation, Wi-Fi/5G
      switches and a device reboot with no Always-on promise.
- [ ] Do not log/copy a .conf, private key, credentials, plaintext stored
      profile or native backend exception.
- [ ] Repeat basic UI/import/connection tests on Samsung A36.
- [ ] Re-run IPv4 full tunnel and Fedora forwarding/NAT tests separately.
      IPv6 can still bypass an IPv4-only VPN. Do not label it leak-safe.
- [ ] Compare status/traffic with the official WireGuard Android client.

## Rollback
Use Disconnect or Android VPN settings, restore the official WireGuard tunnel,
and re-enable Tailscale if needed. The server's Podman MTProxy and Navidrome
containers are not modified by this Android branch.
