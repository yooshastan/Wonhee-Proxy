# Alpha 0.4 — experimental WireGuard validation

This branch depends on the unmerged Alpha 0.3 branch. It adds a *real
WireGuard userspace tunnel engine*, **not** a finished VPN or privacy product.

## Before testing

- [ ] Back up MTProto secrets *privately*. GitHub Actions debug signing keys
      can differ between builds; uninstalling may permanently destroy encrypted
      proxy profiles. Never publish WireGuard private keys or .conf files.
- [ ] Use a spare Android test device if possible. The VPN permission may
      disconnect your existing Tailscale session.
- [ ] Independently configure a real WireGuard gateway. Your existing
      Telegram MTProxy TCP/8443 is **not** that gateway.
- [ ] Ensure you have a non-VPN recovery path and no pending critical tasks.
- [ ] Do not enable Android's always-on or lockdown mode: always-on metadata
      is disabled until persistent secure config and reconnect are implemented.

## Android integration

1. Confirm normal proxy profile load, TCP check, Ultgram import and Alpha 0.3
   opt-in monitor still work. The VPN must stay off unless explicitly started.
2. Open the separate experimental VPN screen. Confirm no secrets are displayed
   or logged, and Start remains disabled without a WireGuard .conf.
3. Import a private WireGuard .conf using the Android system picker. Confirm
   valid profiles are recognized; invalid/oversize files do not crash or echo
   configuration text.
4. Tap Start. Confirm an explicit warning appears. Cancel and confirm the
   existing VPN is unchanged. Accept only when ready to replace Tailscale.
5. When the gateway is available, verify tunnel start reports interface UP.
   Independently inspect the **server** with `sudo wg show` for actual peer
   handshake and traffic counters. Interface UP alone is insufficient.
6. Test a full-route config (`AllowedIPs = 0.0.0.0/0, ::/0`) and a split-route
   config (only the necessary private IP prefixes) **in separate sessions**.
   Alpha 0.4 does not yet offer safe in-place mode switching.
7. Stop VPN and confirm Android no longer reports Wonhee as active. Relaunch
   the screen and confirm no private profile was saved on disk.
8. Repeat with Pixel 8a and Samsung A36 after obtaining a safe gateway.

## Required security tests *before* calling this production-safe

- [ ] Gateway and client key authentication, replay/reconnect, wrong key cases.
- [ ] DNS and IPv6 packet capture on Wi-Fi and cellular; no unexpected direct
      fallback. The Alpha 0.4 app **does not** enforce DNS filtering.
- [ ] Network loss/reconnect, app kill, device reboot, roaming, and switching
      from a competing VPN. Validate fail-closed behavior *after implemented*.
- [ ] Home private Navidrome access across tunnel; do not bind Navidrome to a
      public interface.
- [ ] WireGuard integration on both ABIs and relevant Android releases.
- [ ] Confirm battery use and VPN Android lifecycle remain healthy.
- [ ] Verify no config, private key, raw exception or DNS history is logged.

## Current limitations

- No key persistence; re-import on process restart. In a process restart,
  the tunnel and its config may be lost, so this cannot be used for lockdown.
- No built-in kill switch, local DNS forwarder, DoQ/DoH, tracker blocking,
  automatic gateway provisioning, key rotation, or privacy audit.
- All apps are eligible under Android's default VPN scope, but routes come
  from the *supplied WireGuard config*. Split-mode excluded routes bypass
  the tunnel. Never represent it as full-device leak protection.
- A WireGuard handshake is not tested by the app. Verify remotely.

## Safety rollback

Use Stop VPN in Wonhee or Android VPN Settings. Re-enable Tailscale if needed.
Do not uninstall Wonhee unless you have securely backed up the existing
MTProto profile credentials. The Fedora MTProxy container and Navidrome stay
unchanged by this branch.
