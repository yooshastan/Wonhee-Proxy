# Wonhee Proxy

**Alpha 0.5 (draft)** · WireGuard-first VPN dashboard and Ultgram proxy companion.

Wonhee helps you protect a home WireGuard connection and configure trusted MTProto/SOCKS5
endpoints for Ultgram. Alpha 0.4 added a **user-initiated**
WireGuard VPN prototype using the official embeddable WireGuard Android
tunnel library. It does not host the Telegram proxy on the phone.

## New in Alpha 0.5 — VPN-first dashboard (draft)

- **VPN on launch:** One-tap Connect/Disconnect and a separate Telegram proxy tools screen.
- **Explicit encrypted tunnel profiles:** Save up to eight configurations with AES-256-GCM and
  a separate non-exportable Android Keystore key. Import with Android's file picker,
  name, save, select later, replace after confirmation or delete. Configs are *not*
  saved on import; no plaintext fallback, remote backup, logs, or automatic startup.
- **Native diagnostic counters:** The WireGuard GoBackend exposes per-peer latest
  handshake timestamps and tunnel receive/transmit totals. The dashboard samples
  while visible, stops updating when hidden, and distinguishes an active interface
  from a recent peer handshake. A handshake does not prove internet or DNS privacy.
- **Preserves existing Telegram proxy functionality:** MTProto and SOCKS5 profiles,
  encrypted proxy credentials, Ultgram handoff and opt-in TCP monitor remain on
  the secondary screen.
- **Still experimental:** Android Always-on is disabled, and there is no reconnect
  guarantee, IPv6 leak prevention, filtering, DoQ/DoH or kill switch yet.
- **Build:** `gradle :app:assembleDebug`. CI artifact:
  `wonhee-proxy-alpha05-debug-apk`.

See [Alpha 0.5 manual test plan](docs/ALPHA05_TEST_PLAN.md).

## New in Alpha 0.4 — experimental WireGuard bring-up

- **Official tunnel engine:** Uses `com.wireguard.android:tunnel:1.0.20260102`
  and its integrated Android `VpnService`. Wonhee does not implement its own
  VPN cryptography.
- **Private config import (Alpha 0.4 baseline):** Import a WireGuard `.conf` with Android's file
  picker. Alpha 0.5 adds separately consented, Keystore-encrypted local saving.
  The import size limit remains 64 KiB. Keys are never uploaded or logged.
- **Explicit system permission:** Android asks before enabling this VPN. The
  permission and activation can replace Tailscale or another active VPN.
  Stop VPN is available on the main dashboard.
- **Routing by WireGuard configuration:** A config with `AllowedIPs =
  0.0.0.0/0, ::/0` requests full-tunnel IPv4/IPv6 routing. Private-network
  prefixes instead request split routing. The robust in-app mode switch is
  planned for Alpha 0.6.
- **Safety constraints:** Off by default, no automatic startup, and Android
  Always-on VPN remains disabled pending reboot/reconnection testing. An active
  tunnel interface is **not** proof of a WireGuard handshake, reachability,
  leak protection, DNS privacy or internet access.
- **No server changes:** Installing the APK does not create a Fedora
  WireGuard listener, open ports, alter MTProxy, or expose Navidrome.

See [Alpha 0.4 test plan](docs/ALPHA04_TEST_PLAN.md) and
[home gateway preparation](docs/ALPHA04_GATEWAY_PLAN.md).

## New in Alpha 0.3

- **Explicit foreground TCP monitor:** A consent dialog shows the chosen
  endpoint. After pressing Start, Wonhee probes the TCP socket roughly every
  15 seconds only while its screen remains visible. Leaving the app stops it.
  This is not background surveillance, Telegram proxy authentication, or
  monitoring of Telegram messages.
- **Redacted diagnostics:** In-memory counts and success-only latency
  statistics; Copy report deliberately excludes the server host, IP, proxy
  secret, username, and password. Clipboard access can still disclose copied
  metadata to other software.
- **Home server operation:** A sample Fedora rootful Podman Quadlet template
  is provided for a separately approved maintenance window. It is not deployed
  by installing the Android app.

## What works from Alpha 0.2

- **Encrypted profiles:** Explicitly save up to 16 named configurations locally.
  The profile list (including any MTProto secret or SOCKS5 credentials) is
  encrypted as one authenticated AES-256-GCM document with a non-exportable
  Android Keystore key. No plaintext fallback or Android Auto Backup.
- **Two endpoints per profile:** A required public IP/DNS name and an optional
  home LAN IPv4 address, with one TCP port and credentials.
- **Endpoint choice:** Public, LAN (manual), or Auto. Auto selects the LAN
  address only if it is an RFC1918 IPv4 literal on the device's active Wi-Fi
  subnet and the active network is not reporting VPN transport. Otherwise it
  selects public. This is a convenience hint, **not authentication of your
  home network**. Check the displayed endpoint before importing.
- **TCP-only diagnostics:** An explicit consent dialog shows the selected
  host and port, then attempts a 4-second TCP connection. Reachability is
  separate from an authenticated MTProto or SOCKS5 connection.
- **Ultgram handoff:** Sends proxy data only through an explicitly package-
  scoped Android intent to known Ultgram variants, including the FOSS debug
  package com.yooshastan.ultmessenger.foss.beta. No generic chooser.

### Important limits

- Changing networks **does not silently switch an already active Ultgram
  proxy**. Auto selection applies only when you press Test or Open in Ultgram.
  After network changes, open Wonhee and re-import if needed.
- The VPN is experimental: WireGuard handshakes and home ping were manually
  tested on a Pixel 8a, but full-tunnel internet routing, fail-closed behavior,
  auto-reconnect, background restart, system-wide DNS/tracker filtering,
  DoQ/DoH, and private Navidrome access are not yet validated. Do not enable it for sensitive traffic or claim leak protection.
- The existing MTProto TCP monitor does not prove proxy authentication;
  WireGuard interface UP does not prove a successful peer handshake.
- No proof of anonymity or zero leaks. The proxy operator can see the client
  IP, and your Telegram account identity remains linked to you.
- Telegram-sponsored messages are delivered via Telegram APIs as required by
  client policy.
- Keystore encryption protects data at rest; it is not a defense against a
  compromised/unlocked phone or an attacker who can operate the installed app.
- Uninstalling Wonhee, changing its signing identity, or resetting Android's
  Keystore may make saved profiles unrecoverable. Keep your own credentials
  securely stored outside the app. Do not publish secrets in GitHub issues.

## How to try it

1. Build or download the wonhee-proxy-alpha05-debug-apk from GitHub Actions.
2. Install the APK (the CI debug signing key can change across workflow runs,
   so Android may require uninstalling an older debug APK first).
3. Enter a **Public server IP or DNS name**, port and secret. For your home
   server, optionally enter the private LAN address separately.
4. Choose Auto / Public / LAN. Tap **Test selected TCP endpoint** and read the
   confirmation. TCP success does *not* mean Telegram authenticated.
5. Tap **Open in Ultgram** and activate the imported profile there.
6. Give the profile a name and tap **Save / update encrypted profile**. Restart
   Wonhee, select the saved profile, and verify its fields reload. Test Public
   on cellular and Auto on your home Wi-Fi.
7. Press **Start foreground TCP monitor** and verify reachability counts and
   redacted clipboard diagnostics. Leave Wonhee and confirm it stops.
8. On launch, use the VPN dashboard. Import a private WireGuard `.conf`,
   give it a name and tap **Save encrypted profile**. After relaunch choose that
   profile, tap **Connect VPN**, then confirm the Android VPN permission.
   Monitor handshake and counters; use **Telegram proxy tools** for MTProto.
9. See [Alpha 0.4 manual test plan](docs/ALPHA04_TEST_PLAN.md),
   [Alpha 0.3 plan](docs/ALPHA03_TEST_PLAN.md) and the
   earlier [Alpha 0.2 plan](docs/ALPHA02_TEST_PLAN.md).

Android SDK API 36, JDK 17, Gradle 8.13:

    gradle :app:assembleDebug

The repository includes an optional MTProxy gateway starter, a WireGuard
gateway checklist, and a longer privacy/network roadmap. Do not expose your Navidrome HTTP port to the open
internet or remove Tailscale until a separate authenticated service tunnel
has been built and audited.

Not affiliated with Telegram or any recording artist. See:
- https://core.telegram.org/proxy
- https://core.telegram.org/api/sponsored-messages
