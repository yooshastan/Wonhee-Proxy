# Wonhee Proxy

**Alpha 0.4** · Android proxy companion and experimental WireGuard VPN for Yooshastan Ultgram and Moka.

Wonhee helps you configure and hand off trusted MTProto or SOCKS5
endpoints to Ultgram. Alpha 0.4 adds a separate, **user-initiated**
WireGuard VPN prototype using the official embeddable WireGuard Android
tunnel library. It does not host the Telegram proxy on the phone.

## New in Alpha 0.4 — experimental WireGuard bring-up

- **Official tunnel engine:** Uses `com.wireguard.android:tunnel:1.0.20260102`
  and its integrated Android `VpnService`. Wonhee does not implement its own
  VPN cryptography.
- **Private config import:** Import a WireGuard `.conf` with Android's file
  picker. The config (including the private key) stays only in app-process
  memory; Wonhee does not save, upload, or log it. Limit: 64 KiB.
- **Explicit system permission:** Android asks before enabling this VPN. The
  permission and activation can replace Tailscale or another active VPN.
  Stop VPN is available on a separate screen.
- **Routing by WireGuard configuration:** A config with `AllowedIPs =
  0.0.0.0/0, ::/0` requests full-tunnel IPv4/IPv6 routing. Private-network
  prefixes instead request split routing. The robust in-app mode switch is
  planned for Alpha 0.6.
- **Safety constraints:** Off by default, no automatic startup, and Android
  Always-on VPN is disabled for this temporary-config experiment. An active
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
- The Alpha 0.4 VPN is experimental: no tested Fedora gateway, no
  fail-closed routing, auto-reconnect, background restart, secure tunnel
  profile storage, system-wide DNS/tracker filtering, DoQ/DoH, or Navidrome
  access yet. Do not enable it for sensitive traffic or claim leak protection.
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

1. Build or download the wonhee-proxy-alpha04-debug-apk from GitHub Actions.
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
8. If you are testing VPN mode, first configure a **separate**, authenticated
   WireGuard gateway. Tap **Open WireGuard VPN (experimental)** and import a
   private `.conf`. Only then consent to starting Android's VPN; this may
   disconnect Tailscale. Test on a spare device with safe fallback internet.
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
