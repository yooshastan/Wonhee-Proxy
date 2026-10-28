# Wonhee Proxy

**Alpha 0.8.6 on main; Alpha 0.8.7/0.8.8 stacked previews; Alpha 0.8.9 opt-in auto-reconnect in development (not a signed release)** · User-selectable WireGuard routing modes, encrypted VPN profiles and Ultgram proxy companion.

Wonhee helps you protect a home WireGuard connection and configure trusted MTProto/SOCKS5
endpoints for Ultgram. Alpha 0.4 added a **user-initiated**
WireGuard VPN prototype using the official embeddable WireGuard Android
tunnel library. It does not host the Telegram proxy on the phone.

## Build with Android Studio (Gradle 8.13 pinned)

Import this repository's source project in Android Studio, **not the prebuilt APK**.
Android Gradle Plugin 8.12.2 requires a compatible Gradle version; Gradle 9.6
fails with a removed `InternalProblems` API. The committed and checksum-verified
Gradle wrapper pins Gradle 8.13; do not override it with a local Gradle 9.6.

1. Open the repository folder in Android Studio and use the **Gradle wrapper**.
2. Use Java/JDK 17 and let Android Studio sync and install missing Android SDKs.
3. Run `./gradlew :app:assembleDebug` from the terminal for a debug APK, or
   choose **Build → Generate Signed Bundle / APK → APK** for a release signed
   with your own privately stored, long-lived keystore.
4. A newly created release signing key will not update an APK signed by an
   incompatible debug key in place. Back up original WireGuard configuration
   and other private settings before uninstalling an older build.

See [release signing instructions](docs/SIGNING.md).

## Alpha 0.8.9 development preview — opt-in VPN auto-reconnect

- New **Retry if WireGuard interface stops** setting, **OFF by default**.
  Requires Android **Always-on VPN** and a successful manual connection
  before unattended retry is armed.
- The foreground tunnel-status notification checks the local interface and,
  only if it is actually **DOWN**, attempts restoration of the last saved
  encrypted profile. Backoff grows 5s → 15s → 30s → 60s → 2m → 5m
  and remains capped at 5m. Handshake age alone never forces reconnection.
- A persisted 15-minute Android JobScheduler check is a best-effort fallback
  if the optional notification monitor is stopped. Doze, battery restrictions,
  process force-stop and Android VPN permission changes may delay or prevent
  background work. **This is not a guaranteed keepalive.**
- Tapping **Disconnect** cancels the requested connection and scheduled
  recovery; reconnect manually to arm it again. Disabling auto-reconnect
  cancels the periodic background job. Neither path changes the device's
  Android Always-on/lockdown setting or silently falls back to direct traffic.
- No external network probes, DNS lookups or credentials are sent by recovery.
  The VPN may still appear **UP** while its gateway/handshake is stale. This
  preview does not handle that case.
- VersionCode 18 / `0.8.9-alpha08.9-preview`. See
  [Alpha 0.8.9 test plan](docs/ALPHA089_RECOVERY_TEST_PLAN.md).

## Alpha 0.8.8 development preview — manual home service reachability

- Enter a numeric private IPv4 address and TCP port, or tap **Use Navidrome
  port (4533)** to fill the port. No target address or results are saved.
- Press **Test home service through VPN** and approve the confirmation.
  The app validates a strict RFC1918 target, finds exactly one Android-reported
  VPN Network, and attempts a single 4-second TCP connection using that
  Network's socket factory. No hostname resolution, retry, or Wi-Fi/cellular
  fallback is permitted. The result does not print the destination.
- A successful test means the port accepted a TCP connection on the
  Android-reported VPN transport; it does not prove the application is
  authenticated, that Navidrome is configured correctly, or that DNS/IPv6
  traffic cannot bypass the VPN. Failed or ambiguous tests are cautious.
- This is useful when checking home services like a locally reachable
  Navidrome gateway without exposing it to the public internet.
- **Navidrome troubleshooting:** The port shortcut does *not* configure
  Navidrome. If the Fedora Podman port is bound to `127.0.0.1:4533`, a phone
  connecting to `10.77.0.1:4533` over WireGuard will fail. Verify the local
  listener and explicitly expose or reverse-proxy the service **only on the
  intended private WireGuard interface**, with suitable host firewall rules.
  Keep public router forwarding closed. A Tailscale HTTPS hostname is not a
  numeric IPv4 target for this manual TCP check.
- Existing WireGuard routing, saved profiles, notifications and proxy
  tools remain unchanged. VersionCode 17 / `0.8.8-alpha08.8-preview`.
- See [manual test plan](docs/ALPHA088_HOME_SERVICE_TEST_PLAN.md).

## Alpha 0.8.7 development preview — local event history and shortcut

- **Recent connection events** is a bounded, in-memory log of state changes
  observed while the VPN dashboard is open: interface down, statistics
  unavailable, waiting for a handshake, recent handshake or potentially stale
  handshake. It stores at most 12 state labels and never records traffic
  destinations or peer endpoints. It is not a background audit.
- **Copy redacted support report** is an explicit clipboard action containing
  only generated connection-health text, the routing *mode* (not CIDRs), and
  those fixed status events. No imported configuration, keys, endpoints, user
  hostnames or raw DNS test output is included. The clipboard is accessible
  to other apps, so inspect before sharing.
- **Quick Settings shortcut:** Add "Wonhee VPN" through Android's tile editor.
  Tapping it opens Wonhee's dashboard, but cannot connect, disconnect,
  bypass VPN approval or change Always-on policy from Quick Settings.
- WireGuard backend, saved profiles, routes, DNS choices, notifications and
  Android Always-on behavior are unchanged. This preview is not a kill switch,
  a secure DNS filter or a verified leak-protection implementation.
- Preview versionCode 16 / `0.8.7-alpha08.7-preview`. See
  [manual test plan](docs/ALPHA087_TEST_PLAN.md).

## Alpha 0.8.6 development preview — traffic chart and route observations

- A **LIVE TUNNEL TRAFFIC** card shows passive WireGuard throughput,
  a bounded ~2-minute blue/pink line chart, and observed peak download/upload
  while the VPN screen is visible. Samples reset when the screen is hidden,
  counters reset, or the VPN disconnects. No background capture or automatic
  network request is added.
- The existing **user-consented VPN-only** DNS and HTTPS diagnostic now also
  shows whether Android reports IPv4/IPv6 default routes and how many DNS
  servers it observes on that VPN network. It does not prove forwarding,
  encryption, filtering, fail-closed behavior or absence of DNS/IP leaks.
  Split-tunnel mode may intentionally omit default routes.
- Keeps the **Alpha 0.8.5 notification and connection behavior**. This change
  is on a feature branch only and is not ready for signed release.
- Build versionCode 14 / `0.8.6-alpha08.6-preview`.
- See [Alpha 0.8.6 manual test plan](docs/ALPHA086_TRAFFIC_ROUTE_TEST_PLAN.md).

## Alpha 0.8.5 preview — ongoing VPN throughput notification

- A silent notification displays **download ↓ and upload ↑ throughput** from
  WireGuard's cumulative RX/TX byte counters, sampled roughly every five seconds
  only while the tunnel is active. It also shows total transferred bytes.
- Tap the notification to open Wonhee. It disappears when the tunnel stops.
  Notifications require Android notification permission on Android 13+.
- The optional `systemExempted` foreground service can be unavailable on a
  device or blocked from starting in the background after Always-on restoration.
  In that case WireGuard still works, and opening Wonhee can start the monitor.
  This notification does **not** send keep-alive packets, enforce VPN lockdown,
  prove connectivity, measure all device traffic, or audit DNS leaks.
- Android Studio/GitHub build uses the existing pinned Gradle 8.13 wrapper;
  build versionCode 13 / `0.8.5-alpha08.5-preview`.
- See [notification test plan](docs/ALPHA085_NOTIFICATION_TEST_PLAN.md).

## Combined Alpha 0.8.4 preview — DNS presets, connection health and signing

This branch combines the next roadmap stages into one future release. It does
**not** yet implement or claim DNS-over-HTTPS/QUIC, tracker filtering,
a standalone kill switch or verified leak protection. Android's native
Always-on/lockdown path is now integrated as an **opt-in, unverified preview**:
the encrypted selected profile can be restored by the official GoBackend
system-start callback, but it requires device testing before a secure release.

- **DNS presets:** Select imported profile DNS (no override), Cloudflare,
  Quad9, AdGuard, Google, or one/two custom numeric DNS IPs. Presets supply
  primary and secondary addresses. Existing single-IP custom profiles are
  preserved; all options use the current Keystore-encrypted profile settings.
  The address must be routed in WireGuard AllowedIPs. Some DNS providers offer
  their own filtering, but Wonhee does not implement DoH/DoQ or tracker blocking.
- **DNS preflight warnings:** All Internet routing with no configured DNS
  shows an on-screen warning and a separate confirmation before connection.
  This is a usability guard, not a connectivity test or leak-proof guarantee.
- **Connection Health:** A local dashboard distinguishes VPN interface state,
  handshake age, configured DNS and Android Always-on/lockdown hints. It does not
  claim the VPN is leak-proof or independently protected.
- **Opt-in VPN-bound diagnostics:** With explicit confirmation, Wonhee resolves
  example.com and makes a single HTTPS HEAD request using Android's VPN Network
  APIs. If no unambiguous VPN transport is available, it does not test on a
  non-VPN network. The result is only a DNS/HTTPS reachability observation.
- **Failure clarity:** Common VPN authorization and configuration failures
  show redacted human-readable reasons without exposing saved secrets.
- **Profiles persist across force stop:** Importing a valid WireGuard `.conf`
  immediately commits its encryption-sealed configuration. The selected profile
  returns when the app is launched again. One on/off button controls the tunnel;
  tapping Connect saves validated routing and DNS choices automatically;
  Save profile settings remains available when saving without connecting. Explicit
  Force stop terminates the active VPN and must not be silently bypassed.
- **Optional Android Always-on & lockdown:** The native VPN settings link
  opens Android's settings for Always-on VPN and Block connections without VPN.
  System-started Always-on attempts to restore the saved profile using the
  WireGuard library callback. This does NOT make a split-tunnel gateway into
  a validated full-tunnel VPN, and lockdown could eliminate all internet access
  until Fedora forwarding/NAT, IPv6, DNS and reboot recovery are tested.
- **Backward-compatible encrypted settings:** Existing profiles restore
  with imported-profile DNS selected where no custom DNS existed.
  VPN credentials remain sealed with AES-GCM and Android Keystore.
- **Pinned release-signing workflow:** CI debug previews still use disposable
  signing. The separate manually dispatched signed-release job requires a
  privately provisioned persistent keystore and a matching SHA-256 certificate
  fingerprint. A mismatch stops publication; no signing material is committed.
  This does not retroactively make existing debug APKs upgrade-compatible.
- **Preview build:** versionCode 12, versionName
  `0.8.4-alpha08.4-preview`, debug artifact
  `wonhee-proxy-alpha08.4-preview-debug-apk`. Do not install expecting an
  in-place upgrade from a differently signed debug build.

See [signing setup](docs/SIGNING.md) and the
[combined preview test plan](docs/ALPHA08_PREVIEW_TEST_PLAN.md) and
[Alpha 0.8.3 DNS test plan](docs/ALPHA083_DNS_TEST_PLAN.md), and
[Alpha 0.8.4 diagnostics/signing test plan](docs/ALPHA084_TEST_PLAN.md).

## New in Alpha 0.6 — explicit connection routing (draft)

- **Three choices on the VPN screen:** Use imported profile routes (default), Home
  access (custom split CIDRs), or All internet (experimental IPv4+IPv6 default
  routes). No routing switch occurs while the VPN is active.
- **Home access:** Enter home networks such as `10.77.0.0/24` and, only when
  your Fedora routing/firewall permits it, `192.168.50.0/24`. Other destinations
  use Android's usual network connection. The app rejects `/0` in Home mode.
- **All internet is an *unverified request*, not a privacy guarantee:** The phone
  requests both IPv4 and IPv6 default routes; the Fedora home gateway must have
  appropriate forwarding, firewall/NAT for IPv4, functional IPv6 routing and DNS.
  A WireGuard handshake or changing egress IP alone does not establish leak
  safety. Without those server changes, internet requests can fail or leak.
- **No silent key changes:** The selected mode modifies only a temporary
  connection configuration. Original imported WireGuard keys/addresses remain
  unchanged. New imports save automatically; tapping **Connect** saves valid
  mode, DNS and home CIDR choices to the encrypted profile. Use **Save profile
  settings** to save preferences without connecting. Existing Alpha 0.5
  profiles remain readable.
- **Guardrails:** Custom mode requires a single WireGuard peer; multi-peer
  profiles can still use their original routing. Warning before Connect;
  Android's single VPN slot means Tailscale is replaced while Wonhee is active.
  Native Always-on is now opt-in and requires validation; no independent
  kill switch, DNS enforcement or leakage claims.
- **Build:** `gradle :app:assembleDebug`. Actions artifact:
  `wonhee-proxy-alpha06-debug-apk`.

See [Alpha 0.6 manual test plan](docs/ALPHA06_TEST_PLAN.md).

## New in Alpha 0.5 — VPN-first dashboard

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
  prefixes instead request split routing. Alpha 0.6 adds an explicit connection-time route selector.
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

1. Build or download the wonhee-proxy-alpha06-debug-apk from GitHub Actions.
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
8. On launch, import a private WireGuard `.conf`. Wonhee saves it securely
   immediately and remembers the selected profile. Tap **Turn VPN On** and
   approve Android VPN permission. Use **Turn VPN Off** to disconnect.
   Force stop ends the active VPN, but reopening the app should restore the
   saved profile without reimporting.
   Use **Telegram proxy tools** for MTProto.
9. Set connection routing: imported profile routes, home split CIDRs, or the
   explicitly experimental all-internet request. Tap **Save profile settings**
   to remember changes, then reconnect and verify their effect.
10. To test persistent VPN, open **Android VPN settings** from Wonhee and
   enable Android Always-on only after validating the saved-profile recovery.
   Enable **Block connections without VPN** only when full internet routing
   and DNS work; otherwise all internet may stop working.
11. See [Alpha 0.6 manual test plan](docs/ALPHA06_TEST_PLAN.md), [Alpha 0.4 manual test plan](docs/ALPHA04_TEST_PLAN.md),
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
