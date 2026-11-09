# Moka + Wonhee root-free interoperability (staged)

Status: **transport-only prototype; disabled and not packaged in the Android app**.
Starting baseline: Wonhee 0.15.26 Batch F.5 (guard paused), Moka 4.0.0-beta06.3.

## Non-negotiable product boundaries

- Moka never requests `su`, uses a root helper, installs firewall rules, or requires root to function.
- Wonhee's existing Android `VpnService` mode works normally on non-rooted devices.
- Wonhee root mode remains optional and must not be enabled by installing Moka.
- An approved private `http://<numeric-private-IP>:<port>` Navidrome session must not fall back to
  Wi-Fi, cellular, AirVPN, a public socket or a generic HTTP proxy when Home WireGuard fails.
- Do not log Navidrome credentials, OpenSubsonic signed query strings or bridge secrets.
- Do not expose the Navidrome server, pairing service or bridge on a public/LAN listener.
- Android Private DNS must remain OFF in the Pixel 8a reference setup.

## Architecture

1. Moka's existing Android-recognized VPN path stays unchanged. This is the default for
   ordinary VpnService users and for private HTTP over an official VPN.
2. When no Android VPN route exists, Moka may show **Connect via Wonhee** as a separate,
   user-chosen transport. It must never automatically retry the previous failed HTTP request
   using an unprotected socket.
3. Wonhee shows a user consent screen, validates the calling app's UID/package and issues a
   random, session-scoped 256-bit capability. Pairing must not rely on the two apps sharing a
   signing key. The capability is distributed through authenticated Android IPC and kept in
   memory; it is never placed in an Intent URI, notification, log or browser page.
4. Wonhee starts a supervised root helper **only after** verifying the selected Home profile,
   live WireGuard identity, destination route and service allowlist. The helper listens on
   `127.0.0.1` at an ephemeral port, accepts only the paired capability and GET/HEAD paths
   under `/rest/`, and forwards only to the one configured private numeric address and port.
5. Every upstream TCP socket is bound with Linux `SO_BINDTODEVICE` to Wonhee's verified Home
   WireGuard interface. `SO_BINDTODEVICE` errors, a missing interface, a failed dial, or any
   HTTP redirect produce an error. There is **no direct-network retry**.
6. Moka's library and Media3 streaming clients use the returned loopback endpoint and token
   rather than attempting their own private HTTP connection. Its HTTPS and official-VPN
   paths remain unaffected. Range requests are supported for seeking and FLAC playback.
7. Wonhee immediately invalidates the capability and stops the owned helper on Safe Stop,
   selected-Home changes, profile removal and revoked user consent. On restart it must
   reconcile stale PID/listener ownership before starting a new helper, following the DNS
   relay's existing orphan-recovery discipline.

## Transport prototype included in this batch

`roothelper/mokabridge` contains a standalone Go localhost transport with:

- One private numeric destination, fixed at process launch.
- One strict `wnm` interface name, validated before startup.
- A private (0600), 32-byte random capability file; constant-time token comparison.
- No public listen address, DNS lookup, redirects, HTTP proxy fallback or dynamic targets.
- Only GET/HEAD `/rest/` requests; Range support and no token forwarding.
- No persistent Android settings, network/firewall mutations or background services.

**Do not start the prototype manually on a phone.** It lacks the Android consent, identity,
session ownership, readiness and recovery controller. The helper's CLI is an internal
implementation interface, not a supported user-facing feature or an APK entry point.

## Required security tests before any phone trial

| Condition | Required behavior |
| --- | --- |
| Standard Android VPN, no root | Existing Moka connection works without Wonhee pairing |
| Root mode enabled, no consent | No bridge starts; Moka's private HTTP remains blocked |
| Unexpected app UID/package | Pairing rejected; no token is disclosed |
| Approved Moka UID, explicit consent | Only approved numeric Navidrome IP:port is usable |
| Wrong token, wrong path, POST/CONNECT, public IP | Refused before any upstream dial |
| Home WireGuard down, changed, or removed mid-stream | No Wi-Fi/cellular/AirVPN fallback; request fails |
| AirVPN default route still active | Home Navidrome traffic stays bound to Home interface |
| WebRTC, DNS and app traffic elsewhere | Existing routes and DNS policies unchanged |
| HTTP 30x from Navidrome | No redirect followed |
| Stream seek, FLAC, large file | HTTP Range and backpressure work correctly |
| App process killed, Safe Stop, reboot | Helper/secret owner reconciled; orphan not silently trusted |
| Official VPN resumed | No stale bridge or root requirement in Moka |

The Go unit tests can validate request restrictions and simulated upstream failures. They
**cannot** prove live kernel binding, root process ownership, per-app identity or absence
of leaks. Those require a rooted Android test device and packet-level audits before a beta.

## Rollout gate

1. Finish Android service IPC, explicit consent, package/UID verification, secret lifecycle,
   and the root session controller in Wonhee on a feature branch.
2. Add opt-in bridge transport to Moka with independent metadata and Media3 playback tests.
3. Run Android emulator/CI unit tests, then full Pixel 8a dual-tunnel fail-closed tests.
4. Only after verification, produce signed builds with the existing app-specific signing keys.
   Do **not** push an untested bridge into Wonhee 0.15.26 or Moka's store release.
