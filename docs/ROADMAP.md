# Wonhee Proxy: privacy, ad filtering and remote-access roadmap

## Alpha 0.1 — device-testable proxy companion

- Native Java Android app, no Google services dependency.
- MTProto and SOCKS5 endpoint validation and deep-link handoff explicitly to
  the known Ultgram package IDs.
- Manual 3-second TCP reachability probe; requires user confirmation because
  the proxy server and DNS resolver can see network metadata.
- No disk persistence of proxy credentials; no analytics, no implicit chooser
  intent that might expose a proxy secret to an unknown app.
- Optional official MTProxy container starter for a dedicated VPS.

**Not done:** Android VpnService, packet routing, actual MTProto/SOCKS5
handshake verification, fail-closed behavior, DNS-over-HTTPS, DNS interception,
ad/domain filtering, Navidrome access, encrypted profile storage, kill switch.

## Milestone 0.2 — genuine proxy health and Ultgram integration

- Implement protocol-aware MTProto/SOCKS5 connectivity verification without
  logging credentials; distinguish remote port reachability from successful
  proxy forwarding.
- Optionally allow explicit named profiles, backed by Android Keystore-backed
  encryption if credentials ever need saving.
- Align Ultgram's built-in proxy manager with the same testable validation
  library. Prove Telegram traffic uses the selected proxy on Wi-Fi and cellular.
- Audit Java/native/media/call/IPv4/IPv6 DNS and direct fallbacks before
  labeling any mode fail-closed.
- Keep Ultgram working without any other Android VPN: the app-internal
  SOCKS5/MTProto transport does not register VpnService.

## Milestone 0.3 — optional ad/tracker filtering

- Decide which traffic is in scope: phone-wide, selected applications or
  in-app HTTP/web links. DNS blocklists cannot suppress Telegram API-delivered
  sponsored posts and must not break login, media or calls.
- If using Android VpnService for app-wide traffic, develop a real packet
  forwarding engine and account for Android's single-active-VPN constraint.
  Do not ship a fake tunnel or claim DNS privacy without leak tests.
- Provide opt-in settings, a clear bypass policy, disable/restore and false
  positive reporting. Do not record visited domains by default.

## Milestone 0.4 — protected Fedora/Navidrome gateway

- Deploy a private, outbound-only Fedora-to-VPS authenticated tunnel,
  disconnected from the public MTProxy service.
- Add per-service HTTPS identity/access controls, key rotation, and abuse
  protection. Navidrome is currently a rootful Podman container listening on
  localhost:4533 and Tailscale Serve. Preserve that until the replacement
  path is proven safe.
- Test remote Moka Music Player streaming, media-library permissions, and
  reconnection on LTE/Wi-Fi. A generic Telegram MTProxy does not transport
  Navidrome Subsonic API calls.

## Threat model

| Threat | Alpha 0.1 status |
| --- | --- |
| Expose public phone IP to Telegram | Proxy only when Ultgram enables it; not independently verified |
| Expose IP to proxy operator | Still possible; use a trusted external VPS |
| Reveal phone number or Telegram account | Unchanged; use account privacy settings |
| Proxy server offline / direct fallback | Not blocked; no kill switch yet |
| DNS leaks, calls, media, IPv6 bypass | Not audited, cannot claim protected |
| Telegram sponsored messages | Third-party API clients must support them |
| Ad/tracker domains in external web traffic | No filtering implemented yet |
| Private Navidrome without Tailscale | Separate later gateway, not implemented |
| Android VPN conflicts with Tailscale | Companion uses no VpnService; future system-wide filter might |

Sources:
- https://core.telegram.org/proxy
- https://core.telegram.org/api/sponsored-messages
- https://developer.android.com/develop/connectivity/vpn
- https://tailscale.com/docs/features/tailscale-funnel
