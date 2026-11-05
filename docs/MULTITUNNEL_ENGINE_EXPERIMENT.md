# Wonhee: rootless multi-tunnel engine experiment

**Status: routing-classifier spike only. NOT a functioning two-VPN APK.**

This branch starts the groundwork for simultaneously connecting two **independently
keyed** WireGuard configurations on an unrooted Pixel 8a or Samsung A36:

- AirVPN WireGuard client: default internet exit.
- Home WireGuard client: private destinations. The tested ASUS router
  baseline currently uses a `10.6.0.0/24` tunnel and `10.0.0.0/24` LAN;
  Navidrome is on Fedora's LAN address `10.0.0.169:4533`. The old
  `10.77.0.0/24` Fedora WireGuard subnet is a legacy fallback, not the
  target of the new home tunnel.
- Both keep their own `[Interface]` private key, tunnel address, gateway public
  key, endpoint, handshake and lifetime.
- One Android `VpnService` captures all device traffic through a single
  virtual TUN, then a userspace multiplexer delivers packets to separate
  encrypted WireGuard *sessions*.

The current official WireGuard Android `GoBackend` used by Wonhee manages
one current tunnel, so adding two toggles or two instances is **not** enough.
WireGuard Android's rooted kernel backend is a different operating mode,
not suitable for the requested unrooted devices.

## Routing classifier implemented in this branch

`MultiTunnelPacketRouter` is a pure-Java **offline-only** route selector:

1. Validate 1–8 explicit, wholly RFC1918 IPv4 home subnets.
2. Require an AirVPN-style IPv4 default route.
3. If destination matches a home subnet, select HOME.
4. Otherwise select INTERNET for valid IPv4; select INTERNET for IPv6 only
   when the internet profile has an IPv6 default route.
5. When the required session is unavailable, or the packet is malformed,
   select DROP. **No direct/non-VPN target exists in the API.**
6. Reject ambiguous overlapping home subnets, public destinations and
   malformed IPv4 CIDRs.

Unit tests cover normal routing, home/exit outage isolation, IPv6 policy,
malformed IP packet rejection, route overlap and public/default CIDR rejection.

This does **not** operate on actual phone traffic or prove fail-closed behavior.
No local VPN configuration is read, no keys are modified, and no native
WireGuard sessions are started by this class.

## Stage 2: control-plane safety and working-client diagnostics

The experimental `MultiTunnelSessionLedger` tracks HOME and INTERNET
session phases independently and rejects stale asynchronous callbacks after
a stop/reconnect. It passes only the sessions marked READY to the existing
packet route classifier. This is an offline-only testable control-plane
prototype; it neither establishes two real cryptographic sessions nor
provides live traffic fail-closed guarantees.

The current single-tunnel app now checks Android VPN default routes before
running an explicit public DNS/HTTPS diagnostic. Home-only split routes
**skip public internet requests** and point users at the existing manual
private-service probe instead. The private TCP test reports one connection
duration (not ping RTT, throughput or a leak assessment). These changes are
safe to validate on the working ASUS router profile without changing keys.

**The stable `WireGuardSession` and automatic recovery behavior remain
unchanged.** The opt-in recovery feature is already implemented in the
existing app; it does not establish a second independent session.

## Next engineering work before an on-phone experiment

1. **Native multi-session transport.** Introduce a new experimental backend
   alongside `WireGuardSession`; do not mutate the stable GoBackend path.
   Feed separate virtual packet interfaces to two genuine wireguard-go
   instances while keeping only one Android system TUN and one VpnService.
2. **Per-session identity and address policy.** Because AirVPN and Home use
   different client tunnel addresses, handle packet source selection and
   validated IPv4/IPv6 checksums. Do not assume two independent `[Interface]`
   keys can be merged into one WireGuard interface. IPv6 needs dedicated
   treatment rather than unchecked fall-through.
3. **Socket protection and endpoint routing.** Every underlying UDP socket
   must be protected via `VpnService.protect`, and packets to the two
   WireGuard peer endpoints must not loop back into the VPN. Handle endpoint
   resolution, roaming and Wi-Fi/cellular network changes.
4. **DNS policy.** Set system DNS within the VPN consistently, route its
   packets through an approved encrypted session, and prevent access to
   external DNS through an unapproved path. Test both IPv4 and IPv6.
5. **Atomic lifecycle.** Start both sessions with an explicit state machine,
   report per-peer handshake/transfer health, and stop routing to any peer that
   is not ready. A degraded HOME path must not leak through INTERNET, and
   a degraded INTERNET path must not fall back to the ISP. Respect manual
   disconnect, Android Always-on and Android's single-VPN ownership.
6. **Opt-in feature gate.** A new dual-tunnel UI must remain disabled until
   the native engine passes basic packet I/O, cancellation and teardown tests.
   Never silently enable an unverified security-critical transport.
7. **Device validation.** Pixel 8a (GrapheneOS), Samsung A36; AirVPN public
   egress IP, Navidrome over `10.77.0.1:4533`, Web/DNS IPv4+IPv6,
   killswitch/lockdown, airplane/Wi-Fi/cellular switches, overnight recovery,
   and repeated process termination. Capture tests at both server and phone.

## Tested ASUS home baseline and AirVPN

The current working Home WireGuard endpoint is the ASUS RT-AX86U, not
Fedora's legacy `wg0`. Phone split routes use the router's WireGuard
subnet and home LAN. Fedora continues hosting Navidrome and MTProxy.
AirVPN may be configured on Fedora and as an ASUS WireGuard **client**,
but neither creates two independent encrypted phone sessions.

Keep the tested router/phone configuration untouched. Do not copy actual
`.conf` secrets into issues, PRs, logs or CI, or move the router's internet
default route as part of this experiment.

## Release gate

This branch is a **draft PR only**. CI compilation of the route selector is
necessary but **insufficient**. No dual-tunnel APK should be advertised until
two independently authenticated WireGuard sessions can remain active and pass
bidirectional packet tests without a non-VPN fallback.
