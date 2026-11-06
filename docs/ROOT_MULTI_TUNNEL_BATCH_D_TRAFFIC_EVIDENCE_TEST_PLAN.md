# Wonhee 0.12.0 — Batch D traffic evidence and protection design

Batch D extends the independently managed kernel multi-tunnel manager with
**read-only endpoint routing and measured byte-counter observations**. The TCP
test makes an outbound socket connection, but does not send an HTTP request.
It never installs kill-switch rules, endpoints exceptions, DNS policies or
Android routing overrides. **Actual kill switch: OFF.**

This is one combined testing batch, not a series of individual releases.

## What the previous batches established

- `wgs_client1` and `AirVPNEurope` were running concurrently with matching
  public identities. They are examples, **not fixed application slots**.
- Home private root route lookups matched `3/3`, IPv4 and IPv6 default routes
  selected the Internet tunnel, and configured DNS route lookups matched `3/3`.
- A TCP socket from Wonhee's app UID connected to `10.0.0.169:4533`.
- Both WireGuard UDP transports used fwmark `0x20000`. On Android that is the
  shared `protectedFromVpn` bit; it cannot identify one specific tunnel.

## Test the whole batch

1. Install the `0.12.0-batchD-traffic-evidence` test APK. Do not uninstall a
   differently signed app without saving its encrypted profiles. Keep USB
   ADB recovery available.
2. Open Multi-Tunnel Lab. Select all intended profiles and confirm their
   connections and existing split-route overrides are in the tested state.
3. Tap **Inspect UDP endpoint egress + Private DNS**. For each selected
   identity-verified tunnel, capture the marked endpoint route. A physical
   interface like `wlan0`/`rmnet16` is an *underlay candidate*, not proof that
   the UDP packets leave there. A selected WireGuard interface is a potential
   routing loop and needs investigation before any firewall design.
4. Enter `10.0.0.169:4533` into the same combined IP:port field as Batch C.1;
   tap **Test app TCP reachability**. Capture the expected selected tunnel,
   UID-0 route, connection result, and per-profile RX/TX counter deltas.
   Background traffic and handshake/keepalive packets can influence deltas.
5. Optionally repeat with a numeric public service destination for the
   Internet-default profile (for example `1.1.1.1:443`). This should remain
   a normal TCP connect only; no credentials or HTTP request are sent.
6. Force-close and reopen Wonhee, then use **Read live kernel status**. As
   before, no unknown interface may be adopted automatically. The previously
   owned Batch B rule ledger must still agree with live rules.
7. Confirm that no `WN_MULTI_GUARD4`/`WN_MULTI_GUARD6` firewall chains were
   installed by the new checks. No new high-priority route overrides should
   appear merely from opening the read-only audits.

**Send one combined report:** marked UDP endpoint egress audit, one or two
app-service probes, and whether the tunnels stayed working after reopening.
Don't paste WireGuard private keys, peer public keys or endpoint credentials.

## How to interpret results

| Observation | What it establishes | What it cannot establish |
| --- | --- | --- |
| Endpoint route to `wlan0` | UID-0 marked route *candidate* | That actual WireGuard UDP exited Wi-Fi |
| App TCP connected | Wonhee app socket completed TCP handshake | Which physical/WireGuard interface carried it |
| Expected WG tx/rx increased | Counter changed during probe | The change belongs to just the probe |
| Private DNS says hostname/opportunistic/off | Android's stored mode | DNS packets, app DoH/DoQ or no fallback |
| IPv4/IPv6 defaults present | Configured default prefixes | All real packets are protected |

No `tcpdump`, eBPF capture or firewall enforcement is started by Batch D.
Follow-on *actual packet-path* verification will require scoped packet
observation or trusted per-UID kernel accounting, including a controlled
comparison on Wi-Fi and mobile data.

## Protection architecture requirements (not yet implemented)

1. Build an **N-profile policy graph** from validated identities, allowed IPs,
   numeric UDP endpoints, endpoint ports, and intended route families.
2. Treat shared mark `0x20000` solely as Android's VPN-protection attribute.
   Never allow *all* traffic with that mark as a tunnel-specific exception.
   Endpoint bypass needs a narrower verified policy and explicit handoff
   handling; endpoint IPs may change.
3. Prove that each app class (ordinary app UID, root helper, Android resolver)
   follows its selected policy, with explicit Private DNS/DoT/DoH/DoQ and IPv6
   expectations. DNS route lookups alone are inadequate.
4. Plan firewall rules per tunnel/service/UID and keep a persistent exact-match
   ownership ledger. Validate every candidate rule before installing any;
   preserve unrelated Android/OEM rules.
5. Fail safely if a tunnel drops, root exits, app crashes or the phone reboots.
   Rollback and recover must remain possible over USB ADB. Test Wi-Fi↔cellular
   transitions and endpoint changes before offering a user-facing kill switch.

No protection mode should be armed automatically based only on the Batch D
audit or traffic-counter evidence.
