# Transport-aware RootLab and Android VPN integration

## Device evidence (2026-11-25)
- The root-only three-interface lab successfully selected the Home route for a private IPv4 TCP destination.
- The UID-scoped IPv6 reject rule also matched outer encrypted IPv6 UDP packets. Its counters and WireGuard TX errors rose together. An exact temporary transport exception matched the expected packets; both counters stopped rising and rollback restored the original guard.
- The remote WireGuard interface observed completed TCP handshakes and clean closes, with no HTTP payload.
- Moka deliberately refused credential-bearing private HTTP without exactly one Android-recognized approved VPN route. The TCP diagnostic does not authorize login or prove fail-closed behavior.

No personal endpoints, keys, logs or credentials are included here.

## Implemented in this commit
Offline exact UDP transport exception compiler and regression tests for both address families. Rule uses RETURN in a private guard chain, not a blanket ACCEPT. Matches full mark, numeric endpoint, local and remote ports, and observed physical uplink. Inverse deletes the exact rule, never flushes a chain. Zero/duplicate marks, invalid targets, changed uplinks and loop candidates are rejected. No root command is executed and no mark is allocated. Current RootLab guard and release behavior remain unchanged.

## Next gated implementation
1. Prove exclusive transport socket identity and collision-safe allocation on the target Android build. The previous experimental mark is not a production reservation. Inventory both families, active socket marks and vendor/BPF writers. Refuse ambiguous ownership.
2. Add a write-ahead journal and real kernel adapter for mark and exact rule lifecycle. Require exact original state and hook ordering; add exception only to owned chain, remove exception before restoring mark, preserve rollback metadata on failure. Never overwrite unknown state. Integrate cleanup before the existing detached chain recovery; current validators expect five staged operations and must not silently adopt a sixth.
3. Test Moka's no-credential TCP diagnostic over both uplinks, captures at the server, root and app packet rejection, transport endpoint changes, tunnel loss, kill switch, process death, safe stop and unrelated system firewall preservation. No HTTP credentials until the approved route condition is met.
4. Prototype one real Android VpnService with an actual TUN forwarding path. Existing GoBackend is a single VPN session; the offline MultiTunnelPacketFlow and native inactive devices are not a live implementation. Use independent protected underlay sockets, bounded queues, ingress ownership, session-generation invalidation and fail-closed routing. Keep the official single-tunnel path intact. A VPN badge or a dummy TUN is not sufficient. Decide whether to extend the userspace backend or bridge to root interfaces after verifying actual packet flow and Android consent.
5. Validate application/protocol classification and precedence, IPv4/IPv6, DNS with system Private DNS OFF, route transitions, no fallback, Moka approved route and authentication, then music streaming. Do not weaken Moka's credential protection or claim a production kill switch based on the TCP probe.

## Release gate
No installable transport-aware build or new VPN service is claimed by this commit. Keep the existing stable release and its signature unchanged. Build/test the prototype separately, require real device acceptance before promoting any release.

## Follow-up: explicit RootLab transport trial
The debug-only kernel adapter now implements a narrow Home IPv6 transport trial, using the device-tested candidate mark rather than declaring a production reservation. Requires existing exact UID/dual-stack/fallback ownership, exactly three known links with marks off, an unchanged cellular route and numeric endpoint/ports. Immutable write-ahead ownership records boot/link identity and exact rule parameters before writes. Recovery removes the exact exception before restoring the mark; unknown state retains the journal and pauses Safe Stop. No Android VPN service, production mark allocation, authenticated Moka traffic or comprehensive leak protection is authorized. Stable release and version are unchanged. This is not a consolidated upgrade.

## Native protected socket foundation
Added a protected wireguard-go bind wrapper with both-family protection before packet I/O, close-on-failure, re-protection on reopen and refusal of profile fwmarks. Added a guarded native session activation method. The Android-facing callback, actual TUN data plane, application/protocol classification and device-level tests remain blocked on integration. This is not an Android VPN frontend or installable upgrade.
