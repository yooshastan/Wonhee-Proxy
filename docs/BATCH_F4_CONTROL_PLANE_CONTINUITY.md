# Batch F.4 — offline control-plane continuity contract

## Grounded field observations (2026-11-08, Pixel 8a / Android 16)

- Dual root WireGuard identities verified: HOME and AirVPN. Three owned split-routing rules matched three live kernel rules.
- Guard was **OFF** and the inspection did not send packets or change network state.
- On Wi-Fi underlay candidate `wlan0`, the five-second F.3d passive capture reported **one outgoing ICMPv6 Neighbor Solicitation (type 135)**; zero captured DHCPv4, direct DNS and HTTP validation candidates in that short window.
- IPv4 and IPv6 filter/OUTPUT counters changed, but these global counters **cannot be tied** to the captured Neighbor Solicitation. We cannot claim it traversed OUTPUT, identify its Android UID or prove that rejecting it caused the previous failure.
- Before the F.3d test, a separate **pure simulation** of the paused Batch F chain predicted REJECT for physical DHCPv4, IPv6 Router Solicitation, direct DNS and HTTP validation; selected Internet/HOME tunnel flows RETURN. These are chain-model outcomes, not successful network deliveries.
- User's subsequent **Safe stop** succeeded; prior separate verification identified and safely terminated a deleted orphan `rootlab` DNS helper after exact socket/PID matching. UDP port 53535 was confirmed free.

## Why an immediate iptables change would be unsafe

The old guard installs app-owned IPv4 and IPv6 OUTPUT chains, with loopback + exact marked WireGuard UDP endpoint exceptions + tunnel egress, followed by a terminal REJECT. The IPv6 Neighbor Discovery packet observed on the physical interface may be handled in a kernel path not proven to traverse filter/OUTPUT. Generic `-p ipv6-icmp -j ACCEPT`, blanket `-o wlan0/rmnet* -j ACCEPT`, or broad `0x20000` bypasses would silently weaken leak protection. The current source's Android mark is shared metadata, **not** kernel WireGuard socket provenance.

## F.4 contract in this PR

`RootGuardF4ContinuityContract` is **pure Java**. It runs the CURRENT policy through representative dual-stack synthetic flows on both `wlan0` and `rmnet16`. It checks the consequences of:
- DHCPv4 renewal and IPv6 NS (135), NA (136), RS (133) on either physical underlay
- Captive portal / HTTP validation on the physical underlay
- Direct IPv4/IPv6 public HTTPS, plaintext DNS and HOME private-address fallbacks
- Correct public HTTPS over the Internet tunnel and HOME Navidrome TCP over HOME
- Transport endpoint UDP/mark on both physical interfaces, an unmarked packet at the same endpoint, and an endpoint IP rotation
- A current-plan-versus-selected-endpoints discrepancy

The test reports modeled control-plane risks and unresolved verification prerequisites. **It never authorizes activation.** CI exercises the current chain grammar; the F activation compile-time gate remains paused.

## Next design and validation stages (not implemented here)

1. Establish whether relevant kernel-originated ND/DHCP/control traffic actually traverses local OUTPUT on Android 16 with root WireGuard, through instrumented packet/hook attribution on a non-primary test device. Do not infer it from a physical header alone.
2. Derive exact required control exceptions by protocol, ICMPv6 type, link scope, interface and legitimate packet origin. Preserve IPv4/IPv6 app traffic fail-closed and refuse broad underlay internet/DNS allowances.
3. Investigate stronger WireGuard transport socket attribution than the common Android `0x20000` protected mark. Confirm correct endpoint revalidation and firewall lifecycle on Wi-Fi-to-cellular transitions and roaming/rotation; no stale exceptions may remain.
4. Implement and independently prove a **crash-resistant, exact-owned automatic rollback** that can restore network access without relying on the interrupted UI app process, while avoiding blanket firewall chain flushes. Validate reboot, shutdown, forced tunnel loss, and app-process death.
5. Only then, on a spare device with working wired ADB rescue, perform bounded actual packet/leak tests for both IP families and revise the source-level activation gate after review.

**No change in this PR enables the Batch F kill switch.** DNS/HOME routing and signing functionality are inherited unchanged from the parent branch.