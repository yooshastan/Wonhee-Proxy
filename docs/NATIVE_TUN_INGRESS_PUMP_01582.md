# Wonhee 0.15.82 — native TUN ingress pump diagnostic

## Purpose

This debug-only increment follows the device-passed 0.15.81 JNI socket-protection test. It tests the next boundary: Android TUN packet capture, Java classification, JNI packet transfer, and consumption by two independent wireguard-go PacketTun devices.

## Exact scope

- One Android VpnService TUN with MTU 1280 and address 10.253.0.1/32.
- The VPN builder allows only the diagnostic app package.
- The only installed route is 198.18.0.0/15, the RFC 2544 benchmarking range.
- 198.18.1.0/24 is the Home test slice; the remainder of 198.18.0.0/15 is the Internet-exit test slice.
- The test sends three UDP datagrams to each synthetic destination.
- Two independent native WireGuard devices use fresh ephemeral keys and no peer endpoints. Both IPv4 and IPv6 UDP sockets must be protected by the owning Android VpnService.
- A bounded native packet queue accepts each packet and the WireGuard device's TUN reader consumes it.
- The VPN installs no IPv6 route; IPv6 is outside this test. If an IPv6 packet reaches the pure classifier, it is rejected. TCP, fragments, malformed packets, and every other destination are rejected, while queue failures are counted as failures.

## Explicit exclusions

This is NOT live multi-exit Internet forwarding. The synthetic peers have no endpoints, so no handshake or remote packet delivery can occur. There is no reply path, profile import, DNS, default route, root command, production mark, kill switch, or other-app routing. The test does not exercise real Moka or Home credentials.

The existing official signed package and release signing configuration remain unchanged. The 0.15.82 artifact is a separate debug-only package.

## Device acceptance

1. Disconnect every other VPN and keep Android Private DNS OFF.
2. Start the diagnostic. Confirm Android's VPN consent and that the screen reports TUN ready.
3. Send six synthetic UDP probes.
4. Require at least three packets queued and consumed by each native session, zero policy drops, zero injection failures, and exactly four protected sockets with zero protection failures.
5. Stop the test and confirm the status says the TUN and native sessions were released.
6. Verify ordinary apps and the official Wonhee installation remain untouched.

A pass proves the Android TUN-to-native ingress and per-session queue boundary only. The next milestone is secure real-profile conversion, actual peer endpoint handshakes, bidirectional packet forwarding, IPv4/IPv6 policy, DNS, tunnel-loss fail-closed behavior, and exact teardown before any app routing or release claim.
