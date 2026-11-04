package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Off-device-tested classifier for a proposed rootless multi-session WireGuard
 * engine. This class does not establish a VPN or encrypt packets.
 *
 * Architecture: ONE Android VpnService/TUN routes packets to separate encrypted
 * WireGuard sessions. Each session retains its own client private key, address,
 * endpoint protection, and handshake lifecycle. HOME only receives explicit
 * private destinations, INTERNET receives everything else, and any unavailable
 * required session causes a DROP, never an unintended direct-network fallback.
 *
 * This class must not be wired into production traffic before a packet I/O
 * engine, source-address handling, DNS and IPv6 tests are implemented.
 */
final class MultiTunnelPacketRouter {
    enum Target { HOME, INTERNET, DROP }

    private static final int MAX_HOME_ROUTES = 8;
    private final List<Ipv4Range> homeRoutes;
    private final boolean internetIpv6Enabled;

    private MultiTunnelPacketRouter(List<Ipv4Range> routes, boolean allowInternetIpv6) {
        homeRoutes = Collections.unmodifiableList(new ArrayList<>(routes));
        internetIpv6Enabled = allowInternetIpv6;
    }

    static MultiTunnelPacketRouter forFullTunnel(
            List<String> homePrivateCidrs, boolean internetHasIpv4Default,
            boolean internetHasIpv6Default) {
        if (!internetHasIpv4Default) {
            throw new IllegalArgumentException("Internet exit must provide IPv4 default route.");
        }
        if (homePrivateCidrs == null || homePrivateCidrs.isEmpty()
                || homePrivateCidrs.size() > MAX_HOME_ROUTES) {
            throw new IllegalArgumentException("One to eight private home IPv4 routes required.");
        }
        List<Ipv4Range> routes = new ArrayList<>();
        for (String cidr : homePrivateCidrs) {
            Ipv4Range candidate = Ipv4Range.parse(cidr);
            if (!candidate.isEntirelyPrivate()) {
                throw new IllegalArgumentException("Home routes must be wholly RFC1918 IPv4.");
            }
            for (Ipv4Range existing : routes) {
                if (candidate.overlaps(existing)) {
                    throw new IllegalArgumentException("Ambiguous overlapping home routes.");
                }
            }
            routes.add(candidate);
        }
        return new MultiTunnelPacketRouter(routes, internetHasIpv6Default);
    }

    /**
     * Returns DROP for malformed packets, absent routes, or unavailable tunnel
     * sessions. It never returns a direct (non-VPN) networking option.
     */
    Target route(byte[] packet, boolean homeReady, boolean internetReady) {
        if (packet == null || packet.length < 1) return Target.DROP;
        int version = (packet[0] & 0xff) >>> 4;
        if (version == 4) {
            if (packet.length < 20) return Target.DROP;
            int headerLength = (packet[0] & 0x0f) * 4;
            if (headerLength < 20 || headerLength > packet.length) return Target.DROP;
            int totalLength = (packet[2] & 0xff) * 256 + (packet[3] & 0xff);
            if (totalLength < headerLength || totalLength > packet.length) return Target.DROP;
            long destination = ipv4(packet, 16);
            for (Ipv4Range range : homeRoutes) {
                if (range.contains(destination)) return homeReady ? Target.HOME : Target.DROP;
            }
            return internetReady ? Target.INTERNET : Target.DROP;
        }
        if (version == 6) {
            if (packet.length < 40) return Target.DROP;
            int payloadLength = (packet[4] & 0xff) * 256 + (packet[5] & 0xff);
            if (payloadLength == 0 && packet.length > 40) {
                // IPv6 jumbo payloads require separate validation; reject here.
                return Target.DROP;
            }
            if (payloadLength + 40 > packet.length) return Target.DROP;
            return internetIpv6Enabled && internetReady ? Target.INTERNET : Target.DROP;
        }
        return Target.DROP;
    }

    private static long ipv4(byte[] bytes, int offset) {
        return ((long) (bytes[offset] & 0xff) << 24)
                | ((long) (bytes[offset + 1] & 0xff) << 16)
                | ((long) (bytes[offset + 2] & 0xff) << 8)
                | (bytes[offset + 3] & 0xff);
    }

    private static final class Ipv4Range {
        final long start;
        final long end;

        private Ipv4Range(long address, int prefix) {
            long mask = prefix == 0 ? 0L : (0xffffffffL << (32 - prefix)) & 0xffffffffL;
            start = address & mask;
            end = start | (~mask & 0xffffffffL);
        }

        boolean contains(long address) {
            return address >= start && address <= end;
        }

        boolean overlaps(Ipv4Range other) {
            return start <= other.end && other.start <= end;
        }

        boolean isEntirelyPrivate() {
            return inside(10L << 24, 8)
                    || inside((172L << 24) | (16L << 16), 12)
                    || inside((192L << 24) | (168L << 16), 16);
        }

        private boolean inside(long address, int prefix) {
            Ipv4Range privateBlock = new Ipv4Range(address, prefix);
            return start >= privateBlock.start && end <= privateBlock.end;
        }

        static Ipv4Range parse(String raw) {
            if (raw == null) throw new IllegalArgumentException("Missing CIDR.");
            String[] split = raw.trim().split("/", -1);
            if (split.length != 2 || !split[1].matches("[0-9]{1,2}")) {
                throw new IllegalArgumentException("Use explicit numeric IPv4 CIDR.");
            }
            int prefix = Integer.parseInt(split[1]);
            if (prefix < 1 || prefix > 32) throw new IllegalArgumentException("Invalid home prefix.");
            String[] octets = split[0].split("\\.", -1);
            if (octets.length != 4) throw new IllegalArgumentException("Invalid IPv4 address.");
            long address = 0;
            for (String part : octets) {
                if (!part.matches("0|[1-9][0-9]{0,2}")) {
                    throw new IllegalArgumentException("Invalid IPv4 address.");
                }
                int number = Integer.parseInt(part);
                if (number > 255) throw new IllegalArgumentException("Invalid IPv4 octet.");
                address = (address << 8) | number;
            }
            return new Ipv4Range(address, prefix);
        }
    }
}
