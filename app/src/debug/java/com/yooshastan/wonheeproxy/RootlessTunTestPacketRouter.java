package com.yooshastan.wonheeproxy;

/**
 * Narrow classifier for the debug-only TUN ingress test.
 *
 * Only unfragmented IPv4 UDP packets addressed to RFC 2544 benchmarking
 * space 198.18.0.0/15 are accepted. 198.18.1.0/24 is the Home test slice;
 * the remaining benchmark range is the Internet-exit test slice.
 *
 * This is not a production classifier. IPv6, TCP, fragments, malformed
 * packets and every other destination are dropped.
 */
final class RootlessTunTestPacketRouter {
    enum Target { HOME, INTERNET, DROP }

    private static final int MTU = 1280;

    private RootlessTunTestPacketRouter() { }

    static Target select(byte[] packet, int length) {
        if (packet == null || length < 28 || length > MTU || length > packet.length) {
            return Target.DROP;
        }
        if (((packet[0] & 0xff) >>> 4) != 4 || (packet[0] & 0x0f) != 5) {
            return Target.DROP;
        }
        int total = u16(packet, 2);
        if (total != length || total < 28 || !validIpv4Checksum(packet)) {
            return Target.DROP;
        }
        if ((packet[9] & 0xff) != 17) return Target.DROP; // UDP only
        int fragment = u16(packet, 6);
        if ((fragment & 0xbfff) != 0) return Target.DROP; // no reserved/MF/offset bits
        int udpLength = u16(packet, 24);
        if (udpLength < 8 || udpLength != total - 20) return Target.DROP;

        int first = packet[16] & 0xff;
        int second = packet[17] & 0xff;
        int third = packet[18] & 0xff;
        if (first != 198 || (second != 18 && second != 19)) return Target.DROP;

        // More-specific Home test route wins over the broad Internet test route.
        if (second == 18 && third == 1) return Target.HOME;
        return Target.INTERNET;
    }

    private static int u16(byte[] packet, int offset) {
        return ((packet[offset] & 0xff) << 8) | (packet[offset + 1] & 0xff);
    }

    private static boolean validIpv4Checksum(byte[] packet) {
        long sum = 0;
        for (int i = 0; i < 20; i += 2) {
            sum += ((packet[i] & 0xff) << 8) | (packet[i + 1] & 0xff);
        }
        while ((sum >>> 16) != 0) sum = (sum & 0xffffL) + (sum >>> 16);
        return (sum & 0xffffL) == 0xffffL;
    }
}
