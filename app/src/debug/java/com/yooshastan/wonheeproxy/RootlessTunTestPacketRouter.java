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
    enum Reason { SIZE, NON_IPV4, IP_HEADER, IP_LENGTH, IP_CHECKSUM, NON_UDP, FRAGMENT, UDP_LENGTH, DESTINATION, OUTSIDE_BATCH, PROBE_MISMATCH, DUPLICATE }

    private static final int MTU = 1280;

    private RootlessTunTestPacketRouter() { }

    static Reason rejection(byte[] packet, int length) {
        if (packet == null || length < 1 || length > MTU || length > packet.length) return Reason.SIZE;
        if (((packet[0] & 0xff) >>> 4) != 4) return Reason.NON_IPV4;
        if (length < 20 || (packet[0] & 0x0f) != 5) return Reason.IP_HEADER;
        int total = u16(packet, 2);
        if (total != length || total < 20) return Reason.IP_LENGTH;
        if (!validIpv4Checksum(packet)) return Reason.IP_CHECKSUM;
        if ((u16(packet, 6) & 0xbfff) != 0) return Reason.FRAGMENT;
        if ((packet[9] & 0xff) != 17) return Reason.NON_UDP;
        if (length < 28) return Reason.UDP_LENGTH;
        int udpLength = u16(packet, 24);
        if (udpLength < 8 || udpLength != total - 20) return Reason.UDP_LENGTH;
        int first = packet[16] & 0xff;
        int second = packet[17] & 0xff;
        if (first != 198 || (second != 18 && second != 19)) return Reason.DESTINATION;
        return null;
    }

    static Target select(byte[] packet, int length) {
        if (rejection(packet, length) != null) return Target.DROP;
        if ((packet[17] & 0xff) == 18 && (packet[18] & 0xff) == 1) return Target.HOME;
        return Target.INTERNET;
    }

    // Only the exact generated batch, source and destination may reach JNI.
    // Return the probe index, or -1. Nonces are never logged.
    static int probeIndex(byte[] packet, int length, int sourcePort, byte[] nonce) {
        if (nonce == null || nonce.length != 16 || rejection(packet, length) != null
                || length != 45 || u16(packet, 20) != sourcePort
                || u16(packet, 22) != 43434
                || (packet[12] & 255) != 10 || (packet[13] & 255) != 253
                || packet[14] != 0 || packet[15] != 1) return -1;
        for (int i = 0; i < nonce.length; i++) {
            if (packet[28 + i] != nonce[i]) return -1;
        }
        int index = packet[44] & 255;
        if (index >= 6 || (packet[17] & 255) != 18 || (packet[19] & 255) != 10
                || (packet[18] & 255) != (index % 2 == 0 ? 1 : 2)) return -1;
        return index;
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
