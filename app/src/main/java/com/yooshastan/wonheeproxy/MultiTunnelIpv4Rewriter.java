package com.yooshastan.wonheeproxy;

import java.util.Arrays;

/**
 * Fail-closed IPv4 source/destination translation for the proposed userspace
 * dual-WireGuard dataplane. This is NOT a WireGuard transport or VpnService.
 *
 * Android apps send traffic from one virtual TUN address, while each encrypted
 * WireGuard session requires its own assigned address. Translate the source
 * only on egress and the destination only on ingress. Each session must have
 * a dedicated rewriter; callers must additionally enforce route ownership.
 *
 * Only unfragmented TCP, UDP, and ICMP echo are supported. Everything else
 * returns null (DROP), including IPv6 and ICMP errors with embedded headers.
 */
final class MultiTunnelIpv4Rewriter {
    private final int tunAddress;
    private final int sessionAddress;

    MultiTunnelIpv4Rewriter(String tunIpv4, String sessionIpv4) {
        tunAddress = parseIpv4(tunIpv4);
        sessionAddress = parseIpv4(sessionIpv4);
        if (!isUnicast(tunAddress) || !isUnicast(sessionAddress)
                || tunAddress == sessionAddress) {
            throw new IllegalArgumentException("Distinct unicast IPv4 addresses required.");
        }
    }

    /** Return a new packet, or null to drop. Never mutate a caller's buffer. */
    byte[] toSession(byte[] packet) {
        return translate(packet, true);
    }

    /** Return a new packet, or null to drop. Never mutate a caller's buffer. */
    byte[] toTun(byte[] packet) {
        return translate(packet, false);
    }

    private byte[] translate(byte[] original, boolean outgoing) {
        if (original == null || original.length < 20
                || (original[0] & 0xf0) != 0x40) return null;
        int headerLength = (original[0] & 0x0f) * 4;
        if (headerLength < 20 || headerLength > 60
                || headerLength > original.length) return null;
        int declaredLength = u16(original, 2);
        if (declaredLength != original.length || declaredLength < headerLength) return null;
        int fragment = u16(original, 6);
        if ((fragment & 0xbfff) != 0) return null; // reserved bit, MF, fragment offset
        if (checksum(original, 0, headerLength, 0L) != 0) return null;

        int originalSource = readIpv4(original, 12);
        int originalDestination = readIpv4(original, 16);
        if (!isUnicast(originalSource) || !isUnicast(originalDestination)) return null;
        if (outgoing ? originalSource != tunAddress
                : originalDestination != sessionAddress) return null;

        int protocol = original[9] & 0xff;
        int transportLength = declaredLength - headerLength;
        if (protocol == 6) {
            if (transportLength < 20) return null;
            int dataOffset = ((original[headerLength + 12] & 0xf0) >>> 4) * 4;
            if (dataOffset < 20 || dataOffset > transportLength) return null;
        } else if (protocol == 17) {
            if (transportLength < 8 || u16(original, headerLength + 4) != transportLength) {
                return null;
            }
        } else if (protocol == 1) {
            if (transportLength < 8) return null;
            int type = original[headerLength] & 0xff;
            if (type != 0 && type != 8) return null;
        } else {
            return null;
        }

        byte[] result = Arrays.copyOf(original, original.length);
        if (outgoing) writeIpv4(result, 12, sessionAddress);
        else writeIpv4(result, 16, tunAddress);

        putU16(result, 10, 0);
        putU16(result, 10, checksum(result, 0, headerLength, 0L));
        if (protocol == 6 || protocol == 17) {
            int checksumOffset = headerLength + (protocol == 6 ? 16 : 6);
            // UDP/IPv4 checksum=0 means disabled. Preserve that convention.
            if (protocol == 6 || u16(original, checksumOffset) != 0) {
                putU16(result, checksumOffset, 0);
                long pseudo = ((long) u16(result, 12) + u16(result, 14)
                        + u16(result, 16) + u16(result, 18)
                        + protocol + transportLength);
                int value = checksum(result, headerLength, transportLength, pseudo);
                putU16(result, checksumOffset,
                        protocol == 17 && value == 0 ? 0xffff : value);
            }
        }
        return result;
    }

    private static boolean isUnicast(int ip) {
        long address = ip & 0xffffffffL;
        int first = (int) (address >>> 24);
        return first > 0 && first < 224 && first != 127
                && (address & 0xffff0000L) != 0xa9fe0000L
                && address != 0xffffffffL;
    }

    static int parseIpv4(String text) {
        if (text == null) throw new IllegalArgumentException("Missing IPv4 address.");
        String[] octets = text.split("\\.", -1);
        if (octets.length != 4) throw new IllegalArgumentException("Invalid IPv4 address.");
        int value = 0;
        for (String octet : octets) {
            if (!octet.matches("0|[1-9][0-9]{0,2}")) {
                throw new IllegalArgumentException("Invalid IPv4 address.");
            }
            int part = Integer.parseInt(octet);
            if (part > 255) throw new IllegalArgumentException("Invalid IPv4 address.");
            value = (value << 8) | part;
        }
        return value;
    }

    private static int readIpv4(byte[] data, int offset) {
        return ((data[offset] & 0xff) << 24) | ((data[offset + 1] & 0xff) << 16)
                | ((data[offset + 2] & 0xff) << 8) | (data[offset + 3] & 0xff);
    }

    private static void writeIpv4(byte[] data, int offset, int address) {
        data[offset] = (byte) (address >>> 24);
        data[offset + 1] = (byte) (address >>> 16);
        data[offset + 2] = (byte) (address >>> 8);
        data[offset + 3] = (byte) address;
    }

    private static int u16(byte[] data, int at) {
        return ((data[at] & 0xff) << 8) | (data[at + 1] & 0xff);
    }

    private static void putU16(byte[] data, int at, int value) {
        data[at] = (byte) (value >>> 8);
        data[at + 1] = (byte) value;
    }

    private static int checksum(byte[] data, int offset, int length, long sum) {
        int end = offset + length;
        for (int pos = offset; pos < end; pos += 2) {
            sum += ((data[pos] & 0xff) << 8)
                    | (pos + 1 < end ? data[pos + 1] & 0xff : 0);
        }
        while ((sum >>> 16) != 0) sum = (sum & 0xffffL) + (sum >>> 16);
        return (int) (~sum) & 0xffff;
    }
}
