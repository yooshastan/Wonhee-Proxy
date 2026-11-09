package com.yooshastan.wonheeproxy;

import java.net.InetAddress;

/**
 * F.5 PURE design candidate: recognize only plausible Wi-Fi local control
 * packets without treating them as permitted system traffic.
 *
 * This is not an iptables rule builder. It is not used by root code or the UI.
 * Actual Android OUTPUT traversal, packet origin and socket provenance remain
 * unverified. A candidate NEVER authorizes firewall activation.
 */
final class RootGuardF5LocalControlCandidate {
    enum Verdict { LOCAL_CONTROL_CANDIDATE, DENY_DIRECT_UNDERLAY }

    private RootGuardF5LocalControlCandidate() { }

    static final class Packet {
        final int family, sourcePort, destinationPort, icmpv6Type, hopLimit;
        final String out, protocol, source, destination;

        Packet(int family, String out, String protocol, String source,
                String destination, int sourcePort, int destinationPort,
                int icmpv6Type, int hopLimit) {
            if ((family != 4 && family != 6) || out == null || protocol == null
                    || source == null || destination == null
                    || sourcePort < 0 || sourcePort > 65535
                    || destinationPort < 0 || destinationPort > 65535
                    || icmpv6Type < 0 || icmpv6Type > 255
                    || hopLimit < 0 || hopLimit > 255) {
                throw new IllegalArgumentException("Invalid synthetic packet.");
            }
            this.family = family;
            this.out = out;
            this.protocol = protocol;
            this.source = source;
            this.destination = destination;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            this.icmpv6Type = icmpv6Type;
            this.hopLimit = hopLimit;
        }
    }

    static boolean activationAllowed() { return false; }

    private static byte[] numeric(int family, String input) {
        // InetAddress.getByName must never look up arbitrary hostnames.
        // This is intentionally a conservative parser for synthetic inputs.
        if (input.length() > 45 || input.contains("%") ||
                !(family == 4 ? input.matches("[0-9.]+")
                               : input.matches("[0-9a-fA-F:]+"))) return null;
        try {
            byte[] bytes = InetAddress.getByName(input).getAddress();
            return bytes.length == (family == 4 ? 4 : 16) ? bytes : null;
        } catch (Exception invalid) {
            return null;
        }
    }

    private static boolean unspecifiedV6(byte[] b) {
        if (b == null || b.length != 16) return false;
        for (byte octet : b) if (octet != 0) return false;
        return true;
    }

    private static boolean linkLocalV6(byte[] b) {
        return b != null && b.length == 16
                && (b[0] & 255) == 0xfe && ((b[1] & 255) & 0xc0) == 0x80;
    }

    private static boolean solicitedNodeV6(byte[] b) {
        if (b == null || b.length != 16 || (b[0] & 255) != 0xff
                || (b[1] & 255) != 0x02 || (b[11] & 255) != 0x01
                || (b[12] & 255) != 0xff) return false;
        for (int i = 2; i < 11; i++) if (b[i] != 0) return false;
        return true;
    }

    private static boolean equalV6(byte[] b, String numeric) {
        byte[] expected = numeric(6, numeric);
        if (b == null || expected == null) return false;
        for (int i = 0; i < 16; i++) if (b[i] != expected[i]) return false;
        return true;
    }

    static Verdict inspect(Packet p) {
        if (p == null) return Verdict.DENY_DIRECT_UNDERLAY;
        // No cellular bypass. Modem-managed data/control paths have not been
        // measured on this device. Never allow arbitrary rmnet traffic.
        if (!p.out.matches("wlan[A-Za-z0-9_.-]*")) {
            return Verdict.DENY_DIRECT_UNDERLAY;
        }
        byte[] src = numeric(p.family, p.source);
        byte[] dst = numeric(p.family, p.destination);
        if (src == null || dst == null) return Verdict.DENY_DIRECT_UNDERLAY;

        if (p.family == 4 && "udp".equals(p.protocol)
                && p.sourcePort == 68 && p.destinationPort == 67
                && "0.0.0.0".equals(p.source)
                && "255.255.255.255".equals(p.destination)) {
            // The discover/initial-request pattern only. Unicast renewals,
            // DHCP options, kernel hook traversal and actual Wi-Fi origin are
            // NOT authenticated by this hypothetical flow shape.
            return Verdict.LOCAL_CONTROL_CANDIDATE;
        }

        if (p.family == 6 && "icmpv6".equals(p.protocol)
                && p.hopLimit == 255 && p.sourcePort == 0
                && p.destinationPort == 0) {
            boolean localSource = linkLocalV6(src);
            boolean unspecifiedSource = unspecifiedV6(src);
            if (p.icmpv6Type == 133 && (localSource || unspecifiedSource)
                    && equalV6(dst, "ff02::2")) {
                return Verdict.LOCAL_CONTROL_CANDIDATE;
            }
            if (p.icmpv6Type == 135 && (localSource || unspecifiedSource)
                    && solicitedNodeV6(dst)) {
                return Verdict.LOCAL_CONTROL_CANDIDATE;
            }
            if (p.icmpv6Type == 136 && localSource
                    && (equalV6(dst, "ff02::1") || linkLocalV6(dst))) {
                return Verdict.LOCAL_CONTROL_CANDIDATE;
            }
        }
        return Verdict.DENY_DIRECT_UNDERLAY;
    }
}
