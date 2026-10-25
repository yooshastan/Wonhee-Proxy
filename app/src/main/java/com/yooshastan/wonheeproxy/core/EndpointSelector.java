package com.yooshastan.wonheeproxy.core;

/**
 * Selects an explicit endpoint without performing DNS lookups or probing.
 * AUTO uses a private IPv4 LAN address only when Android reports a directly
 * connected Wi-Fi subnet containing it. It otherwise uses the public host.
 * The UI shows the selected endpoint before any network action.
 */
public final class EndpointSelector {
    public enum Mode { AUTO, PUBLIC, LAN }

    public static final class Selection {
        public final String host;
        public final boolean local;
        public final String reason;

        Selection(String host, boolean local, String reason) {
            this.host = host;
            this.local = local;
            this.reason = reason;
        }
    }

    private EndpointSelector() { }

    public static Selection select(String publicHost, String lanHost, Mode mode,
                                   boolean sameWifiSubnet) {
        if (publicHost == null || publicHost.trim().isEmpty() || mode == null) {
            throw new IllegalArgumentException("Enter a public server host.");
        }
        String publicValue = publicHost.trim();
        String lanValue = lanHost == null ? "" : lanHost.trim();
        if (mode == Mode.LAN) {
            if (lanValue.isEmpty()) {
                throw new IllegalArgumentException("Enter a LAN host before selecting LAN only.");
            }
            return new Selection(lanValue, true, "LAN selected manually");
        }
        if (mode == Mode.AUTO && !lanValue.isEmpty() && sameWifiSubnet) {
            return new Selection(lanValue, true, "LAN address matches active Wi-Fi subnet");
        }
        return new Selection(publicValue, false,
                mode == Mode.PUBLIC ? "Public selected manually"
                        : "Public selected (LAN subnet not verified)");
    }

    /** No DNS: only literal RFC1918 IPv4 destinations may be auto-selected. */
    public static boolean samePrivateSubnet(String deviceAddress, int prefix,
                                             String serverAddress) {
        long device = parseIpv4(deviceAddress);
        long server = parseIpv4(serverAddress);
        if (device < 0 || server < 0 || prefix < 8 || prefix > 32
                || !isPrivate(server) || !isPrivate(device)) {
            return false;
        }
        long mask = prefix == 32 ? 0xffffffffL : (0xffffffffL << (32 - prefix)) & 0xffffffffL;
        return (device & mask) == (server & mask);
    }

    private static boolean isPrivate(long address) {
        return (address >>> 24) == 10
                || (address >>> 20) == 0xac1
                || (address >>> 16) == 0xc0a8;
    }

    private static long parseIpv4(String value) {
        if (value == null) return -1;
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) return -1;
        long out = 0;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3) return -1;
            for (int i = 0; i < part.length(); i++) {
                if (part.charAt(i) < '0' || part.charAt(i) > '9') return -1;
            }
            int octet;
            try {
                octet = Integer.parseInt(part);
            } catch (NumberFormatException bad) {
                return -1;
            }
            if (octet > 255) return -1;
            out = (out << 8) | octet;
        }
        return out;
    }
}
