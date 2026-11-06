package com.yooshastan.wonheeproxy;

import java.net.InetAddress;
import java.util.List;

/**
 * Pure destination-to-interface expectation for any compatible set of
 * experimental kernel WireGuard profiles. It models intended AllowedIPs,
 * NOT Android app fwmarks, actual packets or a firewall policy.
 */
final class RootProtectionPolicy {
    private RootProtectionPolicy() { }

    static String expectedDevice(List<RootMultiTunnelPlan.Entry> entries, String numericIp) {
        RootMultiTunnelPlan.validate(entries);
        byte[] target = numericAddress(numericIp);
        if (target == null) return "";
        int longest = -1;
        String device = "";
        for (RootMultiTunnelPlan.Entry entry : entries) {
            for (String cidr : entry.peerRoutes) {
                String[] parts = cidr.split("/", -1);
                if (parts.length != 2) continue;
                byte[] network = numericAddress(parts[0]);
                if (network == null || network.length != target.length) continue;
                int bits = Integer.parseInt(parts[1]); // validated above
                if (bits > longest && within(target, network, bits)) {
                    longest = bits;
                    device = entry.device;
                }
            }
        }
        return device;
    }

    static boolean hasInternetDefault(List<RootMultiTunnelPlan.Entry> entries, int family) {
        for (RootMultiTunnelPlan.Entry entry : entries) {
            for (String cidr : entry.peerRoutes) {
                if (cidr.endsWith("/0") && (cidr.contains(":") ? 6 : 4) == family) {
                    return true;
                }
            }
        }
        return false;
    }

    private static byte[] numericAddress(String literal) {
        if (literal == null || literal.isEmpty()) return null;
        boolean ipv6 = literal.contains(":");
        if (ipv6 ? !literal.matches("[0-9a-fA-F:.]+")
                : !literal.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) return null;
        try {
            byte[] value = InetAddress.getByName(literal).getAddress();
            return value.length == (ipv6 ? 16 : 4) ? value : null;
        } catch (Exception invalid) { return null; }
    }

    private static boolean within(byte[] target, byte[] network, int bits) {
        if (bits < 0 || bits > target.length * 8) return false;
        for (int i = 0; i < bits; i++) {
            int mask = 1 << (7 - i % 8);
            if ((target[i / 8] & mask) != (network[i / 8] & mask)) return false;
        }
        return true;
    }
}
