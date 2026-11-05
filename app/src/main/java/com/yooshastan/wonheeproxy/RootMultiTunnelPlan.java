package com.yooshastan.wonheeproxy;

import java.net.InetAddress;
import java.security.MessageDigest;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Pure preflight for the opt-in multi-kernel lab. Does not invoke root, touch
 * Android's routing tables or modify imported WireGuard configurations.
 */
final class RootMultiTunnelPlan {
    // Current encrypted store's safe alpha limit; lift both limits together later.
    static final int MAX_TUNNELS = 8;
    static final class Entry {
        final String name;
        final String device;
        final List<String> peerRoutes;
        final List<String> interfaceAddresses;

        Entry(String name, List<String> peerRoutes, List<String> interfaceAddresses) {
            this.name = name;
            this.device = interfaceName(name);
            this.peerRoutes = new ArrayList<>(peerRoutes);
            this.interfaceAddresses = new ArrayList<>(interfaceAddresses);
        }
    }

    private static final class Cidr {
        final byte[] network;
        final int prefix;

        Cidr(String value) {
            if (value == null || value.length() > 80) throw invalid();
            String[] fields = value.trim().split("/", -1);
            if (fields.length != 2 || fields[0].isEmpty() || fields[1].isEmpty()) {
                throw invalid();
            }
            String ip = fields[0];
            // Restrict InetAddress to numeric literals: no DNS queries in preflight.
            boolean ipv6 = ip.indexOf(':') >= 0;
            if (ipv6 ? !ip.matches("[0-9a-fA-F:.]+")
                    : !ip.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")) throw invalid();
            try {
                if (fields[1].length() > 3 || !fields[1].matches("[0-9]+")) throw invalid();
                prefix = Integer.parseInt(fields[1]);
                network = InetAddress.getByName(ip).getAddress();
                if ((ipv6 && network.length != 16) || (!ipv6 && network.length != 4)
                        || prefix < 0 || prefix > network.length * 8) throw invalid();
            } catch (IllegalArgumentException invalid) {
                throw invalid;
            } catch (Exception invalid) {
                throw invalid();
            }
        }

        boolean overlaps(Cidr other) {
            if (network.length != other.network.length) return false;
            int sharedBits = Math.min(prefix, other.prefix);
            for (int i = 0; i < sharedBits; i++) {
                int mask = 1 << (7 - i % 8);
                if ((network[i / 8] & mask) != (other.network[i / 8] & mask)) {
                    return false;
                }
            }
            return true;
        }

        boolean isDefault() { return prefix == 0; }

        private static IllegalArgumentException invalid() {
            return new IllegalArgumentException("Routes and interface addresses must be numeric CIDRs.");
        }
    }

    private RootMultiTunnelPlan() { }

    /** Names are deterministic across process restarts and fit Linux IFNAMSIZ. */
    static String interfaceName(String profileName) {
        if (profileName == null || profileName.trim().isEmpty()) {
            throw new IllegalArgumentException("A stored profile needs a name.");
        }
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(
                    profileName.trim().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8));
            StringBuilder name = new StringBuilder("wnm");
            for (int i = 0; i < 6; i++) {
                name.append(Character.forDigit((hash[i] >>> 4) & 0xf, 16));
                name.append(Character.forDigit(hash[i] & 0xf, 16));
            }
            return name.toString(); // 15 characters, within the Linux limit.
        } catch (Exception unavailable) {
            throw new IllegalStateException("Cannot derive a stable tunnel identity.");
        }
    }

    static void validate(List<Entry> entries) {
        if (entries == null || entries.isEmpty()) {
            throw new IllegalArgumentException("Select at least one tunnel.");
        }
        if (entries.size() > MAX_TUNNELS) {
            throw new IllegalArgumentException("Too many selected profiles for this alpha.");
        }
        Set<String> devices = new HashSet<>();
        Set<String> names = new HashSet<>();
        List<List<Cidr>> allRoutes = new ArrayList<>();
        List<List<Cidr>> allAddresses = new ArrayList<>();
        for (Entry entry : entries) {
            if (!devices.add(entry.device)
                    || !names.add(entry.name.toLowerCase(Locale.ROOT))) {
                throw new IllegalArgumentException("Selected profiles need unique names and interfaces.");
            }
            if (entry.peerRoutes.isEmpty() || entry.interfaceAddresses.isEmpty()) {
                throw new IllegalArgumentException("Every tunnel needs routes and an interface address.");
            }
            List<Cidr> routes = new ArrayList<>();
            for (String value : entry.peerRoutes) routes.add(new Cidr(value));
            List<Cidr> addresses = new ArrayList<>();
            for (String value : entry.interfaceAddresses) addresses.add(new Cidr(value));
            allRoutes.add(routes);
            allAddresses.add(addresses);
        }
        for (int i = 0; i < entries.size(); i++) {
            for (int j = i + 1; j < entries.size(); j++) {
                for (Cidr left : allRoutes.get(i)) {
                    for (Cidr right : allRoutes.get(j)) {
                        // One default exit can coexist with split destinations;
                        // longest-prefix routing sends those to the split interface.
                        // Two defaults or intersecting non-default routes are refused.
                        if (left.overlaps(right)
                                && !(left.isDefault() ^ right.isDefault())) {
                            throw new IllegalArgumentException("Overlapping tunnel destinations: "
                                    + entries.get(i).name + " and " + entries.get(j).name
                                    + ". Use distinct routes or a future explicit policy.");
                        }
                    }
                }
                for (Cidr left : allAddresses.get(i)) {
                    for (Cidr right : allAddresses.get(j)) {
                        // Conservative: overlapping interface subnets are unsafe in this alpha.
                        if (left.overlaps(right)) {
                            throw new IllegalArgumentException("Overlapping tunnel interface networks: "
                                    + entries.get(i).name + " and " + entries.get(j).name + ".");
                        }
                    }
                }
            }
        }
    }

    static String preview(List<Entry> entries) {
        validate(entries);
        StringBuilder summary = new StringBuilder("READ-ONLY MULTI-TUNNEL ROUTE PREVIEW\n");
        for (Entry entry : entries) {
            summary.append(entry.name).append(" → ").append(entry.device)
                    .append("\nRoutes: ").append(String.join(", ", entry.peerRoutes)).append('\n');
        }
        summary.append("No overlapping selected routes or interface networks detected. "
                + "This does NOT verify Android fwmarks, other running VPNs, DNS leaks, "
                + "actual routing, Internet reachability or fail-closed behavior. "
                + "No kernel or firewall changes were made.");
        return summary.toString();
    }
}
