package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * First active-lab milestone: two independent Internet WG links only.
 *
 * NO per-app UID rules, packet marks, Android DNS changes, or main routes.
 * A link plan is NOT proof of physical endpoint transport or a successful
 * WireGuard handshake; it cannot authorize activation on its own.
 *
 * This compiler is intentionally independent of RootPerAppUidPolicyPlan,
 * which would require inventing app UIDs simply to test two peer links.
 */
final class RootIsolatedTwoPeerLinkPlan {
    private RootIsolatedTwoPeerLinkPlan() { }

    static RootIsolatedWireGuardBootstrapPlan.Plan compile(
            List<RootMultiTunnelPlan.Entry> selected) {
        if (selected == null || selected.size() != 2) {
            throw new IllegalArgumentException("Select exactly two Internet peers.");
        }
        RootMultiTunnelPlan.validateIndependentInterfaceAddresses(selected);
        List<RootMultiTunnelPlan.Entry> sorted = new ArrayList<>(selected);
        sorted.sort(Comparator.comparing(e -> e.name.toLowerCase(Locale.ROOT)));
        List<RootIsolatedWireGuardBootstrapPlan.Step> operations = new ArrayList<>();
        Set<String> allLinks = new HashSet<>();
        int count = 0;
        for (int index = 0; index < sorted.size(); index++) {
            RootMultiTunnelPlan.Entry e = sorted.get(index);
            RootMultiTunnelPlan.validate(Collections.singletonList(e));
            if (!allLinks.add(e.device) || !e.device.matches("wnm[0-9a-f]{12}")) {
                throw new IllegalArgumentException("Ambiguous managed interface.");
            }
            if (!e.peerRoutes.contains("0.0.0.0/0")) {
                throw new IllegalArgumentException("Internet pilot needs an IPv4 default peer.");
            }
            boolean ipv6Default = e.peerRoutes.contains("::/0")
                    || e.peerRoutes.contains("0:0:0:0:0:0:0:0/0");
            if (e.peerRoutes.size() != (ipv6Default ? 2 : 1)) {
                // No more-specific routes until split-route ownership has
                // its own verified, exact-owned transaction.
                throw new IllegalArgumentException("Peer-only pilot permits "
                        + "IPv4/IPv6 default AllowedIPs, no split destinations.");
            }
            if (e.interfaceAddresses.isEmpty()) {
                throw new IllegalArgumentException("WireGuard interface host required.");
            }
            String device = e.device;
            operations.add(new RootIsolatedWireGuardBootstrapPlan.Step("LINK_CREATE",
                    "ip link add dev " + device + " type wireguard",
                    "ip link del dev " + device, device));
            operations.add(new RootIsolatedWireGuardBootstrapPlan.Step(
                    "PEER_CONFIG", "", "", device));
            for (String host : e.interfaceAddresses) {
                boolean ipv6 = host.indexOf(':') >= 0;
                if (!host.endsWith(ipv6 ? "/128" : "/32")) {
                    throw new IllegalArgumentException("A /32 or /128 WireGuard "
                            + "interface host is required; connected subnet "
                            + "routes could modify Android's main table.");
                }
                String family = ipv6 ? "-6" : "-4";
                String base = "ip " + family + " addr ";
                String args = host + " dev " + device;
                operations.add(new RootIsolatedWireGuardBootstrapPlan.Step(
                        "HOST_ADDRESS", base + "add " + args,
                        base + "del " + args, device));
            }
            operations.add(new RootIsolatedWireGuardBootstrapPlan.Step(
                    "LINK_UP", "ip link set dev " + device + " up",
                    "ip link set dev " + device + " down", device));
            // Tables are intentionally private. No 'ip rule add' command is
            // produced, so Android cannot steer any application to either
            // of these just-created links in this milestone.
            int table = RootPerAppUidPolicyPlan.FIRST_TABLE + index;
            for (String route : e.peerRoutes) {
                boolean ipv6 = route.indexOf(':') >= 0;
                String prefix = "ip " + (ipv6 ? "-6" : "-4") + " route ";
                String args = "table " + table + " " + route + " dev " + device;
                operations.add(new RootIsolatedWireGuardBootstrapPlan.Step(
                        "PRIVATE_ROUTE", prefix + "add " + args,
                        prefix + "del " + args, device));
                count++;
            }
        }
        // The executor still requires a separate, verified safety gate and
        // a durable journal, even for UID-less peer-only smoke testing.
        return new RootIsolatedWireGuardBootstrapPlan.Plan(
                operations, sorted.size(), count);
    }
}
