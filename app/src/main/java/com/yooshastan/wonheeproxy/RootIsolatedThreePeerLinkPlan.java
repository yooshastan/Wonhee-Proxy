package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.List;

/**
 * Isolated link-only pilot: the two proven full-Internet peers plus an
 * OPTIONAL third, specifically private-LAN Home WireGuard peer.
 *
 * Does not install any Android app UID/mark selectors, main routes, DNS,
 * packet filters or a device-wide default. Thus it does not provide a
 * system VPN or any no-fallback guarantee for Android application traffic.
 * Home peer destinations live exclusively in private table 51002.
 *
 * The Android executor still requires explicit user action, exact-owned
 * journal-first rollback and independent Rootlab safety preflight.
 */
final class RootIsolatedThreePeerLinkPlan {
    private RootIsolatedThreePeerLinkPlan() { }

    static RootIsolatedWireGuardBootstrapPlan.Plan compile(
            List<RootMultiTunnelPlan.Entry> internetExits,
            RootMultiTunnelPlan.Entry home) {
        RootTwoExitHomeRoutingPreview.Plan policy =
                RootTwoExitHomeRoutingPreview.compile(internetExits, home);
        RootIsolatedWireGuardBootstrapPlan.Plan exits = policy.internetLinks;
        List<RootIsolatedWireGuardBootstrapPlan.Step> steps =
                new ArrayList<>(exits.steps);
        String dev = home.device;
        if (!dev.matches("wnm[0-9a-f]{12}")) {
            throw new IllegalArgumentException("Unsafe Home device name.");
        }
        steps.add(new RootIsolatedWireGuardBootstrapPlan.Step(
                "LINK_CREATE", "ip link add dev " + dev + " type wireguard",
                "ip link del dev " + dev, dev));
        steps.add(new RootIsolatedWireGuardBootstrapPlan.Step(
                "PEER_CONFIG", "", "", dev));
        for (String host : home.interfaceAddresses) {
            boolean ipv6 = host.indexOf(':') >= 0;
            if (!host.endsWith(ipv6 ? "/128" : "/32")) {
                // A /24 could add a connected route to Android's main table.
                throw new IllegalArgumentException(
                        "Home WireGuard local interface must be a host address.");
            }
            String prefix = "ip -" + (ipv6 ? "6" : "4") + " addr ";
            String args = host + " dev " + dev;
            steps.add(new RootIsolatedWireGuardBootstrapPlan.Step(
                    "HOST_ADDRESS", prefix + "add " + args,
                    prefix + "del " + args, dev));
        }
        steps.add(new RootIsolatedWireGuardBootstrapPlan.Step(
                "LINK_UP", "ip link set dev " + dev + " up",
                "ip link set dev " + dev + " down", dev));
        for (String network : policy.homeDestinations) {
            String args = "table " + RootTwoExitHomeRoutingPreview.HOME_TABLE
                    + " " + network + " dev " + dev;
            steps.add(new RootIsolatedWireGuardBootstrapPlan.Step(
                    "PRIVATE_ROUTE", "ip -4 route add " + args,
                    "ip -4 route del " + args, dev));
        }
        // Important: no ip rule add, no additional netd fwmark, and no
        // app/system traffic is automatically steered through Home.
        return new RootIsolatedWireGuardBootstrapPlan.Plan(
                steps, 3, exits.privateRoutes + policy.homeDestinations.size());
    }
}
