package com.yooshastan.wonheeproxy;

import java.util.List;

/**
 * Read-only selection guidance based on the actual validated route CIDRs,
 * NEVER on a tunnel's friendly name, category or assumed country.
 *
 * This does not modify routing or make an unverified multi-exit policy safe.
 */
final class RootTunnelSelectionAdvisor {
    static final class Review {
        final boolean ready;
        final String message;
        final String internetExit;
        final int splitTunnelCount;
        Review(boolean ready, String message, String internetExit, int splitTunnelCount) {
            this.ready = ready;
            this.message = message;
            this.internetExit = internetExit;
            this.splitTunnelCount = splitTunnelCount;
        }
    }

    private RootTunnelSelectionAdvisor() { }

    static Review review(List<RootMultiTunnelPlan.Entry> entries) {
        if (entries == null || entries.isEmpty()) {
            return refused("Select an Internet exit and at least one destination tunnel.");
        }
        if (entries.size() > RootMultiTunnelPlan.MAX_TUNNELS) {
            return refused("At most eight saved tunnels can be selected at once.");
        }
        RootMultiTunnelPlan.Entry firstDefault = null;
        boolean hasIpv4 = false, hasIpv6 = false;
        int splits = 0;
        for (RootMultiTunnelPlan.Entry entry : entries) {
            boolean v4 = false, v6 = false, specific = false;
            for (String route : entry.peerRoutes) {
                if ("0.0.0.0/0".equals(route)) v4 = true;
                else if ("::/0".equals(route)
                        || "0:0:0:0:0:0:0:0/0".equals(route)) v6 = true;
                else specific = true;
            }
            if (v4 || v6) {
                if (firstDefault != null && !firstDefault.name.equals(entry.name)) {
                    return refused("Both " + firstDefault.name + " and "
                            + entry.name + " are full Internet exits. "
                            + "Only one default Internet exit can run in this "
                            + "routing mode. Set the other tunnel to Specific "
                            + "destinations with non-overlapping CIDRs in "
                            + "Tunnels > Edit settings, or keep it as a saved "
                            + "regional alternative. Per-app exit routing is "
                            + "not enabled in this release.");
                }
                firstDefault = entry;
                hasIpv4 |= v4;
                hasIpv6 |= v6;
            } else if (specific) {
                splits++;
            }
        }
        if (firstDefault == null) {
            return refused("No Internet exit selected. Choose one tunnel with "
                    + "IPv4 and IPv6 default routes; other tunnels can target "
                    + "specific private, work or regional destinations.");
        }
        if (!hasIpv4 || !hasIpv6) {
            return refused("The selected Internet exit does not cover both IPv4 "
                    + "and IPv6. Configure a dual-stack Internet exit before "
                    + "using the guarded Home connection.");
        }
        if (splits == 0) {
            return refused("Choose at least one Specific destinations tunnel "
                    + "with distinct network routes alongside the Internet exit. "
                    + "For a single-tunnel connection use Standard mode.");
        }
        try {
            RootMultiTunnelPlan.validate(entries);
            RootSplitRouteRules.plan(entries);
        } catch (IllegalArgumentException invalid) {
            return refused("Selected network destinations overlap or interface "
                    + "addresses conflict. Edit the affected tunnel routes to "
                    + "use non-overlapping CIDRs. No network changes were made.");
        }
        return new Review(true, entries.size() + " compatible tunnels: "
                + firstDefault.name + " is the Internet exit and " + splits
                + " tunnel" + (splits == 1 ? "" : "s")
                + " handle" + (splits == 1 ? "s" : "")
                + " specific destinations. Routing and DNS still require "
                + "live preflight verification.", firstDefault.name, splits);
    }

    private static Review refused(String message) {
        return new Review(false, message, "", 0);
    }
}
