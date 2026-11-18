package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Pure route-policy tests: zero root access, zero DNS, zero network writes. */
public final class RootTunnelSelectionAdvisorTest {
    private static RootMultiTunnelPlan.Entry entry(String name, String address,
            String... routes) {
        return new RootMultiTunnelPlan.Entry(name,
                Arrays.asList(routes), Collections.singletonList(address));
    }

    private static void accepted(List<RootMultiTunnelPlan.Entry> profiles,
            int splitCount) {
        RootTunnelSelectionAdvisor.Review result =
                RootTunnelSelectionAdvisor.review(profiles);
        if (!result.ready || result.splitTunnelCount != splitCount) {
            throw new AssertionError("Expected compatible " + splitCount
                    + " split tunnels: " + result.message);
        }
    }

    private static void refused(String reason,
            RootMultiTunnelPlan.Entry... profiles) {
        RootTunnelSelectionAdvisor.Review result =
                RootTunnelSelectionAdvisor.review(Arrays.asList(profiles));
        if (result.ready || !result.message.contains(reason)) {
            throw new AssertionError("Expected a refusal describing "
                    + reason + ": " + result.message);
        }
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry nl = entry("Privacy Netherlands",
                "10.150.0.2/32", "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry us = entry("Regional United States",
                "10.151.0.2/32", "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry home = entry("Home network",
                "10.6.0.2/32", "10.0.0.0/24", "10.6.0.0/24");
        RootMultiTunnelPlan.Entry work = entry("Work network",
                "10.7.0.2/32", "10.20.0.0/16");
        RootMultiTunnelPlan.Entry region = entry("Regional exact routes",
                "10.8.0.2/32", "203.0.113.0/24");
        accepted(Arrays.asList(nl, home), 1);
        accepted(Arrays.asList(nl, home, work, region), 3);
        refused("Only one default Internet exit", nl, us, home);
        refused("No Internet exit", home, work);
        refused("Specific destinations", nl);
        refused("does not cover both IPv4", entry("IPv4 only",
                "10.33.0.2/32", "0.0.0.0/0"), home);
        refused("overlap", nl, home, entry("Overlapping LAN",
                "10.9.0.2/32", "10.0.0.0/25"));
        refused("interface addresses conflict", nl, home,
                entry("Duplicate address", "10.6.0.2/32", "10.30.0.0/16"));

        List<RootMultiTunnelPlan.Entry> eight = new ArrayList<>();
        eight.add(nl);
        for (int i = 1; i < 8; i++) {
            eight.add(entry("Specific " + i,
                    "10." + (170 + i) + ".0.2/32",
                    "10." + (170 + i) + ".1.0/24"));
        }
        accepted(eight, 7);
        List<RootMultiTunnelPlan.Entry> nine = new ArrayList<>(eight);
        nine.add(entry("Too many", "10.200.0.2/32", "10.200.1.0/24"));
        if (RootTunnelSelectionAdvisor.review(nine).ready) {
            throw new AssertionError("More than eight profiles must be refused");
        }
        for (int i = 0; i < TunnelUseCategories.LABELS.length; i++) {
            if (!TunnelUseCategories.valid(i)
                    || TunnelUseCategories.label(i).isEmpty()) {
                throw new AssertionError("Unknown category " + i);
            }
        }
        if (TunnelUseCategories.valid(99)
                || TunnelUseCategories.migratedCategory(1)
                != TunnelUseCategories.PRIVATE_NETWORK
                || TunnelUseCategories.migratedCategory(2)
                != TunnelUseCategories.GENERAL) {
            throw new AssertionError("Category migration changed route intent");
        }
        System.out.println("RootTunnelSelectionAdvisorTest passed");
    }
}
