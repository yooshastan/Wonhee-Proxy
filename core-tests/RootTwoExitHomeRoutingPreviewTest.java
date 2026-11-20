package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Pure regression: a third Home tunnel must never become Internet default. */
public final class RootTwoExitHomeRoutingPreviewTest {
    private static RootMultiTunnelPlan.Entry profile(
            String name, String address, String... destinations) {
        return new RootMultiTunnelPlan.Entry(name,
                Arrays.asList(destinations),
                Collections.singletonList(address));
    }

    private static void check(boolean condition, String why) {
        if (!condition) throw new AssertionError(why);
    }

    private static void reject(List<RootMultiTunnelPlan.Entry> exits,
            RootMultiTunnelPlan.Entry home, String why) {
        try {
            RootTwoExitHomeRoutingPreview.compile(exits, home);
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Unsafe Home route accepted: " + why);
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry europe = profile(
                "Europe", "10.150.0.2/32", "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry america = profile(
                "America", "10.151.0.2/32", "0.0.0.0/0", "::/0");
        List<RootMultiTunnelPlan.Entry> exits = Arrays.asList(europe, america);
        RootMultiTunnelPlan.Entry home = profile(
                "Home", "10.6.0.2/32", "10.0.0.0/24", "10.77.0.0/24");
        RootTwoExitHomeRoutingPreview.Plan preview =
                RootTwoExitHomeRoutingPreview.compile(exits, home);
        check(!preview.activationAllowed(), "Home preview must be NON-executing");
        check(preview.internetLinks.devices == 2
                        && preview.internetLinks.privateRoutes == 4,
                "Existing proven dual-WG full-Internet engine unchanged");
        check(preview.homeTable == 51002
                        && preview.homePriority == 12700
                        && preview.homePriority < RootPerAppUidPolicyPlan.FIRST_PRIORITY,
                "Home private table reserved before normal per-app exit selection");
        check(preview.homeDestinations.size() == 2
                        && preview.homeDestinations.contains("10.0.0.0/24"),
                "Home routes restricted to explicit private LAN CIDRs");
        check(preview.summary().contains("NOT ACTIVE")
                        && preview.summary().contains("block")
                        && !preview.summary().contains("10.0.0.0")
                        && !preview.summary().contains("10.77.0.0"),
                "Safe summary makes no leak-proof claims and reveals no internal addresses");

        reject(exits, profile("Home", "10.6.0.2/32", "0.0.0.0/0"),
                "Home must not be full-tunnel Internet default");
        reject(exits, profile("Home", "10.6.0.2/32", "::/0"),
                "Home ULA/IPv6 requires a separate dual-stack review");
        reject(exits, profile("Home", "10.6.0.2/32", "8.8.8.0/24"),
                "Home cannot hijack a public Internet prefix");
        reject(exits, profile("Home", "10.6.0.2/32", "10.0.0.0/8"),
                "Broad private routes cannot swallow other tunnel networks");
        reject(exits, profile("Home", "10.6.0.2/32", "10.0.0.2/24"),
                "Home CIDR must be a canonical destination network");
        reject(exits, profile("Home", "10.6.0.2/32",
                        "10.0.0.0/24", "10.0.0.3/32"),
                "Overlapping home destination subnets rejected");
        reject(exits, profile("Home", "10.6.0.2/32",
                        "10.0.0.0/24", "10.0.0.0/24"),
                "Duplicate Home route rejected");
        reject(exits, profile("America", "10.6.0.2/32", "10.0.0.0/24"),
                "Home and Internet exit cannot have the same interface name");
        reject(exits, profile("Home", "10.150.0.2/32", "10.0.0.0/24"),
                "Home cannot share Internet exit interface addresses");
        reject(Collections.singletonList(europe), home,
                "No live Home-only or one Internet exit fallback");
        // The same pair in reversed order has the same explicit Home table
        // reservation; no implicit third route in Android's main table.
        RootTwoExitHomeRoutingPreview.Plan reversed =
                RootTwoExitHomeRoutingPreview.compile(
                        Arrays.asList(america, europe), home);
        check(reversed.homeTable == preview.homeTable
                        && reversed.homePriority == preview.homePriority,
                "Home identity deterministic across exit selection order");
        System.out.println("RootTwoExitHomeRoutingPreviewTest passed");
    }
}
