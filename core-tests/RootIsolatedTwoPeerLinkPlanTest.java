package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Rootless first two-link smoke stage: does NOT execute any networking. */
public final class RootIsolatedTwoPeerLinkPlanTest {
    private static RootMultiTunnelPlan.Entry peer(
            String name, String host, String... routes) {
        return new RootMultiTunnelPlan.Entry(name,
                Arrays.asList(routes), Collections.singletonList(host));
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void refuse(Runnable operation, String why) {
        try { operation.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("Accepted unsafe link-only pilot: " + why);
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry eu = peer(
                "Europe", "10.150.0.2/32", "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry us = peer(
                "America", "10.151.0.2/32", "0.0.0.0/0", "::/0");
        List<RootMultiTunnelPlan.Entry> choice = Arrays.asList(eu, us);
        RootIsolatedWireGuardBootstrapPlan.Plan plan =
                RootIsolatedTwoPeerLinkPlan.compile(choice);
        check(!plan.activationAllowed() && plan.devices == 2
                        && plan.privateRoutes == 4,
                "Independent two-link plan cannot authorize activation");
        String europeanDevice = eu.device;
        String americanDevice = us.device;
        int creates = 0, configs = 0, up = 0, addresses = 0, routes = 0;
        for (RootIsolatedWireGuardBootstrapPlan.Step step : plan.steps) {
            check(RootIsolatedWireGuardTransaction.safeStep(step),
                    "Every planned operation must match exact root whitelist");
            String command = step.install;
            String inverse = step.inverse;
            check(!command.contains("table main")
                            && !command.contains("ip rule ")
                            && !command.contains("ip6tables")
                            && !command.contains("iptables")
                            && !command.contains("wg-quick up")
                            && !command.contains("set-mark")
                            && !command.contains("DNS="),
                    "No UID rules, netd marks, firewall or main/default route changes");
            check((step.device.equals(europeanDevice)
                            || step.device.equals(americanDevice)),
                    "Operations must only touch the two selected peers");
            if ("LINK_CREATE".equals(step.kind)) creates++;
            if ("PEER_CONFIG".equals(step.kind)) {
                configs++;
                check(command.isEmpty() && inverse.isEmpty(),
                        "Private keys must remain outside shell plans");
            }
            if ("HOST_ADDRESS".equals(step.kind)) addresses++;
            if ("LINK_UP".equals(step.kind)) up++;
            if ("PRIVATE_ROUTE".equals(step.kind)) {
                routes++;
                String table = step.device.equals(americanDevice)
                        ? "51000" : "51001";
                check(command.contains(" route add table " + table + " ")
                                && inverse.contains(" route del table " + table + " "),
                        "Each full default belongs only to its own private table");
            }
        }
        check(creates == 2 && configs == 2 && addresses == 2
                        && up == 2 && routes == 4,
                "Exact two-peer startup sequence is complete");
        List<RootIsolatedWireGuardBootstrapPlan.Step> reversed =
                plan.rollbackOrder();
        check("PRIVATE_ROUTE".equals(reversed.get(0).kind)
                        && "LINK_CREATE".equals(
                                reversed.get(reversed.size() - 1).kind),
                "Inverse cleanup removes routes before interfaces");
        try {
            plan.steps.clear();
            throw new AssertionError("Mutable kernel action plan");
        } catch (UnsupportedOperationException expected) { }

        RootIsolatedWireGuardBootstrapPlan.Plan reversedInput =
                RootIsolatedTwoPeerLinkPlan.compile(Arrays.asList(us, eu));
        for (int i = 0; i < plan.steps.size(); i++) {
            check(plan.steps.get(i).install.equals(
                            reversedInput.steps.get(i).install),
                    "Private table assignments must not depend on selection order");
        }

        refuse(() -> RootIsolatedTwoPeerLinkPlan.compile(
                Collections.singletonList(eu)), "one peer is not a two-peer test");
        refuse(() -> RootIsolatedTwoPeerLinkPlan.compile(
                Arrays.asList(eu, eu)), "same key/profile twice");
        refuse(() -> RootIsolatedTwoPeerLinkPlan.compile(
                Arrays.asList(eu, peer("US", "10.150.0.2/32", "0.0.0.0/0"))),
                "overlapping tunnel address");
        refuse(() -> RootIsolatedTwoPeerLinkPlan.compile(
                Arrays.asList(eu, peer("US", "10.151.0.2/24", "0.0.0.0/0"))),
                "connected /24 may inject Android main connected routes");
        refuse(() -> RootIsolatedTwoPeerLinkPlan.compile(
                Arrays.asList(eu, peer("US", "10.151.0.2/32", "::/0"))),
                "IPv6-only Internet peer not supported by this pilot");
        refuse(() -> RootIsolatedTwoPeerLinkPlan.compile(
                Arrays.asList(eu, peer("US", "10.151.0.2/32",
                        "0.0.0.0/0", "10.0.0.0/8"))),
                "unreviewed private split destinations not permitted");

        RootMultiTunnelPlan.Entry ipv4Only = peer(
                "US", "10.151.0.2/32", "0.0.0.0/0");
        RootIsolatedWireGuardBootstrapPlan.Plan v4 =
                RootIsolatedTwoPeerLinkPlan.compile(
                        Arrays.asList(eu, ipv4Only));
        check(v4.privateRoutes == 3 && !v4.activationAllowed(),
                "Peer-only smoke permits IPv4-only profiles without routing users");
        System.out.println("RootIsolatedTwoPeerLinkPlanTest passed");
    }
}
