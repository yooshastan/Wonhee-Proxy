package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Rootless, socketless policy tests; never apply kernel/network rules. */
public final class RootAppProtocolPolicyPlanTest {
    private static RootMultiTunnelPlan.Entry entry(String name, String address,
            String... routes) {
        return new RootMultiTunnelPlan.Entry(name,
                Arrays.asList(routes), Collections.singletonList(address));
    }

    private static void expectRefused(Runnable action, String description) {
        try {
            action.run();
        } catch (IllegalArgumentException accepted) {
            return;
        }
        throw new AssertionError("Should have refused: " + description);
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry nl = entry("NL privacy", "10.150.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry us = entry("US regional", "10.151.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry home = entry("Home private", "10.6.0.2/32",
                "10.0.0.0/24", "10.6.0.0/24");
        List<RootMultiTunnelPlan.Entry> peers = Arrays.asList(nl, us, home);
        RootPerAppUidPolicyPlan.App app =
                new RootPerAppUidPolicyPlan.App("com.example.shopping", 10341,
                        "NL privacy");

        RootProtocolRouteDraft.Override tcp443 =
                new RootProtocolRouteDraft.Override("com.example.shopping",
                        RootProtocolRouteDraft.TCP, 443, "US regional");
        RootProtocolRouteDraft.Override tcpOther =
                new RootProtocolRouteDraft.Override("com.example.shopping",
                        RootProtocolRouteDraft.TCP, 0, "NL privacy");
        RootProtocolRouteDraft.Override udp443 =
                new RootProtocolRouteDraft.Override("com.example.shopping",
                        RootProtocolRouteDraft.UDP, 443, "US regional");
        List<RootProtocolRouteDraft.Override> overrides =
                Arrays.asList(tcpOther, tcp443, udp443);

        RootPerAppUidPolicyPlan.Plan plan = RootPerAppUidPolicyPlan.prepare(
                "NL privacy", peers, Collections.singletonList(app), overrides);
        if (plan.activationAllowed() || plan.rules.size() != 4
                || plan.routes.size() != 6 || plan.blockers.isEmpty()) {
            throw new AssertionError("Dry-run must never activate packet routing.");
        }
        if (plan.rules.get(0).transport != RootProtocolRouteDraft.TCP
                || plan.rules.get(0).destinationPort != 443
                || !plan.rules.get(0).tunnelName.equals("US regional")
                || plan.rules.get(1).destinationPort != 0
                || plan.rules.get(2).transport != RootProtocolRouteDraft.UDP
                || plan.rules.get(3).transport != 0) {
            throw new AssertionError("Unexpected exact-port/app fallback ordering.");
        }
        for (int i = 0; i < plan.rules.size(); i++) {
            RootPerAppUidPolicyPlan.PerAppRule rule = plan.rules.get(i);
            if (rule.lookupPriority != 12800 + 2 * i
                    || rule.blockPriority != rule.lookupPriority + 1
                    || rule.table < 51000) {
                throw new AssertionError("A selector lacks a proposed terminal block.");
            }
        }
        if (!plan.summary().contains("DRY-RUN ONLY")
                || !plan.summary().contains("TCP port 443")
                || !plan.summary().contains("UDP port 443")) {
            throw new AssertionError("Dry-run policy does not identify its limits.");
        }

        List<RootProtocolRouteDraft.Override> sorted =
                RootProtocolRouteDraft.validateAndSort(overrides);
        if (!"US regional".equals(RootProtocolRouteDraft.matchingTunnel(
                sorted, "com.example.shopping", 6, 443, "NL privacy"))
                || !"NL privacy".equals(RootProtocolRouteDraft.matchingTunnel(
                        sorted, "com.example.shopping", 6, 80, "US regional"))
                || !"US regional".equals(RootProtocolRouteDraft.matchingTunnel(
                        sorted, "com.example.shopping", 17, 443, "NL privacy"))
                || !"NL privacy".equals(RootProtocolRouteDraft.matchingTunnel(
                        sorted, "com.example.shopping", 17, 53, "NL privacy"))) {
            throw new AssertionError("Transport or exact-port precedence is invalid.");
        }
        expectRefused(() -> new RootProtocolRouteDraft.Override(
                "com.example.shopping", 1, 443, "NL privacy"), "unsupported ICMP");
        expectRefused(() -> new RootProtocolRouteDraft.Override(
                "com.example.shopping", 6, 65536, "NL privacy"), "invalid port");
        expectRefused(() -> RootProtocolRouteDraft.validateAndSort(
                Arrays.asList(tcp443, tcp443)), "duplicate selector");
        expectRefused(() -> RootPerAppUidPolicyPlan.prepare(
                "NL privacy", peers, Collections.singletonList(app),
                Collections.singletonList(new RootProtocolRouteDraft.Override(
                        "com.example.shopping", 6, 443, "Home private"))),
                "private-only tunnel must not become public Internet exit");
        expectRefused(() -> RootPerAppUidPolicyPlan.prepare(
                "NL privacy", peers, Collections.singletonList(
                        new RootPerAppUidPolicyPlan.App("com.example.shopping",
                                10341, "Home private"))),
                "home-only app-wide routing must be refused");
        expectRefused(() -> RootPerAppUidPolicyPlan.prepare(
                "NL privacy", peers, Collections.singletonList(app),
                Collections.singletonList(new RootProtocolRouteDraft.Override(
                        "com.example.unassigned", 6, 443, "US regional"))),
                "protocol override for an unassigned app");
        expectRefused(() -> RootPerAppUidPolicyPlan.prepare(
                "NL privacy", peers,
                Arrays.asList(app, new RootPerAppUidPolicyPlan.App(
                        "com.example.second", 10341, "US regional"))),
                "shared or duplicated UID cannot isolate applications");
        expectRefused(() -> RootPerAppUidPolicyPlan.prepare(
                "NL privacy", peers,
                Collections.singletonList(new RootPerAppUidPolicyPlan.App(
                        "com.example.shopping", 1000, "US regional"))),
                "Android system UID cannot be treated as ordinary app UID");
        expectRefused(() -> RootPerAppUidPolicyPlan.prepare(
                "NL privacy", Collections.singletonList(
                        entry("NL privacy", "10.150.0.2/32", "0.0.0.0/0")),
                Collections.singletonList(app)), "IPv4-only default must refuse");
        System.out.println("RootAppProtocolPolicyPlanTest passed");
    }
}
