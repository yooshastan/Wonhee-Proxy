package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Pure tests. These commands NEVER execute against Android or Fedora. */
public final class RootMultiExitKernelPlanTest {
    private static RootMultiTunnelPlan.Entry peer(String name, String address,
            String... routes) {
        return new RootMultiTunnelPlan.Entry(name, Arrays.asList(routes),
                Collections.singletonList(address));
    }

    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    private static void refused(Runnable body, String reason) {
        try {
            body.run();
        } catch (IllegalArgumentException expected) {
            return;
        }
        throw new AssertionError("Unsafe plan accepted: " + reason);
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry nl = peer("AirVPN Europe", "10.150.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry us = peer("AirVPN America", "10.151.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry home = peer("Fedora Home", "10.77.0.3/32",
                "10.0.0.169/32", "10.77.0.0/24");
        List<RootMultiTunnelPlan.Entry> tunnels = Arrays.asList(nl, us, home);
        RootPerAppUidPolicyPlan.App shopping =
                new RootPerAppUidPolicyPlan.App("com.example.shopping", 10341,
                        "AirVPN America");
        RootPerAppUidPolicyPlan.App messenger =
                new RootPerAppUidPolicyPlan.App("com.example.messenger", 10342,
                        "AirVPN Europe");
        List<RootProtocolRouteDraft.Override> overrides = Arrays.asList(
                new RootProtocolRouteDraft.Override("com.example.shopping",
                        RootProtocolRouteDraft.TCP, 443, "AirVPN Europe"),
                new RootProtocolRouteDraft.Override("com.example.shopping",
                        RootProtocolRouteDraft.TCP, 0, "AirVPN America"));
        RootPerAppUidPolicyPlan.Plan source = RootPerAppUidPolicyPlan.prepare(
                "AirVPN Europe", tunnels, Arrays.asList(shopping, messenger), overrides);
        RootMultiExitKernelPlan.Result plan = RootMultiExitKernelPlan.compile(source);
        check(!plan.activationAllowed() && !source.activationAllowed(),
                "Compilation must remain non-enforcing");
        check(plan.independentTables == 3 && plan.routes.size() == 6,
                "Two full dual-stack exits and one private Home need three tables");
        check(plan.policy.size() == source.rules.size() * 4
                && plan.ipv4Rules == plan.ipv6Rules,
                "Each selector requires IPv4+IPv6 lookup and terminal block");
        check(plan.summary().contains("DRY-RUN")
                && plan.summary().contains("NOT CONNECTED"),
                "Dry-run must not claim multiple VPN connections succeeded");

        for (RootMultiExitKernelPlan.Step step : plan.routes) {
            check(step.kind.equals("ROUTE")
                    && step.install.startsWith("ip -" + step.family + " route add table ")
                    && step.rollback.startsWith("ip -" + step.family + " route del table ")
                    && step.install.contains(" dev wnm"),
                    "Only exact owned private-table route mutations may be planned");
        }
        for (int i = 0; i < source.rules.size(); i++) {
            RootPerAppUidPolicyPlan.PerAppRule appRule = source.rules.get(i);
            for (int familyIdx = 0; familyIdx < 2; familyIdx++) {
                int index = i * 4 + familyIdx * 2;
                int family = familyIdx == 0 ? 4 : 6;
                RootMultiExitKernelPlan.Step lookup = plan.policy.get(index);
                RootMultiExitKernelPlan.Step block = plan.policy.get(index + 1);
                check(lookup.kind.equals("LOOKUP") && block.kind.equals("BLOCK")
                        && lookup.family == family && block.family == family,
                        "Every family must have an adjacent lookup and block");
                check(lookup.install.contains("pref " + appRule.lookupPriority + " ")
                        && block.install.contains("pref " + appRule.blockPriority + " ")
                        && lookup.install.contains("lookup " + appRule.table)
                        && block.install.endsWith(" unreachable"),
                        "A missing selected route must be blocked, not fall back");
                check(lookup.install.contains("uidrange " + appRule.uid + "-"
                        + appRule.uid)
                        && lookup.install.contains("fwmark 0x0/0x20000")
                        && lookup.rollback.contains(" rule del ")
                        && block.rollback.contains(" rule del "),
                        "UID, unprotected fwmark and exact inverse operations required");
            }
        }
        check(plan.policy.get(0).install.contains(" ipproto 6 dport 443 "),
                "Explicit exact TCP/443 must take precedence");
        check(plan.policy.get(4).install.contains(" ipproto 6 ")
                && !plan.policy.get(4).install.contains(" dport "),
                "App-wide TCP override must follow its exact-port override");

        String defaultDevice = nl.device;
        List<RootPerAppUidPolicyPlan.Route> tamperedRoutes =
                new ArrayList<>(source.routes);
        tamperedRoutes.add(source.routes.get(0));
        refused(() -> RootMultiExitKernelPlan.compile(
                new RootPerAppUidPolicyPlan.Plan(source.defaultExit, tamperedRoutes,
                        source.rules)), "duplicate route");
        List<RootPerAppUidPolicyPlan.Route> foreign = new ArrayList<>(source.routes);
        RootPerAppUidPolicyPlan.Route before = foreign.get(0);
        foreign.set(0, new RootPerAppUidPolicyPlan.Route(before.family,
                before.destination, defaultDevice, before.table));
        if (!before.device.equals(defaultDevice)) {
            refused(() -> RootMultiExitKernelPlan.compile(
                    new RootPerAppUidPolicyPlan.Plan(source.defaultExit, foreign,
                            source.rules)), "private table owned by another device");
        }
        List<RootPerAppUidPolicyPlan.PerAppRule> badPriority =
                new ArrayList<>(source.rules);
        RootPerAppUidPolicyPlan.PerAppRule first = badPriority.get(0);
        badPriority.set(0, new RootPerAppUidPolicyPlan.PerAppRule(first.uid,
                first.packageName, first.tunnelName, first.device, first.table,
                first.lookupPriority, first.blockPriority + 2,
                first.transport, first.destinationPort));
        refused(() -> RootMultiExitKernelPlan.compile(
                new RootPerAppUidPolicyPlan.Plan(source.defaultExit, source.routes,
                        badPriority)), "non-adjacent terminal block");

        List<RootPerAppUidPolicyPlan.PerAppRule> wrongUid =
                new ArrayList<>(source.rules);
        wrongUid.set(0, new RootPerAppUidPolicyPlan.PerAppRule(1000,
                first.packageName, first.tunnelName, first.device, first.table,
                first.lookupPriority, first.blockPriority, first.transport,
                first.destinationPort));
        refused(() -> RootMultiExitKernelPlan.compile(
                new RootPerAppUidPolicyPlan.Plan(source.defaultExit, source.routes,
                        wrongUid)), "system UID cannot be routed");

        List<RootPerAppUidPolicyPlan.Route> badCidr = new ArrayList<>(source.routes);
        badCidr.set(0, new RootPerAppUidPolicyPlan.Route(before.family,
                "anything.invalid/32", before.device, before.table));
        refused(() -> RootMultiExitKernelPlan.compile(
                new RootPerAppUidPolicyPlan.Plan(source.defaultExit, badCidr,
                        source.rules)), "non-numeric route");

        List<RootPerAppUidPolicyPlan.Route> noV6 = new ArrayList<>();
        for (RootPerAppUidPolicyPlan.Route route : source.routes) {
            if (!(route.family == 6
                    && route.device.equals(source.rules.get(0).device))) {
                noV6.add(route);
            }
        }
        refused(() -> RootMultiExitKernelPlan.compile(
                new RootPerAppUidPolicyPlan.Plan(source.defaultExit, noV6,
                        source.rules)), "an app cannot use an IPv4-only Internet exit");

        check(RootMultiExitKernelPlan.compile(source).policy.get(0).install
                        .equals(plan.policy.get(0).install),
                "Repeated compilation of the same plan must be deterministic");
        System.out.println("RootMultiExitKernelPlanTest passed");
    }
}
