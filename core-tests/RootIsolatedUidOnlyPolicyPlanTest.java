package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Dry-run only; does not install policy rules or change Android DNS. */
public final class RootIsolatedUidOnlyPolicyPlanTest {
    private static RootMultiTunnelPlan.Entry tunnel(String name, String addr,
            String... routes) {
        return new RootMultiTunnelPlan.Entry(name, Arrays.asList(routes),
                Collections.singletonList(addr));
    }

    private static void check(boolean pass, String message) {
        if (!pass) throw new AssertionError(message);
    }

    private static void reject(Runnable action, String message) {
        try { action.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("Unsafe UID plan accepted: " + message);
    }

    public static void main(String[] args) {
        List<RootMultiTunnelPlan.Entry> entries = Arrays.asList(
                tunnel("Europe", "10.150.0.2/32", "0.0.0.0/0", "::/0"),
                tunnel("America", "10.151.0.2/32", "0.0.0.0/0", "::/0"),
                tunnel("Home", "10.6.0.2/32", "10.0.0.169/32"));
        List<RootPerAppUidPolicyPlan.App> apps = Arrays.asList(
                new RootPerAppUidPolicyPlan.App("com.example.privacy", 10341, "Europe"),
                new RootPerAppUidPolicyPlan.App("com.example.shop", 10342, "America"));
        RootPerAppUidPolicyPlan.Plan draft =
                RootPerAppUidPolicyPlan.prepare("Europe", entries, apps);
        RootIsolatedUidOnlyPolicyPlan.Plan plan =
                RootIsolatedUidOnlyPolicyPlan.compile(draft);
        check(!plan.activationAllowed() && plan.assignedApps == 2
                        && plan.selectedExits == 2
                        && plan.blockers.size() == 4
                        && plan.uidSelectors.size() == 4,
                "UID-only plan spans exactly two dual-stack Internet exits");
        check(plan.summary().contains("NOT ACTIVE")
                && plan.summary().contains("DNS UID"),
                "Never claim a successful live VPN from a policy planner");
        for (RootIsolatedUidOnlyPolicyPlan.Step block : plan.blockers) {
            check(block.kind.equals("TERMINAL_ROUTE")
                    && block.add.matches(
                        "ip -[46] route add unreachable default table 5100[0-7] metric 42700")
                    && block.remove.equals(block.add.replace(" route add ", " route del ")),
                    "Each exit needs an exact private-table terminal unreachable route");
        }
        for (RootIsolatedUidOnlyPolicyPlan.Step rule : plan.uidSelectors) {
            check(rule.kind.equals("APP_UID")
                    && rule.add.contains(" fwmark 0x0/0x20000 iif lo uidrange ")
                    && !rule.add.contains("ipproto")
                    && !rule.add.contains("dport")
                    && !rule.add.contains("--set-mark")
                    && !rule.add.contains(" unreachable"),
                    "Use only Android-advertised UID/fwmark selector syntax");
        }
        List<RootIsolatedUidOnlyPolicyPlan.Step> start = plan.startOrder();
        List<RootIsolatedUidOnlyPolicyPlan.Step> stop = plan.stopOrder();
        check(start.get(0).kind.equals("TERMINAL_ROUTE")
                && start.get(start.size() - 1).kind.equals("APP_UID")
                && stop.get(0).kind.equals("APP_UID")
                && stop.get(stop.size() - 1).kind.equals("TERMINAL_ROUTE"),
                "Fail-closed routes must exist before selectors and disappear after them");
        try {
            stop.clear();
            throw new AssertionError("Mutable stop plan could lose rollback ordering");
        } catch (UnsupportedOperationException expected) { }

        RootPerAppUidPolicyPlan.Plan withOverride =
                RootPerAppUidPolicyPlan.prepare("Europe", entries, apps,
                        Arrays.asList(new RootProtocolRouteDraft.Override(
                                "com.example.shop", 6, 443, "Europe")));
        reject(() -> RootIsolatedUidOnlyPolicyPlan.compile(withOverride),
                "No TCP/UDP selector support on tested Pixel 8a ip tool");

        List<RootPerAppUidPolicyPlan.PerAppRule> changed = new ArrayList<>(draft.rules);
        RootPerAppUidPolicyPlan.PerAppRule first = changed.get(0);
        changed.add(first);
        reject(() -> RootIsolatedUidOnlyPolicyPlan.compile(
                new RootPerAppUidPolicyPlan.Plan(draft.defaultExit,
                        draft.routes, changed)),
                "Duplicate UID must be rejected even across different selectors");

        check(!start.get(0).add.contains("table main")
                        && !stop.get(0).remove.contains("table main"),
                "Pilot must never overwrite Android's default network");
        System.out.println("RootIsolatedUidOnlyPolicyPlanTest passed");
    }
}
