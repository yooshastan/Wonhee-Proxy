package com.yooshastan.wonheeproxy;

import com.wireguard.android.util.RootShell;

import java.util.ArrayList;
import java.util.List;

/** Exact-owned root firewall lifecycle. No broad OUTPUT flush or policy change. */
final class RootFailClosedFirewallRuntime {
    private RootFailClosedFirewallRuntime() { }

    private static boolean existsChain(RootShell shell, int family) throws Exception {
        return shell.run(null, RootFailClosedFirewallPlan.prefix(family)
                + " -S " + RootFailClosedFirewallPlan.chain(family)) == 0;
    }

    private static List<String> listing(RootShell shell, int family, String chain) throws Exception {
        List<String> lines = new ArrayList<>();
        if (shell.run(lines, RootFailClosedFirewallPlan.prefix(family) + " -S " + chain) != 0) {
            throw new IllegalStateException("Guard firewall listing unavailable.");
        }
        return lines;
    }

    private static int anchorCount(RootShell shell, int family) throws Exception {
        int count = 0;
        for (String line : listing(shell, family, "OUTPUT")) {
            if (line.contains(RootFailClosedFirewallPlan.tag(family))) count++;
        }
        if (count > 1) throw new IllegalStateException("Duplicate kill-switch anchor tag.");
        if (count == 1 && shell.run(null, RootFailClosedFirewallPlan.prefix(family)
                + " -C OUTPUT " + RootFailClosedFirewallPlan.anchorArgs(family)) != 0) {
            throw new IllegalStateException("Kill-switch anchor tag belongs to a different rule.");
        }
        return count;
    }

    static void preflight(RootShell shell) throws Exception {
        for (int family : new int[]{4, 6}) {
            if (existsChain(shell, family) || anchorCount(shell, family) != 0) {
                throw new IllegalStateException("Existing guard chain or anchor; refusing takeover.");
            }
        }
    }

    private static void verifyFamily(RootShell shell, RootFailClosedFirewallPlan.Plan plan,
                                     int family, boolean full, boolean requireAnchor) throws Exception {
        boolean chainExists = existsChain(shell, family);
        int anchored = anchorCount(shell, family);
        if (requireAnchor && anchored != 1) {
            throw new IllegalStateException("Guard OUTPUT anchor missing.");
        }
        if (!chainExists) {
            if (anchored != 0 || full) throw new IllegalStateException("Guard chain missing/mismatched.");
            return;
        }
        int actualRules = 0;
        for (String line : listing(shell, family, RootFailClosedFirewallPlan.chain(family))) {
            if (line.startsWith("-A " + RootFailClosedFirewallPlan.chain(family) + " ")) actualRules++;
        }
        int exactMatches = 0;
        for (RootFailClosedFirewallPlan.Rule rule : plan.family(family)) {
            if (shell.run(null, rule.exists()) == 0) exactMatches++;
        }
        // Allow a crash-time subset of planned rules for recovery, but NEVER
        // silently flush an unrecognized or duplicate rule from the chain.
        if (actualRules != exactMatches || (full && exactMatches != plan.family(family).size())) {
            throw new IllegalStateException("Guard chain contains unowned or missing rules.");
        }
    }

    static void verify(RootShell shell, RootFailClosedFirewallPlan.Plan plan) throws Exception {
        for (int family : new int[]{4, 6}) verifyFamily(shell, plan, family, true, true);
    }

    static void install(RootShell shell, RootFailClosedFirewallPlan.Plan plan) throws Exception {
        preflight(shell);
        for (int family : new int[]{4, 6}) {
            if (shell.run(null, RootFailClosedFirewallPlan.prefix(family) + " -N "
                    + RootFailClosedFirewallPlan.chain(family)) != 0) {
                throw new IllegalStateException("Cannot create owned kill-switch chain.");
            }
            for (RootFailClosedFirewallPlan.Rule rule : plan.family(family)) {
                if (shell.run(null, rule.add()) != 0 || shell.run(null, rule.exists()) != 0) {
                    throw new IllegalStateException("Cannot install exact guard rule.");
                }
            }
            verifyFamily(shell, plan, family, true, false);
        }
        // Anchor last, only after BOTH chains are fully validated. There is
        // no period where an OUTPUT anchor points to an incomplete chain.
        for (int family : new int[]{4, 6}) {
            if (shell.run(null, RootFailClosedFirewallPlan.prefix(family)
                    + " -I OUTPUT 1 " + RootFailClosedFirewallPlan.anchorArgs(family)) != 0) {
                throw new IllegalStateException("Cannot activate kill-switch anchor.");
            }
        }
        verify(shell, plan);
    }

    static void removeOwned(RootShell shell, RootFailClosedFirewallPlan.Plan plan) throws Exception {
        // Check BOTH chains and anchors before deleting anything. Chain rules
        // may be a planned subset after a crash; unknown rules prevent flush.
        for (int family : new int[]{4, 6}) verifyFamily(shell, plan, family, false, false);
        for (int family : new int[]{4, 6}) {
            if (anchorCount(shell, family) == 1
                    && shell.run(null, RootFailClosedFirewallPlan.prefix(family)
                    + " -D OUTPUT " + RootFailClosedFirewallPlan.anchorArgs(family)) != 0) {
                throw new IllegalStateException("Cannot remove exact kill-switch anchor.");
            }
        }
        for (int family : new int[]{4, 6}) {
            if (!existsChain(shell, family)) continue;
            if (shell.run(null, RootFailClosedFirewallPlan.prefix(family)
                    + " -F " + RootFailClosedFirewallPlan.chain(family)) != 0
                    || shell.run(null, RootFailClosedFirewallPlan.prefix(family)
                    + " -X " + RootFailClosedFirewallPlan.chain(family)) != 0) {
                throw new IllegalStateException("Owned kill-switch chain cleanup failed.");
            }
        }
        preflight(shell);
    }
}
