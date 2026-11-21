package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Non-executing proposal for an initial *UID-only* multi-exit pilot.
 *
 * Pixel 8a's ip rule advertises uidrange/fwmark but not ipproto/dport or
 * action 'unreachable'. The proposed terminal block is therefore a
 * HIGH-METRIC UNREACHABLE DEFAULT ROUTE INSIDE THE SELECTED PRIVATE TABLE,
 * NOT an ip-rule unreachable action. Actual Android ip-route syntax and
 * fail-closed packet behavior must still be proved on device.
 *
 * Any protocol/port override is deliberately refused by this compiler.
 * The existing Android DNS resolver does not necessarily run under the
 * requesting application's UID. This plan NEVER authorizes activation.
 */
final class RootIsolatedUidOnlyPolicyPlan {
    static final class Step {
        final int family;
        final String kind;
        final String add;
        final String remove;
        Step(int family, String kind, String add, String remove) {
            this.family = family;
            this.kind = kind;
            this.add = add;
            this.remove = remove;
        }
    }

    static final class Plan {
        final List<Step> blockers;
        final List<Step> uidSelectors;
        final int assignedApps;
        final int selectedExits;

        Plan(List<Step> blocks, List<Step> selectors,
                int assignedApps, int selectedExits) {
            blockers = Collections.unmodifiableList(new ArrayList<>(blocks));
            uidSelectors = Collections.unmodifiableList(new ArrayList<>(selectors));
            this.assignedApps = assignedApps;
            this.selectedExits = selectedExits;
        }

        List<Step> startOrder() {
            List<Step> ordered = new ArrayList<>(blockers);
            ordered.addAll(uidSelectors);
            return Collections.unmodifiableList(ordered);
        }

        List<Step> stopOrder() {
            List<Step> ordered = new ArrayList<>(uidSelectors);
            Collections.reverse(ordered);
            List<Step> blocks = new ArrayList<>(blockers);
            Collections.reverse(blocks);
            ordered.addAll(blocks);
            return Collections.unmodifiableList(ordered);
        }

        boolean activationAllowed() { return false; }

        String summary() {
            return "UID-ONLY MULTI-EXIT PROPOSAL — NOT ACTIVE: "
                    + assignedApps + " explicitly assigned app UID(s), "
                    + selectedExits + " independently routed exit(s), "
                    + blockers.size() + " proposed terminal private-table "
                    + "unreachable defaults. Android CLI support, DNS UID "
                    + "attribution, socket packet path, endpoint protection "
                    + "and fail-closed behavior NOT VERIFIED. No network change.";
        }
    }

    private RootIsolatedUidOnlyPolicyPlan() { }

    static Plan compile(RootPerAppUidPolicyPlan.Plan input) {
        if (input == null || input.activationAllowed()
                || input.rules == null || input.rules.isEmpty()) {
            throw new IllegalArgumentException("Empty or unsafe UID policy.");
        }
        // Guarantees private route, table, device and UID ownership shapes.
        RootMultiExitKernelPlan.compile(input);
        Map<Integer, Set<Integer>> familyTables = new HashMap<>();
        for (RootPerAppUidPolicyPlan.Route route : input.routes) {
            if ((route.family == 4 && "0.0.0.0/0".equals(route.destination))
                    || (route.family == 6 && ("::/0".equals(route.destination)
                    || "0:0:0:0:0:0:0:0/0".equals(route.destination)))) {
                familyTables.computeIfAbsent(route.table, unused -> new HashSet<>())
                        .add(route.family);
            }
        }
        List<Step> blockers = new ArrayList<>();
        List<Integer> orderedTables = new ArrayList<>(familyTables.keySet());
        Collections.sort(orderedTables);
        for (int table : orderedTables) {
            Set<Integer> families = familyTables.get(table);
            if (!families.contains(4) || !families.contains(6)) {
                throw new IllegalArgumentException("Incomplete dual-stack exit.");
            }
            for (int family : new int[] {4, 6}) {
                String cmd = "ip -" + family + " route ";
                String args = "unreachable default table " + table
                        + " metric 42700";
                blockers.add(new Step(family, "TERMINAL_ROUTE",
                        cmd + "add " + args, cmd + "del " + args));
            }
        }
        Set<Integer> uids = new HashSet<>();
        List<Step> selectors = new ArrayList<>();
        for (RootPerAppUidPolicyPlan.PerAppRule rule : input.rules) {
            if (rule.transport != 0 || rule.destinationPort != 0
                    || !uids.add(rule.uid)
                    || !familyTables.containsKey(rule.table)) {
                throw new IllegalArgumentException("UID-only pilot refuses "
                        + "port overrides, duplicate UIDs and private-only routes.");
            }
            // Do not set a new fwmark: Android's observed masks already
            // span all 32 bits. Match only unprotected application sockets.
            for (int family : new int[]{4, 6}) {
                String cmd = "ip -" + family + " rule ";
                String args = "pref " + rule.lookupPriority
                        + " fwmark 0x0/0x20000 iif lo uidrange "
                        + rule.uid + "-" + rule.uid + " lookup " + rule.table;
                selectors.add(new Step(family, "APP_UID",
                        cmd + "add " + args, cmd + "del " + args));
            }
        }
        if (uids.size() < 1 || orderedTables.isEmpty()) {
            throw new IllegalArgumentException("No usable UID exit.");
        }
        return new Plan(blockers, selectors, uids.size(), orderedTables.size());
    }
}
