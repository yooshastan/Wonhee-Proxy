package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Rootless policy transaction failure injection, with a deterministic mock
 * of Android's two-family UID rules and terminal private-table block routes.
 */
public final class RootIsolatedUidPolicyTransactionTest {
    private static final class Journal
            implements RootIsolatedUidPolicyTransaction.Journal {
        final List<RootIsolatedUidOnlyPolicyPlan.Step> saved = new ArrayList<>();
        int writes;
        int failWriteAt = -1;

        @Override public boolean empty() { return saved.isEmpty(); }

        @Override public void recordIntent(RootIsolatedUidOnlyPolicyPlan.Step step)
                throws Exception {
            if (++writes == failWriteAt) {
                throw new IllegalStateException("Persistent journal unavailable.");
            }
            saved.add(step);
        }

        @Override public void recordApplied(RootIsolatedUidOnlyPolicyPlan.Step step)
                throws Exception {
            if (!saved.contains(step)) {
                throw new IllegalStateException("Cannot commit without an intent.");
            }
        }

        @Override public List<RootIsolatedUidOnlyPolicyPlan.Step> snapshot() {
            return new ArrayList<>(saved);
        }

        @Override public void clearExact(RootIsolatedUidOnlyPolicyPlan.Step step)
                throws Exception {
            if (saved.isEmpty() || saved.get(saved.size() - 1) != step) {
                throw new IllegalStateException("UID recovery must pop exact last intent.");
            }
            saved.remove(saved.size() - 1);
        }
    }

    private static final class Kernel
            implements RootIsolatedUidPolicyTransaction.Kernel {
        final Set<RootIsolatedUidOnlyPolicyPlan.Step> owned = new HashSet<>();
        final Set<RootIsolatedUidOnlyPolicyPlan.Step> foreign = new HashSet<>();
        boolean preflight = true;
        int preflightCalls;
        int writes;
        int deletes;
        int failWriteAt = -1;
        int failDeleteAt = -1;

        @Override public void requireFailClosedPreflight() {
            preflightCalls++;
            if (!preflight) {
                throw new IllegalStateException("DNS or dual-stack underlay unverified.");
            }
        }

        @Override public RootIsolatedUidPolicyTransaction.Presence inspect(
                RootIsolatedUidOnlyPolicyPlan.Step step) {
            if (foreign.contains(step)) {
                return RootIsolatedUidPolicyTransaction.Presence.FOREIGN_OR_CHANGED;
            }
            return owned.contains(step)
                    ? RootIsolatedUidPolicyTransaction.Presence.EXACT_OWNED
                    : RootIsolatedUidPolicyTransaction.Presence.ABSENT;
        }

        @Override public void apply(RootIsolatedUidOnlyPolicyPlan.Step step)
                throws Exception {
            writes++;
            if (!preflight) {
                throw new AssertionError("Kernel changed without safety proof.");
            }
            if ("APP_UID".equals(step.kind)) {
                for (RootIsolatedUidOnlyPolicyPlan.Step other : owned) {
                    if ("TERMINAL_ROUTE".equals(other.kind)) continue;
                }
                if (!owned.containsAll(terminalBlocks)) {
                    throw new AssertionError("UID selector preceded fail-closed block.");
                }
            }
            owned.add(step);
            if (writes == failWriteAt) {
                throw new IllegalStateException("Kernel changed before command error.");
            }
        }

        @Override public void undo(RootIsolatedUidOnlyPolicyPlan.Step step)
                throws Exception {
            deletes++;
            if (deletes == failDeleteAt) {
                throw new IllegalStateException("Interrupted kernel cleanup.");
            }
            if (!owned.remove(step)) {
                throw new AssertionError("Attempted to remove a foreign policy.");
            }
        }

        final Set<RootIsolatedUidOnlyPolicyPlan.Step> terminalBlocks =
                new HashSet<>();
    }

    private static void check(boolean value, String reason) {
        if (!value) throw new AssertionError(reason);
    }

    private static void reject(Runnable task, String reason) {
        try { task.run(); }
        catch (IllegalArgumentException expected) { return; }
        throw new AssertionError("Unsafe policy plan accepted: " + reason);
    }

    private static RootIsolatedUidOnlyPolicyPlan.Plan plan() {
        List<RootMultiTunnelPlan.Entry> peers = Arrays.asList(
                new RootMultiTunnelPlan.Entry("Europe",
                        Arrays.asList("0.0.0.0/0", "::/0"),
                        Collections.singletonList("10.150.0.2/32")),
                new RootMultiTunnelPlan.Entry("America",
                        Arrays.asList("0.0.0.0/0", "::/0"),
                        Collections.singletonList("10.151.0.2/32")));
        RootPerAppUidPolicyPlan.Plan model = RootPerAppUidPolicyPlan.prepare(
                "Europe", peers, Arrays.asList(
                        new RootPerAppUidPolicyPlan.App(
                                "com.example.privacy", 10341, "Europe"),
                        new RootPerAppUidPolicyPlan.App(
                                "com.example.commerce", 10342, "America")));
        return RootIsolatedUidOnlyPolicyPlan.compile(model);
    }

    private static Kernel kernelWithPlan(
            RootIsolatedUidOnlyPolicyPlan.Plan plan) {
        Kernel kernel = new Kernel();
        kernel.terminalBlocks.addAll(plan.blockers);
        return kernel;
    }

    public static void main(String[] args) throws Exception {
        RootIsolatedUidOnlyPolicyPlan.Plan plan = plan();
        check(!plan.activationAllowed(),
                "Policy plans cannot authorize kernel activation by themselves.");
        Kernel kernel = kernelWithPlan(plan);
        Journal journal = new Journal();
        RootIsolatedUidPolicyTransaction.Outcome result =
                RootIsolatedUidPolicyTransaction.start(plan, kernel, journal);
        check(result.applied && journal.saved.size() == plan.startOrder().size()
                        && kernel.owned.size() == plan.startOrder().size(),
                "Successful policy phase retains a complete exact-owned ledger");
        check(!RootIsolatedUidPolicyTransaction.start(plan, kernel, journal).applied
                        && kernel.preflightCalls == 1,
                "A second Start cannot adopt existing owned policy rules.");
        result = RootIsolatedUidPolicyTransaction.stop(kernel, journal);
        check(result.clean && journal.empty() && kernel.owned.isEmpty(),
                "Safe Stop removes selectors then terminal private-table blocks.");
        check(RootIsolatedUidPolicyTransaction.stop(kernel, journal).clean,
                "Safe Stop must be idempotent.");

        for (int n = 1; n <= plan.startOrder().size(); n++) {
            kernel = kernelWithPlan(plan);
            journal = new Journal();
            kernel.failWriteAt = n;
            result = RootIsolatedUidPolicyTransaction.start(plan, kernel, journal);
            check(!result.applied && result.clean
                            && journal.empty() && kernel.owned.isEmpty(),
                    "Failure after kernel write at step " + n + " must roll back.");
        }

        kernel = kernelWithPlan(plan);
        journal = new Journal();
        journal.failWriteAt = 3;
        result = RootIsolatedUidPolicyTransaction.start(plan, kernel, journal);
        check(!result.applied && result.clean && journal.empty()
                        && kernel.owned.isEmpty() && kernel.writes == 2,
                "No kernel step without a prior durable journal intent.");

        kernel = kernelWithPlan(plan);
        journal = new Journal();
        kernel.preflight = false;
        boolean refused = false;
        try {
            RootIsolatedUidPolicyTransaction.start(plan, kernel, journal);
        } catch (IllegalStateException expected) { refused = true; }
        check(refused && kernel.writes == 0 && journal.empty(),
                "No UID routing while DNS/fail-closed proof is missing.");

        kernel = kernelWithPlan(plan);
        journal = new Journal();
        RootIsolatedUidOnlyPolicyPlan.Step first = plan.startOrder().get(0);
        kernel.foreign.add(first);
        result = RootIsolatedUidPolicyTransaction.start(plan, kernel, journal);
        check(!result.applied && result.clean && kernel.foreign.contains(first)
                        && kernel.writes == 0 && journal.empty(),
                "Do not remove another owner's private-table block.");

        kernel = kernelWithPlan(plan);
        journal = new Journal();
        RootIsolatedUidPolicyTransaction.start(plan, kernel, journal);
        RootIsolatedUidOnlyPolicyPlan.Step last =
                plan.startOrder().get(plan.startOrder().size() - 1);
        kernel.foreign.add(last);
        result = RootIsolatedUidPolicyTransaction.stop(kernel, journal);
        check(!result.clean && !journal.empty()
                        && kernel.foreign.contains(last) && kernel.deletes == 0,
                "Unknown UID selector pauses all cleanup and retains the ledger.");
        kernel.foreign.remove(last);
        check(RootIsolatedUidPolicyTransaction.stop(kernel, journal).clean,
                "Retry after exact ownership audit can finish cleanup.");

        kernel = kernelWithPlan(plan);
        journal = new Journal();
        RootIsolatedUidPolicyTransaction.start(plan, kernel, journal);
        kernel.failDeleteAt = 2;
        result = RootIsolatedUidPolicyTransaction.stop(kernel, journal);
        check(!result.clean && !journal.empty(),
                "Interrupted policy cleanup keeps pending ownership.");
        kernel.failDeleteAt = -1;
        check(RootIsolatedUidPolicyTransaction.stop(kernel, journal).clean,
                "Retry resumes incomplete rollback.");

        List<RootIsolatedUidOnlyPolicyPlan.Step> corrupted =
                new ArrayList<>(plan.uidSelectors);
        corrupted.set(corrupted.size() - 1,
                new RootIsolatedUidOnlyPolicyPlan.Step(4, "APP_UID",
                        "ip -4 rule add pref 12800 lookup main",
                        "ip -4 rule del pref 12800 lookup main"));
        RootIsolatedUidOnlyPolicyPlan.Plan unsafe =
                new RootIsolatedUidOnlyPolicyPlan.Plan(
                        plan.blockers, corrupted, 2, 2);
        Kernel noChanges = kernelWithPlan(unsafe);
        Journal empty = new Journal();
        reject(() -> {
            try {
                RootIsolatedUidPolicyTransaction.start(unsafe, noChanges, empty);
            } catch (RuntimeException runtime) { throw runtime; }
            catch (Exception checked) { throw new AssertionError(checked); }
        }, "A late invalid selector must be rejected before any block mutation.");
        check(noChanges.writes == 0 && noChanges.preflightCalls == 0
                        && empty.empty(), "Malformed policy never reaches root.");

        System.out.println("RootIsolatedUidPolicyTransactionTest passed");
    }
}
