package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Write-ahead, exact-owned UID-only routing phase for the isolated kernel
 * multi-exit pilot. Not connected to Start/Stop. A future Android Kernel
 * implementation must verify installed WireGuard exits and DNS/no-fallback
 * ownership before any policy rule becomes visible to Android sockets.
 */
final class RootIsolatedUidPolicyTransaction {
    enum Presence { ABSENT, EXACT_OWNED, FOREIGN_OR_CHANGED }

    interface Kernel {
        /**
         * Verify BOTH families, exact WireGuard endpoint underlay, rootnetd
         * coexistence, protected system sockets, app UIDs, DNS ownership,
         * and no-fallback coverage before ANY mutable command.
         */
        void requireFailClosedPreflight() throws Exception;
        Presence inspect(RootIsolatedUidOnlyPolicyPlan.Step step) throws Exception;
        void apply(RootIsolatedUidOnlyPolicyPlan.Step step) throws Exception;
        void undo(RootIsolatedUidOnlyPolicyPlan.Step step) throws Exception;
    }

    interface Journal {
        /** Durable, exact-plan-bound ledger, never process-only state. */
        boolean empty() throws Exception;
        void recordIntent(RootIsolatedUidOnlyPolicyPlan.Step step) throws Exception;
        void recordApplied(RootIsolatedUidOnlyPolicyPlan.Step step) throws Exception;
        List<RootIsolatedUidOnlyPolicyPlan.Step> snapshot() throws Exception;
        void clearExact(RootIsolatedUidOnlyPolicyPlan.Step step) throws Exception;
    }

    static final class Outcome {
        final boolean applied;
        final boolean clean;
        final String phase;
        final int journalCount;

        Outcome(boolean applied, boolean clean, String phase, int journalCount) {
            this.applied = applied;
            this.clean = clean;
            this.phase = phase;
            this.journalCount = journalCount;
        }

        String summary() {
            return (applied ? "UID POLICY STEPS APPLIED, PACKET PROOF PENDING"
                    : clean ? "UID POLICY REFUSED, EXACT CLEANUP COMPLETE"
                    : "UID POLICY REFUSED, RECOVERY REQUIRED")
                    + "; phase=" + phase + "; journal steps=" + journalCount;
        }
    }

    private RootIsolatedUidPolicyTransaction() { }

    static Outcome start(RootIsolatedUidOnlyPolicyPlan.Plan plan,
            Kernel kernel, Journal journal) throws Exception {
        if (plan == null || kernel == null || journal == null) {
            throw new IllegalArgumentException("Missing UID policy transaction input.");
        }
        if (!journal.empty()) {
            return new Outcome(false, false, "EXISTING_JOURNAL",
                    journal.snapshot().size());
        }
        List<RootIsolatedUidOnlyPolicyPlan.Step> steps = plan.startOrder();
        if (plan.activationAllowed() || steps.isEmpty() || plan.blockers.isEmpty()
                || plan.uidSelectors.isEmpty()) {
            throw new IllegalArgumentException("UID-only plan is unsafe.");
        }
        int blockers = 0;
        for (RootIsolatedUidOnlyPolicyPlan.Step step : steps) {
            if (!safeStep(step)) {
                throw new IllegalArgumentException("Unexpected UID policy command.");
            }
            if ("TERMINAL_ROUTE".equals(step.kind)) {
                if (blockers >= plan.blockers.size()) {
                    throw new IllegalArgumentException("Terminal block after UID selector.");
                }
                blockers++;
            } else if (blockers != plan.blockers.size()) {
                throw new IllegalArgumentException("UID selector before terminal block.");
            }
        }
        if (blockers != plan.blockers.size()) {
            throw new IllegalArgumentException("Missing exit block.");
        }
        kernel.requireFailClosedPreflight();
        String phase = "PREFLIGHT";
        try {
            for (RootIsolatedUidOnlyPolicyPlan.Step step : steps) {
                phase = step.kind;
                if (kernel.inspect(step) != Presence.ABSENT) {
                    throw new IllegalStateException("Rule collides with existing Android policy.");
                }
                // If an operation partially completes before throwing, the
                // durable intent lets Safe Stop verify its exact kernel state.
                journal.recordIntent(step);
                kernel.apply(step);
                if (kernel.inspect(step) != Presence.EXACT_OWNED) {
                    throw new IllegalStateException("Kernel policy readback mismatch.");
                }
                journal.recordApplied(step);
            }
            return new Outcome(true, false, "VERIFIED_STEPS",
                    journal.snapshot().size());
        } catch (Exception failed) {
            boolean clean = recoverOwned(kernel, journal);
            return new Outcome(false, clean, phase, journal.snapshot().size());
        }
    }

    static Outcome stop(Kernel kernel, Journal journal) throws Exception {
        if (kernel == null || journal == null) {
            throw new IllegalArgumentException("Missing UID recovery kernel/journal.");
        }
        boolean clean = recoverOwned(kernel, journal);
        return new Outcome(false, clean,
                clean ? "CLEAN_STOPPED" : "RECOVERY_PAUSED",
                journal.snapshot().size());
    }

    private static boolean recoverOwned(Kernel kernel, Journal journal)
            throws Exception {
        List<RootIsolatedUidOnlyPolicyPlan.Step> owned =
                new ArrayList<>(journal.snapshot());
        Collections.reverse(owned);
        for (RootIsolatedUidOnlyPolicyPlan.Step step : owned) {
            if (!safeStep(step)) return false;
            try {
                Presence state = kernel.inspect(step);
                if (state == null || state == Presence.FOREIGN_OR_CHANGED) {
                    return false;
                }
                if (state == Presence.EXACT_OWNED) {
                    kernel.undo(step);
                    if (kernel.inspect(step) != Presence.ABSENT) return false;
                }
                journal.clearExact(step);
            } catch (Exception uncertain) {
                return false; // Keep the remaining ledger for manual retry.
            }
        }
        return journal.empty();
    }

    /**
     * Narrowly whitelist only the syntax emitted by the UID pilot compiler.
     * Do not permit mark writes, L4 port selectors, global/main tables or
     * Android-owned policy priorities.
     */
    static boolean safeStep(RootIsolatedUidOnlyPolicyPlan.Step s) {
        if (s == null || s.add == null || s.remove == null
                || (s.family != 4 && s.family != 6)) return false;
        String family = "ip -" + s.family;
        if ("TERMINAL_ROUTE".equals(s.kind)) {
            return s.add.matches(family
                    + " route add unreachable default table 5100[0-7] metric 42700")
                    && s.remove.equals(s.add.replace(" route add ", " route del "));
        }
        if ("APP_UID".equals(s.kind)) {
            return s.add.matches(family + " rule add pref 12[89][0-9]{2}"
                    + " fwmark 0x0/0x20000 iif lo uidrange"
                    + " (?:[1-9][0-9]{4})-(?:[1-9][0-9]{4})"
                    + " lookup 5100[0-7]")
                    && s.remove.equals(s.add.replace(" rule add ", " rule del "));
        }
        return false;
    }

}
