package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Journal-first rule lifecycle contract, deliberately NOT connected to any
 * live Android shell adapter. A production backend must provide independent
 * Android capability checks, rule-order evidence and packet-level proof.
 */
final class RootMokaHomeFirewallPilotTransaction {
    enum Presence { ABSENT, EXACT_OWNED, FOREIGN_OR_CHANGED }
    interface Kernel {
        void requirePreflight() throws Exception;
        Presence inspect(RootMokaHomeFirewallPilotPlan.Step step) throws Exception;
        void apply(RootMokaHomeFirewallPilotPlan.Step step) throws Exception;
        void undo(RootMokaHomeFirewallPilotPlan.Step step) throws Exception;
    }
    interface Journal {
        boolean empty() throws Exception;
        void intent(RootMokaHomeFirewallPilotPlan.Step step) throws Exception;
        void applied(RootMokaHomeFirewallPilotPlan.Step step) throws Exception;
        List<RootMokaHomeFirewallPilotPlan.Step> snapshot() throws Exception;
        void clearExact(RootMokaHomeFirewallPilotPlan.Step step) throws Exception;
    }
    static final class Outcome {
        final boolean applied;
        final boolean clean;
        final String phase;
        final int pending;
        Outcome(boolean applied, boolean clean, String phase, int pending) {
            this.applied = applied;
            this.clean = clean;
            this.phase = phase;
            this.pending = pending;
        }
    }

    private RootMokaHomeFirewallPilotTransaction() { }

    static Outcome start(RootMokaHomeFirewallPilotPlan.Plan plan,
            Kernel kernel, Journal journal) throws Exception {
        if (plan == null || kernel == null || journal == null) {
            throw new IllegalArgumentException("Missing exact-owned firewall plan.");
        }
        // Preview-only plans must never silently authorize activation.
        if (plan.activationAllowed()) throw new IllegalArgumentException("Unsafe plan.");
        if (!journal.empty()) return new Outcome(false, false, "EXISTING_OWNER", journal.snapshot().size());
        validate(plan);
        kernel.requirePreflight();
        String phase = "PREFLIGHT";
        try {
            for (RootMokaHomeFirewallPilotPlan.Step step : plan.steps) {
                phase = step.kind;
                if (kernel.inspect(step) != Presence.ABSENT) {
                    throw new IllegalStateException("Foreign firewall rule or chain.");
                }
                journal.intent(step);
                kernel.apply(step);
                if (kernel.inspect(step) != Presence.EXACT_OWNED) {
                    throw new IllegalStateException("Incomplete firewall readback.");
                }
                journal.applied(step);
            }
            // This is only structural evidence, NEVER packet-level authorization.
            return new Outcome(true, false, "STRUCTURAL_ONLY", journal.snapshot().size());
        } catch (Exception problem) {
            boolean clean = recover(plan, kernel, journal);
            return new Outcome(false, clean, clean ? "ROLLED_BACK" : phase,
                    journal.snapshot().size());
        }
    }

    static Outcome stop(RootMokaHomeFirewallPilotPlan.Plan plan,
            Kernel kernel, Journal journal) throws Exception {
        boolean clean = recover(plan, kernel, journal);
        return new Outcome(false, clean, clean ? "CLEAN_STOPPED" : "RECOVERY_PAUSED",
                journal.snapshot().size());
    }

    private static boolean recover(RootMokaHomeFirewallPilotPlan.Plan plan,
            Kernel kernel, Journal journal) throws Exception {
        if (plan == null || kernel == null || journal == null) return false;
        List<RootMokaHomeFirewallPilotPlan.Step> reverse =
                new ArrayList<>(journal.snapshot());
        Collections.reverse(reverse);
        for (RootMokaHomeFirewallPilotPlan.Step step : reverse) {
            if (!RootMokaHomeFirewallPilotPlan.safeStep(plan, step)) return false;
            try {
                Presence presence = kernel.inspect(step);
                if (presence == null || presence == Presence.FOREIGN_OR_CHANGED) return false;
                if (presence == Presence.EXACT_OWNED) {
                    kernel.undo(step);
                    if (kernel.inspect(step) != Presence.ABSENT) return false;
                }
                journal.clearExact(step);
            } catch (Exception uncertain) {
                return false; // Journal retained, do not delete foreign state.
            }
        }
        return journal.empty();
    }

    static void validate(RootMokaHomeFirewallPilotPlan.Plan plan) {
        RootMokaHomeFirewallPilotPlan.Plan canonical =
                RootMokaHomeFirewallPilotPlan.compile(plan.uid, plan.homeDevice);
        if (plan.steps.size() != canonical.steps.size()) {
            throw new IllegalArgumentException("Firewall sequence changed.");
        }
        for (int i = 0; i < plan.steps.size(); i++) {
            RootMokaHomeFirewallPilotPlan.Step actual = plan.steps.get(i);
            RootMokaHomeFirewallPilotPlan.Step expected = canonical.steps.get(i);
            if (!RootMokaHomeFirewallPilotPlan.safeStep(plan, actual)
                    || actual.family != expected.family
                    || !actual.kind.equals(expected.kind)
                    || !actual.install.equals(expected.install)
                    || !actual.inverse.equals(expected.inverse)) {
                throw new IllegalArgumentException("Noncanonical firewall order.");
            }
        }
    }
}
