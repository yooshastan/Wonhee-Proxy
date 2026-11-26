package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Root-independent transaction controller for the isolated WireGuard plan.
 *
 * This controller has no Android/root-shell implementation and is NOT wired
 * into Start or Safe Stop. It expresses the contract a future device adapter
 * must meet: durable intent BEFORE every mutation, exact post-operation
 * ownership, and strict inverse rollback of only verified owned objects.
 *
 * In particular, failing midway through link creation can still leave an
 * interface behind; the in-flight journal entry must be re-auditable after a
 * process crash. A missing/foreign entry is NEVER permission to delete an
 * object just because its kernel name resembles Wonhee's naming convention.
 */
final class RootIsolatedWireGuardTransaction {
    enum Presence { ABSENT, EXACT_OWNED, FOREIGN_OR_CHANGED }

    interface Kernel {
        /**
         * Verify root tools, live interfaces, profile fingerprints, Android
         * mark/UID ownership, protected physical WireGuard UDP underlay, DNS,
         * IPv4/IPv6 fail-closed enforcement, and empty initial rule ownership.
         * No mutation is allowed if any check is uncertain.
         */
        void requireActivationPreflight() throws Exception;
        Presence inspect(RootIsolatedWireGuardBootstrapPlan.Step step) throws Exception;
        void apply(RootIsolatedWireGuardBootstrapPlan.Step step) throws Exception;
        void undo(RootIsolatedWireGuardBootstrapPlan.Step step) throws Exception;
    }

    interface Journal {
        /** Must be durable and collision-safe; a RAM-only journal is invalid. */
        boolean empty() throws Exception;
        void beforeMutation(RootIsolatedWireGuardBootstrapPlan.Step step) throws Exception;
        void committed(RootIsolatedWireGuardBootstrapPlan.Step step) throws Exception;
        /** Order is persistent insertion order across app restarts. */
        List<RootIsolatedWireGuardBootstrapPlan.Step> snapshot() throws Exception;
        void clearExact(RootIsolatedWireGuardBootstrapPlan.Step step) throws Exception;
    }

    /**
     * Sanitized, non-secret error code that may be carried into logs.
     * Never pass original shell stderr, configuration lines or endpoints.
     */
    static final class SafeFailure extends Exception {
        final String code;

        SafeFailure(String code) {
            super("Isolated peer stage refused");
            if (code == null || !code.matches("[A-Z0-9_]{3,64}")) {
                throw new IllegalArgumentException("Invalid safe stage failure code.");
            }
            this.code = code;
        }
    }

    static final class Outcome {
        final boolean connected;
        final boolean cleanupComplete;
        final int remainingJournalEntries;
        final String stage;
        final String failurePhase;
        final String failureCode;

        Outcome(boolean connected, boolean cleanupComplete,
                int remainingJournalEntries, String stage) {
            this(connected, cleanupComplete, remainingJournalEntries, stage,
                    "NONE", "NONE");
        }

        Outcome(boolean connected, boolean cleanupComplete,
                int remainingJournalEntries, String stage,
                String failurePhase, String failureCode) {
            this.connected = connected;
            this.cleanupComplete = cleanupComplete;
            this.remainingJournalEntries = remainingJournalEntries;
            this.stage = stage;
            this.failurePhase = failurePhase;
            this.failureCode = failureCode;
        }

        String summary() {
            // Manual Safe Stop is NOT a failed Start. Preserve the distinct
            // recovery statuses so users do not mistake a clean shutdown for
            // a refusal or discard pending ownership after a paused stop.
            String outcome;
            if ("CLEAN_STOPPED".equals(stage) && cleanupComplete
                    && remainingJournalEntries == 0) {
                outcome = "EXACT-OWNED SAFE STOP COMPLETE";
            } else if ("RECOVERY_PAUSED".equals(stage)) {
                outcome = "SAFE STOP PAUSED; OWNERSHIP AUDIT REQUIRED";
            } else if (connected) {
                outcome = "BOOTSTRAP STRUCTURALLY APPLIED";
            } else if (cleanupComplete) {
                outcome = "START REFUSED/FAILED; EXACT ROLLBACK COMPLETE";
            } else {
                outcome = "START REFUSED/FAILED; MANUAL OWNERSHIP AUDIT REQUIRED";
            }
            return outcome
                    + " (stage=" + stage
                    + "; phase=" + failurePhase
                    + "; reason=" + failureCode
                    + "; persistent entries=" + remainingJournalEntries + "). "
                    + "This result alone does not prove VPN reachability, "
                    + "Android DNS, private packet paths or kill-switch safety.";
        }
    }

    private RootIsolatedWireGuardTransaction() { }

    /**
     * This method is for an injected, verified adapter only. Neither this
     * class nor the existing App Routing planner supplies a live adapter.
     */
    static Outcome start(RootIsolatedWireGuardBootstrapPlan.Plan plan,
            Kernel kernel, Journal journal) throws Exception {
        if (plan == null || kernel == null || journal == null
                || plan.steps.isEmpty()) {
            throw new IllegalArgumentException("Missing isolated startup inputs.");
        }
        if (!journal.empty()) {
            return new Outcome(false, false, journal.snapshot().size(),
                    "EXISTING_RECOVERY_JOURNAL");
        }
        // Validate the ENTIRE plan before root preflight. A malformed late
        // step must never cause an earlier legitimate interface to start.
        for (RootIsolatedWireGuardBootstrapPlan.Step step : plan.steps) {
            if (!safeStep(step)) {
                throw new IllegalArgumentException("Invalid isolated bootstrap operation.");
            }
        }
        // This gate must run before ANY journal entry or kernel mutation.
        // A candidate has no authority to relax this requirement.
        kernel.requireActivationPreflight();
        String stage = "PREFLIGHT";
        String phase = "PRECHECK";
        try {
            for (RootIsolatedWireGuardBootstrapPlan.Step step : plan.steps) {
                stage = step.kind;
                if (step == null || !safeStep(step)) {
                    throw new IllegalArgumentException("Unsafe startup plan step.");
                }
                phase = "READ_BEFORE";
                if (kernel.inspect(step) != Presence.ABSENT) {
                    throw new IllegalStateException("Kernel object already exists.");
                }
                // A crash at ANY point after this durable write is recoverable.
                phase = "JOURNAL_INTENT";
                journal.beforeMutation(step);
                phase = "KERNEL_APPLY";
                kernel.apply(step);
                phase = "READ_AFTER";
                if (kernel.inspect(step) != Presence.EXACT_OWNED) {
                    throw new IllegalStateException("Applied kernel object unverified.");
                }
                phase = "JOURNAL_COMMIT";
                journal.committed(step);
            }
            // Entries intentionally remain: Safe Stop will consume them.
            return new Outcome(true, false, journal.snapshot().size(), "VERIFIED_STEPS");
        } catch (Exception failure) {
            // Deliberately expose only a fixed safe enum value or Java
            // exception class; never error text or root command output.
            String reason = failure instanceof SafeFailure
                    ? ((SafeFailure) failure).code
                    : failure.getClass().getSimpleName();
            boolean clean = recoverOwned(kernel, journal);
            return new Outcome(false, clean, journal.snapshot().size(), stage,
                    phase, reason);
        }
    }

    /** The same exact cleanup path is used after interruption / Safe Stop. */
    static Outcome recover(Kernel kernel, Journal journal) throws Exception {
        if (kernel == null || journal == null) {
            throw new IllegalArgumentException("Recovery adapter missing.");
        }
        boolean clean = recoverOwned(kernel, journal);
        return new Outcome(false, clean, journal.snapshot().size(),
                clean ? "CLEAN_STOPPED" : "RECOVERY_PAUSED");
    }

    private static boolean recoverOwned(Kernel kernel, Journal journal)
            throws Exception {
        List<RootIsolatedWireGuardBootstrapPlan.Step> pending =
                new ArrayList<>(journal.snapshot());
        Collections.reverse(pending);
        for (RootIsolatedWireGuardBootstrapPlan.Step step : pending) {
            if (!safeStep(step)) return false;
            try {
                Presence current = kernel.inspect(step);
                if (current == Presence.FOREIGN_OR_CHANGED || current == null) {
                    return false; // NEVER touch an unknown kernel object.
                }
                if (current == Presence.EXACT_OWNED) {
                    kernel.undo(step);
                    if (kernel.inspect(step) != Presence.ABSENT) return false;
                }
                journal.clearExact(step);
            } catch (Exception uncertain) {
                // Keep the remaining journal for an independent audit/retry.
                return false;
            }
        }
        return journal.empty();
    }

    static boolean safeStep(RootIsolatedWireGuardBootstrapPlan.Step s) {
        if (s == null || s.device == null
                || !s.device.matches("wnm[0-9a-f]{12}")) return false;
        if ("PEER_CONFIG".equals(s.kind)) {
            return s.install != null && s.inverse != null
                    && s.install.isEmpty() && s.inverse.isEmpty();
        }
        if (s.install == null || s.inverse == null
                || s.install.isEmpty() || s.inverse.isEmpty()) return false;
        String dev = s.device;
        if ("LINK_CREATE".equals(s.kind)) {
            return s.install.equals("ip link add dev " + dev + " type wireguard")
                    && s.inverse.equals("ip link del dev " + dev);
        }
        if ("LINK_UP".equals(s.kind)) {
            return s.install.equals("ip link set dev " + dev + " up")
                    && s.inverse.equals("ip link set dev " + dev + " down");
        }
        if ("HOST_ADDRESS".equals(s.kind)) {
            return (s.install.matches("ip -4 addr add [0-9.]+/32 dev " + dev)
                    || s.install.matches("ip -6 addr add [0-9a-fA-F:]+/128 dev " + dev))
                    && s.inverse.equals(s.install.replace(" addr add ", " addr del "));
        }
        if ("PRIVATE_ROUTE".equals(s.kind)) {
            return (s.install.matches(
                        "ip -4 route add table 5100[0-7] [0-9.]+/[0-9]{1,2} dev " + dev)
                    || s.install.matches(
                        "ip -6 route add table 5100[0-7] [0-9a-fA-F:]+/[0-9]{1,3} dev " + dev))
                    && s.inverse.equals(s.install.replace(" route add ", " route del "));
        }
        return false;
    }
}
