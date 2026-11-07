package com.yooshastan.wonheeproxy;

/**
 * Batch F activation quarantine after the observed Pixel 8a loss of connectivity.
 *
 * This is intentionally a build-time safety gate, not a user preference:
 * neither the UI nor an internal callback can bypass it. Audit and exact owned
 * guard removal remain available. Reactivation requires a separately reviewed
 * source change and additional regression + independent recovery validation.
 */
final class RootGuardSafetyGate {
    private RootGuardSafetyGate() { }

    static boolean activationPaused() { return true; }

    static String message() {
        return "BATCH F ACTIVATION PAUSED after the connectivity interruption "
                + "(Wonhee issue #41). No firewall rules or test packets changed. "
                + "Use read-only control-plane impact review; keep the working "
                + "Batch B.1 split routing intact. An independently validated "
                + "recovery and runtime continuity design is required first.";
    }

    static void requireActivationAllowed() {
        if (activationPaused()) throw new IllegalStateException(message());
    }
}
