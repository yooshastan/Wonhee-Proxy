package com.yooshastan.wonheeproxy;

public final class RootGuardSafetyGateTest {
    private static void check(boolean value, String message) {
        if (!value) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        check(RootGuardSafetyGate.activationPaused(),
                "Batch F must remain quarantined pending connectivity incident analysis");
        check(RootGuardSafetyGate.message().contains("No firewall rules or test packets changed"),
                "quarantine refusal must explain no side effects");
        try {
            RootGuardSafetyGate.requireActivationAllowed();
            throw new AssertionError("activation must not be possible in diagnostic build");
        } catch (IllegalStateException expected) {
            check(expected.getMessage().contains("ACTIVATION PAUSED"),
                    "explicit and actionable refusal message");
        }
        System.out.println("RootGuardSafetyGateTest PASS");
    }
}
