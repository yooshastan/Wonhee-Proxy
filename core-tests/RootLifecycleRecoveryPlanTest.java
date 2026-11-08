package com.yooshastan.wonheeproxy;

/** Batch H.2a: no automatic mutation from a merely plausible ownership state. */
public final class RootLifecycleRecoveryPlanTest {
    private static void is(RootLifecycleRecoveryPlan.State expected,
            RootLifecycleRecoveryPlan actual, String reason) {
        if (actual.state != expected) throw new AssertionError(reason + ": " + actual.state);
    }

    public static void main(String[] args) {
        RootLifecycleRecoveryPlan.State clean =
                RootLifecycleRecoveryPlan.State.CLEAN_STOPPED;
        RootLifecycleRecoveryPlan.State repair =
                RootLifecycleRecoveryPlan.State.REPAIRABLE_STOPPED;
        RootLifecycleRecoveryPlan.State active =
                RootLifecycleRecoveryPlan.State.RUNNING_OR_PARTIAL;
        RootLifecycleRecoveryPlan.State blocked =
                RootLifecycleRecoveryPlan.State.BLOCKED_UNKNOWN;

        is(clean, RootLifecycleRecoveryPlan.assess(true, true, false, false,
                false, false, 0, 0, 0, 0), "clean stopped state");
        is(repair, RootLifecycleRecoveryPlan.assess(true, true, false, false,
                true, true, 0, 0, 0, 0), "stale DNS and routing ledger after reboot");
        is(repair, RootLifecycleRecoveryPlan.assess(true, true, false, false,
                true, true, 2, 1, 2, 1), "partial interrupted exact-owned cleanup");
        is(active, RootLifecycleRecoveryPlan.assess(true, true, true, false,
                true, true, 2, 3, 2, 3), "running tunnel must use safe stop");
        is(blocked, RootLifecycleRecoveryPlan.assess(true, true, false, true,
                true, false, 0, 0, 0, 0), "live untracked relay is not stale");
        is(blocked, RootLifecycleRecoveryPlan.assess(false, true, false, false,
                true, false, 0, 0, 0, 0), "Batch F kill switch collision");
        is(blocked, RootLifecycleRecoveryPlan.assess(true, false, false, false,
                false, true, 0, 1, 0, 1), "unknown policy format");
        is(blocked, RootLifecycleRecoveryPlan.assess(true, true, false, false,
                false, false, 0, 0, 1, 0), "foreign DNS firewall tags");
        is(blocked, RootLifecycleRecoveryPlan.assess(true, true, false, false,
                false, false, 0, 0, 0, 1), "untracked route");
        is(blocked, RootLifecycleRecoveryPlan.assess(true, true, false, false,
                true, true, 0, 0, 1, 1), "unowned counts cannot reconcile");
        is(blocked, RootLifecycleRecoveryPlan.assess(true, true, false, false,
                true, true, 2, 0, 1, 0), "invalid negative ownership count");
        System.out.println("RootLifecycleRecoveryPlanTest PASS");
    }
}
