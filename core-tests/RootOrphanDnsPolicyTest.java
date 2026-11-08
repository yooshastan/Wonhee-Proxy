package com.yooshastan.wonheeproxy;

/** Regression tests for the Pixel 8a missing-ledger + eight-rule DNS trap. */
public final class RootOrphanDnsPolicyTest {
    private static void expect(RootOrphanDnsPolicy.State expected,
            RootOrphanDnsPolicy.State actual, String reason) {
        if (expected != actual) {
            throw new AssertionError(reason + ": " + actual + " instead of " + expected);
        }
    }

    public static void main(String[] args) {
        RootOrphanDnsPolicy.State clean = RootOrphanDnsPolicy.State.CLEAN;
        RootOrphanDnsPolicy.State ready =
                RootOrphanDnsPolicy.State.READY_FOR_EXPLICIT_REPAIR;
        RootOrphanDnsPolicy.State pending =
                RootOrphanDnsPolicy.State.PENDING_EXACT_REPAIR;
        RootOrphanDnsPolicy.State finished =
                RootOrphanDnsPolicy.State.PENDING_CLEARED;
        RootOrphanDnsPolicy.State owned =
                RootOrphanDnsPolicy.State.SAVED_OWNERSHIP;
        RootOrphanDnsPolicy.State blocked =
                RootOrphanDnsPolicy.State.BLOCKED;

        expect(clean, RootOrphanDnsPolicy.classify(
                false, true, true, true, true, 0, 0, false), "ordinary clean stop");
        expect(ready, RootOrphanDnsPolicy.classify(
                false, true, true, true, true, 8, 8, false), "eight exact orphan rules");
        expect(owned, RootOrphanDnsPolicy.classify(
                true, true, false, false, false, 8, 8, false),
                "normal owner ledger uses normal disable");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, true, false, true, true, 8, 8, false),
                "still running tunnel blocks orphan recovery");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, true, true, false, true, 8, 8, false),
                "still running relay blocks orphan recovery");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, false, true, true, true, 8, 8, false),
                "owned/unknown Batch F guard blocks orphan recovery");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, true, true, true, false, 8, 8, false),
                "live reserved routing rule blocks orphan recovery");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, true, true, true, true, 7, 7, false),
                "partial orphan rules with no pending marker must refuse");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, true, true, true, true, 8, 9, false),
                "extra WN_ OUTPUT tag must refuse");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, true, true, true, true, 6, 5, false),
                "invalid counts must refuse");
        expect(pending, RootOrphanDnsPolicy.classify(
                false, true, true, true, true, 5, 5, true),
                "durable marker permits exact leftover subset after crash");
        expect(finished, RootOrphanDnsPolicy.classify(
                false, true, true, true, true, 0, 0, true),
                "all rules gone but marker still recorded");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, true, false, true, true, 0, 0, true),
                "pending marker does not bypass active tunnel safety");
        System.out.println("RootOrphanDnsPolicyTest PASS");
    }
}
