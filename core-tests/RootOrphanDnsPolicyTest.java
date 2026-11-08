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
                false, true, 0, 0, false), "ordinary clean firewall");
        expect(ready, RootOrphanDnsPolicy.classify(
                false, true, 8, 8, false), "eight exact orphan rules");
        expect(owned, RootOrphanDnsPolicy.classify(
                true, true, 8, 8, false), "normal owner ledger uses normal disable");
        // Whether tunnels, routing or native DNS relay are running is
        // deliberately NOT a precondition for DNS-only rule removal. This
        // avoids deadlocking the device if DNS ownership disappeared while
        // either WireGuard interface was still UP.
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, false, 8, 8, false),
                "live Batch F guard quarantines orphan recovery");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, true, 7, 7, false),
                "partial orphan rules with no pending marker must refuse");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, true, 8, 9, false),
                "extra WN_ OUTPUT rule must refuse");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, true, 6, 5, false),
                "invalid counts must refuse");
        expect(pending, RootOrphanDnsPolicy.classify(
                false, true, 5, 5, true),
                "durable marker permits exact leftover subset after crash");
        expect(finished, RootOrphanDnsPolicy.classify(
                false, true, 0, 0, true),
                "all rules gone but marker still recorded");
        expect(blocked, RootOrphanDnsPolicy.classify(
                false, false, 0, 0, true),
                "guard remains quarantine even with pending cleanup marker");
        System.out.println("RootOrphanDnsPolicyTest PASS");
    }
}
