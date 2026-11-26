package com.yooshastan.wonheeproxy;

/** Counting-only Navidrome rule must never be confused with final REJECT. */
public final class RootBraveHomeTargetCounterEvidenceTest {
    private static int n;
    private static void check(boolean ok) {
        if (!ok) throw new AssertionError("Brave target count " + ++n);
        n++;
    }

    public static void main(String[] args) {
        String listing = "Chain WN_BRAVE_HOME4 (1 references)\n"
                + "    pkts      bytes target prot opt in out source destination\n"
                + "       7       420        tcp  --  *  *  0.0.0.0/0"
                + "  10.0.0.169 tcp dpt:4533 /* WN_BRAVE_TARGET_COUNT_V1 */\n"
                + "       0         0 RETURN tcp  --  *  wnm4ea140588150"
                + "  0.0.0.0/0 10.0.0.169 tcp dpt:4533\n"
                + "      99      5940 REJECT all  --  *  *  0.0.0.0/0"
                + "  0.0.0.0/0 reject-with icmp-port-unreachable\n";
        RootMokaIpv6CounterParser.Counts observed =
                RootBraveHomeTargetCounterEvidence.firstRule(listing);
        check(observed.packets == 7 && observed.bytes == 420);
        try {
            RootBraveHomeTargetCounterEvidence.firstRule(
                    "0 0 tcp blah\n0 0 RETURN blah\n");
            throw new AssertionError("Accepted missing REJECT");
        } catch (IllegalArgumentException expected) { check(true); }
        try {
            RootBraveHomeTargetCounterEvidence.firstRule(
                    listing + "     1       2 ACCEPT all extra\n");
            throw new AssertionError("Accepted extra chain rule");
        } catch (IllegalArgumentException expected) { check(true); }
        try {
            RootBraveHomeTargetCounterEvidence.firstRule(
                    listing.replace("       7       420", "18446744073709551615 420"));
            throw new AssertionError("Accepted overflowing counter");
        } catch (IllegalArgumentException expected) { check(true); }
        System.out.println("BRAVE_TARGET_COUNTER " + n + " PASS");
    }
}
