package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class RootGuardProbeEvidenceTest {
    private static void check(boolean condition, String reason) {
        if (!condition) throw new AssertionError(reason);
    }

    public static void main(String[] args) {
        check(RootGuardProbeEvidence.terminalRejectPackets(Arrays.asList(
                "Chain WN_MULTI_GUARD4 (1 references)",
                " pkts bytes target prot opt in out source destination",
                "   12  1000 RETURN all -- * lo 0.0.0.0/0 0.0.0.0/0",
                "   41  3200 REJECT all -- * * 0.0.0.0/0 0.0.0.0/0")) == 41,
                "read final exact packet counter");
        check(RootGuardProbeEvidence.terminalRejectPackets(Arrays.asList(
                "  5 100 REJECT all -- * * ::/0 ::/0")) == 5, "IPv6 reject counter");
        check(RootGuardProbeEvidence.terminalRejectPackets(Arrays.asList(
                "  5 100 REJECT all -- * * ::/0 ::/0",
                "  9 900 RETURN all -- * lo ::/0 ::/0")) == -1,
                "refuse nonterminal reject");
        check(RootGuardProbeEvidence.terminalRejectPackets(Collections.emptyList()) == -1,
                "refuse missing output");
        check(RootGuardProbeEvidence.outcome(0, 1, 2).startsWith("ALERT"),
                "positive ping always suspected leak");
        check(RootGuardProbeEvidence.outcome(1, 1, 2).startsWith("GUARD"),
                "negative ping with reject delta is limited evidence");
        check(RootGuardProbeEvidence.outcome(1, 1, 1).startsWith("INCONCLUSIVE"),
                "no delta is not an enforcement pass");
        System.out.println("RootGuardProbeEvidenceTest PASS");
    }
}
