package com.yooshastan.wonheeproxy;

import java.util.Arrays;

public final class RootPacketEvidenceTest {
    private static void check(boolean value) { if (!value) throw new AssertionError(); }

    public static void main(String[] ignored) {
        int count = RootPacketEvidence.packetLines(Arrays.asList(
                "1762390012.332211 IP 10.0.0.3.1234 > 10.0.0.169.4533: tcp 0",
                "1762390012.334455 IP6 fd00::1.1234 > fd00::2.443: tcp 0",
                "listening on wnmhost, link-type RAW",
                "0 packets captured"));
        check(count == 2);
        check(RootPacketEvidence.packetLines(null) == 0);
        check(RootPacketEvidence.interpretation(2, true).contains("OBSERVED"));
        check(RootPacketEvidence.interpretation(0, true).contains("not proof"));
        check(RootPacketEvidence.interpretation(4, false).contains("INCOMPLETE"));
        System.out.println("RootPacketEvidenceTest passed");
    }
}
