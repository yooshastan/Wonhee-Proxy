package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public final class RootUidRouteAuditTest {
    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) {
        check(RootUidRouteAudit.supportedUid(1000), "system UID must be eligible");
        check(RootUidRouteAudit.supportedUid(10170), "typical app UID supported");
        check(!RootUidRouteAudit.supportedUid(-1), "unknown UID cannot be guessed");
        check(!RootUidRouteAudit.supportedUid(100000), "multiuser UID refused for this route range");
        check(RootUidRouteAudit.header("Messages", -1).contains("UNAVAILABLE"),
                "Missing package must not inherit past PCAP UID");
        check(RootUidRouteAudit.header("Android", 1000).contains("UID 1000"),
                "System UID identifies the operating system, not a guessed package");

        List<Long> marks = RootUidRouteAudit.sampledUnprotectedMarks(
                Arrays.asList(null, -1L, 0L, 0x20000L, 0x10002L, 0x10002L,
                        0x2ffffL, 0x10003L, 0x400000000L));
        check(marks.equals(Arrays.asList(0L, 0x10002L)),
                "Use bounded real unprotected fwmarks only; never sample protected bits");
        check(RootUidRouteAudit.sampledUnprotectedMarks(null).equals(
                        Collections.singletonList(0L)),
                "No live mark inventory means only mark zero is sampled");
        check(RootUidRouteAudit.sampledUnprotectedMarks(
                Arrays.asList(0x20000L, 0x20001L)).size() == 1,
                "Protected-only marks should not masquerade as app normal marks");

        check(RootUidRouteAudit.matchesExpected("wnmabcdef012345", "wnmabcdef012345"),
                "Kernel-selected tunnel identity comparison");
        check(!RootUidRouteAudit.matchesExpected("wnmabcdef012345", "wlan0"),
                "Physical egress prediction differs from selected VPN");
        check(!RootUidRouteAudit.matchesExpected("", ""), "Two missing routes never match");

        String expected = RootUidRouteAudit.routePrediction(
                "wnmabcdef012345", "wnmabcdef012345", false);
        String diverted = RootUidRouteAudit.routePrediction(
                "wnmabcdef012345", "wlan0", false);
        String protectedRoute = RootUidRouteAudit.routePrediction(
                "wnmabcdef012345", "wlan0", true);
        check(expected.contains("EXPECTED"), "Matching normal route prediction");
        check(diverted.contains("UNEXPECTED ROUTE"), "Unexpected physical route flagged");
        check(protectedRoute.contains("no live socket proof"),
                "Protected-mark bypass is NOT claimed to be a live app connection");
        check(!protectedRoute.contains("UNEXPECTED ROUTE"),
                "Protected mark intentionally follows different policy");
        check(RootUidRouteAudit.routePrediction(
                "wnmabcdef012345", "", false).contains("UNVERIFIED"),
                "Missing route cannot be called safe");
        check(RootUidRouteAudit.routePrediction(
                "wnmabcdef012345", "wlan0;rm -rf /", true).equals("UNVERIFIED"),
                "Unexpected command-like interface names cannot render into output");

        System.out.println("RootUidRouteAuditTest passed");
    }
}
