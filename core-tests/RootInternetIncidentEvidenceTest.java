package com.yooshastan.wonheeproxy;

public final class RootInternetIncidentEvidenceTest {
    private static void check(boolean condition, String explanation) {
        if (!condition) throw new AssertionError(explanation);
    }

    public static void main(String[] args) {
        String moved = RootInternetIncidentEvidence.trafficDelta(
                100, 200, 125, 230, 1500, true);
        check(moved.contains("RX +25 B") && moved.contains("TX +30 B"),
                "Only validated counter movement may be displayed");
        check(moved.contains("not proof of Internet reachability"),
                "Counter movement must not be presented as proof of connectivity");

        String idle = RootInternetIncidentEvidence.trafficDelta(
                100, 200, 100, 200, 1500, true);
        check(idle.contains("UNCHANGED") && idle.contains("idle traffic is normal"),
                "Idle traffic cannot be called a VPN failure");

        for (String invalid : new String[]{
                RootInternetIncidentEvidence.trafficDelta(100, 200, 200, 300, 0, true),
                RootInternetIncidentEvidence.trafficDelta(100, 200, 200, 300, 31000, true),
                RootInternetIncidentEvidence.trafficDelta(100, 200, 99, 300, 1500, true),
                RootInternetIncidentEvidence.trafficDelta(100, 200, 200, 199, 1500, true),
                RootInternetIncidentEvidence.trafficDelta(100, 200, 200, 300, 1500, false),
                RootInternetIncidentEvidence.trafficDelta(-1, 200, 200, 300, 1500, true)
        }) {
            check(invalid.startsWith("UNAVAILABLE"),
                    "Counter reset, clock mismatch or lost identity must fail closed");
        }

        check(RootInternetIncidentEvidence.handshake(-1, 1500).equals("UNAVAILABLE"),
                "Unknown handshakes remain unknown");
        check(RootInternetIncidentEvidence.handshake(0, 1500).contains("NEVER OBSERVED"),
                "Zero handshake is not a successful connection");
        check(RootInternetIncidentEvidence.handshake(1501, 1500).contains("CLOCK SKEW"),
                "Future handshake clock skew must not look healthy");
        check(RootInternetIncidentEvidence.handshake(1300, 1500).contains("possibly idle"),
                "Stale handshakes are advisory and do not prove a broken VPN");
        check(RootInternetIncidentEvidence.handshake(1490, 1500).equals("10s ago"),
                "Recent handshake age should be clear");

        check(RootInternetIncidentEvidence.ownership(true, 3, 3, 3, true, true)
                        .equals("EXACT MATCH (3 rules)"),
                "A match requires every independent ownership check");
        check(RootInternetIncidentEvidence.ownership(false, 3, 3, 3, true, true)
                        .contains("CHECK REQUIRED"),
                "Missing ledger never silently implies ownership");
        check(RootInternetIncidentEvidence.ownership(true, 3, 3, 4, true, true)
                        .contains("CHECK REQUIRED"),
                "Foreign reserved rules must fail ownership");
        check(RootInternetIncidentEvidence.ownership(true, 3, 3, 3, false, true)
                        .contains("CHECK REQUIRED"),
                "Inexact kernel selectors must fail ownership");
        check(RootInternetIncidentEvidence.ownership(true, 3, 3, 3, true, false)
                        .contains("CHECK REQUIRED"),
                "Changed selected profile plan must fail ownership");

        String combined = moved + idle + RootInternetIncidentEvidence.handshake(1490, 1500);
        check(!combined.contains("private") && !combined.contains("peer")
                        && !combined.contains("endpoint"),
                "Pure formatter must not accidentally emit peer endpoint data");
        System.out.println("RootInternetIncidentEvidenceTest passed");
    }
}
