package com.yooshastan.wonheeproxy;

/**
 * Privacy-safe formatting for a user-initiated, read-only connectivity incident.
 * These are two observations of kernel WireGuard counters, not a reachability
 * test, speed test, flow attribution, or proof that the Internet works.
 */
final class RootInternetIncidentEvidence {
    private RootInternetIncidentEvidence() { }

    static String trafficDelta(long beforeRx, long beforeTx, long afterRx, long afterTx,
            long elapsedMillis, boolean identityVerifiedAgain) {
        if (!identityVerifiedAgain || elapsedMillis <= 0 || elapsedMillis > 30_000
                || beforeRx < 0 || beforeTx < 0 || afterRx < beforeRx
                || afterTx < beforeTx) {
            return "UNAVAILABLE (identity, clock or counters changed)";
        }
        long rx = afterRx - beforeRx;
        long tx = afterTx - beforeTx;
        if (rx == 0 && tx == 0) {
            return "UNCHANGED over " + elapsedMillis
                    + " ms (idle traffic is normal; not a failure verdict)";
        }
        return "RX +" + rx + " B; TX +" + tx + " B in "
                + elapsedMillis + " ms (not proof of Internet reachability)";
    }

    static String handshake(long timestamp, long now) {
        if (timestamp < 0) return "UNAVAILABLE";
        if (timestamp == 0) return "NEVER OBSERVED (may be idle)";
        if (now < timestamp) return "CLOCK SKEW — UNAVAILABLE";
        long age = now - timestamp;
        return age <= 180 ? age + "s ago"
                : age + "s ago (possibly idle/stale; not a verdict)";
    }

    static String ownership(boolean ledgerPresent, int expected, int saved,
            int live, boolean exactLive, boolean selectedPlanMatches) {
        return ledgerPresent && expected == saved && saved == live
                && exactLive && selectedPlanMatches
                ? "EXACT MATCH (" + live + " rules)"
                : "CHECK REQUIRED (saved " + saved + ", live " + live
                        + ", selected plan " + expected
                        + "; no policies changed)";
    }
}
