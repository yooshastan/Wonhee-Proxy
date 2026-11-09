package com.yooshastan.wonheeproxy;

public final class RootDnsContinuityBaselineTest {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    private static RootDnsContinuityBaseline.Reading read(long wall, long elapsed,
            int pid, int verified, int present, long received, long blocked,
            long forwarded, long failed, boolean relay, boolean filtering) {
        return new RootDnsContinuityBaseline.Reading(wall, elapsed,
                true, relay, filtering, verified, present, pid,
                received, blocked, forwarded, failed);
    }

    private static void invalid(String raw) {
        try {
            RootDnsContinuityBaseline.decode(raw);
            throw new AssertionError("Invalid baseline accepted.");
        } catch (IllegalArgumentException expected) { /* fail closed */ }
    }

    public static void main(String[] args) {
        long wall = 1790000000000L, uptime = 1200000L;
        RootDnsContinuityBaseline.Reading base =
                read(wall, uptime, 300, 2, 2, 50, 20, 25, 5, true, true);
        String encoded = RootDnsContinuityBaseline.encode(base);
        check(encoded.startsWith("WN_DNS_BASELINE_V1|"), "Versioned record");
        check(!encoded.contains("10.0.0.169") && !encoded.contains("doubleclick"),
                "No endpoints/domains in baseline");
        RootDnsContinuityBaseline.Reading decoded =
                RootDnsContinuityBaseline.decode(encoded);
        check(decoded.relayPid == 300 && decoded.blocked == 20, "Round-trip metrics");
        RootDnsContinuityBaseline.Reading good = read(wall + 3600000L,
                uptime + 3600000L, 300, 2, 2, 150, 70, 73, 7, true, true);
        String summary = RootDnsContinuityBaseline.compare(decoded, good);
        check(summary.contains("60 min") && summary.contains("blocked +50")
                && summary.contains("received +100")
                && summary.contains("cannot prove"), "Aggregate diff and limits");
        check(RootDnsContinuityBaseline.compare(null, good).contains("No saved baseline"),
                "Missing baseline not assumed to be zero");
        check(RootDnsContinuityBaseline.compare(decoded,
                read(wall + 1000, uptime + 1000, 300, 2, 2, 55, 22, 28, 5,
                        false, true)).contains("NOT VERIFIED"), "Missing relay");
        check(RootDnsContinuityBaseline.compare(decoded,
                read(wall + 1000, uptime + 1000, 300, 2, 2, 55, 22, 28, 5,
                        true, false)).contains("TRACKER FILTER"), "Disabled filter");
        check(RootDnsContinuityBaseline.compare(decoded,
                read(wall + 1000, uptime + 1000, 301, 2, 2, 55, 22, 28, 5,
                        true, true)).contains("PID CHANGED"), "Relay restart");
        check(RootDnsContinuityBaseline.compare(decoded,
                read(wall + 1000, uptime + 1000, 300, 1, 2, 55, 22, 28, 5,
                        true, true)).contains("TUNNEL"), "Tunnel degraded");
        check(RootDnsContinuityBaseline.compare(decoded,
                read(wall + 1000, uptime + 1000, 300, 2, 2, 40, 10, 25, 5,
                        true, true)).contains("COUNTER RESET"), "Counter reset");
        check(RootDnsContinuityBaseline.compare(decoded,
                read(wall + 3600000, uptime + 5000, 300, 2, 2, 55, 22, 28, 5,
                        true, true)).contains("CLOCK"), "Reboot/clock mismatch");
        check(RootDnsContinuityBaseline.compare(decoded,
                read(wall + 1000, 1000, 300, 2, 2, 55, 22, 28, 5,
                        true, true)).contains("REBOOTED"), "Elapsed reset");
        invalid("");
        invalid("WN_DNS_BASELINE_V1|1|2|3");
        invalid("WN_DNS_BASELINE_V1|1|2|3|0|1|0|1|0");
        invalid("WN_DNS_BASELINE_V1|1|2|3|2|1|2|0|0");
        invalid("WN_DNS_BASELINE_V1|1|2|3|2|1|0|0|0|notnumber");
        try {
            RootDnsContinuityBaseline.encode(read(wall, uptime,
                    300, 2, 2, 10, 20, 0, 0, true, true));
            throw new AssertionError("Invalid aggregate counters accepted.");
        } catch (IllegalArgumentException expected) { /* expected */ }
        System.out.println("RootDnsContinuityBaselineTest PASS");
    }
}
