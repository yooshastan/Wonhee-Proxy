package com.yooshastan.wonheeproxy;

public final class RootDnsCountersTest {
    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    private static void rejects(String raw, int pid) {
        try {
            RootDnsCounters.parse(raw, pid);
            throw new AssertionError("accepted invalid counters");
        } catch (IllegalStateException expected) { /* fail closed */ }
    }

    public static void main(String[] args) {
        String snapshot = "WN_DNS_STATS_V1 pid=123 received=50 blocked=15 forwarded=32 failed=3";
        RootDnsCounters valid = RootDnsCounters.parse(snapshot, 123);
        check(valid.received == 50 && valid.blocked == 15
                && valid.forwarded == 32 && valid.failed == 3, "correct counts");
        check(!valid.summary().contains("example.com"), "no domain names in summary");
        rejects(snapshot, 124);
        rejects("WN_DNS_STATS_V1 pid=123 received=50 blocked=60 forwarded=0 failed=0", 123);
        rejects("WN_DNS_STATS_V1 pid=123 received=50 blocked=40 forwarded=40 failed=0", 123);
        rejects("WN_DNS_STATS_V1 pid=123 received=-1 blocked=0 forwarded=0 failed=0", 123);
        rejects("WN_DNS_STATS_V1 pid=123 received=1 blocked=0 forwarded=0 failed=0 foo=bar", 123);
        rejects("WN_DNS_STATS_V2 pid=123 received=1 blocked=0 forwarded=0 failed=0", 123);
        System.out.println("RootDnsCountersTest PASS");
    }
}
