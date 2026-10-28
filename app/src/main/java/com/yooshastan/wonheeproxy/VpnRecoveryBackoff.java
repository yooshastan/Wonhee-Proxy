package com.yooshastan.wonheeproxy;

/** Bounded backoff for actual VPN interface-down restoration attempts only. */
final class VpnRecoveryBackoff {
    private static final long[] DELAYS_MS = {
            5_000L, 15_000L, 30_000L, 60_000L, 120_000L, 300_000L
    };
    private int failures;
    private long nextAttemptAtMs;

    boolean isDue(long nowMs) {
        return nowMs >= nextAttemptAtMs;
    }

    void failed(long nowMs) {
        failures++;
        long delay = DELAYS_MS[Math.min(failures - 1, DELAYS_MS.length - 1)];
        nextAttemptAtMs = nowMs > Long.MAX_VALUE - delay
                ? Long.MAX_VALUE : nowMs + delay;
    }

    void reset() {
        failures = 0;
        nextAttemptAtMs = 0;
    }

    int failures() {
        return failures;
    }

    long secondsUntilNext(long nowMs) {
        return Math.max(0L, (nextAttemptAtMs - nowMs + 999L) / 1000L);
    }
}
