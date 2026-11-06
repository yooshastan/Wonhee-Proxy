package com.yooshastan.wonheeproxy;

/**
 * Pure, bounded retry policy for Product Batch C. This class does not start
 * tunnels or alter routes; the rooted controller performs all identity checks.
 */
final class RootMultiRecoveryPolicy {
    static final int MAX_FAILURES = 6;
    private static final long[] DELAYS_MILLIS = {
            5_000L, 15_000L, 30_000L, 60_000L, 120_000L, 300_000L
    };

    private RootMultiRecoveryPolicy() { }

    static boolean permitted(boolean enabled, boolean desired, boolean manuallyStopped,
            int failures, long nextAttemptAtMillis, long nowMillis) {
        return enabled && desired && !manuallyStopped && failures < MAX_FAILURES
                && nowMillis >= nextAttemptAtMillis;
    }

    static long nextAttemptAt(long nowMillis, int failuresAfterAttempt) {
        if (failuresAfterAttempt <= 0) return 0L;
        int index = Math.min(failuresAfterAttempt - 1, DELAYS_MILLIS.length - 1);
        long delay = DELAYS_MILLIS[index];
        return nowMillis > Long.MAX_VALUE - delay ? Long.MAX_VALUE : nowMillis + delay;
    }
}
