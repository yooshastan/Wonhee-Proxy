package com.yooshastan.wonheeproxy;

/** Bounded in-process repair attempts; not a VPN, background service or kill switch. */
public final class VpnReconnectPolicy {
    public static final int MAX_ATTEMPTS = 3;

    private VpnReconnectPolicy() { }

    public static boolean canAttempt(boolean optedIn, boolean userRequestedUp,
            boolean alwaysOnManaged, boolean backendBusy, boolean interfaceUp,
            int attempts, long nowElapsedMs, long nextAllowedMs) {
        return optedIn && userRequestedUp && !alwaysOnManaged && !backendBusy
                && !interfaceUp && attempts < MAX_ATTEMPTS
                && nowElapsedMs >= nextAllowedMs;
    }

    public static long retryDelayMs(int attemptsMade) {
        if (attemptsMade <= 0) return 0;
        return 10_000L << Math.min(attemptsMade - 1, 2);
    }
}
