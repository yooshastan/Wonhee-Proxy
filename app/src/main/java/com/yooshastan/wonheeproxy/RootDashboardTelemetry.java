package com.yooshastan.wonheeproxy;

/**
 * Read-only, aggregate root WireGuard rate sampler shared by the dashboard and
 * optional notification. Never shows partial or stale transfer rates as live.
 * Counts reflect verified tunnel byte counters, NOT all device traffic.
 */
final class RootDashboardTelemetry {
    private static final long MAX_SAMPLE_GAP_MS = 60_000L;
    private TunnelTrafficRates.Sample previous;
    private int previousVerified = -1;
    private int previousPresent = -1;

    TunnelTrafficRates.Result observe(long elapsedMs, boolean countersAvailable,
            int verified, int present, long received, long sent) {
        if (!countersAvailable || verified <= 0 || present != verified
                || received < 0 || sent < 0 || elapsedMs < 0) {
            reset();
            return null;
        }
        TunnelTrafficRates.Sample current =
                new TunnelTrafficRates.Sample(elapsedMs, received, sent);
        boolean compatible = previous != null && verified == previousVerified
                && present == previousPresent
                && elapsedMs > previous.elapsedMillis
                && elapsedMs - previous.elapsedMillis <= MAX_SAMPLE_GAP_MS;
        TunnelTrafficRates.Result result = compatible
                ? TunnelTrafficRates.calculate(previous, current) : null;
        previous = current;
        previousVerified = verified;
        previousPresent = present;
        return result;
    }

    void reset() {
        previous = null;
        previousVerified = -1;
        previousPresent = -1;
    }
}
