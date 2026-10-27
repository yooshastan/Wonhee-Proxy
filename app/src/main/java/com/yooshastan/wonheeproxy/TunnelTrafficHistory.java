package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.List;

/**
 * UI-only, bounded history of passive WireGuard counter deltas.
 * Sampling is paused when the screen is hidden. These points never measure
 * whole-device traffic or prove that other network paths are blocked.
 */
final class TunnelTrafficHistory {
    static final int MAX_POINTS = 24; // Roughly two minutes at a 5-second interval.
    private static final long MAX_VALID_INTERVAL_MS = 30_000L;

    private final List<TunnelTrafficRates.Result> points = new ArrayList<>();
    private TunnelTrafficRates.Sample previous;

    TunnelTrafficRates.Result add(long elapsedMillis, long rx, long tx) {
        TunnelTrafficRates.Sample current =
                new TunnelTrafficRates.Sample(elapsedMillis, rx, tx);
        if (previous == null) {
            previous = current;
            return null;
        }
        long delta = elapsedMillis - previous.elapsedMillis;
        if (delta <= 0L || delta > MAX_VALID_INTERVAL_MS) {
            // Do not mislabel a background interval as a live data rate.
            previous = current;
            points.clear();
            return null;
        }
        TunnelTrafficRates.Result rate = TunnelTrafficRates.calculate(previous, current);
        previous = current;
        if (rate == null) {
            // Counters may reset when a tunnel reconnects.
            points.clear();
            return null;
        }
        points.add(rate);
        if (points.size() > MAX_POINTS) points.remove(0);
        return rate;
    }

    void pause() {
        // Hidden-screen samples would otherwise appear as recent live traffic.
        previous = null;
        points.clear();
    }

    void clear() {
        pause();
    }

    List<TunnelTrafficRates.Result> values() {
        return new ArrayList<>(points);
    }

    double peakDownloadMbps() {
        double peak = 0;
        for (TunnelTrafficRates.Result point : points)
            peak = Math.max(peak, point.downloadMbps);
        return peak;
    }

    double peakUploadMbps() {
        double peak = 0;
        for (TunnelTrafficRates.Result point : points)
            peak = Math.max(peak, point.uploadMbps);
        return peak;
    }
}
