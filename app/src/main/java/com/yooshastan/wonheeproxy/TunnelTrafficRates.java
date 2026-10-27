package com.yooshastan.wonheeproxy;

import java.util.Locale;

/**
 * Passive WireGuard transfer-rate math. These are tunnel byte counters, not
 * device-wide traffic, a connectivity test, or evidence of leak protection.
 */
final class TunnelTrafficRates {
    static final class Sample {
        final long elapsedMillis;
        final long receivedBytes;
        final long transmittedBytes;

        Sample(long elapsedMillis, long receivedBytes, long transmittedBytes) {
            this.elapsedMillis = elapsedMillis;
            this.receivedBytes = receivedBytes;
            this.transmittedBytes = transmittedBytes;
        }
    }

    static final class Result {
        final double downloadMbps;
        final double uploadMbps;

        Result(double downloadMbps, double uploadMbps) {
            this.downloadMbps = downloadMbps;
            this.uploadMbps = uploadMbps;
        }
    }

    private TunnelTrafficRates() { }

    static Result calculate(Sample previous, Sample current) {
        if (previous == null || current == null) return null;
        long elapsed = current.elapsedMillis - previous.elapsedMillis;
        if (elapsed <= 0 || current.receivedBytes < previous.receivedBytes
                || current.transmittedBytes < previous.transmittedBytes) {
            return null;
        }
        // bytes * 8 bits / (milliseconds / 1000) / 1,000,000
        double down = (current.receivedBytes - previous.receivedBytes) * 8.0
                / (elapsed * 1000.0);
        double up = (current.transmittedBytes - previous.transmittedBytes) * 8.0
                / (elapsed * 1000.0);
        return new Result(down, up);
    }

    static String formatSpeed(double mbps) {
        if (!Double.isFinite(mbps) || mbps < 0) return "—";
        if (mbps < 1.0) return String.format(Locale.US, "%.0f Kbps", mbps * 1000.0);
        return String.format(Locale.US, "%.2f Mbps", mbps);
    }

    static String formatTotal(long bytes) {
        if (bytes < 0) return "—";
        double mib = bytes / (1024.0 * 1024.0);
        if (mib < 1024.0) return String.format(Locale.US, "%.1f MiB", mib);
        return String.format(Locale.US, "%.2f GiB", mib / 1024.0);
    }
}
