package com.yooshastan.wonheeproxy;

public final class TunnelTrafficHistoryTest {
    public static void main(String[] args) {
        TunnelTrafficHistory samples = new TunnelTrafficHistory();
        check(samples.add(1_000, 0, 0) == null, "baseline is not a measurement");
        TunnelTrafficRates.Result one = samples.add(6_000, 1_250_000, 625_000);
        near(one.downloadMbps, 2.0, "download rate");
        near(one.uploadMbps, 1.0, "upload rate");
        check(samples.values().size() == 1, "first sample stored");
        for (int i = 2; i < 34; ++i) {
            samples.add(1_000 + i * 5_000L, i * 1_250_000L, i * 625_000L);
        }
        check(samples.values().size() == TunnelTrafficHistory.MAX_POINTS,
                "bounded graph memory");
        near(samples.peakDownloadMbps(), 2.0, "peak down");
        near(samples.peakUploadMbps(), 1.0, "peak up");
        samples.pause();
        check(samples.add(200_000, 99_000_000, 50_000_000) == null,
                "resuming after background is not a live interval");
        check(samples.values().isEmpty(),
                "pause clears stale live history");
        check(samples.add(205_000, 99_000_001, 50_000_000) != null,
                "sampling resumes with a new baseline");
        check(samples.add(210_000, 5, 5) == null, "counter reset is not a speed");
        check(samples.values().isEmpty(), "counter reset clears stale graph");
        check(samples.add(215_000, 500, 500) != null, "recover after counter reset");
        check(samples.add(250_100, 550, 550) == null, "long gap never averaged");
        check(samples.values().isEmpty(), "gap clears stale live history");
        samples.clear();
        check(samples.values().isEmpty(), "manual reset");
        check(samples.add(251_000, 0, 0) == null, "fresh baseline");
        System.out.println("TunnelTrafficHistoryTest: PASS");
    }

    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }

    private static void near(double actual, double expected, String message) {
        if (Math.abs(actual - expected) > 0.000001)
            throw new AssertionError(message + " (" + actual + ")");
    }
}
