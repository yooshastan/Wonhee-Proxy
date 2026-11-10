package com.yooshastan.wonheeproxy;

public final class RootDashboardTelemetryTest {
    private static void check(boolean condition, String why) {
        if (!condition) throw new AssertionError(why);
    }

    public static void main(String[] args) {
        RootDashboardTelemetry model = new RootDashboardTelemetry();
        check(model.observe(1000, true, 2, 2, 1000, 2000) == null,
                "First reading must measure rather than invent a rate");
        TunnelTrafficRates.Result rate = model.observe(
                6000, true, 2, 2, 1251000, 627000);
        check(rate != null && rate.downloadMbps == 2.0 && rate.uploadMbps == 1.0,
                "Known 5-second counter deltas must yield correct down/up Mbps");
        check(model.observe(7000, false, 2, 2, 1251000, 627000) == null,
                "Any unverified snapshot resets the rate baseline");
        check(model.observe(8000, true, 2, 2, 1300000, 630000) == null,
                "Reappearance must measure from scratch after verification loss");
        check(model.observe(9000, true, 1, 1, 200000, 100000) == null,
                "Changing verified tunnel count must reset the aggregate");
        check(model.observe(10000, true, 1, 1, 210000, 105000) != null,
                "Stable count and monotonically increasing counters produce a rate");
        check(model.observe(11000, true, 1, 2, 220000, 110000) == null,
                "Partial tunnel verification cannot show partial aggregate rate");
        check(model.observe(12000, true, 1, 1, 230000, 115000) == null,
                "Recovery from partial verify cannot inherit stale counters");
        check(model.observe(90000, true, 1, 1, 999999, 999999) == null,
                "Long process suspension resets sample to avoid misleading throughput");
        check(model.observe(92000, true, 1, 1, 1000000, 1000000) != null,
                "Subsequent stable reading works after long pause");
        check(model.observe(93000, true, 1, 1, 0, 0) == null,
                "Counter reset must not synthesize negative speed");
        check(model.observe(94000, true, 1, 1, 5000, 10000) != null,
                "Sampler recovers after a counter reset");
        model.reset();
        check(model.observe(95000, true, 1, 1, 10000, 20000) == null,
                "Explicit reset hides stale rates across screen/service lifecycle");
        check(model.observe(96000, true, 1, 1, 11000, 21000) != null,
                "Sampler restarts after explicit reset");
        check(model.observe(97000, true, 0, 0, 0, 0) == null,
                "Stopped sessions never show stale traffic");
        check(model.observe(98000, true, 2, 2, 100, 100) == null,
                "Reconnecting tunnels start with a fresh speed sample");
        System.out.println("RootDashboardTelemetryTest passed");
    }
}
