package com.yooshastan.wonheeproxy;

public final class TunnelTrafficRatesTest {
    public static void main(String[] args) {
        TunnelTrafficRates.Sample a = new TunnelTrafficRates.Sample(1_000, 1_000, 2_000);
        TunnelTrafficRates.Sample b = new TunnelTrafficRates.Sample(3_000, 501_000, 252_000);
        check(TunnelTrafficRates.calculate(null, b) == null, "No baseline");
        TunnelTrafficRates.Result r = TunnelTrafficRates.calculate(a, b);
        check(r != null, "Valid interval");
        near(r.downloadMbps, 2.0, "RX bytes to Mbps");
        near(r.uploadMbps, 1.0, "TX bytes to Mbps");
        check("2.00 Mbps".equals(TunnelTrafficRates.formatSpeed(r.downloadMbps)),
                "Mbps display");
        check("450 Kbps".equals(TunnelTrafficRates.formatSpeed(0.45)),
                "Kbps display");
        check("0 Kbps".equals(TunnelTrafficRates.formatSpeed(0)),
                "Idle display");
        check(TunnelTrafficRates.calculate(b, a) == null, "Clock or counter reset");
        check(TunnelTrafficRates.calculate(a, new TunnelTrafficRates.Sample(
                1_000, 20_000, 30_000)) == null, "Zero elapsed duration");
        check(TunnelTrafficRates.calculate(a, new TunnelTrafficRates.Sample(
                3_000, 99, 3_000)) == null, "RX reset");
        check(TunnelTrafficRates.calculate(a, new TunnelTrafficRates.Sample(
                3_000, 3_000, 99)) == null, "TX reset");
        check("1.0 MiB".equals(TunnelTrafficRates.formatTotal(1_048_576)),
                "Binary totals");
        System.out.println("TunnelTrafficRatesTest: PASS");
    }

    private static void check(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    private static void near(double actual, double expected, String message) {
        if (Math.abs(actual - expected) > 0.000001) {
            throw new AssertionError(message + ": " + actual);
        }
    }
}
