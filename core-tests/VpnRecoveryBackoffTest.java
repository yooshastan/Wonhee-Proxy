package com.yooshastan.wonheeproxy;

public final class VpnRecoveryBackoffTest {
    public static void main(String[] args) {
        VpnRecoveryBackoff b = new VpnRecoveryBackoff();
        if (!b.isDue(100)) throw new AssertionError("initial due");
        long[] expected = {5000, 15000, 30000, 60000, 120000, 300000, 300000};
        long now = 100;
        for (long delay : expected) {
            b.failed(now);
            if (b.isDue(now) || b.isDue(now + delay - 1)) {
                throw new AssertionError("retry attempted before delay");
            }
            now += delay;
            if (!b.isDue(now)) throw new AssertionError("retry not due");
            if (b.secondsUntilNext(now) != 0) throw new AssertionError("negative countdown");
        }
        if (b.failures() != expected.length) throw new AssertionError("failure count");
        b.reset();
        if (b.failures() != 0 || !b.isDue(0)) {
            throw new AssertionError("reset must rearm immediately");
        }
        System.out.println("PASS VpnRecoveryBackoffTest");
    }
}
