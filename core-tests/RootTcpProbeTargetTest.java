package com.yooshastan.wonheeproxy;

public final class RootTcpProbeTargetTest {
    private static void check(boolean value) { if (!value) throw new AssertionError(); }

    private static void rejected(String input) {
        try {
            RootTcpProbeTarget.parse(input);
            throw new AssertionError("Accepted invalid target: " + input);
        } catch (IllegalArgumentException expected) { /* as intended */ }
    }

    public static void main(String[] unused) {
        RootTcpProbeTarget home = RootTcpProbeTarget.parse(" 10.0.0.169:4533 ");
        check(home.family == 4 && home.port == 4533);
        check("10.0.0.169:4533".equals(home.label()));
        RootTcpProbeTarget v6 = RootTcpProbeTarget.parse("[2606:4700:4700::1111]:443");
        check(v6.family == 6 && v6.port == 443);
        check("[2606:4700:4700::1111]:443".equals(v6.label()));
        rejected(null);
        rejected("https://10.0.0.169:4533/app/");
        rejected("navidrome.example.com:4533");
        rejected("10.0.0.999:443");
        rejected("10.0.0.1:0");
        rejected("10.0.0.1:65536");
        rejected("fe80::1:443");
        rejected("[fe80::1%eth0]:443");
        rejected("[::ffff:10.0.0.1]:443");
        System.out.println("RootTcpProbeTargetTest passed");
    }
}
