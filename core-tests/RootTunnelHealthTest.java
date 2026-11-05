package com.yooshastan.wonheeproxy;

public final class RootTunnelHealthTest {
    private static void require(boolean condition) {
        if (!condition) throw new AssertionError("RootTunnelHealth status formatting failed");
    }

    public static void main(String[] args) {
        require(RootTunnelHealth.render("Home", false, 0, 0, -1, null).equals("Home: DOWN"));
        String first = RootTunnelHealth.render("Home", true, 0, 0, -1, null);
        require(first.contains("none observed") && first.contains("measuring"));
        String recent = RootTunnelHealth.render("AirVPN", true, 2000000, 3000000, 70,
                new TunnelTrafficRates.Result(1.2, 0.4));
        require(recent.contains("70s ago") && recent.contains("1.20 Mbps")
                && !recent.contains("stale"));
        require(RootTunnelHealth.render("AirVPN", true, 0, 0, 181, null)
                .contains("possibly idle/stale"));
        System.out.println("RootTunnelHealthTest passed");
    }
}
