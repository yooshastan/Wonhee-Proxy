package com.yooshastan.wonheeproxy;

public final class VpnHealthSummaryTest {
    private static void check(boolean ok) {
        if (!ok) throw new AssertionError("Unexpected VPN health summary");
    }

    public static void main(String[] args) {
        String down = VpnHealthSummary.render(false, false, -1, false, true, true);
        check(down.contains("Interface: DOWN"));
        check(down.contains("configuration: missing"));
        check(down.contains("Block outside VPN: ON"));
        String up = VpnHealthSummary.render(true, true, 8, true, true, true);
        check(up.contains("Handshake: observed 8s ago"));
        check(up.contains("present, not tested"));
        String stale = VpnHealthSummary.render(true, true, 190, true, false, false);
        check(stale.contains("possibly stale"));
        check(!up.contains("leak-free") && !up.contains("fully protected"));
        System.out.println("Wonhee local health summary tests passed");
    }
}
