package com.yooshastan.wonheeproxy;

public final class VpnRouteInspectionTest {
    public static void main(String[] args) {
        String full = VpnRouteInspection.render(true, true, 2);
        check(full.contains("IPv4 default route via VPN: reported"), "IPv4 full route");
        check(full.contains("IPv6 default route via VPN: reported"), "IPv6 full route");
        check(full.contains("VPN DNS servers reported by Android: 2"), "DNS count");
        String split = VpnRouteInspection.render(false, false, 0);
        check(split.contains("IPv4 default route via VPN: not reported"), "split route");
        check(split.contains("may intentionally omit default routes"), "split warning");
        check(split.contains("not a leak test"), "scope");
        check(!full.toLowerCase().contains("leak-free"), "no guarantee");
        System.out.println("VpnRouteInspectionTest: PASS");
    }

    private static void check(boolean ok, String message) {
        if (!ok) throw new AssertionError(message);
    }
}
