package com.yooshastan.wonheeproxy;

import java.util.Arrays;

public final class RootTransportRouteTest {
    private static void check(boolean ok) { if (!ok) throw new AssertionError(); }

    public static void main(String[] ignored) {
        // No pair-specific assumptions; any selected tunnel must be excluded
        // from the outer WireGuard transport path.
        java.util.List<String> selected = Arrays.asList("wnmhome", "wnminternet", "wnmthird");
        check(RootTransportRoute.isPotentialLoop("wnmthird", selected));
        check(!RootTransportRoute.isPotentialLoop("wlan0", selected));
        check(RootTransportRoute.classifiedDevice("wnminternet", selected).contains("LOOP"));
        check(RootTransportRoute.classifiedDevice("rmnet16", selected).contains("CANDIDATE"));
        check(RootTransportRoute.classifiedDevice("ipsec49", selected).contains("UNVERIFIED"));
        check("UNRESOLVED".equals(RootTransportRoute.classifiedDevice("", selected)));
        System.out.println("RootTransportRouteTest passed");
    }
}
