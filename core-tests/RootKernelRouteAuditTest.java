package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

public final class RootKernelRouteAuditTest {
    private static void expect(boolean actual, boolean expected) {
        if (actual != expected) throw new AssertionError("Expected " + expected + ", got " + actual);
    }

    public static void main(String[] ignored) {
        expect(RootKernelRouteAudit.routesThrough(Arrays.asList(
                "1.1.1.1 dev wnair0 table wnair0 src 10.159.187.150 uid 0", "    cache"),
                "wnair0"), true);
        expect(RootKernelRouteAudit.routesThrough(Arrays.asList(
                "2606:4700:4700::1111 dev wnair0 table wnair0 proto static"),
                "wnair0"), true);
        expect(RootKernelRouteAudit.routesThrough(Arrays.asList(
                "10.0.0.169 dev wnhome0 table wnhome0 src 10.6.0.2"),
                "wnhome0"), true);
        expect(RootKernelRouteAudit.routesThrough(Arrays.asList(
                "1.1.1.1 via 10.0.0.1 dev rmnet16 src 10.0.0.2"),
                "wnair0"), false);
        expect(RootKernelRouteAudit.routesThrough(Arrays.asList(
                "unreachable 1.1.1.1"), "wnair0"), false);
        expect(RootKernelRouteAudit.routesThrough(Collections.emptyList(), "wnair0"), false);
        expect(RootKernelRouteAudit.routesThrough(Arrays.asList(
                "1.1.1.1 dev wnair0bad table wnair0"), "wnair0"), false);
        expect(RootKernelRouteAudit.routesThrough(Arrays.asList(
                "1.1.1.1 dev rmnet16 table wnair0"), "wnair0"), false);
        System.out.println("RootKernelRouteAuditTest passed");
    }
}
