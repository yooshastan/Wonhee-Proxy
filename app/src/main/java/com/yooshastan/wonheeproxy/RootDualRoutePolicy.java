package com.yooshastan.wonheeproxy;

import java.util.Collection;

/** Route preflight independent of Android, WireGuard keys and endpoint details. */
final class RootDualRoutePolicy {
    private RootDualRoutePolicy() { }

    static void validate(Collection<String> home, Collection<String> internet) {
        if (home == null || home.isEmpty() || internet == null || internet.isEmpty()) {
            throw new IllegalArgumentException("Both tunnels need peer routes.");
        }
        for (String route : home) {
            if (isDefault(route)) {
                throw new IllegalArgumentException("Home must be split-tunnel, with no default route.");
            }
        }
        if (!internet.contains("0.0.0.0/0") ||
                !(internet.contains("::/0") || internet.contains("0:0:0:0:0:0:0:0/0"))) {
            throw new IllegalArgumentException(
                    "AirVPN must include both IPv4 and IPv6 default routes for this test.");
        }
    }

    private static boolean isDefault(String route) {
        return "0.0.0.0/0".equals(route) || "::/0".equals(route)
                || "0:0:0:0:0:0:0:0/0".equals(route);
    }
}
