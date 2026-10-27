package com.yooshastan.wonheeproxy;

/**
 * Describes the Android-reported VPN LinkProperties without assuming the
 * kernel enforces a leak-free route or that Fedora forwards a given family.
 */
final class VpnRouteInspection {
    private VpnRouteInspection() { }

    static String render(boolean defaultIpv4, boolean defaultIpv6, int dnsCount) {
        return "Android VPN routing observation (not a leak test):"
                + "\nIPv4 default route via VPN: " + (defaultIpv4 ? "reported" : "not reported")
                + "\nIPv6 default route via VPN: " + (defaultIpv6 ? "reported" : "not reported")
                + "\nVPN DNS servers reported by Android: " + Math.max(0, dnsCount)
                + "\nSplit tunnels may intentionally omit default routes."
                + " These values do not verify packet egress or gateway behavior.";
    }
}
