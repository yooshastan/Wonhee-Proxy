package com.yooshastan.wonheeproxy;

/**
 * Avoid performing a public-internet request on a HOME-only split tunnel.
 * Android's VPN network existence alone is NOT evidence that a public
 * destination is encrypted or that another path cannot bypass the VPN.
 */
final class VpnRouteProbePolicy {
    enum Decision { PRIVATE_ONLY, IPV6_ONLY, MISSING_DNS, TEST_IPV4_INTERNET }

    private VpnRouteProbePolicy() { }

    static Decision decide(boolean defaultIpv4, boolean defaultIpv6, int dnsCount) {
        if (!defaultIpv4) {
            return defaultIpv6 ? Decision.IPV6_ONLY : Decision.PRIVATE_ONLY;
        }
        if (dnsCount <= 0) return Decision.MISSING_DNS;
        return Decision.TEST_IPV4_INTERNET;
    }

    static String explanation(Decision decision) {
        switch (decision) {
            case PRIVATE_ONLY:
                return "HOME/SPLIT TUNNEL: Android reports no VPN default route. "
                        + "Skipping external DNS/HTTPS so this test cannot be mistaken "
                        + "for protected internet egress. Use the manual private-service "
                        + "probe for Navidrome or other LAN destinations. Ordinary internet "
                        + "may use Wi-Fi/cellular; this is not a leak assessment.";
            case IPV6_ONLY:
                return "PARTIAL ROUTING: Android reports an IPv6 but no IPv4 VPN "
                        + "default route. Skipping the public-internet probe because "
                        + "its route and IP-family behavior are ambiguous.";
            case MISSING_DNS:
                return "Android reports an IPv4 VPN default route but no VPN DNS "
                        + "server. Skipping DNS/HTTPS. Inspect the imported DNS settings "
                        + "and server routing; no normal-network fallback was attempted.";
            case TEST_IPV4_INTERNET:
                return "VPN internet test permitted by observed IPv4 default route and DNS.";
            default:
                throw new IllegalArgumentException("Unknown route policy.");
        }
    }
}
