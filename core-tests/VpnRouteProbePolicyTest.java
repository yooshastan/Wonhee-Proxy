package com.yooshastan.wonheeproxy;

public final class VpnRouteProbePolicyTest {
    private static void equal(VpnRouteProbePolicy.Decision expected,
                              VpnRouteProbePolicy.Decision actual) {
        if (expected != actual) throw new AssertionError(expected + " != " + actual);
    }

    public static void main(String[] args) {
        equal(VpnRouteProbePolicy.Decision.PRIVATE_ONLY,
                VpnRouteProbePolicy.decide(false, false, 0));
        equal(VpnRouteProbePolicy.Decision.PRIVATE_ONLY,
                VpnRouteProbePolicy.decide(false, false, 2));
        equal(VpnRouteProbePolicy.Decision.IPV6_ONLY,
                VpnRouteProbePolicy.decide(false, true, 1));
        equal(VpnRouteProbePolicy.Decision.MISSING_DNS,
                VpnRouteProbePolicy.decide(true, false, 0));
        equal(VpnRouteProbePolicy.Decision.TEST_IPV4_INTERNET,
                VpnRouteProbePolicy.decide(true, false, 1));
        equal(VpnRouteProbePolicy.Decision.TEST_IPV4_INTERNET,
                VpnRouteProbePolicy.decide(true, true, 2));
        String split = VpnRouteProbePolicy.explanation(VpnRouteProbePolicy.Decision.PRIVATE_ONLY);
        if (!split.contains("Skipping external DNS/HTTPS")
                || !split.contains("Navidrome") || split.contains("leak-free")) {
            throw new AssertionError("Split tunnel diagnostic safety copy.");
        }
        System.out.println("PASS VpnRouteProbePolicyTest");
    }
}
