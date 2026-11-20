package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** Rootless checks for the real two-peer RootLab import/refusal regression. */
public final class RootTwoPeerProfileReadinessTest {
    private static RootMultiTunnelPlan.Entry config(
            String name, String address, String... allowedIps) {
        return new RootMultiTunnelPlan.Entry(name, Arrays.asList(allowedIps),
                Collections.singletonList(address));
    }

    private static void assertReason(RootTwoPeerProfileReadiness.Reason wanted,
            List<RootMultiTunnelPlan.Entry> profiles, boolean uniqueServers) {
        RootTwoPeerProfileReadiness.Reason actual =
                RootTwoPeerProfileReadiness.assess(profiles, uniqueServers);
        if (actual != wanted) {
            throw new AssertionError("Expected " + wanted + ", got " + actual);
        }
        String safe = RootTwoPeerProfileReadiness.explain(actual);
        if (safe.contains("10.150.") || safe.contains("10.151.")
                || safe.contains("198.51.100") || safe.contains("PrivateKey")
                || safe.contains("Endpoint=")) {
            throw new AssertionError("Profile readiness exposed sensitive values.");
        }
    }

    public static void main(String[] args) {
        RootMultiTunnelPlan.Entry eu = config("Exit A", "10.150.0.2/32",
                "0.0.0.0/0", "::/0");
        RootMultiTunnelPlan.Entry us = config("Exit B", "10.151.0.2/32",
                "0.0.0.0/0", "::/0");
        assertReason(RootTwoPeerProfileReadiness.Reason.READY,
                Arrays.asList(eu, us), true);
        assertReason(RootTwoPeerProfileReadiness.Reason.NEED_TWO_PROFILES,
                Collections.singletonList(eu), true);
        assertReason(RootTwoPeerProfileReadiness.Reason.SAME_SERVER_PEER,
                Arrays.asList(eu, us), false);

        // Two provider configs can have distinct remote servers and still
        // reuse the same assigned client IPv4 tunnel address.
        assertReason(RootTwoPeerProfileReadiness.Reason.OVERLAPPING_INTERFACE_ADDRESSES,
                Arrays.asList(eu, config("Exit B", "10.150.0.2/32",
                        "0.0.0.0/0", "::/0")), true);
        assertReason(RootTwoPeerProfileReadiness.Reason.OVERLAPPING_INTERFACE_ADDRESSES,
                Arrays.asList(eu, config("Exit B", "10.150.0.3/24",
                        "0.0.0.0/0", "::/0")), true);

        assertReason(RootTwoPeerProfileReadiness.Reason.INTERFACE_HOST_PREFIX_REQUIRED,
                Arrays.asList(eu, config("Exit B", "10.151.0.2/24",
                        "0.0.0.0/0", "::/0")), true);
        assertReason(RootTwoPeerProfileReadiness.Reason.INTERFACE_HOST_PREFIX_REQUIRED,
                Arrays.asList(eu, config("Exit B", "fd02::3/64",
                        "0.0.0.0/0", "::/0")), true);
        assertReason(RootTwoPeerProfileReadiness.Reason.IPV4_DEFAULT_ALLOWEDIPS_REQUIRED,
                Arrays.asList(eu, config("Exit B", "10.151.0.2/32",
                        "::/0")), true);
        assertReason(RootTwoPeerProfileReadiness.Reason.EXTRA_ALLOWEDIPS_UNSUPPORTED,
                Arrays.asList(eu, config("Exit B", "10.151.0.2/32",
                        "0.0.0.0/0", "10.0.0.0/8")), true);
        assertReason(RootTwoPeerProfileReadiness.Reason.INVALID_OR_AMBIGUOUS_PLAN,
                Arrays.asList(eu, config("Exit B", "not-an-address",
                        "0.0.0.0/0")), true);

        // Reversed import order is not an error. Private table assignment
        // remains deterministic in the downstream link-only compiler.
        assertReason(RootTwoPeerProfileReadiness.Reason.READY,
                Arrays.asList(us, eu), true);
        System.out.println("RootTwoPeerProfileReadinessTest passed");
    }
}
