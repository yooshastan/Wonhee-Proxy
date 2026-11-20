package com.yooshastan.wonheeproxy;

import java.util.List;

/**
 * Privacy-safe validation for the first two-peer link-only experiment.
 * Never return IP addresses, public/private keys, endpoint hosts or raw
 * parser exception text in a user-visible diagnostic.
 *
 * Importing two independent VPN files is not enough if both contain the
 * same tunnel-side interface address. A different endpoint does not fix
 * this; the provider must allocate independent client tunnel addresses.
 */
final class RootTwoPeerProfileReadiness {
    enum Reason {
        READY,
        NEED_TWO_PROFILES,
        SAME_SERVER_PEER,
        OVERLAPPING_INTERFACE_ADDRESSES,
        INTERFACE_HOST_PREFIX_REQUIRED,
        IPV4_DEFAULT_ALLOWEDIPS_REQUIRED,
        EXTRA_ALLOWEDIPS_UNSUPPORTED,
        INVALID_OR_AMBIGUOUS_PLAN
    }

    private RootTwoPeerProfileReadiness() { }

    static Reason assess(List<RootMultiTunnelPlan.Entry> selected,
            boolean distinctServerPeers) {
        if (selected == null || selected.size() != 2) {
            return Reason.NEED_TWO_PROFILES;
        }
        if (!distinctServerPeers) {
            return Reason.SAME_SERVER_PEER;
        }
        try {
            RootMultiTunnelPlan.validateIndependentInterfaceAddresses(selected);
        } catch (IllegalArgumentException invalid) {
            // Classification only, not leaking raw profile CIDRs or names.
            String description = invalid.getMessage();
            if (description != null
                    && description.toLowerCase(java.util.Locale.ROOT)
                            .contains("overlap")) {
                return Reason.OVERLAPPING_INTERFACE_ADDRESSES;
            }
            return Reason.INVALID_OR_AMBIGUOUS_PLAN;
        }
        for (RootMultiTunnelPlan.Entry entry : selected) {
            if (entry == null || entry.interfaceAddresses == null
                    || entry.interfaceAddresses.isEmpty()) {
                return Reason.INVALID_OR_AMBIGUOUS_PLAN;
            }
            for (String host : entry.interfaceAddresses) {
                if (host == null || !host.endsWith(
                        host.indexOf(':') >= 0 ? "/128" : "/32")) {
                    return Reason.INTERFACE_HOST_PREFIX_REQUIRED;
                }
            }
            if (entry.peerRoutes == null
                    || !entry.peerRoutes.contains("0.0.0.0/0")) {
                return Reason.IPV4_DEFAULT_ALLOWEDIPS_REQUIRED;
            }
            boolean v6 = entry.peerRoutes.contains("::/0")
                    || entry.peerRoutes.contains("0:0:0:0:0:0:0:0/0");
            if (entry.peerRoutes.size() != (v6 ? 2 : 1)) {
                return Reason.EXTRA_ALLOWEDIPS_UNSUPPORTED;
            }
        }
        try {
            RootIsolatedTwoPeerLinkPlan.compile(selected);
            return Reason.READY;
        } catch (IllegalArgumentException invalid) {
            return Reason.INVALID_OR_AMBIGUOUS_PLAN;
        }
    }

    static String explain(Reason reason) {
        if (reason == null) return "Profile check unavailable. No connection attempted.";
        switch (reason) {
            case READY:
                return "Both imported profiles passed link-only structural checks. "
                        + "This does not prove a handshake or protected routing.";
            case NEED_TWO_PROFILES:
                return "Import both Exit A and Exit B before Start.";
            case SAME_SERVER_PEER:
                return "The two profiles specify the same WireGuard server peer. "
                        + "Generate profiles for two different exit servers.";
            case OVERLAPPING_INTERFACE_ADDRESSES:
                return "Exit A and Exit B have overlapping internal WireGuard "
                        + "interface addresses. Generate two provider-assigned "
                        + "profiles with distinct tunnel addresses. Do not "
                        + "manually invent client IPs or disable this guard.";
            case INTERFACE_HOST_PREFIX_REQUIRED:
                return "At least one profile uses a local interface subnet "
                        + "prefix instead of /32 (IPv4) or /128 (IPv6). "
                        + "This link-only test refuses connected-subnet routes "
                        + "that could enter Android's main routing table.";
            case IPV4_DEFAULT_ALLOWEDIPS_REQUIRED:
                return "At least one profile lacks AllowedIPs 0.0.0.0/0. "
                        + "The first two-peer lab accepts Internet exits only.";
            case EXTRA_ALLOWEDIPS_UNSUPPORTED:
                return "One profile includes additional AllowedIPs routes. "
                        + "This two-peer test supports only 0.0.0.0/0 and "
                        + "optional ::/0; split routes require a later test.";
            default:
                return "The two configurations cannot form a safe isolated "
                        + "link plan. No root networking was changed.";
        }
    }
}
