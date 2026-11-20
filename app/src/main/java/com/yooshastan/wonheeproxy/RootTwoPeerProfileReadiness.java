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
        SAME_SERVER_PEER, // Legacy diagnostic label, no longer a Start condition.
        SAME_SERVER_ENDPOINT,
        SAME_CLIENT_IDENTITY,
        OVERLAPPING_INTERFACE_ADDRESSES,
        INTERFACE_HOST_PREFIX_REQUIRED,
        IPV4_DEFAULT_ALLOWEDIPS_REQUIRED,
        EXTRA_ALLOWEDIPS_UNSUPPORTED,
        INVALID_OR_AMBIGUOUS_PLAN
    }

    private RootTwoPeerProfileReadiness() { }

    /**
     * A provider may deliberately use the same remote WireGuard public key
     * at multiple geographically distinct endpoints. That is not, by itself,
     * proof of a duplicate server, so validate remote ENDPOINTS instead.
     *
     * Distinct client keys and provider-assigned interface addresses remain
     * required to avoid sharing a WireGuard peer registration across live
     * tunnels. Neither key nor endpoint ever enters the result string.
     */
    static Reason assess(List<RootMultiTunnelPlan.Entry> selected,
            boolean distinctRemoteEndpoints, boolean distinctLocalClients) {
        if (selected == null || selected.size() != 2) {
            return Reason.NEED_TWO_PROFILES;
        }
        if (!distinctRemoteEndpoints) {
            return Reason.SAME_SERVER_ENDPOINT;
        }
        if (!distinctLocalClients) {
            return Reason.SAME_CLIENT_IDENTITY;
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
                return "This older app compared server public keys rather than "
                        + "endpoints. Provider-shared public keys can be legitimate. "
                        + "Recheck using the newer endpoint-aware validator.";
            case SAME_SERVER_ENDPOINT:
                return "Both profiles target the same WireGuard server endpoint. "
                        + "Select two separate provider exit destinations.";
            case SAME_CLIENT_IDENTITY:
                return "Both configurations reuse the same WireGuard client key "
                        + "pair. Generate a second provider-registered device/key "
                        + "identity with its own assigned tunnel addresses; "
                        + "do not edit the private key or interface IP by hand.";
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
