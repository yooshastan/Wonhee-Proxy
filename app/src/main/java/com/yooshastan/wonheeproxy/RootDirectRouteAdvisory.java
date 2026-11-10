package com.yooshastan.wonheeproxy;

/**
 * Privacy-preserving advisory model for a user-invoked snapshot of live
 * socket/peer/UID/fwmark route predictions.
 *
 * Only counts and a bounded UDP/443 hint survive into the report.
 * This is NOT packet egress measurement, a firewall or a kill switch.
 */
final class RootDirectRouteAdvisory {
    static final int INTERNET_VPN = 0;
    static final int PHYSICAL_WIFI = 1;
    static final int OTHER_TUNNEL = 2;
    static final int UNKNOWN = 3;

    private RootDirectRouteAdvisory() { }

    static final class Totals {
        int candidates;
        int throughInternet;
        int possiblePhysical;
        int otherTunnel;
        int unknown;
        int protectedPhysical;
        int ordinaryPhysical;
        int udp443Candidates;
        int udp443PossiblePhysical;

        void add(int category, boolean protectedBit, boolean udp443) {
            candidates++;
            if (udp443) udp443Candidates++;
            switch (category) {
                case INTERNET_VPN:
                    throughInternet++;
                    break;
                case PHYSICAL_WIFI:
                    possiblePhysical++;
                    if (protectedBit) protectedPhysical++;
                    else ordinaryPhysical++;
                    if (udp443) udp443PossiblePhysical++;
                    break;
                case OTHER_TUNNEL:
                    otherTunnel++;
                    break;
                default:
                    unknown++;
                    break;
            }
        }

        String safeWarning(boolean androidSystem, String appLabel) {
            String prefix = appLabel + ": ";
            if (candidates == 0) {
                return prefix + "NO PUBLIC SOCKET PEER OBSERVED during this "
                        + "short watch. This is not evidence of VPN-only routing.";
            }
            if (possiblePhysical > 0) {
                String warning = prefix
                        + "POTENTIAL DIRECT PUBLIC ROUTE: "
                        + possiblePhysical + " observed public-peer UID/fwmark "
                        + "combination(s) select physical Wi-Fi in a kernel "
                        + "route prediction ("
                        + protectedPhysical + " protected-marked, "
                        + ordinaryPhysical + " ordinary-marked).";
                if (udp443PossiblePhysical > 0) {
                    warning += " " + udp443PossiblePhysical
                            + " UDP/443 combination(s) are compatible with "
                            + "QUIC; protocol contents were NOT inspected.";
                }
                if (androidSystem) {
                    warning += " Android system traffic may be carrier IMS/"
                            + "Wi-Fi Calling. Do not block automatically.";
                } else {
                    warning += " Do not disable RCS, push or other app services.";
                }
                return warning;
            }
            if (unknown > 0 || otherTunnel > 0) {
                return prefix + "ROUTE NEEDS REVIEW: no physical route in "
                        + "classified peers, but " + unknown
                        + " route(s) unknown and " + otherTunnel
                        + " use another selected tunnel. "
                        + "No global fail-closed claim.";
            }
            return prefix + "NO DIRECT ROUTE PREDICTED among "
                    + candidates + " sampled public peer/mark combinations. "
                    + "Other connections may be missed; NOT proof of "
                    + "system-wide VPN-only egress.";
        }
    }

    /**
     * Results must be derived from the SAME live socket record's UID, mark
     * and numeric peer, then a read-only kernel route lookup to that peer.
     */
    static int category(String selectedDevice, String internetDevice,
                        boolean isOtherSelectedTunnel) {
        if (selectedDevice == null || selectedDevice.isEmpty()) return UNKNOWN;
        if (!internetDevice.isEmpty() && internetDevice.equals(selectedDevice)) {
            return INTERNET_VPN;
        }
        if ("wlan0".equals(selectedDevice)) return PHYSICAL_WIFI;
        if (isOtherSelectedTunnel) return OTHER_TUNNEL;
        return UNKNOWN;
    }
}
