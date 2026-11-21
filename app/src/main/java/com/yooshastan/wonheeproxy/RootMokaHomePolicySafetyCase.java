package com.yooshastan.wonheeproxy;

/**
 * Non-mutating safety contract for the first Moka -> Home TCP/4533 pilot.
 *
 * A private route or handshake is not a VPN. The contract cannot authorize
 * app UID steering until every fail-closed proof and recovery requirement
 * is present. No Android shell, netd, firewall, or VPN mutation is possible.
 */
final class RootMokaHomePolicySafetyCase {
    enum Gate {
        READY_FOR_DEVICE_TEST,
        BAD_UID,
        BAD_HOME_DESTINATION,
        NO_OWNED_HOME_LINK,
        MISSING_IPV4_DENY,
        MISSING_IPV6_DENY,
        MISSING_UNDERLAY_ISOLATION,
        MISSING_TCP_PORT_ENFORCEMENT,
        MISSING_DNS_ISOLATION,
        MISSING_CRASH_RECOVERY,
        MISSING_STOP_PROOF,
        NO_LOSS_TEST
    }

    static final class Evidence {
        final int uid;
        final String destination;
        final int port;
        final boolean homeIdentityAndJournal;
        final boolean deny4;
        final boolean deny6;
        final boolean underlay;
        final boolean tcpOnly;
        final boolean dns;
        final boolean restartRecovery;
        final boolean exactSafeStop;
        final boolean linkLossBlocked;

        Evidence(int uid, String destination, int port, boolean homeIdentityAndJournal,
                 boolean deny4, boolean deny6, boolean underlay, boolean tcpOnly,
                 boolean dns, boolean restartRecovery, boolean exactSafeStop,
                 boolean linkLossBlocked) {
            this.uid = uid;
            this.destination = destination;
            this.port = port;
            this.homeIdentityAndJournal = homeIdentityAndJournal;
            this.deny4 = deny4;
            this.deny6 = deny6;
            this.underlay = underlay;
            this.tcpOnly = tcpOnly;
            this.dns = dns;
            this.restartRecovery = restartRecovery;
            this.exactSafeStop = exactSafeStop;
            this.linkLossBlocked = linkLossBlocked;
        }
    }

    private RootMokaHomePolicySafetyCase() { }

    static Gate assess(Evidence e) {
        if (e == null || e.uid < 10000 || e.uid > 99999) return Gate.BAD_UID;
        if (!"10.0.0.169".equals(e.destination) || e.port != 4533) {
            return Gate.BAD_HOME_DESTINATION;
        }
        if (!e.homeIdentityAndJournal) return Gate.NO_OWNED_HOME_LINK;
        if (!e.deny4) return Gate.MISSING_IPV4_DENY;
        if (!e.deny6) return Gate.MISSING_IPV6_DENY;
        if (!e.underlay) return Gate.MISSING_UNDERLAY_ISOLATION;
        if (!e.tcpOnly) return Gate.MISSING_TCP_PORT_ENFORCEMENT;
        if (!e.dns) return Gate.MISSING_DNS_ISOLATION;
        if (!e.restartRecovery) return Gate.MISSING_CRASH_RECOVERY;
        if (!e.exactSafeStop) return Gate.MISSING_STOP_PROOF;
        if (!e.linkLossBlocked) return Gate.NO_LOSS_TEST;
        return Gate.READY_FOR_DEVICE_TEST;
    }

    /**
     * These capabilities are absent in the current RootLab. Never confuse
     * a VERIFIED read-only route preflight with activation readiness.
     */
    static Gate currentLabGate(int uid, boolean homeIdentityAndJournal) {
        return assess(new Evidence(uid, "10.0.0.169", 4533,
                homeIdentityAndJournal, false, false, false, false,
                false, false, false, false));
    }
}
