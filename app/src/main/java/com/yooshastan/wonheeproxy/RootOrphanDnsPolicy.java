package com.yooshastan.wonheeproxy;

/**
 * Conservative opt-in classification of *orphaned* Wonhee DNS firewall rules.
 * A matching tag is not ownership by itself: callers must separately verify
 * every exact iptables -C rule and reject all unexpected WN_ OUTPUT rules.
 * Never authorizes an automated orphan cleanup on app launch or reboot.
 */
final class RootOrphanDnsPolicy {
    static final String RECOVERY_MARKER = "WN_DNS_ORPHAN_CLEANUP_V1";
    static final int EXPECTED_RULES = 8;

    enum State {
        CLEAN, SAVED_OWNERSHIP, READY_FOR_EXPLICIT_REPAIR,
        PENDING_EXACT_REPAIR, PENDING_CLEARED, BLOCKED
    }

    private RootOrphanDnsPolicy() { }

    static State classify(boolean ownsDnsLedger, boolean guardClear,
            boolean tunnelsDown, boolean relayAbsent, boolean routingClear,
            int exactRules, int allWonheeTags, boolean pendingRecord) {
        if (exactRules < 0 || allWonheeTags < 0 || exactRules > EXPECTED_RULES
                || allWonheeTags != exactRules) return State.BLOCKED;
        if (ownsDnsLedger) return State.SAVED_OWNERSHIP;
        if (!guardClear || !tunnelsDown || !relayAbsent || !routingClear) {
            return State.BLOCKED;
        }
        if (pendingRecord) {
            return exactRules == 0 ? State.PENDING_CLEARED : State.PENDING_EXACT_REPAIR;
        }
        if (exactRules == 0) return State.CLEAN;
        if (exactRules == EXPECTED_RULES) return State.READY_FOR_EXPLICIT_REPAIR;
        // No orphan recovery marker was committed before a partial cleanup.
        // A partial set with no ledger cannot safely be adopted.
        return State.BLOCKED;
    }
}
