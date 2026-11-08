package com.yooshastan.wonheeproxy;

/**
 * Pure, conservative lifecycle classification. Exact ownership verification
 * happens in the root controller BEFORE constructing this summary. A displayed
 * "repairable" state means only that an explicit, repeated preflight may
 * attempt exact-owned cleanup; it is not permission to delete kernel rules.
 */
final class RootLifecycleRecoveryPlan {
    enum State { CLEAN_STOPPED, RUNNING_OR_PARTIAL, REPAIRABLE_STOPPED, BLOCKED_UNKNOWN }

    final State state;
    final String nextAction;

    private RootLifecycleRecoveryPlan(State state, String nextAction) {
        this.state = state;
        this.nextAction = nextAction;
    }

    static RootLifecycleRecoveryPlan assess(boolean guardClear, boolean exactOwnership,
            boolean anyTunnelUp, boolean relayListening,
            boolean dnsLedger, boolean routingLedger, int ownedDnsTags, int ownedRoutes,
            int totalDnsTags, int totalReservedRoutes) {
        if (ownedDnsTags < 0 || ownedRoutes < 0 || totalDnsTags < 0 || totalReservedRoutes < 0
                || ownedDnsTags > totalDnsTags || ownedRoutes > totalReservedRoutes
                || !guardClear || !exactOwnership
                || (!dnsLedger && totalDnsTags != 0)
                || (!routingLedger && totalReservedRoutes != 0)
                || totalDnsTags != ownedDnsTags || totalReservedRoutes != ownedRoutes) {
            return new RootLifecycleRecoveryPlan(State.BLOCKED_UNKNOWN,
                    "Foreign, duplicated, modified or unverifiable policy. Inspect with USB ADB; do not clear ledgers.");
        }
        if (anyTunnelUp) {
            return new RootLifecycleRecoveryPlan(State.RUNNING_OR_PARTIAL,
                    "One or more tunnels are UP. Use the coordinated Safe stop; no orphan repair while connected.");
        }
        if (relayListening) {
            return new RootLifecycleRecoveryPlan(State.BLOCKED_UNKNOWN,
                    "A DNS listener remains active with no selected tunnel. Audit the relay; metadata repair refused.");
        }
        if (!dnsLedger && !routingLedger && totalDnsTags == 0 && totalReservedRoutes == 0) {
            return new RootLifecycleRecoveryPlan(State.CLEAN_STOPPED,
                    "No stale owned state; ready for manual full-stack startup.");
        }
        return new RootLifecycleRecoveryPlan(State.REPAIRABLE_STOPPED,
                "Tunnels and relay are stopped. Exact owned DNS/routing cleanup may be retried after explicit approval.");
    }
}
