package com.yooshastan.wonheeproxy;

/**
 * Experimental control plane for two independently keyed WireGuard sessions.
 * This is NOT an Android VPN backend: no sockets, private keys, or packets
 * are processed here. A future native engine must supply verified sessions.
 */
final class MultiTunnelSessionLedger {
    enum Phase { STOPPED, CONNECTING, READY, DEGRADED }

    private long homeEpoch;
    private long internetEpoch;
    private Phase homePhase = Phase.STOPPED;
    private Phase internetPhase = Phase.STOPPED;

    /**
     * Invalidate previous callbacks and begin a new session attempt.
     * The returned epoch must be passed with every asynchronous result.
     */
    synchronized long begin(MultiTunnelPacketRouter.Target session) {
        checkSession(session);
        if (session == MultiTunnelPacketRouter.Target.HOME) {
            homePhase = Phase.CONNECTING;
            return ++homeEpoch;
        }
        internetPhase = Phase.CONNECTING;
        return ++internetEpoch;
    }

    synchronized void ready(MultiTunnelPacketRouter.Target session, long epoch) {
        checkSession(session);
        if (session == MultiTunnelPacketRouter.Target.HOME) {
            if (epoch == homeEpoch && homePhase == Phase.CONNECTING) homePhase = Phase.READY;
        } else if (epoch == internetEpoch && internetPhase == Phase.CONNECTING) {
            internetPhase = Phase.READY;
        }
    }

    synchronized void failed(MultiTunnelPacketRouter.Target session, long epoch) {
        checkSession(session);
        if (session == MultiTunnelPacketRouter.Target.HOME) {
            if (epoch == homeEpoch && homePhase != Phase.STOPPED) homePhase = Phase.DEGRADED;
        } else if (epoch == internetEpoch && internetPhase != Phase.STOPPED) {
            internetPhase = Phase.DEGRADED;
        }
    }

    synchronized void stop(MultiTunnelPacketRouter.Target session) {
        checkSession(session);
        if (session == MultiTunnelPacketRouter.Target.HOME) {
            ++homeEpoch;
            homePhase = Phase.STOPPED;
        } else {
            ++internetEpoch;
            internetPhase = Phase.STOPPED;
        }
    }

    synchronized Phase phase(MultiTunnelPacketRouter.Target session) {
        checkSession(session);
        return session == MultiTunnelPacketRouter.Target.HOME ? homePhase : internetPhase;
    }

    /** A stalled/failed HOME must not be redirected through INTERNET, or vice versa. */
    synchronized MultiTunnelPacketRouter.Target route(
            MultiTunnelPacketRouter router, byte[] packet) {
        if (router == null) return MultiTunnelPacketRouter.Target.DROP;
        return router.route(packet, homePhase == Phase.READY, internetPhase == Phase.READY);
    }

    private static void checkSession(MultiTunnelPacketRouter.Target session) {
        if (session != MultiTunnelPacketRouter.Target.HOME
                && session != MultiTunnelPacketRouter.Target.INTERNET) {
            throw new IllegalArgumentException("Expected HOME or INTERNET session.");
        }
    }
}
