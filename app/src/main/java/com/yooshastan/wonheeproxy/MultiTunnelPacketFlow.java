package com.yooshastan.wonheeproxy;

/**
 * Experimental packet preparation and ingress ownership checks for a future
 * rootless dual-session WireGuard backend. Offline-only: does not open sockets,
 * obtain VPN permission, process keys, or transmit traffic.
 *
 * IPv6 and fragmented IPv4 remain blocked here until there are independent
 * tests for safe translation on both encrypted interfaces.
 */
final class MultiTunnelPacketFlow {
    static final class Outbound {
        final MultiTunnelPacketRouter.Target target;
        final byte[] packet;
        final MultiTunnelSessionLedger.Permit permit;

        private Outbound(MultiTunnelPacketRouter.Target target, byte[] packet,
                         MultiTunnelSessionLedger.Permit permit) {
            this.target = target;
            this.packet = packet;
            this.permit = permit;
        }

        boolean dropped() { return target == MultiTunnelPacketRouter.Target.DROP; }
    }

    private final MultiTunnelPacketRouter router;
    private final MultiTunnelSessionLedger ledger;
    private final MultiTunnelIpv4Rewriter home;
    private final MultiTunnelIpv4Rewriter internet;

    MultiTunnelPacketFlow(MultiTunnelPacketRouter router,
                          MultiTunnelSessionLedger ledger,
                          String virtualTunIpv4, String homeClientIpv4,
                          String internetClientIpv4) {
        if (router == null || ledger == null) {
            throw new IllegalArgumentException("Router and ledger required.");
        }
        if (MultiTunnelIpv4Rewriter.parseIpv4(homeClientIpv4)
                == MultiTunnelIpv4Rewriter.parseIpv4(internetClientIpv4)) {
            throw new IllegalArgumentException("Tunnel addresses must be unique.");
        }
        this.router = router;
        this.ledger = ledger;
        home = new MultiTunnelIpv4Rewriter(virtualTunIpv4, homeClientIpv4);
        internet = new MultiTunnelIpv4Rewriter(virtualTunIpv4, internetClientIpv4);
    }

    Outbound outgoing(byte[] androidTunPacket) {
        MultiTunnelSessionLedger.Permit permit = ledger.authorizeOutbound(router, androidTunPacket);
        if (permit == null) return drop();
        byte[] translated = rewriter(permit.target).toSession(androidTunPacket);
        if (translated == null || !ledger.permits(permit)) return drop();
        return new Outbound(permit.target, translated, permit);
    }

    /** Must also be invoked by the future sender on its serialized send queue. */
    boolean stillAuthorized(Outbound outbound) {
        return outbound != null && !outbound.dropped()
                && ledger.permits(outbound.permit);
    }

    /** Null means DROP. Ingress ownership must match the wireguard-go instance. */
    byte[] incoming(MultiTunnelPacketRouter.Target from, byte[] encryptedSessionPacket) {
        if (from != MultiTunnelPacketRouter.Target.HOME
                && from != MultiTunnelPacketRouter.Target.INTERNET) return null;
        if (!ledger.isReady(from)
                || router.expectedReplySource(encryptedSessionPacket) != from) return null;
        return rewriter(from).toTun(encryptedSessionPacket);
    }

    private MultiTunnelIpv4Rewriter rewriter(MultiTunnelPacketRouter.Target target) {
        return target == MultiTunnelPacketRouter.Target.HOME ? home : internet;
    }

    private static Outbound drop() {
        return new Outbound(MultiTunnelPacketRouter.Target.DROP, null, null);
    }
}
