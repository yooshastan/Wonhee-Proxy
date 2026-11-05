package com.yooshastan.wonheeproxy;

/** Passive, per-interface WireGuard status. No packet-leak or reachability claims. */
final class RootTunnelHealth {
    private RootTunnelHealth() { }

    static String render(String label, boolean up, long received, long sent,
                         long handshakeAgeSeconds, TunnelTrafficRates.Result rates) {
        if (!up) return label + ": DOWN";
        String handshake = handshakeAgeSeconds < 0 ? "none observed"
                : handshakeAgeSeconds <= 180 ? handshakeAgeSeconds + "s ago"
                : handshakeAgeSeconds + "s ago (possibly idle/stale)";
        String speed = rates == null ? "measuring" :
                "↓ " + TunnelTrafficRates.formatSpeed(rates.downloadMbps)
                + ", ↑ " + TunnelTrafficRates.formatSpeed(rates.uploadMbps);
        return label + ": UP | handshake " + handshake
                + "\n  Total ↓ " + TunnelTrafficRates.formatTotal(received)
                + "  ↑ " + TunnelTrafficRates.formatTotal(sent)
                + "\n  Speed " + speed;
    }
}
