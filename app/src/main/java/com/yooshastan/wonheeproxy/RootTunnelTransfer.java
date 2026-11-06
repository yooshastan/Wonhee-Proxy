package com.yooshastan.wonheeproxy;

import java.util.List;

/** Non-secret, cumulative WireGuard byte counters for one verified peer. */
final class RootTunnelTransfer {
    final long received;
    final long sent;

    private RootTunnelTransfer(long received, long sent) {
        this.received = received;
        this.sent = sent;
    }

    static RootTunnelTransfer parse(List<String> lines) {
        if (lines == null || lines.size() != 1 || lines.get(0) == null) return null;
        String[] fields = lines.get(0).trim().split("\\s+");
        // `wg show IFACE transfer` = peer-public-key, rx bytes, tx bytes.
        // Never expose, save, or render the peer key in a report.
        if (fields.length != 3 || fields[0].isEmpty()) return null;
        if (!fields[1].matches("[0-9]{1,19}") || !fields[2].matches("[0-9]{1,19}")) {
            return null;
        }
        try {
            return new RootTunnelTransfer(Long.parseLong(fields[1]),
                    Long.parseLong(fields[2]));
        } catch (NumberFormatException invalid) { return null; }
    }

    static String delta(RootTunnelTransfer before, RootTunnelTransfer after) {
        if (before == null || after == null || after.received < before.received
                || after.sent < before.sent) return "UNAVAILABLE / COUNTER RESET";
        return "rx +" + (after.received - before.received) + " B; tx +"
                + (after.sent - before.sent) + " B";
    }
}
