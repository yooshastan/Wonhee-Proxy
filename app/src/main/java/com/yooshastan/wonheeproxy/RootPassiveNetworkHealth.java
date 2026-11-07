package com.yooshastan.wonheeproxy;

import java.util.List;

/**
 * Manual, memory-only WireGuard health snapshots. No packet probes, background
 * monitoring, network mutation, profile secrets or persistent endpoint history.
 * A quiet tunnel is not necessarily broken and route predictions do not prove egress.
 */
final class RootPassiveNetworkHealth {
    private RootPassiveNetworkHealth() { }

    static final class Snapshot {
        final String device;
        final long epochSeconds;
        final long handshakeEpoch;
        final long rx;
        final long tx;
        final long transportMark;
        final String endpointIdentity; // RAM only; NEVER emitted to reports/logs.
        final String endpointFamily;
        final String underlay;

        Snapshot(String device, long epochSeconds, long handshakeEpoch,
                long rx, long tx, long transportMark, String endpointIdentity,
                String endpointFamily, String underlay) {
            if (device == null || !device.matches("wnm[0-9a-f]{12}")
                    || epochSeconds <= 0 || handshakeEpoch < -1
                    || rx < 0 || tx < 0 || transportMark < 0
                    || endpointIdentity == null || endpointFamily == null
                    || underlay == null) {
                throw new IllegalArgumentException("Invalid health snapshot shape.");
            }
            this.device = device;
            this.epochSeconds = epochSeconds;
            this.handshakeEpoch = handshakeEpoch;
            this.rx = rx;
            this.tx = tx;
            this.transportMark = transportMark;
            this.endpointIdentity = endpointIdentity;
            this.endpointFamily = endpointFamily;
            this.underlay = underlay;
        }
    }

    /** wg show IFACE latest-handshakes: exactly one peer key plus epoch. */
    static long handshakeTimestamp(List<String> lines) {
        if (lines == null || lines.size() != 1 || lines.get(0) == null) return -1;
        String[] fields = lines.get(0).trim().split("\\s+");
        // Parse but NEVER display, save or log the peer public key.
        if (fields.length != 2 || fields[0].isEmpty()
                || !fields[1].matches("[0-9]{1,19}")) return -1;
        try { return Long.parseLong(fields[1]); }
        catch (NumberFormatException ignored) { return -1; }
    }

    static String handshakeAge(long handshakeEpoch, long nowEpoch) {
        if (handshakeEpoch < 0) return "UNAVAILABLE";
        if (handshakeEpoch == 0) return "never observed";
        if (nowEpoch < handshakeEpoch) return "DEVICE CLOCK SKEW / UNKNOWN";
        long age = nowEpoch - handshakeEpoch;
        return age + " seconds ago" + (age > 180
                ? " (possibly idle; NOT proof of a broken tunnel)" : "");
    }

    static String render(String label, Snapshot previous, Snapshot current) {
        if (current == null) return label + ": NO VERIFIED SNAPSHOT";
        StringBuilder out = new StringBuilder(label).append(" (")
                .append(current.device).append(")\n");
        out.append("  Last handshake: ")
                .append(handshakeAge(current.handshakeEpoch, current.epochSeconds))
                .append('\n');
        out.append("  Cumulative WireGuard RX/TX: ")
                .append(current.rx).append(" / ").append(current.tx)
                .append(" bytes\n");
        out.append("  UDP mark: ").append(RootFirewallMark.display(current.transportMark))
                .append("; numeric endpoint: ").append(current.endpointFamily)
                .append("; predicted physical underlay: ")
                .append(current.underlay.isEmpty() ? "UNVERIFIED" : current.underlay)
                .append('\n');

        if (previous == null || !previous.device.equals(current.device)) {
            out.append("  Previous sample: none in this app process; repeat manually to compare.");
            return out.toString();
        }
        if (current.epochSeconds < previous.epochSeconds
                || current.rx < previous.rx || current.tx < previous.tx) {
            out.append("  Counter or clock reset; no reliable delta. Do not infer a leak.");
            return out.toString();
        }
        out.append("  Since last manual snapshot: ")
                .append(current.epochSeconds - previous.epochSeconds)
                .append(" s, RX +").append(current.rx - previous.rx)
                .append(" B, TX +").append(current.tx - previous.tx).append(" B\n");
        if (!previous.underlay.isEmpty() && !current.underlay.isEmpty()
                && !previous.underlay.equals(current.underlay)) {
            out.append("  UNDERLAY ROUTE PREDICTION CHANGED since last snapshot\n");
        }
        if (!previous.endpointIdentity.isEmpty() && !current.endpointIdentity.isEmpty()
                && !previous.endpointIdentity.equals(current.endpointIdentity)) {
            out.append("  WIREGUARD ENDPOINT CHANGED since last snapshot (address withheld)\n");
        }
        if (current.rx == previous.rx && current.tx == previous.tx) {
            out.append("  No counter increase observed (may be idle; NOT a failure diagnosis)");
        } else {
            out.append("  Counter movement observed (not end-to-end reachability proof)");
        }
        return out.toString();
    }
}
