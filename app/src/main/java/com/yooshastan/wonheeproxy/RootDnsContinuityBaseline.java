package com.yooshastan.wonheeproxy;

import java.util.Locale;

/**
 * Aggregated, user-requested before/after DNS observation only.
 * No addresses, queried domains, process names, keys, or traffic payloads.
 * Does not prove firewall enforcement, tunnel continuity or a lack of DNS bypass.
 */
final class RootDnsContinuityBaseline {
    private static final String VERSION = "WN_DNS_BASELINE_V1";
    private static final long CLOCK_TOLERANCE_MS = 5 * 60 * 1000L;
    private static final long MAX_AGE_MS = 30L * 24 * 60 * 60 * 1000L;

    static final class Reading {
        final long wallMs, elapsedMs;
        final boolean rootsAvailable, relayVerified, trackerEnabled;
        final int verifiedTunnels, presentTunnels, relayPid;
        final long received, blocked, forwarded, failed;

        Reading(long wallMs, long elapsedMs, boolean rootsAvailable,
                boolean relayVerified, boolean trackerEnabled,
                int verifiedTunnels, int presentTunnels, int relayPid,
                long received, long blocked, long forwarded, long failed) {
            this.wallMs = wallMs;
            this.elapsedMs = elapsedMs;
            this.rootsAvailable = rootsAvailable;
            this.relayVerified = relayVerified;
            this.trackerEnabled = trackerEnabled;
            this.verifiedTunnels = verifiedTunnels;
            this.presentTunnels = presentTunnels;
            this.relayPid = relayPid;
            this.received = received;
            this.blocked = blocked;
            this.forwarded = forwarded;
            this.failed = failed;
        }

        boolean usable() {
            return rootsAvailable && relayVerified && trackerEnabled
                    && verifiedTunnels > 0 && verifiedTunnels == presentTunnels
                    && relayPid >= 2 && wallMs > 0 && elapsedMs >= 0
                    && received >= 0 && blocked >= 0 && forwarded >= 0 && failed >= 0
                    && blocked <= received && forwarded <= received - blocked
                    && failed <= received;
        }
    }

    private RootDnsContinuityBaseline() { }

    static String encode(Reading sample) {
        if (sample == null || !sample.usable()) {
            throw new IllegalArgumentException("A verified DNS relay, tracker filter, counters and tunnels are required.");
        }
        return VERSION + "|" + sample.wallMs + "|" + sample.elapsedMs + "|"
                + sample.relayPid + "|" + sample.verifiedTunnels + "|"
                + sample.received + "|" + sample.blocked + "|"
                + sample.forwarded + "|" + sample.failed;
    }

    static Reading decode(String raw) {
        if (raw == null || raw.length() > 240) {
            throw new IllegalArgumentException("Unrecognized DNS baseline.");
        }
        String[] parts = raw.split("\\|", -1);
        if (parts.length != 9 || !VERSION.equals(parts[0])) {
            throw new IllegalArgumentException("Unrecognized DNS baseline.");
        }
        try {
            Reading sample = new Reading(Long.parseLong(parts[1]),
                    Long.parseLong(parts[2]), true, true, true,
                    Integer.parseInt(parts[4]), Integer.parseInt(parts[4]),
                    Integer.parseInt(parts[3]), Long.parseLong(parts[5]),
                    Long.parseLong(parts[6]), Long.parseLong(parts[7]),
                    Long.parseLong(parts[8]));
            if (!sample.usable()) throw new IllegalArgumentException("Invalid DNS baseline.");
            return sample;
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("Invalid DNS baseline.", invalid);
        }
    }

    static String compare(Reading baseline, Reading current) {
        if (baseline == null) return "No saved baseline. Capture a verified working state first.";
        if (current == null || !current.rootsAvailable) {
            return "CURRENT STATE UNAVAILABLE. Cannot compare DNS service after baseline.";
        }
        if (current.wallMs < baseline.wallMs || current.elapsedMs < baseline.elapsedMs
                || current.wallMs - baseline.wallMs > MAX_AGE_MS) {
            return "BASELINE STALE OR DEVICE REBOOTED. Capture a new baseline.";
        }
        long wallDelta = current.wallMs - baseline.wallMs;
        long uptimeDelta = current.elapsedMs - baseline.elapsedMs;
        if (Math.abs(wallDelta - uptimeDelta) > CLOCK_TOLERANCE_MS) {
            return "REBOOT OR DEVICE CLOCK CHANGE SUSPECTED. Baseline cannot prove continuity.";
        }
        if (!current.relayVerified) {
            return "DNS RELAY NOT VERIFIED NOW. Check live listener and DNS firewall audit.";
        }
        if (current.relayPid < 2 || current.received < 0 || current.blocked < 0
                || current.forwarded < 0 || current.failed < 0) {
            return "DNS AGGREGATE COUNTERS UNAVAILABLE NOW. Relay may still be running; "
                    + "check its statistics and live audit.";
        }
        if (!current.trackerEnabled) {
            return "TRACKER FILTER NOT VERIFIED AS ENABLED NOW. Check the DNS audit.";
        }
        if (current.presentTunnels != baseline.presentTunnels
                || current.verifiedTunnels != baseline.verifiedTunnels) {
            return "TUNNEL COUNT OR IDENTITY HEALTH CHANGED. Audit the active tunnels.";
        }
        if (current.relayPid != baseline.relayPid) {
            return "DNS RELAY PID CHANGED. A restart or different process is possible.";
        }
        if (current.received < baseline.received || current.blocked < baseline.blocked
                || current.forwarded < baseline.forwarded || current.failed < baseline.failed) {
            return "DNS COUNTER RESET OR REPLACEMENT DETECTED. Recheck relay identity.";
        }
        long minutes = wallDelta / 60000L;
        return String.format(Locale.ROOT,
                "Same verified relay PID; %d min since baseline. "
                + "DNS received +%d, blocked +%d, forwarded +%d, failed +%d. "
                + "Counters cannot prove continuous uptime or browser DNS coverage.",
                minutes,
                current.received - baseline.received,
                current.blocked - baseline.blocked,
                current.forwarded - baseline.forwarded,
                current.failed - baseline.failed);
    }
}
