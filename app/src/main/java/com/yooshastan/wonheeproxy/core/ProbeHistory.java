package com.yooshastan.wonheeproxy.core;

import java.util.Locale;

/**
 * In-memory, endpoint-free TCP probe statistics. This does not represent
 * MTProto authentication, a Telegram route, a VPN, or server uptime.
 */
public final class ProbeHistory {
    private static final int MAX_SAMPLES = 32;
    private final ProxyProbe.Status[] recent = new ProxyProbe.Status[MAX_SAMPLES];
    private int cursor;
    private int size;
    private long samples;
    private long successes;
    private long timeouts;
    private long dnsFailures;
    private long refusedOrUnreachable;
    private long totalSuccessLatencyMs;
    private long maxSuccessLatencyMs;
    private ProxyProbe.Status last;
    private long lastElapsedMs;

    public void record(ProxyProbe.Status result, long elapsedMillis) {
        if (result == null || elapsedMillis < 0) {
            throw new IllegalArgumentException("Invalid TCP probe result");
        }
        recent[cursor] = result;
        cursor = (cursor + 1) % MAX_SAMPLES;
        size = Math.min(MAX_SAMPLES, size + 1);
        samples++;
        last = result;
        lastElapsedMs = elapsedMillis;
        switch (result) {
            case REACHABLE:
                successes++;
                totalSuccessLatencyMs += elapsedMillis;
                maxSuccessLatencyMs = Math.max(maxSuccessLatencyMs, elapsedMillis);
                break;
            case TIMEOUT: timeouts++; break;
            case DNS_FAILURE: dnsFailures++; break;
            case UNREACHABLE: refusedOrUnreachable++; break;
        }
    }

    public long sampleCount() { return samples; }
    public long reachableCount() { return successes; }
    public long failedCount() { return samples - successes; }

    public int recentReachableCount() {
        int passed = 0;
        for (int i = 0; i < size; i++) {
            if (recent[i] == ProxyProbe.Status.REACHABLE) passed++;
        }
        return passed;
    }

    public int recentSampleCount() { return size; }

    public String shortSummary() {
        if (samples == 0) return "No probes yet.";
        String lastResult = last == ProxyProbe.Status.REACHABLE ? "reachable"
                : last == ProxyProbe.Status.TIMEOUT ? "timeout"
                : last == ProxyProbe.Status.DNS_FAILURE ? "DNS failure" : "connection failed";
        return String.format(Locale.US,
                "Last TCP check: %s (%d ms). Reachable: %d/%d. "
                        + "Recent window: %d/%d reachable.",
                lastResult, lastElapsedMs, successes, samples,
                recentReachableCount(), recentSampleCount());
    }

    /** Shares no server IP, host, secret, username, or password. */
    public String redactedSnapshot(boolean running, long observedMillis) {
        StringBuilder report = new StringBuilder("Wonhee Proxy TCP diagnostics");
        report.append("\nMonitor: ").append(running ? "foreground-only active" : "stopped");
        report.append("\nObservation: ").append(Math.max(0L, observedMillis / 1000)).append(" s");
        report.append("\nTCP samples: ").append(samples);
        report.append("\nTCP reachable: ").append(successes);
        report.append("\nTCP failures: ").append(failedCount());
        report.append("\nTimeouts: ").append(timeouts);
        report.append("\nDNS failures: ").append(dnsFailures);
        report.append("\nOther connect failures: ").append(refusedOrUnreachable);
        if (successes > 0) {
            report.append("\nMean successful TCP latency: ")
                    .append(totalSuccessLatencyMs / successes).append(" ms");
            report.append("\nMax successful TCP latency: ")
                    .append(maxSuccessLatencyMs).append(" ms");
        }
        report.append("\nLast: ").append(last == null ? "not tested" : last.name());
        report.append("\nNot an MTProto/SOCKS5 handshake test.");
        report.append("\nNot a Telegram routing, DNS, identity or leak audit.");
        return report.toString();
    }
}
