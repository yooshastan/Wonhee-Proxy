package com.yooshastan.wonheeproxy;

/** Local status only; the report is not a protection or leak audit. */
final class VpnHealthSummary {
    private VpnHealthSummary() { }

    static String render(boolean interfaceUp, boolean statsAvailable, long handshakeAgeSeconds,
                         boolean dnsConfigured, boolean alwaysOn, boolean lockdown) {
        StringBuilder summary = new StringBuilder();
        summary.append("Interface: ").append(interfaceUp ? "UP" : "DOWN").append('\n');
        if (!interfaceUp) {
            summary.append("Handshake: not active");
        } else if (!statsAvailable) {
            summary.append("Handshake: statistics unavailable");
        } else if (handshakeAgeSeconds < 0) {
            summary.append("Handshake: not observed yet");
        } else if (handshakeAgeSeconds <= 180) {
            summary.append("Handshake: observed ").append(handshakeAgeSeconds).append("s ago");
        } else {
            summary.append("Handshake: possibly stale (").append(handshakeAgeSeconds)
                    .append("s ago)");
        }
        summary.append("\nVPN DNS configuration: ")
                .append(dnsConfigured ? "present, not tested" : "missing");
        summary.append("\nAndroid Always-on: ").append(alwaysOn ? "ON" : "OFF");
        summary.append(" | Block outside VPN: ").append(lockdown ? "ON" : "OFF");
        summary.append("\nLocal status only. DNS, HTTPS and leak behavior are not proven.");
        return summary.toString();
    }
}
