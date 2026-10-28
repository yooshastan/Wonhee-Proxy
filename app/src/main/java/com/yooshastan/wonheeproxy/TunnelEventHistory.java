package com.yooshastan.wonheeproxy;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Bounded, ephemeral history of local WireGuard observations.
 * Never accepts peer addresses, profile contents, keys or endpoint names.
 * No network calls or disk persistence.
 */
final class TunnelEventHistory {
    private static final int MAX_EVENTS = 12;
    private final Deque<String> events = new ArrayDeque<>();
    private String lastState;

    void observe(boolean interfaceUp, boolean statisticsAvailable, long handshakeAgeSeconds) {
        String state = stateFor(interfaceUp, statisticsAvailable, handshakeAgeSeconds);
        if (state.equals(lastState)) return;
        lastState = state;
        events.addFirst(state);
        while (events.size() > MAX_EVENTS) events.removeLast();
    }

    private static String stateFor(boolean up, boolean stats, long ageSeconds) {
        if (!up) return "VPN interface down";
        if (!stats) return "VPN interface active; statistics unavailable";
        if (ageSeconds < 0) return "Waiting for first WireGuard handshake";
        if (ageSeconds <= 180) return "Recent WireGuard handshake observed";
        return "Last WireGuard handshake may be stale";
    }

    int size() {
        return events.size();
    }

    String render() {
        if (events.isEmpty()) return "Waiting for a local VPN status sample...";
        StringBuilder output = new StringBuilder();
        for (String event : events) {
            if (output.length() > 0) output.append('\n');
            output.append("• ").append(event);
        }
        return output.toString();
    }
}
