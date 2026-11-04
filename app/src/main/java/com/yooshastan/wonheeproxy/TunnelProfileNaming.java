package com.yooshastan.wonheeproxy;

import java.util.List;
import java.util.Locale;

/** Only handles display names; never reads, logs or transforms WireGuard keys. */
final class TunnelProfileNaming {
    private static final int MAX_LENGTH = 64;

    private TunnelProfileNaming() { }

    static String fromFilename(String filename) {
        String value = filename == null ? "" : filename.trim();
        int separator = Math.max(value.lastIndexOf('/'), value.lastIndexOf('\\'));
        if (separator >= 0) value = value.substring(separator + 1);
        if (value.toLowerCase(Locale.ROOT).endsWith(".conf")) {
            value = value.substring(0, value.length() - 5);
        }
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < value.length() && result.length() < MAX_LENGTH; i++) {
            char symbol = value.charAt(i);
            if (Character.isISOControl(symbol) || symbol == '/' || symbol == '\\'
                    || symbol == '"' || symbol == '<' || symbol == '>') {
                result.append(' ');
            } else {
                result.append(symbol);
            }
        }
        String cleaned = result.toString().trim();
        return cleaned.isEmpty() ? "WireGuard tunnel" : cleaned;
    }

    static String unique(String requested, List<String> existing) {
        String base = fromFilename(requested);
        if (!alreadyPresent(base, existing)) return base;
        for (int suffix = 2; suffix <= 100; suffix++) {
            String tail = " (" + suffix + ")";
            String stem = base.substring(0, Math.min(base.length(), MAX_LENGTH - tail.length())).trim();
            String candidate = stem + tail;
            if (!alreadyPresent(candidate, existing)) return candidate;
        }
        throw new IllegalArgumentException("Too many similarly named tunnels.");
    }

    private static boolean alreadyPresent(String name, List<String> existing) {
        if (existing == null) return false;
        for (String other : existing) {
            if (other != null && other.equalsIgnoreCase(name)) return true;
        }
        return false;
    }
}
