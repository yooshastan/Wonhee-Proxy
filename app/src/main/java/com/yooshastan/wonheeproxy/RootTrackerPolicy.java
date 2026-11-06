package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Offline, explicit DNS tracker policy. No download, reporting, or telemetry. */
final class RootTrackerPolicy {
    private RootTrackerPolicy() { }

    // Deliberately narrow baseline to reduce site breakage. These are not a
    // substitute for a maintained, independently audited filtering catalog.
    private static final List<String> BUILT_INS = Collections.unmodifiableList(Arrays.asList(
            "app-measurement.com", "google-analytics.com", "doubleclick.net",
            "googlesyndication.com", "adservice.google.com", "analytics.twitter.com",
            "ads.yahoo.com", "scorecardresearch.com", "pixel.facebook.com"));

    static List<String> builtIns() { return BUILT_INS; }

    static final class Config {
        final boolean enabled;
        final List<String> blocked;
        final List<String> allowed;

        Config(boolean enabled, List<String> blocked, List<String> allowed) {
            this.enabled = enabled;
            this.blocked = blocked;
            this.allowed = allowed;
        }

        String serialized() {
            if (!enabled) return "";
            StringBuilder result = new StringBuilder();
            for (String domain : blocked) result.append("block ").append(domain).append('\n');
            for (String domain : allowed) result.append("allow ").append(domain).append('\n');
            return result.toString();
        }

        boolean shouldBlock(String domain) {
            if (!enabled) return false;
            String name = normalize(domain);
            for (String exception : allowed) if (matches(name, exception)) return false;
            for (String blockedDomain : blocked) if (matches(name, blockedDomain)) return true;
            return false;
        }
    }

    static Config compile(boolean enabled, String customBlocks, String exceptions) {
        if (!enabled) return new Config(false, Collections.emptyList(), Collections.emptyList());
        LinkedHashSet<String> blocked = new LinkedHashSet<>(BUILT_INS);
        blocked.addAll(parseDomains(customBlocks));
        List<String> allowed = parseDomains(exceptions);
        return new Config(true, Collections.unmodifiableList(new ArrayList<>(blocked)),
                Collections.unmodifiableList(allowed));
    }

    private static List<String> parseDomains(String lines) {
        Set<String> parsed = new LinkedHashSet<>();
        if (lines == null || lines.trim().isEmpty()) return new ArrayList<>();
        if (lines.length() > 24_000) throw new IllegalArgumentException("Tracker list is too large.");
        for (String line : lines.split("\\r?\\n", -1)) {
            String value = line.trim();
            if (value.isEmpty()) continue;
            if (parsed.size() >= 128) throw new IllegalArgumentException("Maximum 128 custom domains.");
            value = normalize(value);
            if (!validDomain(value) || value.endsWith(".local")
                    || value.endsWith(".internal") || value.endsWith(".arpa")) {
                throw new IllegalArgumentException("Use plain domain names only; no wildcard, IP, URL or local suffix.");
            }
            parsed.add(value);
        }
        return new ArrayList<>(parsed);
    }

    static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    static boolean validDomain(String value) {
        if (value.isEmpty() || value.length() > 253 || !value.contains(".") || value.endsWith(".")
                || value.matches("[0-9]+(\\.[0-9]+){3}")) {
            return false;
        }
        String[] labels = value.split("\\.", -1);
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63 || label.startsWith("-")
                    || label.endsWith("-")) return false;
            for (int i = 0; i < label.length(); i++) {
                char c = label.charAt(i);
                if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-') {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean matches(String name, String suffix) {
        return name.equals(suffix) || name.endsWith("." + suffix);
    }
}
