package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure, read-only interpretation of independent root audit reports.
 * A completed audit is never described as a running kill switch or DNS protection.
 */
final class RootSafetyGuide {
    static final String[] TITLES = {
            "Kernel tunnel identities", "Root route selection", "Configured DNS routes",
            "Endpoint and Android DNS inventory", "Firewall readiness (not enforcement)"
    };
    static final int STEP_COUNT = TITLES.length;
    private static final Pattern RATIO = Pattern.compile("(\\d+)/(\\d+)");

    static final class Finding {
        final String label;
        final boolean needsAttention;
        final String explanation;
        final String detail;

        Finding(String label, boolean needsAttention, String explanation, String detail) {
            this.label = label;
            this.needsAttention = needsAttention;
            this.explanation = explanation;
            this.detail = detail;
        }
    }

    private RootSafetyGuide() { }

    static Finding assess(int step, int selected, boolean completed, String report) {
        if (step < 0 || step >= STEP_COUNT) throw new IllegalArgumentException("Invalid step.");
        String value = report == null ? "" : report;
        if (!completed) {
            return new Finding("CHECK REQUIRED", true,
                    "This read-only check could not finish. Review its report before changing routes.", value);
        }
        switch (step) {
            case 0:
                int verified = 0;
                for (String line : value.split("\\n")) {
                    if (line.contains(": UP; identity MATCH")) verified++;
                }
                boolean identities = selected > 0 && verified == selected;
                return new Finding(identities ? "IDENTITIES MATCH" : "CHECK IDENTITIES", !identities,
                        identities ? "Selected kernel links are UP with matching saved identities."
                                : "At least one selected tunnel is down or its identity was not verified.", value);
            case 1:
                boolean routeMismatch = value.contains("MISMATCH") || value.contains("WARNING");
                int[] routeCount = countAfter(value, "Split-route matches:");
                boolean routeMatches = routeCount != null && routeCount[0] == routeCount[1];
                return new Finding(!routeMismatch && routeMatches ? "ROUTES MATCH" : "CHECK ROUTING",
                        routeMismatch || !routeMatches,
                        !routeMismatch && routeMatches ? "Root route selection matches the planned split destinations."
                                : "A route or routing ownership issue needs review. Do not disconnect or overwrite rules.", value);
            case 2:
                int[] resolver = countAfter(value, "Configured resolver root-route matches:");
                boolean configured = resolver != null && resolver[1] > 0;
                boolean dnsRoutesMatch = configured && resolver[0] == resolver[1]
                        && !value.contains("MISMATCH/UNROUTED");
                return new Finding(dnsRoutesMatch ? "DNS ROUTES MATCH"
                        : configured ? "CHECK DNS ROUTES" : "NO RESOLVERS AUDITED",
                        !dnsRoutesMatch,
                        dnsRoutesMatch ? "Configured DNS addresses route to the expected tunnel; actual resolver traffic was not tested."
                                : configured ? "A configured resolver routes unexpectedly."
                                : "No resolver addresses were available for route verification.", value);
            case 3:
                return new Finding("INVENTORY RECORDED", false,
                        "Transport and Android DNS state were inspected. This is not a packet or DNS leak test.", value);
            case 4:
                return new Finding("KILL SWITCH OFF", false,
                        "Protection prerequisites were inspected; no firewall, DNS blocking or fail-closed rules were installed.", value);
            default:
                throw new IllegalStateException("Unknown step.");
        }
    }

    private static int[] countAfter(String report, String heading) {
        int start = report.indexOf(heading);
        if (start < 0) return null;
        int end = report.indexOf('\n', start);
        String section = report.substring(start, end < 0 ? report.length() : end);
        Matcher matched = RATIO.matcher(section);
        if (!matched.find()) return null;
        return new int[] {Integer.parseInt(matched.group(1)), Integer.parseInt(matched.group(2))};
    }

    static String summary(List<Finding> findings) {
        if (findings.isEmpty()) return "Select running profiles, then run a guided read-only check.";
        List<String> issues = new ArrayList<>();
        StringBuilder text = new StringBuilder();
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            text.append(i + 1).append(". ").append(TITLES[i]).append(": ")
                    .append(f.label).append('\n');
            if (f.needsAttention) issues.add(TITLES[i]);
        }
        if (findings.size() < STEP_COUNT) {
            text.append("Next: review the last failed check before continuing.");
        } else if (!issues.isEmpty()) {
            text.append("Next: review ").append(issues.get(0))
                    .append(" in details. Changes require separate confirmation.");
        } else {
            text.append("Next: choose a tunnel and explicitly test root-bound DoH. "
                    + "No DNS protection or kill switch was activated.");
        }
        return text.toString();
    }
}
