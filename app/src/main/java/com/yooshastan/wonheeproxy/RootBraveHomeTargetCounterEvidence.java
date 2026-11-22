package com.yooshastan.wonheeproxy;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Reads only packet totals for the first known counting-only Brave rule. */
final class RootBraveHomeTargetCounterEvidence {
    private static final Pattern COUNTER = Pattern.compile(
            "^\\s*([0-9]+)\\s+([0-9]+)\\s+\\S.*$");

    private RootBraveHomeTargetCounterEvidence() { }

    static RootMokaIpv6CounterParser.Counts firstRule(String listing) {
        if (listing == null || listing.length() > 32768) {
            throw new IllegalArgumentException("Missing or oversized counter inventory.");
        }
        RootMokaIpv6CounterParser.Counts first = null;
        int rows = 0;
        for (String raw : listing.split("\\r?\\n")) {
            Matcher match = COUNTER.matcher(raw);
            if (!match.matches()) continue;
            rows++;
            if (rows == 1) {
                try {
                    first = new RootMokaIpv6CounterParser.Counts(
                            Long.parseLong(match.group(1)),
                            Long.parseLong(match.group(2)));
                } catch (NumberFormatException invalid) {
                    throw new IllegalArgumentException("Invalid kernel counters.", invalid);
                }
            }
        }
        // The chain is verified separately to have exactly three rules,
        // in this order: count-only target; Home RETURN; terminal REJECT.
        if (rows != 3 || first == null) {
            throw new IllegalArgumentException("Unexpected firewall counter inventory.");
        }
        return first;
    }
}
