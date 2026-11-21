package com.yooshastan.wonheeproxy;

/**
 * Pure parser for private table 51002, protecting 10.0.0.169/32 only.
 *
 * This is structural route evidence, not a proof of Android socket routing,
 * routing-rule precedence, Home link-loss behavior or fail-closed delivery.
 */
final class RootMokaHomeTerminalRouteEvidence {
    static final class Snapshot {
        final boolean homePresent;
        final boolean terminalPresent;
        final boolean collision;
        Snapshot(boolean homePresent, boolean terminalPresent,
                boolean collision) {
            this.homePresent = homePresent;
            this.terminalPresent = terminalPresent;
            this.collision = collision;
        }
    }
    private RootMokaHomeTerminalRouteEvidence() { }

    static Snapshot inspect(String listing, String homeDevice) {
        if (listing == null || listing.length() > 32768
                || homeDevice == null
                || !homeDevice.matches("wnm[0-9a-f]{12}")) {
            throw new IllegalArgumentException("Invalid private Home table listing.");
        }
        int home = 0, terminal = 0;
        boolean foreign = false;
        for (String line : listing.split("\\r?\\n")) {
            String trimmed = line.trim().replaceAll("\\s+", " ");
            if (trimmed.isEmpty()) continue;
            String[] tokens = trimmed.split(" ");
            int index = tokens[0].equals("unreachable") ? 1 : 0;
            if (tokens.length <= index) continue;
            String dest = tokens[index];
            if (!dest.equals("10.0.0.169")
                    && !dest.equals("10.0.0.169/32")) continue;
            if (index == 1) {
                boolean expected = true;
                int metricCount = 0;
                for (int i = 2; i < tokens.length; i++) {
                    String t = tokens[i];
                    if (t.equals("metric")) {
                        metricCount++;
                        if (++i >= tokens.length || !tokens[i].equals("42700")) {
                            expected = false;
                            break;
                        }
                    } else if (t.equals("proto")) {
                        if (++i >= tokens.length || !tokens[i].matches("[a-z0-9_]+")) {
                            expected = false;
                            break;
                        }
                    } else {
                        expected = false;
                    }
                }
                if (expected && metricCount == 1) terminal++;
                else foreign = true;
            } else {
                // An existing route is acceptable only when it is exactly
                // an on-link route to the independently verified Home device.
                boolean expected = tokens.length >= 3
                        && tokens[1].equals("dev")
                        && tokens[2].equals(homeDevice);
                for (int i = 3; i < tokens.length; i++) {
                    if (tokens[i].equals("scope") && i + 1 < tokens.length
                            && tokens[i + 1].equals("link")) {
                        i++;
                    } else if (tokens[i].equals("proto") && i + 1 < tokens.length
                            && tokens[i + 1].matches("[a-z0-9_]+")) {
                        i++;
                    } else {
                        expected = false;
                    }
                }
                if (expected) home++;
                else foreign = true;
            }
        }
        return new Snapshot(home == 1, terminal == 1,
                foreign || home > 1 || terminal > 1);
    }
}
