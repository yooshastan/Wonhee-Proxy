package com.yooshastan.wonheeproxy;

import java.util.HashSet;
import java.util.Set;

/**
 * Pure, narrow readback of Android iproute2 UID rule and terminal private
 * route listings. This is only part of the ownership check; persistent
 * journal identity and current tunnel public keys must ALSO be verified.
 */
final class RootIsolatedUidPolicyListing {
    enum Match { ABSENT, EXACT, FOREIGN_OR_CHANGED }

    private RootIsolatedUidPolicyListing() { }

    static Match selector(String output, int family, int priority,
            int uid, int table) {
        if (output == null || (family != 4 && family != 6)
                || priority < 12800 || priority > 12999
                || uid < 10000 || uid > 99999
                || table < 51000 || table > 51007) {
            return Match.FOREIGN_OR_CHANGED;
        }
        String exact = "from all fwmark 0x0/0x20000 iif lo uidrange "
                + uid + "-" + uid + " lookup " + table;
        boolean matched = false;
        for (String raw : output.split("\\r?\\n")) {
            String line = raw.trim().replaceAll("\\s+", " ");
            if (!line.startsWith(priority + ":")) continue;
            int colon = line.indexOf(':');
            String body = line.substring(colon + 1).trim();
            if (!exact.equals(body) || matched) {
                return Match.FOREIGN_OR_CHANGED;
            }
            matched = true;
        }
        return matched ? Match.EXACT : Match.ABSENT;
    }

    static Match terminalDefault(String output, int family) {
        if (output == null || (family != 4 && family != 6)) {
            return Match.FOREIGN_OR_CHANGED;
        }
        boolean seen = false;
        for (String raw : output.split("\\r?\\n")) {
            String line = raw.trim().replaceAll("\\s+", " ");
            if (line.isEmpty()) continue;
            if (!line.startsWith("unreachable default")) continue;
            String[] tokens = line.split(" ");
            Set<String> parts = new HashSet<>();
            java.util.Collections.addAll(parts, tokens);
            // Supported iproute2 displays: unreachable default metric N
            // and unreachable default proto boot metric N. A strange
            // attribute is foreign until verified, never auto-adopted.
            boolean exactly = line.equals("unreachable default metric 42700")
                    || line.equals("unreachable default proto boot metric 42700");
            if (!exactly || seen) {
                return Match.FOREIGN_OR_CHANGED;
            }
            seen = true;
        }
        return seen ? Match.EXACT : Match.ABSENT;
    }
}
