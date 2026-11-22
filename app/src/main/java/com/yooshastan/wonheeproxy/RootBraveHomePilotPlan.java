package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.List;

/** Exact command and read-only inventory contract for debug-only Brave Nightly. */
final class RootBraveHomePilotPlan {
    static final int PRIORITY = 12699;
    static final String HOST = "10.0.0.169";
    static final String TARGET = HOST + "/32";
    static final int TABLE = 51002;
    static final String CHAIN4 = "WN_BRAVE_HOME4";
    static final String CHAIN6 = "WN_BRAVE_HOME6";
    static final String TAG4 = "WN_BRAVE_HOME4_EXACT_V1";
    static final String TAG6 = "WN_BRAVE_HOME6_EXACT_V1";

    final int uid;
    final String dev;
    final String selector;
    final String hook4;
    final String hook6;
    final String allow4;

    private RootBraveHomePilotPlan(int uid, String dev) {
        this.uid = uid;
        this.dev = dev;
        selector = "ip -4 rule add pref " + PRIORITY + " iif lo uidrange "
                + uid + "-" + uid + " to " + TARGET + " lookup " + TABLE;
        hook4 = "-A OUTPUT -m owner --uid-owner " + uid
                + " -m comment --comment " + TAG4 + " -j " + CHAIN4;
        hook6 = "-A OUTPUT -m owner --uid-owner " + uid
                + " -m comment --comment " + TAG6 + " -j " + CHAIN6;
        allow4 = "-A " + CHAIN4 + " -o " + dev + " -d "
                + TARGET + " -p tcp -m tcp --dport 4533 -j RETURN";
    }

    static RootBraveHomePilotPlan compile(int uid, String dev) {
        if (uid < 10000 || uid > 99999 || dev == null
                || !dev.matches("wnm[0-9a-f]{12}")) {
            throw new IllegalArgumentException("Invalid Brave UID/Home identity.");
        }
        return new RootBraveHomePilotPlan(uid, dev);
    }

    static String normalized(String rule) {
        return rule.trim().replace("\"", "").replaceAll("\\s+", " ");
    }

    // Strict enough to distinguish priority collision from an exact owned rule.
    static int exactSelector(String policy, int uid) {
        if (policy == null || policy.length() > 100000) return -1;
        int matches = 0;
        for (String raw : policy.split("\\r?\\n")) {
            String line = normalized(raw);
            if (!line.startsWith(PRIORITY + ":")) continue;
            if (!line.matches("^12699: from all to 10\\.0\\.0\\.169(?:/32)? "
                    + "iif lo uidrange " + uid + "-" + uid
                    + " (?:lookup|table) 51002$")) return -1;
            matches++;
        }
        return matches <= 1 ? matches : -1;
    }

    static boolean onlyExactOutputHook(String listing, String chain,
            String tag, String expected, boolean allowPresent) {
        if (listing == null || listing.length() > 100000) return false;
        int count = 0;
        for (String line : listing.split("\\r?\\n")) {
            String item = normalized(line);
            if (!item.contains(chain) && !item.contains(tag)) continue;
            if (!item.equals(expected)) return false;
            count++;
        }
        return count == (allowPresent ? 1 : 0);
    }

    static boolean chainIsExactPrefix(String listing, String chain,
            String dev, boolean ipv4) {
        if (listing == null || listing.length() > 32000) return false;
        if (!chain.equals(ipv4 ? CHAIN4 : CHAIN6)) return false;
        List<String> rules = new ArrayList<>();
        for (String line : listing.split("\\r?\\n")) {
            String item = normalized(line);
            if (!item.isEmpty()) rules.add(item);
        }
        if (rules.isEmpty() || !rules.get(0).equals("-N " + chain)
                || rules.size() > (ipv4 ? 3 : 2)) return false;
        for (int i = 1; i < rules.size(); i++) {
            String item = rules.get(i);
            if (ipv4 && i == 1) {
                String canonical = "-A " + CHAIN4 + " -d " + TARGET
                        + " -o " + dev + " -p tcp -m tcp --dport 4533 -j RETURN";
                String commandOrder = "-A " + CHAIN4 + " -o " + dev
                        + " -d " + TARGET + " -p tcp -m tcp --dport 4533 -j RETURN";
                if (!item.equals(canonical) && !item.equals(commandOrder)) return false;
                continue;
            }
            String reject = "-A " + chain + " -j REJECT";
            String defaultReject = reject + " --reject-with "
                    + (ipv4 ? "icmp-port-unreachable" : "icmp6-port-unreachable");
            if (!item.equals(reject) && !item.equals(defaultReject)) return false;
        }
        return true;
    }

    private RootBraveHomePilotPlan() { throw new AssertionError(); }
}
