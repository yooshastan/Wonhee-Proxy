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
    static final String COUNT_TAG = "WN_BRAVE_TARGET_COUNT_V1";

    final int uid;
    final String dev;
    final String selector;
    final String hook4;
    final String hook6;
    final String allow4;
    final String count4;

    private RootBraveHomePilotPlan(int uid, String dev) {
        this.uid = uid;
        this.dev = dev;
        selector = "ip -4 rule add pref " + PRIORITY + " iif lo uidrange "
                + uid + "-" + uid + " to " + TARGET + " lookup " + TABLE;
        hook4 = "-A OUTPUT -m owner --uid-owner " + uid
                + " -m comment --comment " + TAG4 + " -j " + CHAIN4;
        hook6 = "-A OUTPUT -m owner --uid-owner " + uid
                + " -m comment --comment " + TAG6 + " -j " + CHAIN6;
        count4 = "-A " + CHAIN4 + " -d " + TARGET
                + " -p tcp -m tcp --dport 4533"
                + " -m comment --comment " + COUNT_TAG;
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
                || rules.size() > (ipv4 ? 4 : 2)) return false;
        for (int i = 1; i < rules.size(); i++) {
            String item = rules.get(i);
            if (ipv4 && i == 1) {
                if (!isExactCountOnlyRule(item)) return false;
                continue;
            }
            if (ipv4 && i == 2) {
                if (!isExactHomeReturn(item, dev)) return false;
                continue;
            }
            String reject = "-A " + chain + " -j REJECT";
            String defaultReject = reject + " --reject-with "
                    + (ipv4 ? "icmp-port-unreachable" : "icmp6-port-unreachable");
            if (!item.equals(reject) && !item.equals(defaultReject)) return false;
        }
        return true;
    }

    static boolean chainFullyPopulated(String listing, String chain,
            String dev, boolean ipv4) {
        if (!chainIsExactPrefix(listing, chain, dev, ipv4)) return false;
        int ruleLines = 0;
        for (String raw : listing.split("\\r?\\n")) {
            if (!normalized(raw).isEmpty()) ruleLines++;
        }
        return ruleLines == (ipv4 ? 4 : 2);
    }

    // Counting-only rule: no -j, no ACCEPT, no mark or routing action.
    // Match exactly six key/value terms, including two distinct -m extensions.
    private static boolean isExactCountOnlyRule(String item) {
        String prefix = "-A " + CHAIN4 + " ";
        if (!item.startsWith(prefix)) return false;
        String[] t = item.substring(prefix.length()).split(" ");
        if (t.length != 12) return false;
        boolean d = false, p = false, port = false, comment = false;
        boolean mTcp = false, mComment = false;
        for (int i = 0; i < t.length; i += 2) {
            String k = t[i], v = t[i + 1];
            switch (k) {
                case "-d":
                    if (d || !TARGET.equals(v)) return false;
                    d = true; break;
                case "-p":
                    if (p || !"tcp".equals(v)) return false;
                    p = true; break;
                case "-m":
                    if ("tcp".equals(v) && !mTcp) mTcp = true;
                    else if ("comment".equals(v) && !mComment) mComment = true;
                    else return false;
                    break;
                case "--dport":
                    if (port || !"4533".equals(v)) return false;
                    port = true; break;
                case "--comment":
                    if (comment || !COUNT_TAG.equals(v)) return false;
                    comment = true; break;
                default:
                    return false;
            }
        }
        return d && p && port && comment && mTcp && mComment;
    }

    // iptables-save may print -d, -o and match-extension fields in
    // different orders; accept ONLY these six exact key/value pairs.
    private static boolean isExactHomeReturn(String item, String dev) {
        String prefix = "-A " + CHAIN4 + " ";
        if (!item.startsWith(prefix)) return false;
        String[] tokens = item.substring(prefix.length()).split(" ");
        if (tokens.length != 12) return false;
        boolean d = false, o = false, p = false, m = false, port = false, jump = false;
        for (int i = 0; i < tokens.length; i += 2) {
            String key = tokens[i], value = tokens[i + 1];
            switch (key) {
                case "-d":
                    if (d || !TARGET.equals(value)) return false;
                    d = true;
                    break;
                case "-o":
                    if (o || !dev.equals(value)) return false;
                    o = true;
                    break;
                case "-p":
                    if (p || !"tcp".equals(value)) return false;
                    p = true;
                    break;
                case "-m":
                    if (m || !"tcp".equals(value)) return false;
                    m = true;
                    break;
                case "--dport":
                    if (port || !"4533".equals(value)) return false;
                    port = true;
                    break;
                case "-j":
                    if (jump || !"RETURN".equals(value)) return false;
                    jump = true;
                    break;
                default:
                    return false;
            }
        }
        return d && o && p && m && port && jump;
    }

    private RootBraveHomePilotPlan() { throw new AssertionError(); }
}
