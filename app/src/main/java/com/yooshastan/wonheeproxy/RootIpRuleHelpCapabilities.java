package com.yooshastan.wonheeproxy;

import java.util.regex.Pattern;

/**
 * Pure read-only interpreter of the *installed ip command's* help text.
 *
 * This is deliberately NOT a kernel feature probe. A Linux kernel may
 * support a netlink rule attribute that Android's ip command cannot parse.
 * Conversely, help advertising a selector does not prove its safe operation
 * with Android netd, WireGuard endpoint sockets or protectedFromVpn marks.
 */
final class RootIpRuleHelpCapabilities {
    static final class Report {
        final boolean helpReadable;
        final boolean uidAndMarkAdvertised;
        final boolean directL4Advertised;
        final boolean unreachableActionAdvertised;

        Report(boolean readable, boolean uid, boolean l4, boolean unreachable) {
            helpReadable = readable;
            uidAndMarkAdvertised = uid;
            directL4Advertised = l4;
            unreachableActionAdvertised = unreachable;
        }

        /** A read-only help check NEVER authorizes a kernel mutation. */
        boolean activationAllowed() { return false; }

        String summary() {
            if (!helpReadable) {
                return "IP RULE CLI: UNKNOWN — help unavailable. "
                        + "Do not activate app, transport or port routing.";
            }
            String base = "IP RULE CLI: uidrange/fwmark "
                    + (uidAndMarkAdvertised ? "ADVERTISED" : "NOT ADVERTISED")
                    + "; ipproto/dport "
                    + (directL4Advertised ? "ADVERTISED" : "NOT ADVERTISED")
                    + "; unreachable action "
                    + (unreachableActionAdvertised ? "ADVERTISED" : "NOT ADVERTISED");
            return base + ". This is a command-line help check, NOT a kernel "
                    + "or fail-closed safety check. Activation stays disabled.";
        }
    }

    private RootIpRuleHelpCapabilities() { }

    static Report review(String ipv4Help, String ipv6Help) {
        if (!readable(ipv4Help) || !readable(ipv6Help)) {
            return new Report(false, false, false, false);
        }
        boolean uid = tokens(ipv4Help, "uidrange", "fwmark", "iif", "pref")
                && tokens(ipv6Help, "uidrange", "fwmark", "iif", "pref");
        boolean l4 = uid
                && tokens(ipv4Help, "ipproto", "dport")
                && tokens(ipv6Help, "ipproto", "dport");
        boolean unreachable = tokens(ipv4Help, "unreachable")
                && tokens(ipv6Help, "unreachable");
        return new Report(true, uid, l4, unreachable);
    }

    private static boolean readable(String value) {
        return value != null
                && (value.contains("Usage: ip rule") || value.contains("Usage: ip -4 rule"))
                && value.contains("SELECTOR");
    }

    private static boolean tokens(String text, String... words) {
        for (String word : words) {
            if (!Pattern.compile("(?<![A-Za-z0-9_])" + Pattern.quote(word)
                    + "(?![A-Za-z0-9_])").matcher(text).find()) {
                return false;
            }
        }
        return true;
    }
}
