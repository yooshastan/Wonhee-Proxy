package com.yooshastan.wonheeproxy;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Pure, non-executing parser for the help text of Android's iptables-legacy
 * / ip6tables-legacy userspace tools. Advertised syntax is NOT evidence of
 * kernel module support, mark ownership, or packet-level leak protection.
 */
final class RootNetfilterHelpCapabilities {
    static final class Family {
        final boolean legacy;
        final boolean ownerUid;
        final boolean tcpDport;
        final boolean udpDport;
        final boolean markXorOr;
        final boolean helpReadable;

        Family(boolean legacy, boolean ownerUid, boolean tcpDport,
                boolean udpDport, boolean markXorOr, boolean helpReadable) {
            this.legacy = legacy;
            this.ownerUid = ownerUid;
            this.tcpDport = tcpDport;
            this.udpDport = udpDport;
            this.markXorOr = markXorOr;
            this.helpReadable = helpReadable;
        }

        boolean syntaxAdvertised() {
            return legacy && helpReadable && ownerUid
                    && tcpDport && udpDport && markXorOr;
        }
    }

    static final class Report {
        final Family ipv4;
        final Family ipv6;

        Report(Family ipv4, Family ipv6) {
            this.ipv4 = ipv4;
            this.ipv6 = ipv6;
        }

        boolean bothFamiliesAdvertiseSyntax() {
            return ipv4.syntaxAdvertised() && ipv6.syntaxAdvertised();
        }

        /** No help text can authorize injecting firewall or route rules. */
        boolean activationAllowed() { return false; }

        String summary() {
            return "NETFILTER CLI: IPv4 "
                    + (ipv4.syntaxAdvertised() ? "SYNTAX ADVERTISED" : "CHECK REQUIRED")
                    + ", IPv6 "
                    + (ipv6.syntaxAdvertised() ? "SYNTAX ADVERTISED" : "CHECK REQUIRED")
                    + ". No rule has been installed. Actual kernel match/target "
                    + "operation, Android fwmark bit ownership, LOCAL_OUT reroute, "
                    + "DNS identity and selected-exit fail-closed behavior remain "
                    + "UNVERIFIED. Activation disabled.";
        }
    }

    private RootNetfilterHelpCapabilities() { }

    static Report review(String v4Version, String v4Owner, String v4Tcp,
            String v4Udp, String v4Mark, String v6Version, String v6Owner,
            String v6Tcp, String v6Udp, String v6Mark) {
        return new Report(family(v4Version, v4Owner, v4Tcp, v4Udp, v4Mark),
                family(v6Version, v6Owner, v6Tcp, v6Udp, v6Mark));
    }

    private static Family family(String version, String owner, String tcp,
            String udp, String mark) {
        boolean legacy = version != null
                && version.matches("(?s).*iptables v1\\.8\\.[0-9]+ \\(legacy\\).*")
                        || version != null
                && version.matches("(?s).*ip6tables v1\\.8\\.[0-9]+ \\(legacy\\).*");
        boolean readable = allPresent(version, owner, tcp, udp, mark);
        return new Family(legacy,
                hasToken(owner, "--uid-owner"),
                hasToken(tcp, "--dport"),
                hasToken(udp, "--dport"),
                hasToken(mark, "--set-xmark") && hasToken(mark, "--set-mark"),
                readable);
    }

    private static boolean allPresent(String... values) {
        for (String value : values) {
            if (value == null || value.isEmpty()) return false;
        }
        return true;
    }

    private static boolean hasToken(String help, String token) {
        if (help == null) return false;
        String escaped = Pattern.quote(token);
        return Pattern.compile("(?<![A-Za-z0-9_-])" + escaped
                + "(?![A-Za-z0-9_-])").matcher(help).find();
    }
}
