package com.yooshastan.wonheeproxy;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure, read-only bitmask inventory of existing Android packet / connection
 * mark operations. Input is existing mangle (-S) and RPDB (ip rule show) text.
 *
 * A broad --set-xmark clear mask is treated as a competing write even where
 * all bits in it are cleared. No 32-bit packet-mark allocation is authorized
 * merely because a bit appears unused in a snapshot; netd's future marks,
 * protected socket flag, socket mark rerouting and owner identity still need
 * independent proofs. This class does not execute any command.
 */
final class RootAndroidMarkCollisionAudit {
    private static final String NUMBER = "(?:0[xX][0-9a-fA-F]+|[0-9]+)";
    private static final Pattern MARK_WRITE = Pattern.compile(
            "--set-(?:xmark|mark)\\s+" + NUMBER + "(?:/(" + NUMBER + "))?");
    private static final Pattern SAVE_MARK = Pattern.compile("--save-mark(?:\\s|$)");
    private static final Pattern MASK = Pattern.compile(
            "--(?:nfmask|ctmask)\\s+(" + NUMBER + ")");
    private static final Pattern FW_MARK = Pattern.compile(
            "fwmark\\s+" + NUMBER + "(?:/(" + NUMBER + "))?");
    private static final Pattern MATCH_MARK = Pattern.compile(
            "--mark\\s+" + NUMBER + "(?:/(" + NUMBER + "))?");

    static final class Family {
        final boolean readable;
        final long referencedBits;
        final long writeBits;
        final long connmarkBits;
        final long routingBits;

        Family(boolean readable, long refs, long writes, long conn, long routing) {
            this.readable = readable;
            referencedBits = refs;
            writeBits = writes;
            connmarkBits = conn;
            routingBits = routing;
        }

        /** Conservative mask coverage, NOT evidence of live rule execution. */
        long observedBits() {
            return (referencedBits | writeBits | connmarkBits | routingBits)
                    & 0xffffffffL;
        }
    }

    static final class Report {
        final Family ipv4;
        final Family ipv6;

        Report(Family ipv4, Family ipv6) {
            this.ipv4 = ipv4;
            this.ipv6 = ipv6;
        }

        boolean noUnreferencedBitsObserved() {
            return ipv4.readable && ipv6.readable
                    && ipv4.observedBits() == 0xffffffffL
                    && ipv6.observedBits() == 0xffffffffL;
        }

        /** Never choose a mark from an incomplete or historical snapshot. */
        boolean candidateVerifiedFree(long mask) { return false; }

        boolean activationAllowed() { return false; }

        String summary() {
            if (!ipv4.readable || !ipv6.readable) {
                return "ANDROID MARK AUDIT: INCOMPLETE; no packet mark is approved.";
            }
            if (noUnreferencedBitsObserved()) {
                return "ANDROID MARK AUDIT: observed v4/v6 mask coverage spans "
                        + "all 32 bits. No packet-mark bit can be assumed "
                        + "unowned. This does NOT establish that every bit "
                        + "is actively allocated. No packet marking enabled.";
            }
            return "ANDROID MARK AUDIT: snapshot shows some unreferenced bits, "
                    + "but they are NOT verified available. No packet marking enabled.";
        }
    }

    private RootAndroidMarkCollisionAudit() { }

    static Report review(String v4Mangle, String v4Rules,
            String v6Mangle, String v6Rules) {
        return new Report(family(v4Mangle, v4Rules),
                family(v6Mangle, v6Rules));
    }

    private static Family family(String mangle, String rules) {
        if (mangle == null || rules == null
                || !mangle.contains("-A ")
                || !rules.contains("fwmark ")
                || mangle.contains("Permission denied")
                || rules.contains("Permission denied")) {
            return new Family(false, 0, 0, 0, 0);
        }
        long referenced = 0, written = 0, conn = 0, routing = 0;
        for (String line : mangle.split("\\r?\\n")) {
            Matcher set = MARK_WRITE.matcher(line);
            if (set.find()) {
                written |= bitMask(set.group(1));
            } else if (line.contains("--set-xmark") || line.contains("--set-mark")) {
                return new Family(false, 0, 0, 0, 0);
            }
            if (SAVE_MARK.matcher(line).find()) {
                Matcher masks = MASK.matcher(line);
                boolean hasMask = false;
                while (masks.find()) {
                    conn |= bitMask(masks.group(1));
                    hasMask = true;
                }
                if (!hasMask) conn |= 0xffffffffL;
            }
            Matcher match = MATCH_MARK.matcher(line);
            if (match.find()) referenced |= bitMask(match.group(1));
        }
        Matcher route = FW_MARK.matcher(rules);
        while (route.find()) routing |= bitMask(route.group(1));
        return new Family(true, referenced & 0xffffffffL,
                written & 0xffffffffL, conn & 0xffffffffL,
                routing & 0xffffffffL);
    }

    private static long bitMask(String value) {
        if (value == null || value.isEmpty()) return 0xffffffffL;
        try {
            long out = value.startsWith("0x") || value.startsWith("0X")
                    ? Long.parseUnsignedLong(value.substring(2), 16)
                    : Long.parseLong(value);
            if (out < 0 || out > 0xffffffffL) {
                throw new IllegalArgumentException("Invalid packet mark mask.");
            }
            return out;
        } catch (NumberFormatException invalid) {
            throw new IllegalArgumentException("Invalid packet mark mask.");
        }
    }
}
