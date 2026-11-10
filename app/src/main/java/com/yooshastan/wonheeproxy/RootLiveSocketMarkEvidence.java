package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses read-only iproute2 ss -H -t/-u -n -e output. Raw socket endpoint,
 * inode, process and peer fields never leave this parser. An absent fwmark
 * is UNKNOWN, never silently treated as mark 0.
 *
 * The Android kernel, netlink security policy or ss implementation can omit
 * uid/fwmark metadata. This is a best-effort passive snapshot, not proof of
 * routing or that all sockets are visible.
 */
final class RootLiveSocketMarkEvidence {
    static final long PROTECTED_BIT = 0x20000L;
    static final int MAX_OUTPUT_LINES = 4096;
    static final int MAX_LINE_CHARS = 4096;
    static final int MAX_MARKS_PER_UID = 4;
    static final int MAX_BURST_SAMPLES = 48;
    static final long MAX_BURST_MILLIS = 15_000L;

    /** Hard, monotonic deadline and count for voluntary high-cadence sampling. */
    static boolean burstAllowed(int completed, long elapsed, boolean cancelled) {
        return !cancelled && completed >= 0 && completed < MAX_BURST_SAMPLES
                && elapsed >= 0 && elapsed < MAX_BURST_MILLIS;
    }

    private static final Pattern UID = Pattern.compile(
            "(?:^|\\s)uid:([0-9]{1,8})(?=\\s|$)");
    private static final Pattern MARK = Pattern.compile(
            "(?:^|\\s)fwmark:(0x[0-9a-fA-F]{1,8}|[0-9]{1,10})(?=\\s|$)");

    private RootLiveSocketMarkEvidence() { }

    static final class Counts {
        int tcp;
        int udp;
        int markVisible;
        int markUnavailable;
        int protectedSockets;
        int ordinaryMarked;
        final Set<Long> distinctMarks = new LinkedHashSet<>();

        int visible() { return tcp + udp; }

        void observe(String transport, Long mark) {
            if ("TCP".equals(transport)) tcp++; else udp++;
            if (mark == null) {
                markUnavailable++;
            } else {
                markVisible++;
                if ((mark & PROTECTED_BIT) != 0) protectedSockets++;
                else ordinaryMarked++;
                distinctMarks.add(mark);
            }
        }

        void mergeMax(Counts other) {
            tcp = Math.max(tcp, other.tcp);
            udp = Math.max(udp, other.udp);
            markVisible = Math.max(markVisible, other.markVisible);
            markUnavailable = Math.max(markUnavailable, other.markUnavailable);
            protectedSockets = Math.max(protectedSockets, other.protectedSockets);
            ordinaryMarked = Math.max(ordinaryMarked, other.ordinaryMarked);
            distinctMarks.addAll(other.distinctMarks);
        }
    }

    static final class Snapshot {
        final Map<Integer, Counts> byUid = new LinkedHashMap<>();
        int unidentified;
        int parsedSockets;
        boolean complete = true;

        Counts forUid(int uid) {
            Counts c = byUid.get(uid);
            if (c == null) {
                c = new Counts();
                byUid.put(uid, c);
            }
            return c;
        }

        void mergeMax(Snapshot sample) {
            unidentified = Math.max(unidentified, sample.unidentified);
            parsedSockets = Math.max(parsedSockets, sample.parsedSockets);
            complete &= sample.complete;
            for (Map.Entry<Integer, Counts> e : sample.byUid.entrySet()) {
                forUid(e.getKey()).mergeMax(e.getValue());
            }
        }
    }

    static Snapshot parse(List<String> tcp, List<String> udp, Set<Integer> uids) {
        Snapshot result = new Snapshot();
        if (uids == null || uids.isEmpty()) {
            result.complete = false;
            return result;
        }
        for (Integer uid : uids) {
            if (uid != null && uid >= 0 && uid <= RootUidRouteAudit.MAX_UID) {
                result.forUid(uid);
            }
        }
        accept(tcp, "TCP", result);
        accept(udp, "UDP", result);
        return result;
    }

    private static void accept(List<String> lines, String protocol, Snapshot result) {
        if (lines == null || lines.size() > MAX_OUTPUT_LINES) {
            result.complete = false;
            return;
        }
        StringBuilder record = new StringBuilder();
        for (String line : lines) {
            if (line == null || line.length() > MAX_LINE_CHARS) {
                result.complete = false;
                continue;
            }
            String trimmed = line.trim();
            if (trimmed.isEmpty()) continue;
            if (!Character.isWhitespace(line.charAt(0))) {
                consume(record, protocol, result);
                record.setLength(0);
                record.append(trimmed);
            } else if (record.length() > 0 && record.length() + trimmed.length() + 1
                    < MAX_LINE_CHARS * 2) {
                record.append(' ').append(trimmed);
            } else {
                // Do not treat stray continuation lines as standalone sockets.
                result.complete = false;
            }
        }
        consume(record, protocol, result);
    }

    private static void consume(StringBuilder record, String protocol, Snapshot result) {
        if (record.length() == 0) return;
        result.parsedSockets++;
        String raw = record.toString();
        Matcher uidMatch = UID.matcher(raw);
        if (!uidMatch.find()) {
            result.unidentified++;
            return;
        }
        // Reject ambiguous multi-UID records instead of assigning to an app.
        int uid;
        try {
            uid = Integer.parseInt(uidMatch.group(1));
        } catch (NumberFormatException bad) {
            result.complete = false;
            return;
        }
        if (uidMatch.find()) {
            result.complete = false;
            return;
        }
        Counts counts = result.byUid.get(uid);
        if (counts == null) return;

        Long mark = null;
        Matcher markMatch = MARK.matcher(raw);
        if (markMatch.find()) {
            String hexOrDecimal = markMatch.group(1);
            try {
                long value = hexOrDecimal.startsWith("0x")
                        ? Long.parseLong(hexOrDecimal.substring(2), 16)
                        : Long.parseLong(hexOrDecimal);
                if (value >= 0 && value <= 0xffffffffL && !markMatch.find()) {
                    mark = value;
                } else {
                    result.complete = false;
                }
            } catch (NumberFormatException bad) {
                result.complete = false;
            }
        }
        counts.observe(protocol, mark);
    }

    static List<Long> boundedMarks(Counts counts) {
        if (counts == null) return Collections.emptyList();
        List<Long> result = new ArrayList<>();
        for (Long mark : counts.distinctMarks) {
            if (result.size() == MAX_MARKS_PER_UID) break;
            result.add(mark);
        }
        return result;
    }

    static String safeSummary(String label, int uid, Counts counts) {
        if (counts == null || counts.visible() == 0) {
            return label + " (UID " + uid + "): NO SOCKETS OBSERVED"
                    + " (short-lived connections may be missed)";
        }
        return label + " (UID " + uid + "): at most "
                + counts.tcp + " TCP / " + counts.udp
                + " UDP sockets in any one sample; fwmark available on "
                + counts.markVisible + ", unavailable on "
                + counts.markUnavailable + "; protected-bit observed on "
                + counts.protectedSockets
                + ", other explicit marks on " + counts.ordinaryMarked
                + ". Counts are peak samples, not unique flows.";
    }
}
