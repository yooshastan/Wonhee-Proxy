package com.yooshastan.wonheeproxy;

import java.util.List;
import java.util.regex.Pattern;

/** Counts narrowly filtered tcpdump packet summaries without retaining addresses. */
final class RootPacketEvidence {
    private static final Pattern LINE = Pattern.compile(
            "^\\d+(?:\\.\\d+)?\\s+IP6?\\s+.+\\s+>\\s+.+:.*$");

    private RootPacketEvidence() { }

    static int packetLines(List<String> output) {
        if (output == null) return 0;
        int count = 0;
        for (String line : output) {
            if (line != null && LINE.matcher(line.trim()).matches()) count++;
        }
        return count;
    }

    static String interpretation(int packets, boolean captureToolCompleted) {
        if (!captureToolCompleted) return "CAPTURE UNAVAILABLE / INCOMPLETE";
        return packets > 0 ? "MATCHING PACKET HEADERS OBSERVED: " + packets
                : "ZERO MATCHING HEADERS IN WINDOW (not proof of absence)";
    }
}
