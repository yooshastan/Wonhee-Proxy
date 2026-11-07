package com.yooshastan.wonheeproxy;

import java.util.List;

/** Read-only extraction of the final guard REJECT counter from iptables -L -v -x. */
final class RootGuardProbeEvidence {
    private RootGuardProbeEvidence() { }

    static long terminalRejectPackets(List<String> lines) {
        if (lines == null) return -1;
        String lastRule = null;
        for (String line : lines) {
            if (line == null) continue;
            String[] fields = line.trim().split("\\s+");
            if (fields.length < 4 || !fields[0].matches("[0-9]+")
                    || !fields[1].matches("[0-9]+")) continue;
            lastRule = line.trim();
        }
        if (lastRule == null) return -1;
        String[] fields = lastRule.split("\\s+");
        if (!"REJECT".equals(fields[2])) return -1;
        try { return Long.parseLong(fields[0]); }
        catch (NumberFormatException ignored) { return -1; }
    }

    static String outcome(int pingExit, long before, long after) {
        if (pingExit == 0) return "ALERT: ICMP REPLY RECEIVED — potential direct-underlay escape";
        if (before >= 0 && after > before) {
            return "GUARD REJECT COUNTER INCREASED — limited blocking evidence";
        }
        return "INCONCLUSIVE — no attributable guard rejection observed";
    }
}
