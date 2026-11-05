package com.yooshastan.wonheeproxy;

import java.util.List;
import java.util.Locale;

/** Validates the non-secret WireGuard UDP socket mark reported by wg(8). */
final class RootFirewallMark {
    private RootFirewallMark() { }

    static long parse(List<String> output) {
        if (output == null || output.size() != 1 || output.get(0) == null) return 0;
        String value = output.get(0).trim().toLowerCase(Locale.ROOT);
        if (value.isEmpty() || "off".equals(value)) return 0;
        try {
            long mark;
            if (value.startsWith("0x")) {
                if (!value.matches("0x[0-9a-f]{1,8}")) return 0;
                mark = Long.parseLong(value.substring(2), 16);
            } else {
                if (!value.matches("[0-9]{1,10}")) return 0;
                mark = Long.parseLong(value);
            }
            return mark > 0 && mark <= 0xffffffffL ? mark : 0;
        } catch (NumberFormatException invalid) {
            return 0;
        }
    }

    static boolean distinctNonzero(long home, long internet) {
        return home > 0 && internet > 0 && home != internet;
    }
}
