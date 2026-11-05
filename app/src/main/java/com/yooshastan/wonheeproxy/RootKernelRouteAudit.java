package com.yooshastan.wonheeproxy;

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses read-only Linux route-get output. A route observation is not proof of
 * packet egress, app socket selection, or protection against fallback.
 */
final class RootKernelRouteAudit {
    private static final Pattern DEVICE = Pattern.compile("(?:^|\\s)dev\\s+([^\\s]+)(?:\\s|$)");

    private RootKernelRouteAudit() { }

    static String selectedDevice(List<String> output) {
        if (output == null) return "";
        for (String line : output) {
            if (line == null) continue;
            Matcher matcher = DEVICE.matcher(line);
            if (matcher.find()) return matcher.group(1);
        }
        return "";
    }

    static boolean routesThrough(List<String> output, String requiredDevice) {
        return requiredDevice != null && !requiredDevice.isEmpty()
                && requiredDevice.equals(selectedDevice(output));
    }
}
