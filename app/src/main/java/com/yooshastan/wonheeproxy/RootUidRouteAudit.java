package com.yooshastan.wonheeproxy;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Non-secret formatting for one-shot Android UID+fwmark root-route simulations.
 * A routing simulation is NOT a live socket observation or an enforced policy.
 */
final class RootUidRouteAudit {
    static final int ANDROID_SYSTEM_UID = 1000;
    static final String MESSAGES_PACKAGE = "com.google.android.apps.messaging";
    static final String GMS_PACKAGE = "com.google.android.gms";
    static final long PROTECTED_MARK = 0x20000L;
    static final int MAX_UID = 99999;
    private static final int MAX_UNPROTECTED_MARKS = 2;

    private RootUidRouteAudit() { }

    static boolean supportedUid(int uid) {
        return uid >= 0 && uid <= MAX_UID;
    }

    /**
     * Always include mark zero plus at most one nonzero, observed unprotected
     * Android mark. Exhaustive mark/sockets tracing is intentionally NOT claimed.
     */
    static List<Long> sampledUnprotectedMarks(List<Long> observed) {
        Set<Long> result = new LinkedHashSet<>();
        result.add(0L);
        if (observed != null) {
            for (Long value : observed) {
                if (value == null || value <= 0 || value > 0xffffffffL
                        || (value & PROTECTED_MARK) != 0) continue;
                result.add(value);
                if (result.size() >= MAX_UNPROTECTED_MARKS) break;
            }
        }
        return new ArrayList<>(result);
    }

    static boolean matchesExpected(String expectedDevice, String selectedDevice) {
        return expectedDevice != null && !expectedDevice.isEmpty()
                && expectedDevice.equals(selectedDevice);
    }

    static String routePrediction(String expectedDevice, String selectedDevice,
            boolean protectedSocket) {
        if (selectedDevice == null || selectedDevice.isEmpty()) {
            return "NO ROUTE/UNVERIFIED";
        }
        String actual = selectedDevice.matches("[a-zA-Z0-9_.-]{1,32}")
                ? selectedDevice : "UNVERIFIED";
        if ("UNVERIFIED".equals(actual)) return actual;
        if (protectedSocket) {
            return actual + (matchesExpected(expectedDevice, actual)
                    ? " (protected mark STILL selects VPN)"
                    : " (protected mark bypass prediction; no live socket proof)");
        }
        return actual + (matchesExpected(expectedDevice, actual)
                ? " · EXPECTED" : " · UNEXPECTED ROUTE");
    }

    static String header(String label, int uid) {
        if (!supportedUid(uid)) return label + ": UID UNAVAILABLE/UNSUPPORTED";
        return label + " (UID " + uid + ")";
    }
}
