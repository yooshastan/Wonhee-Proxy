package com.yooshastan.wonheeproxy;

import java.util.List;

/** Pure, conservative checks for marked WireGuard endpoint route selection. */
final class RootTransportRoute {
    private RootTransportRoute() { }

    static String classifiedDevice(String device, List<String> selectedTunnelDevices) {
        if (device == null || device.isEmpty()) return "UNRESOLVED";
        if (selectedTunnelDevices != null && selectedTunnelDevices.contains(device)) {
            return device + " · TUNNEL LOOP RISK";
        }
        if (device.matches("(wlan|rmnet|eth|usb|clat)[A-Za-z0-9_.-]*")) {
            // An ordinary-looking interface is still only an underlay
            // candidate: netd or a firewall may block its actual packets.
            return device + " · UNDERLAY CANDIDATE";
        }
        return device + " · OTHER DEVICE — UNVERIFIED";
    }

    static boolean isPotentialLoop(String device, List<String> selectedTunnelDevices) {
        return device != null && selectedTunnelDevices != null
                && selectedTunnelDevices.contains(device);
    }
}
