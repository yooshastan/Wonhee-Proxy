package com.yooshastan.wonheeproxy;

import java.util.Arrays;
import java.util.Collections;

/** Deterministic pure tests — no Android APIs, root commands, sockets or packets. */
public final class RootPassiveNetworkHealthTest {
    private static void check(boolean ok, String reason) {
        if (!ok) throw new AssertionError(reason);
    }

    public static void main(String[] args) {
        String dev = "wnm68fe81200daa";
        check(RootPassiveNetworkHealth.handshakeTimestamp(Arrays.asList(
                "PUBLICKEY-NEVER-PRINT 1730500123")) == 1730500123L,
                "parse latest single-peer handshake epoch without outputting key");
        check(RootPassiveNetworkHealth.handshakeTimestamp(Arrays.asList(
                "peer 0")) == 0, "no-handshake epoch must remain distinguishable");
        check(RootPassiveNetworkHealth.handshakeTimestamp(Arrays.asList(
                "peer 1", "peer2 2")) == -1,
                "multiple peer rows must never be silently combined");
        check(RootPassiveNetworkHealth.handshakeTimestamp(Arrays.asList(
                "peer invalid")) == -1, "invalid epoch refused");
        check(RootPassiveNetworkHealth.handshakeTimestamp(
                Collections.emptyList()) == -1, "missing handshake marked unavailable");
        check(RootPassiveNetworkHealth.handshakeAge(0, 500)
                .equals("never observed"), "no handshake must not be called an outage");
        check(RootPassiveNetworkHealth.handshakeAge(-1, 500)
                .equals("UNAVAILABLE"), "missing handshake kept distinct");
        check(RootPassiveNetworkHealth.handshakeAge(400, 500)
                .contains("100 seconds ago"), "handshake age computed from snapshot time");
        check(RootPassiveNetworkHealth.handshakeAge(100, 500)
                .contains("possibly idle"), "stale handshake not interpreted as a failure");
        check(RootPassiveNetworkHealth.handshakeAge(600, 500)
                .contains("CLOCK SKEW"), "clock regression not misdiagnosed");

        RootPassiveNetworkHealth.Snapshot first = new RootPassiveNetworkHealth.Snapshot(
                dev, 1000, 900, 100, 200, 0x20000, "203.0.113.4:51820",
                "IPv4", "wlan0");
        String firstReport = RootPassiveNetworkHealth.render("AirVPN", null, first);
        check(firstReport.contains("Previous sample: none")
                        && !firstReport.contains("203.0.113.4"),
                "single snapshot must hide raw endpoint, no implicit health assertion");

        RootPassiveNetworkHealth.Snapshot changed = new RootPassiveNetworkHealth.Snapshot(
                dev, 1045, 1005, 150, 260, 0x20000, "198.51.100.4:51820",
                "IPv4", "rmnet16");
        String changeReport = RootPassiveNetworkHealth.render("AirVPN", first, changed);
        check(changeReport.contains("RX +50 B, TX +60 B")
                        && changeReport.contains("UNDERLAY ROUTE PREDICTION CHANGED")
                        && changeReport.contains("WIREGUARD ENDPOINT CHANGED")
                        && !changeReport.contains("198.51.100.4")
                        && !changeReport.contains("203.0.113.4"),
                "passive differences report changes but never endpoint identities");

        String sameReport = RootPassiveNetworkHealth.render(
                "AirVPN", changed, new RootPassiveNetworkHealth.Snapshot(
                        dev, 1060, 1005, 150, 260, 0x20000, "198.51.100.4:51820",
                        "IPv4", "rmnet16"));
        check(sameReport.contains("No counter increase observed")
                        && sameReport.contains("NOT a failure diagnosis"),
                "idle traffic must not be classified as a broken connection");
        String resetReport = RootPassiveNetworkHealth.render("AirVPN", changed,
                new RootPassiveNetworkHealth.Snapshot(dev, 1065, 0, 0, 10,
                        0x20000, "198.51.100.4:51820", "IPv4", "rmnet16"));
        check(resetReport.contains("Counter or clock reset"),
                "interface restart is not mistaken for negative traffic");
        check(RootPassiveNetworkHealth.render("HOME", null, null)
                .contains("NO VERIFIED SNAPSHOT"), "missing device is not a false pass");

        try {
            new RootPassiveNetworkHealth.Snapshot("wlan0", 1000, 0, 0, 0,
                    0, "", "", "wlan0");
            throw new AssertionError("physical interface cannot be represented as WireGuard");
        } catch (IllegalArgumentException expected) { /* must refuse */ }

        System.out.println("RootPassiveNetworkHealthTest PASS");
    }
}
