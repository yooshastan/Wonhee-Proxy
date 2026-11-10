package com.yooshastan.wonheeproxy;

public final class RootDirectRouteAdvisoryTest {
    private static void check(boolean good, String why) {
        if (!good) throw new AssertionError(why);
    }

    public static void main(String[] args) {
        check(RootDirectRouteAdvisory.category(
                        "wnm68fe81200daa", "wnm68fe81200daa", true)
                        == RootDirectRouteAdvisory.INTERNET_VPN,
                "Selected Internet WG must override other selected-tunnel category");
        check(RootDirectRouteAdvisory.category(
                        "wlan0", "wnm68fe81200daa", false)
                        == RootDirectRouteAdvisory.PHYSICAL_WIFI,
                "Real peer with a physical Wi-Fi prediction must warn");
        check(RootDirectRouteAdvisory.category(
                        "wnma292ddb4b6da", "wnm68fe81200daa", true)
                        == RootDirectRouteAdvisory.OTHER_TUNNEL,
                "Home tunnel != public Internet tunnel");
        check(RootDirectRouteAdvisory.category(
                        "", "wnm68fe81200daa", false)
                        == RootDirectRouteAdvisory.UNKNOWN,
                "Unrouted must remain unknown");
        check(RootDirectRouteAdvisory.category(
                        "rmnet_data0", "wnm68fe81200daa", false)
                        == RootDirectRouteAdvisory.UNKNOWN,
                "Unknown physical interface is not falsely labeled Wi-Fi");

        RootDirectRouteAdvisory.Totals blank =
                new RootDirectRouteAdvisory.Totals();
        String none = blank.safeWarning(false, "Google Messages");
        check(none.contains("NO PUBLIC SOCKET PEER OBSERVED")
                        && none.contains("not evidence"),
                "Zero observations cannot assert leak freedom");

        RootDirectRouteAdvisory.Totals normal =
                new RootDirectRouteAdvisory.Totals();
        normal.add(RootDirectRouteAdvisory.INTERNET_VPN, false, true);
        normal.add(RootDirectRouteAdvisory.INTERNET_VPN, true, false);
        check(normal.candidates == 2 && normal.throughInternet == 2,
                "Aggregate current per-peer route predictions");
        check(normal.udp443Candidates == 1 && normal.udp443PossiblePhysical == 0,
                "UDP443 hint alone must NOT trigger direct Wi-Fi warning");
        check(normal.safeWarning(false, "Messages").contains(
                        "NOT proof of system-wide VPN-only egress"),
                "Normal route predictions do not prove all-app fail closed");

        RootDirectRouteAdvisory.Totals risk =
                new RootDirectRouteAdvisory.Totals();
        risk.add(RootDirectRouteAdvisory.PHYSICAL_WIFI, true, true);
        risk.add(RootDirectRouteAdvisory.PHYSICAL_WIFI, false, false);
        risk.add(RootDirectRouteAdvisory.UNKNOWN, false, false);
        String warning = risk.safeWarning(false, "Google Messages");
        check(warning.contains("POTENTIAL DIRECT PUBLIC ROUTE"),
                "Observed protected mark + actual public peer Wi-Fi prediction flagged");
        check(warning.contains("1 protected-marked, 1 ordinary-marked"),
                "Separate protected/ordinary rather than claiming all traffic is intentional");
        check(warning.contains("UDP/443") && warning.contains("QUIC"),
                "Only UDP443 + predicted physical route warrants QUIC-compatible hint");
        check(warning.contains("NOT inspected") && warning.contains("Do not disable RCS"),
                "No fake deep inspection or advice to disable RCS");
        check(!warning.contains("leaked") && !warning.contains("guaranteed")
                        && !warning.contains("192.168."),
                "Route warning cannot present packet leak proof or private IPs");

        RootDirectRouteAdvisory.Totals carrier =
                new RootDirectRouteAdvisory.Totals();
        carrier.add(RootDirectRouteAdvisory.PHYSICAL_WIFI, true, false);
        String carrierMessage = carrier.safeWarning(true, "Android system");
        check(carrierMessage.contains("Wi-Fi Calling")
                        && carrierMessage.contains("Do not block"),
                "Carrier/IMS warning must preserve Wi-Fi Calling");

        RootDirectRouteAdvisory.Totals ambiguous =
                new RootDirectRouteAdvisory.Totals();
        ambiguous.add(RootDirectRouteAdvisory.UNKNOWN, false, false);
        check(ambiguous.safeWarning(false, "Google Messages")
                        .contains("ROUTE NEEDS REVIEW"),
                "Unknown root kernel device not declared VPN-safe");

        System.out.println("RootDirectRouteAdvisoryTest passed");
    }
}
