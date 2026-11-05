package com.yooshastan.wonheeproxy;

import java.util.Collections;

public final class MultiTunnelSessionLedgerTest {
    private static byte[] v4(int a, int b, int c, int d) {
        byte[] p = new byte[20];
        p[0] = 0x45;
        p[3] = 20;
        p[16] = (byte) a; p[17] = (byte) b;
        p[18] = (byte) c; p[19] = (byte) d;
        return p;
    }

    private static void equal(Object expected, Object actual, String caseName) {
        if (!expected.equals(actual)) throw new AssertionError(
                caseName + ": expected " + expected + ", got " + actual);
    }

    public static void main(String[] args) {
        MultiTunnelPacketRouter router = MultiTunnelPacketRouter.forFullTunnel(
                Collections.singletonList("10.0.0.0/24"), true, false);
        MultiTunnelSessionLedger ledger = new MultiTunnelSessionLedger();
        byte[] navidrome = v4(10, 0, 0, 169);
        byte[] internet = v4(1, 1, 1, 1);
        equal(MultiTunnelPacketRouter.Target.DROP, ledger.route(router, navidrome), "down");
        long home1 = ledger.begin(MultiTunnelPacketRouter.Target.HOME);
        long net1 = ledger.begin(MultiTunnelPacketRouter.Target.INTERNET);
        equal(MultiTunnelPacketRouter.Target.DROP, ledger.route(router, navidrome), "connecting");
        ledger.ready(MultiTunnelPacketRouter.Target.HOME, home1);
        equal(MultiTunnelPacketRouter.Target.HOME, ledger.route(router, navidrome), "home ready");
        equal(MultiTunnelPacketRouter.Target.DROP, ledger.route(router, internet), "exit down");
        ledger.ready(MultiTunnelPacketRouter.Target.INTERNET, net1);
        equal(MultiTunnelPacketRouter.Target.INTERNET, ledger.route(router, internet), "exit ready");
        ledger.failed(MultiTunnelPacketRouter.Target.HOME, home1);
        equal(MultiTunnelPacketRouter.Target.DROP, ledger.route(router, navidrome), "home failed");
        equal(MultiTunnelPacketRouter.Target.INTERNET, ledger.route(router, internet), "exit survives");

        long home2 = ledger.begin(MultiTunnelPacketRouter.Target.HOME);
        ledger.ready(MultiTunnelPacketRouter.Target.HOME, home1);
        equal(MultiTunnelSessionLedger.Phase.CONNECTING,
                ledger.phase(MultiTunnelPacketRouter.Target.HOME), "old ready ignored");
        ledger.failed(MultiTunnelPacketRouter.Target.HOME, home1);
        ledger.ready(MultiTunnelPacketRouter.Target.HOME, home2);
        equal(MultiTunnelPacketRouter.Target.HOME, ledger.route(router, navidrome), "new home ready");
        ledger.stop(MultiTunnelPacketRouter.Target.HOME);
        ledger.ready(MultiTunnelPacketRouter.Target.HOME, home2);
        equal(MultiTunnelPacketRouter.Target.DROP, ledger.route(router, navidrome), "stop beats stale");
        ledger.stop(MultiTunnelPacketRouter.Target.INTERNET);
        ledger.ready(MultiTunnelPacketRouter.Target.INTERNET, net1);
        equal(MultiTunnelPacketRouter.Target.DROP, ledger.route(router, internet), "no post-stop exit");
        try {
            ledger.begin(MultiTunnelPacketRouter.Target.DROP);
            throw new AssertionError("DROP is not a WireGuard session.");
        } catch (IllegalArgumentException expected) { }
        System.out.println("PASS MultiTunnelSessionLedgerTest");
    }
}
